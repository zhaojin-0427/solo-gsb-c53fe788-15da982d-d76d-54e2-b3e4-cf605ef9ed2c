"""End-to-end and unit tests for the anonymization API."""
from __future__ import annotations

import hashlib
import io
import json
import os
import socket
import subprocess
import sys
import time
import zipfile
from datetime import datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from pydicom import dcmread
from pydicom.dataset import Dataset, FileDataset, FileMetaDataset
from pydicom.uid import CTImageStorage, ExplicitVRLittleEndian, JPEGBaseline

from app.config import Settings, secret_fingerprint
from app.dicom_ops import UIDMapper, compute_offset
from app.engine import anonymize_zip
from app.main import compute_job_id, create_app
from app.policy import canonical_json
from app.store import JobStore

SECRET = "test-secret"
SECRET_B = "rotated-secret"
BASE_POLICY = {
    "version": "1.0",
    "salt": "unit-test",
    "date_shift": {"enabled": True, "max_days": 365},
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def make_dcm(
    study_uid,
    series_uid,
    sop_uid,
    *,
    patient_id="PAT-001",
    patient_name="Doe^John",
    study_date="20200101",
    study_time="120000",
    modality="CT",
    rows=64,
    cols=64,
    bits=8,
    pixel_value=255,
    instance_number=1,
    transfer_syntax=ExplicitVRLittleEndian,
    with_private=False,
    referenced_uid=None,
    nested_sq=None,
    omit=(),
):
    meta = FileMetaDataset()
    meta.MediaStorageSOPClassUID = CTImageStorage
    meta.MediaStorageSOPInstanceUID = sop_uid
    meta.TransferSyntaxUID = transfer_syntax
    meta.ImplementationClassUID = "2.25.999"
    ds = FileDataset("mem", {}, file_meta=meta, preamble=b"\x00" * 128)
    ds.SOPClassUID = CTImageStorage
    ds.SOPInstanceUID = sop_uid
    ds.StudyInstanceUID = study_uid
    ds.SeriesInstanceUID = series_uid
    ds.PatientName = patient_name
    ds.PatientID = patient_id
    ds.PatientBirthDate = "19800101"
    ds.PatientSex = "M"
    ds.Modality = modality
    ds.StudyDate = study_date
    ds.StudyTime = study_time
    ds.SeriesDate = study_date
    ds.ContentDate = study_date
    ds.ReferringPhysicianName = "Smith^Alice"
    ds.InstitutionName = "General Hospital"
    ds.AccessionNumber = "ACC123"
    ds.StudyID = "STUDY1"
    ds.InstanceNumber = instance_number
    ds.Rows = rows
    ds.Columns = cols
    ds.BitsAllocated = bits
    ds.BitsStored = bits
    ds.HighBit = bits - 1
    ds.SamplesPerPixel = 1
    ds.PhotometricInterpretation = "MONOCHROME2"
    ds.PixelRepresentation = 0
    if bits == 8:
        ds.PixelData = bytes([pixel_value & 0xFF]) * (rows * cols)
    else:
        ds.PixelData = (pixel_value & 0xFFFF).to_bytes(2, "little") * (rows * cols)
    if transfer_syntax not in (ExplicitVRLittleEndian,):
        # compressed/encapsulated syntaxes require encapsulated pixel data
        from pydicom.encaps import encapsulate

        ds.PixelData = encapsulate([ds.PixelData])
    if with_private:
        ds.add_new(0x00090010, "LO", "ACME")
        ds.add_new(0x00091001, "LO", "SECRET-INFO")
    if referenced_uid:
        ref = Dataset()
        ref.ReferencedSOPClassUID = CTImageStorage
        ref.ReferencedSOPInstanceUID = referenced_uid
        ds.ReferencedSOPSequence = [ref]
    if nested_sq is not None:
        ds.VerifyingObserverSequence = nested_sq
    for keyword in omit:
        if keyword in ds:
            del ds[keyword]
    ds.is_little_endian = True
    ds.is_implicit_VR = False
    buf = io.BytesIO()
    ds.save_as(buf, write_like_original=False)
    return buf.getvalue()


def make_zip(files: dict) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in files.items():
            zf.writestr(name, data)
    return buf.getvalue()


def make_nested_sq(referenced_uid=None):
    """A multi-level SQ tree carrying PHI (and optionally a UID reference)
    at several depths, including a private tag inside an item dataset:

    VerifyingObserverSequence[0]
      PatientName / InstitutionName / VerifyingObserverName  (depth 1)
      private creator-style tag (odd group)
      OriginalAttributesSequence[0]                           (depth 2)
        PatientName / ReferringPhysicianName
        OriginalAttributesSequence[0]                         (depth 3)
          PatientName / InstitutionName
          ReferencedSOPSequence[0] -> referenced_uid          (depth 4)
    """
    leaf = Dataset()
    leaf.PatientName = "Leaf^Patient"
    leaf.InstitutionName = "Leaf Clinic"
    if referenced_uid:
        leaf_ref = Dataset()
        leaf_ref.ReferencedSOPClassUID = CTImageStorage
        leaf_ref.ReferencedSOPInstanceUID = referenced_uid
        leaf.ReferencedSOPSequence = [leaf_ref]

    middle = Dataset()
    middle.PatientName = "Middle^Patient"
    middle.ReferringPhysicianName = "Middle^Doctor"
    middle.OriginalAttributesSequence = [leaf]

    top = Dataset()
    top.PatientName = "Observer^Patient"
    top.InstitutionName = "Top Clinic"
    top.VerifyingObserverName = "Observer^Verifier"
    top.add_new(0x00091002, "LO", "SQ-SECRET")
    top.OriginalAttributesSequence = [middle]
    return [top]


@pytest.fixture()
def client(tmp_path):
    app = create_app(Settings(data_dir=str(tmp_path), secret=SECRET))
    with TestClient(app) as test_client:
        yield test_client


def submit(client, zip_bytes, policy, redactions=None):
    data = {"policy": json.dumps(policy)}
    if redactions is not None:
        data["redactions"] = json.dumps(redactions)
    response = client.post(
        "/jobs",
        files={"file": ("input.zip", zip_bytes, "application/zip")},
        data=data,
    )
    assert response.status_code in (200, 202), response.text
    return response.json()["job_id"]


def get_job(client, job_id):
    response = client.get(f"/jobs/{job_id}")
    assert response.status_code == 200, response.text
    return response.json()


def download(client, job_id):
    response = client.get(f"/jobs/{job_id}/download")
    assert response.status_code == 200, response.text
    return response.content


def read_output_instances(zip_bytes):
    zf = zipfile.ZipFile(io.BytesIO(zip_bytes))
    out = {}
    for name in zf.namelist():
        if name.endswith(".dcm"):
            out[name] = dcmread(io.BytesIO(zf.read(name)))
    return out


def three_instance_zip():
    study, series_a, series_b = "1.2.3.1", "1.2.3.2", "1.2.3.3"
    files = {
        "b/ct2.dcm": make_dcm(study, series_a, "1.2.3.11", study_date="20200105", instance_number=2),
        "a/ct1.dcm": make_dcm(study, series_a, "1.2.3.10", study_date="20200101", instance_number=1),
        "c/mr1.dcm": make_dcm(study, series_b, "1.2.3.12", study_date="20200103", instance_number=1, modality="MR"),
    }
    return make_zip(files)


def policy_key(policy):
    return hashlib.sha256(f"{SECRET}|{canonical_json(policy)}".encode("utf-8")).digest()


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------
def test_happy_path_anonymizes_and_audits(client):
    job_id = submit(client, three_instance_zip(), BASE_POLICY)
    status = get_job(client, job_id)
    assert status["status"] == "done"
    assert status["policy_version"] == "1.0"

    audit = status["audit"]
    assert audit["summary"]["studies"] == 1
    assert audit["summary"]["series"] == 2
    assert audit["summary"]["instances"] == 3
    assert audit["summary"]["tags_emptied"] > 0
    assert audit["summary"]["tags_hashed"] == 3  # PatientID per instance
    assert audit["date_shift"]["enabled"] is True

    result_zip = download(client, job_id)
    assert hashlib.sha256(result_zip).hexdigest() == status["result"]["sha256"]
    assert hashlib.sha256(result_zip).hexdigest() == audit["output"]["zip_sha256"]

    zf = zipfile.ZipFile(io.BytesIO(result_zip))
    names = zf.namelist()
    assert names[0] == "manifest.json"
    dcms = [n for n in names if n.endswith(".dcm")]
    assert dcms == [
        "STUDY_0001/SERIES_0001/INSTANCE_00001.dcm",
        "STUDY_0001/SERIES_0001/INSTANCE_00002.dcm",
        "STUDY_0001/SERIES_0002/INSTANCE_00001.dcm",
    ]
    manifest = json.loads(zf.read("manifest.json"))
    assert len(manifest["files"]) == 3
    for entry in manifest["files"]:
        payload = zf.read(entry["path"])
        assert hashlib.sha256(payload).hexdigest() == entry["sha256"]

    mapper = UIDMapper(policy_key(BASE_POLICY))
    offset = compute_offset(policy_key(BASE_POLICY), "PAT-001", 365)
    expected_dates = {
        (datetime.strptime(d, "%Y%m%d") + offset).strftime("%Y%m%d")
        for d in ("20200101", "20200105", "20200103")
    }
    seen_dates = set()
    for ds in read_output_instances(result_zip).values():
        # PHI cleared
        assert str(getattr(ds, "PatientName", "")) == ""
        assert str(getattr(ds, "PatientBirthDate", "")) == ""
        assert str(getattr(ds, "ReferringPhysicianName", "")) == ""
        assert str(getattr(ds, "InstitutionName", "")) == ""
        assert "AccessionNumber" not in ds or str(ds.AccessionNumber) == ""
        # PatientID hashed, not plaintext
        assert str(ds.PatientID) != "PAT-001"
        assert len(str(ds.PatientID)) == 16
        # deterministic UID mapping, consistent with file meta
        assert str(ds.StudyInstanceUID) == mapper.map("1.2.3.1")
        assert str(ds.SOPInstanceUID).startswith("2.25.")
        assert str(ds.file_meta.MediaStorageSOPInstanceUID) == str(ds.SOPInstanceUID)
        assert str(ds.file_meta.TransferSyntaxUID) == str(ExplicitVRLittleEndian)
        # non-PHI attributes survive
        assert ds.Modality in ("CT", "MR")
        assert str(ds.PatientSex) == "M"
        seen_dates.add(str(ds.StudyDate))
    # dates shifted by the expected deterministic offset, deltas preserved
    assert seen_dates == expected_dates


def test_date_delta_preserved_exactly(client):
    study, series = "1.5.1", "1.5.2"
    files = {
        "d1.dcm": make_dcm(study, series, "1.5.10", study_date="20200101", instance_number=1),
        "d2.dcm": make_dcm(study, series, "1.5.11", study_date="20200111", instance_number=2),
    }
    job_id = submit(client, make_zip(files), BASE_POLICY)
    assert get_job(client, job_id)["status"] == "done"
    instances = read_output_instances(download(client, job_id))
    dates = sorted(
        datetime.strptime(str(ds.StudyDate), "%Y%m%d") for ds in instances.values()
    )
    assert (dates[1] - dates[0]).days == 10


def test_pixel_redaction_burns_box(client):
    files = {"img.dcm": make_dcm("1.9.1", "1.9.2", "1.9.3", rows=64, cols=64, pixel_value=200)}
    redactions = [{"scope": "instance", "uid": "1.9.3", "boxes": [[10, 10, 20, 20]], "fill": 0}]
    job_id = submit(client, make_zip(files), BASE_POLICY, redactions)
    status = get_job(client, job_id)
    assert status["status"] == "done"
    assert status["audit"]["summary"]["redaction_boxes_applied"] == 1
    (ds,) = read_output_instances(download(client, job_id)).values()
    pixels = ds.PixelData
    for row in range(64):
        for col in range(64):
            value = pixels[row * 64 + col]
            if 10 <= row < 30 and 10 <= col < 30:
                assert value == 0, f"pixel ({col},{row}) not redacted"
            else:
                assert value == 200, f"pixel ({col},{row}) unexpectedly modified"


def test_pixel_redaction_16bit(client):
    files = {"img16.dcm": make_dcm("1.10.1", "1.10.2", "1.10.3", rows=32, cols=32, bits=16, pixel_value=4000)}
    redactions = [{"scope": "series", "uid": "1.10.2", "boxes": [[0, 0, 8, 8]], "fill": 100}]
    job_id = submit(client, make_zip(files), BASE_POLICY, redactions)
    assert get_job(client, job_id)["status"] == "done"
    (ds,) = read_output_instances(download(client, job_id)).values()
    pixels = ds.PixelData
    for row in range(32):
        for col in range(32):
            value = int.from_bytes(pixels[(row * 32 + col) * 2 : (row * 32 + col) * 2 + 2], "little")
            assert value == (100 if row < 8 and col < 8 else 4000)


def test_private_tags_removed(client):
    files = {"p.dcm": make_dcm("1.11.1", "1.11.2", "1.11.3", with_private=True)}
    job_id = submit(client, make_zip(files), BASE_POLICY)
    status = get_job(client, job_id)
    assert status["status"] == "done"
    assert status["audit"]["summary"]["private_tags_removed"] >= 2
    (ds,) = read_output_instances(download(client, job_id)).values()
    assert all(elem.tag.group % 2 == 0 for elem in ds)


def test_referenced_uid_remapped_consistently(client):
    study, series = "1.12.1", "1.12.2"
    files = {
        "a.dcm": make_dcm(study, series, "1.12.10", instance_number=1),
        "b.dcm": make_dcm(study, series, "1.12.11", instance_number=2, referenced_uid="1.12.10"),
    }
    job_id = submit(client, make_zip(files), BASE_POLICY)
    assert get_job(client, job_id)["status"] == "done"
    mapper = UIDMapper(policy_key(BASE_POLICY))
    instances = read_output_instances(download(client, job_id))
    refs = [
        str(ds.ReferencedSOPSequence[0].ReferencedSOPInstanceUID)
        for ds in instances.values()
        if "ReferencedSOPSequence" in ds
    ]
    assert refs == [mapper.map("1.12.10")]


# ---------------------------------------------------------------------------
# Nested SQ items: default + explicit tag actions at every dataset level
# ---------------------------------------------------------------------------
def _assert_no_nested_phi(ds):
    """No default-profile PHI value may survive at any retained SQ depth."""
    phi_keywords = ("PatientName", "InstitutionName", "ReferringPhysicianName",
                    "VerifyingObserverName", "VerifyingOrganization")
    for elem in ds.iterall():
        assert elem.VR != "PN" or not str(elem.value or "").strip(), (elem.tag, elem.value)
        if elem.keyword in phi_keywords:
            assert not str(elem.value or "").strip(), (elem.keyword, elem.value)
        if elem.tag.group % 2 == 1:
            raise AssertionError(f"private tag survived inside sequence: {elem.tag}")


def test_default_actions_reach_all_sq_levels(client):
    study, series = "1.30.1", "1.30.2"
    files = {
        "a.dcm": make_dcm(
            study, series, "1.30.10", instance_number=1,
            nested_sq=make_nested_sq(referenced_uid="1.30.11"),
        ),
        "b.dcm": make_dcm(
            study, series, "1.30.11", instance_number=2,
            nested_sq=make_nested_sq(),
        ),
    }
    job_id = submit(client, make_zip(files), BASE_POLICY)
    status = get_job(client, job_id)
    assert status["status"] == "done", status
    summary = status["audit"]["summary"]
    # the nested tree contributes PatientName/InstitutionName/... occurrences on
    # three levels; counts reflect every processed occurrence, not just tops
    assert summary["tags_emptied"] >= 10
    # the in-SQ private tag and two top-level-less private tags are all removed
    assert summary["private_tags_removed"] >= 2

    instances = read_output_instances(download(client, job_id))
    mapper = UIDMapper(policy_key(BASE_POLICY))
    for ds in instances.values():
        _assert_no_nested_phi(ds)
        # hierarchy / sequence shells survive
        seq = ds.VerifyingObserverSequence
        assert len(seq) == 1
        assert len(seq[0].OriginalAttributesSequence) == 1
        assert len(seq[0].OriginalAttributesSequence[0].OriginalAttributesSequence) == 1
    # nested UID references remap consistently to their mapped instances
    a = [ds for ds in instances.values() if str(ds.SOPInstanceUID) == mapper.map("1.30.10")][0]
    leaf = a.VerifyingObserverSequence[0].OriginalAttributesSequence[0].OriginalAttributesSequence[0]
    assert str(leaf.ReferencedSOPSequence[0].ReferencedSOPInstanceUID) == mapper.map("1.30.11")
    # class UIDs inside sequences are preserved, not remapped
    assert str(leaf.ReferencedSOPSequence[0].ReferencedSOPClassUID) == str(CTImageStorage)


def make_removed_sq_tree(extra_uid):
    """3-level SQ tree with PHI, a private tag and an otherwise-unseen UI."""
    leaf = Dataset()
    leaf.PatientName = "Leaf^Patient"
    leaf.InstitutionName = "Leaf Clinic"
    leaf.DeviceUID = extra_uid
    leaf.add_new(0x00091003, "LO", "PRIVATE-IN-SQ")
    middle = Dataset()
    middle.PatientName = "Mid^Patient"
    middle.OriginalAttributesSequence = [leaf]
    top = Dataset()
    top.PatientName = "Top^Patient"
    top.OriginalAttributesSequence = [middle]
    return [top]


def test_removed_sequence_subtree_is_not_processed_or_counted(client):
    study, series = "1.31.1", "1.31.2"
    extra_uid = "1.31.999"

    def build():
        files = {
            "a.dcm": make_dcm(study, series, "1.31.10", instance_number=1),
            "b.dcm": make_dcm(study, series, "1.31.11", instance_number=2),
        }
        out = {}
        for name, payload in files.items():
            ds = dcmread(io.BytesIO(payload))
            ds.RequestAttributesSequence = make_removed_sq_tree(extra_uid)
            buf = io.BytesIO()
            ds.save_as(buf, write_like_original=False)
            out[name] = buf.getvalue()
        return make_zip(out)

    payload = build()
    control_id = submit(client, payload, BASE_POLICY)
    control = get_job(client, control_id)
    assert control["status"] == "done"

    remove_policy = dict(BASE_POLICY, tags={"remove": ["RequestAttributesSequence"]})
    job_id = submit(client, payload, remove_policy)
    status = get_job(client, job_id)
    assert status["status"] == "done", status
    removed_output = read_output_instances(download(client, job_id))
    assert all("RequestAttributesSequence" not in ds for ds in removed_output.values())

    cs, rs = control["audit"]["summary"], status["audit"]["summary"]
    # sequence itself counted once per instance as removed ...
    assert rs["tags_removed"] == 2
    # ... but its subtree is neither processed nor counted
    assert rs["tags_emptied"] < cs["tags_emptied"]
    assert rs["uids_mapped"] < cs["uids_mapped"]
    assert rs["private_tags_removed"] < cs["private_tags_removed"]
    assert extra_uid not in status["audit"]["uid_mapping"]
    assert extra_uid in control["audit"]["uid_mapping"]
    # removing the SQ changes the bytes, which stay deterministic
    from app.engine import anonymize_zip
    e1, z1, a1, _ = anonymize_zip(payload, remove_policy, None, SECRET)
    e2, z2, a2, _ = anonymize_zip(payload, remove_policy, None, SECRET)
    assert e1 == e2 == [] and z1 == z2 and a1 == a2


def test_explicit_actions_reach_all_sq_levels(client):
    study, series = "1.32.1", "1.32.2"
    policy = dict(
        BASE_POLICY,
        tags={
            "empty": ["Manufacturer"],
            "hash": ["DeviceID"],
            "replace": {"PerformingPhysicianName": "DOC^ANON"},
        },
    )

    def item_with_explicit_tags():
        item = Dataset()
        item.Manufacturer = "ACME"
        item.DeviceID = "DEV-42"
        item.PerformingPhysicianName = "Real^Doc"
        return item

    files = {"d.dcm": make_dcm(study, series, "1.32.10")}
    ds = dcmread(io.BytesIO(files["d.dcm"]))
    ds.Manufacturer = "ACME"
    ds.DeviceID = "DEV-42"
    ds.PerformingPhysicianName = "Real^Doc"
    top_item = item_with_explicit_tags()
    nested_item = item_with_explicit_tags()
    # depth 2 item, then depth 3 item
    deeper = item_with_explicit_tags()
    nested_item.OriginalAttributesSequence = [deeper]
    top_item.OriginalAttributesSequence = [nested_item]
    ds.VerifyingObserverSequence = [top_item]
    buf = io.BytesIO()
    ds.save_as(buf, write_like_original=False)
    files = {"d.dcm": buf.getvalue()}

    job_id = submit(client, make_zip(files), policy)
    status = get_job(client, job_id)
    assert status["status"] == "done", status
    summary = status["audit"]["summary"]
    # 1 top-level + 3 nested occurrences (top_item, nested_item, deeper)
    assert summary["tags_emptied"] >= 4
    assert summary["tags_hashed"] >= 4
    assert summary["tags_replaced"] >= 4

    (out,) = read_output_instances(download(client, job_id)).values()

    def check_level(d):
        assert str(d.Manufacturer) == ""
        assert len(str(d.DeviceID)) == 16 and str(d.DeviceID) != "DEV-42"
        assert str(d.PerformingPhysicianName) == "DOC^ANON"

    check_level(out)
    lvl1 = out.VerifyingObserverSequence[0]
    lvl2 = lvl1.OriginalAttributesSequence[0]
    lvl3 = lvl2.OriginalAttributesSequence[0]
    check_level(lvl1)
    check_level(lvl2)
    check_level(lvl3)


def test_empty_sq_action_keeps_empty_sequence(client):
    files = {
        "r.dcm": make_dcm("1.33.1", "1.33.2", "1.33.10", referenced_uid="1.33.11"),
        "t.dcm": make_dcm("1.33.1", "1.33.2", "1.33.11"),
    }
    policy = dict(BASE_POLICY, tags={"empty": ["ReferencedSOPSequence"]})
    job_id = submit(client, make_zip(files), policy)
    status = get_job(client, job_id)
    assert status["status"] == "done", status
    instances = read_output_instances(download(client, job_id))
    ref_ds = [ds for ds in instances.values() if "ReferencedSOPSequence" in ds][0]
    assert list(ref_ds.ReferencedSOPSequence) == []


def test_illegal_vr_inside_sq_rejected_per_item(client):
    meta = FileMetaDataset()
    meta.MediaStorageSOPClassUID = CTImageStorage
    meta.MediaStorageSOPInstanceUID = "1.34.10"
    meta.TransferSyntaxUID = ExplicitVRLittleEndian
    ds = FileDataset("m", {}, file_meta=meta, preamble=b"\x00" * 128)
    ds.is_little_endian, ds.is_implicit_VR = True, False
    ds.SOPClassUID = CTImageStorage
    ds.SOPInstanceUID = "1.34.10"
    ds.StudyInstanceUID = "1.34.1"
    ds.SeriesInstanceUID = "1.34.2"
    ds.PatientID = "p"
    item = Dataset()
    item.InstitutionName = "SQVRCLINIC"
    ds.VerifyingObserverSequence = [item]
    buf = io.BytesIO()
    ds.save_as(buf, write_like_original=False)
    raw = buf.getvalue()
    marker = raw.find(b"SQVRCLINIC")
    assert raw[marker - 4 : marker - 2] == b"LO"
    patched = raw[: marker - 4] + b"XX" + raw[marker - 2 :]

    job_id = submit(client, make_zip({"bad_sq.dcm": patched}), BASE_POLICY)
    status = get_job(client, job_id)
    assert status["status"] == "failed"
    assert any(
        e["code"] == "INVALID_VR" and e["file"] == "bad_sq.dcm"
        and e.get("tag") == "(0008, 0080)"
        for e in status["errors"]
    )
    assert client.get(f"/jobs/{job_id}/download").status_code == 409


def test_illegal_value_inside_sq_rejected_per_item(client):
    item = Dataset()
    item.ContentDate = "20201340"
    ds = dcmread(io.BytesIO(make_dcm("1.35.1", "1.35.2", "1.35.10")))
    ds.VerifyingObserverSequence = [item]
    buf = io.BytesIO()
    ds.save_as(buf, write_like_original=False)
    job_id = submit(client, make_zip({"bad.dcm": buf.getvalue()}), BASE_POLICY)
    status = get_job(client, job_id)
    assert status["status"] == "failed"
    assert any(
        e["code"] == "INVALID_VALUE" and e["file"] == "bad.dcm" and e.get("tag")
        for e in status["errors"]
    )


def test_policy_conflict_for_sequence_actions(client):
    policy = dict(
        BASE_POLICY,
        tags={"hash": ["RequestAttributesSequence"],
              "replace": {"ReferencedSOPSequence": "not-a-sequence"}},
    )
    job_id = submit(client, three_instance_zip(), policy)
    status = get_job(client, job_id)
    assert status["status"] == "failed"
    assert sum(1 for e in status["errors"] if e["code"] == "POLICY_CONFLICT") >= 2
    assert client.get(f"/jobs/{job_id}/download").status_code == 409


# ---------------------------------------------------------------------------
# Determinism / idempotency
# ---------------------------------------------------------------------------
def test_same_input_same_job_and_bytes(client):
    payload = three_instance_zip()
    job_a = submit(client, payload, BASE_POLICY)
    job_b = submit(client, payload, BASE_POLICY)
    assert job_a == job_b
    status = get_job(client, job_a)
    assert status["status"] == "done"
    assert hashlib.sha256(download(client, job_a)).hexdigest() == status["result"]["sha256"]


def test_engine_is_byte_deterministic():
    payload = three_instance_zip()
    errors1, result1, audit1, _ = anonymize_zip(payload, BASE_POLICY, None, SECRET)
    errors2, result2, audit2, _ = anonymize_zip(payload, BASE_POLICY, None, SECRET)
    assert errors1 == errors2 == []
    assert result1 == result2
    assert audit1 == audit2


def test_different_policy_changes_output():
    payload = three_instance_zip()
    other_policy = dict(BASE_POLICY, salt="other-project")
    _, result1, _, _ = anonymize_zip(payload, BASE_POLICY, None, SECRET)
    _, result2, _, _ = anonymize_zip(payload, other_policy, None, SECRET)
    assert result1 != result2


# ---------------------------------------------------------------------------
# Secret rotation: dedup scope must match the secret the engine uses
# ---------------------------------------------------------------------------
@pytest.fixture()
def rotating_apps(tmp_path):
    """Two app instances sharing one persistent data dir, as a restart after
    rotating ANON_SECRET would."""

    def make(secret):
        app = create_app(Settings(data_dir=str(tmp_path), secret=secret))
        return TestClient(app)

    client_a = make(SECRET)
    client_b = make(SECRET_B)
    with client_a, client_b:
        yield client_a, client_b


def test_job_id_includes_secret_scope():
    payload = three_instance_zip()
    digest = hashlib.sha256(payload).hexdigest()
    id_a = compute_job_id(digest, BASE_POLICY, None, secret_fingerprint(SECRET))
    id_b = compute_job_id(digest, BASE_POLICY, None, secret_fingerprint(SECRET_B))
    assert id_a != id_b
    # fingerprint is a non-reversible digest, not the plaintext secret
    assert SECRET not in secret_fingerprint(SECRET)
    assert secret_fingerprint(SECRET) != secret_fingerprint(SECRET_B)
    # same secret resubmits keep the same id
    assert compute_job_id(digest, BASE_POLICY, None, secret_fingerprint(SECRET)) == id_a


def test_secret_rotation_creates_independent_job_and_result(rotating_apps):
    client_a, client_b = rotating_apps
    payload = three_instance_zip()

    # first submission under secret A
    resp_a1 = client_a.post(
        "/jobs",
        files={"file": ("input.zip", payload, "application/zip")},
        data={"policy": json.dumps(BASE_POLICY)},
    )
    assert resp_a1.status_code == 202
    id_a = resp_a1.json()["job_id"]
    status_a = get_job(client_a, id_a)
    assert status_a["status"] == "done"
    assert status_a["secret_fingerprint"] == secret_fingerprint(SECRET)
    zip_a = download(client_a, id_a)
    sha_a = hashlib.sha256(zip_a).hexdigest()
    assert status_a["result"]["sha256"] == sha_a

    # identical resubmit under the same secret reuses the job
    resp_a2 = client_a.post(
        "/jobs",
        files={"file": ("input.zip", payload, "application/zip")},
        data={"policy": json.dumps(BASE_POLICY)},
    )
    assert resp_a2.status_code == 200
    assert resp_a2.json()["job_id"] == id_a

    # restart with ANON_SECRET=B and resubmit verbatim: new job, new id
    resp_b = client_b.post(
        "/jobs",
        files={"file": ("input.zip", payload, "application/zip")},
        data={"policy": json.dumps(BASE_POLICY)},
    )
    assert resp_b.status_code == 202, resp_b.text
    id_b = resp_b.json()["job_id"]
    assert id_b != id_a

    status_b = get_job(client_b, id_b)
    assert status_b["status"] == "done"
    assert status_b["secret_fingerprint"] == secret_fingerprint(SECRET_B)
    zip_b = download(client_b, id_b)
    sha_b = hashlib.sha256(zip_b).hexdigest()

    # independent audit and hash: B must not have received A's bytes
    assert sha_b != sha_a
    assert status_b["audit"]["output"]["zip_sha256"] == sha_b
    assert status_b["audit"]["secret_fingerprint"] == secret_fingerprint(SECRET_B)

    # the output was genuinely produced under B
    _, expected_b, audit_b, _ = anonymize_zip(payload, BASE_POLICY, None, SECRET_B)
    assert zip_b == expected_b
    assert sha_b == hashlib.sha256(expected_b).hexdigest()

    # old job remains queryable and downloadable after rotation, still A's bytes
    old = client_b.get(f"/jobs/{id_a}")
    assert old.status_code == 200
    assert old.json()["status"] == "done"
    assert old.json()["secret_fingerprint"] == secret_fingerprint(SECRET)
    legacy_dl = client_b.get(f"/jobs/{id_a}/download")
    assert legacy_dl.status_code == 200
    assert hashlib.sha256(legacy_dl.content).hexdigest() == sha_a

    # manifest of each result carries its own secret scope
    def manifest_fp(zbytes):
        return json.loads(zipfile.ZipFile(io.BytesIO(zbytes)).read("manifest.json"))[
            "secret_fingerprint"
        ]

    assert manifest_fp(zip_a) == secret_fingerprint(SECRET)
    assert manifest_fp(zip_b) == secret_fingerprint(SECRET_B)


def test_legacy_unfingerprinted_job_is_never_reused_after_rotation(tmp_path):
    """A row written by the pre-fingerprint build (secret_fp NULL) stays
    fetchable but cannot satisfy a new submission under any secret."""
    from app.store import JobStore

    db = JobStore(str(tmp_path / "jobs.db"))
    legacy_id = "a" * 32
    with db._conn:  # simulate an old-version row: no fingerprint
        db._conn.execute(
            "INSERT INTO jobs (job_id, status, created_at, updated_at, policy_json,"
            " redactions_json, input_sha256, secret_fp) VALUES (?, 'done', 't', 't', '{}', NULL, ?, NULL)",
            (legacy_id, "0" * 64),
        )

    # direct lookup/download of the old id still works
    assert db.get(legacy_id) is not None
    assert db.get(legacy_id)["secret_fp"] is None
    # scoped lookups never bind it to a fingerprinted submission
    assert db.find_scoped(legacy_id, secret_fingerprint(SECRET)) is None
    assert db.find_scoped(legacy_id, secret_fingerprint(SECRET_B)) is None


def test_old_database_is_migrated_on_start(tmp_path):
    """A SQLite file created by the pre-fingerprint schema migrates and keeps
    its legacy rows queryable."""
    import sqlite3

    db_path = str(tmp_path / "jobs.db")
    conn = sqlite3.connect(db_path)
    conn.execute(
        "CREATE TABLE jobs (job_id TEXT PRIMARY KEY, status TEXT NOT NULL, created_at TEXT,"
        " updated_at TEXT, policy_json TEXT NOT NULL, redactions_json TEXT, input_sha256 TEXT,"
        " result_path TEXT, result_sha256 TEXT, audit_json TEXT, errors_json TEXT)"
    )
    conn.execute(
        "INSERT INTO jobs VALUES (?, 'done', 't', 't', '{}', NULL, ?, NULL, NULL, NULL, NULL)",
        ("deadbeef" * 4, "0" * 64),
    )
    conn.commit()
    conn.close()

    from app.store import JobStore

    store = JobStore(db_path)
    row = store.get("deadbeef" * 4)
    assert row is not None and row["secret_fp"] is None
    assert store.find_scoped("deadbeef" * 4, secret_fingerprint(SECRET)) is None


# ---------------------------------------------------------------------------
# Itemized failures (no partial output)
# ---------------------------------------------------------------------------
def test_compressed_pixels_rejected(client):
    files = {"c.dcm": make_dcm("1.20.1", "1.20.2", "1.20.3", transfer_syntax=JPEGBaseline)}
    job_id = submit(client, make_zip(files), BASE_POLICY)
    status = get_job(client, job_id)
    assert status["status"] == "failed"
    assert any(e["code"] == "COMPRESSED_PIXELS" and e["file"] == "c.dcm" for e in status["errors"])
    assert client.get(f"/jobs/{job_id}/download").status_code == 409


def test_missing_reference_rejected(client):
    files = {"r.dcm": make_dcm("1.21.1", "1.21.2", "1.21.3", referenced_uid="9.9.9")}
    job_id = submit(client, make_zip(files), BASE_POLICY)
    status = get_job(client, job_id)
    assert status["status"] == "failed"
    assert any(e["code"] == "MISSING_REFERENCE" and "9.9.9" in e["message"] for e in status["errors"])


def test_missing_required_uid_rejected(client):
    files = {"m.dcm": make_dcm("1.22.1", "1.22.2", "1.22.3", omit=("SeriesInstanceUID",))}
    job_id = submit(client, make_zip(files), BASE_POLICY)
    status = get_job(client, job_id)
    assert status["status"] == "failed"
    assert any(e["code"] == "MISSING_UID" for e in status["errors"])


def test_duplicate_instance_rejected(client):
    files = {
        "x.dcm": make_dcm("1.23.1", "1.23.2", "1.23.3"),
        "y.dcm": make_dcm("1.23.1", "1.23.2", "1.23.3"),
    }
    job_id = submit(client, make_zip(files), BASE_POLICY)
    status = get_job(client, job_id)
    assert status["status"] == "failed"
    assert any(e["code"] == "DUPLICATE_INSTANCE" for e in status["errors"])


def test_illegal_vr_value_rejected(client):
    files = {"bad.dcm": make_dcm("1.24.1", "1.24.2", "1.24.3", study_date="20201340")}
    job_id = submit(client, make_zip(files), BASE_POLICY)
    status = get_job(client, job_id)
    assert status["status"] == "failed"
    assert any(e["code"] == "INVALID_VALUE" and e["tag"] for e in status["errors"])


def test_policy_conflict_rejected(client):
    policy = dict(BASE_POLICY, tags={"keep": ["PatientName"], "remove": ["PatientName"]})
    job_id = submit(client, three_instance_zip(), policy)
    status = get_job(client, job_id)
    assert status["status"] == "failed"
    assert any(e["code"] == "POLICY_CONFLICT" for e in status["errors"])


def test_policy_cannot_touch_managed_tags(client):
    policy = dict(BASE_POLICY, tags={"remove": ["StudyInstanceUID"]})
    job_id = submit(client, three_instance_zip(), policy)
    status = get_job(client, job_id)
    assert status["status"] == "failed"
    assert any(e["code"] == "POLICY_CONFLICT" for e in status["errors"])


def test_bad_replace_value_rejected(client):
    policy = dict(BASE_POLICY, tags={"replace": {"PatientBirthDate": "not-a-date"}})
    job_id = submit(client, three_instance_zip(), policy)
    status = get_job(client, job_id)
    assert status["status"] == "failed"
    assert any(e["code"] == "POLICY_CONFLICT" for e in status["errors"])


def test_unsupported_policy_version_rejected(client):
    job_id = submit(client, three_instance_zip(), {"version": "99.0"})
    status = get_job(client, job_id)
    assert status["status"] == "failed"
    assert any(e["code"] == "POLICY_INVALID" for e in status["errors"])


def test_redaction_out_of_bounds_rejected(client):
    files = {"img.dcm": make_dcm("1.25.1", "1.25.2", "1.25.3", rows=64, cols=64)}
    redactions = [{"scope": "instance", "uid": "1.25.3", "boxes": [[60, 60, 10, 10]]}]
    job_id = submit(client, make_zip(files), BASE_POLICY, redactions)
    status = get_job(client, job_id)
    assert status["status"] == "failed"
    assert any(e["code"] == "REDACTION_OUT_OF_BOUNDS" for e in status["errors"])


def test_redaction_target_not_found(client):
    redactions = [{"scope": "instance", "uid": "8.8.8", "boxes": [[0, 0, 5, 5]]}]
    job_id = submit(client, three_instance_zip(), BASE_POLICY, redactions)
    status = get_job(client, job_id)
    assert status["status"] == "failed"
    assert any(e["code"] == "REDACTION_TARGET_NOT_FOUND" for e in status["errors"])


def test_invalid_zip_rejected(client):
    job_id = submit(client, b"this is not a zip file", BASE_POLICY)
    status = get_job(client, job_id)
    assert status["status"] == "failed"
    assert any(e["code"] == "ZIP_INVALID" for e in status["errors"])


def test_multiple_errors_reported_together(client):
    files = {
        "bad1.dcm": make_dcm("1.26.1", "1.26.2", "1.26.3", study_date="20201340"),
        "bad2.dcm": make_dcm("1.26.1", "1.26.2", "1.26.4", transfer_syntax=JPEGBaseline),
    }
    job_id = submit(client, make_zip(files), BASE_POLICY)
    status = get_job(client, job_id)
    assert status["status"] == "failed"
    codes = {e["code"] for e in status["errors"]}
    assert {"INVALID_VALUE", "COMPRESSED_PIXELS"} <= codes


# ---------------------------------------------------------------------------
# Misc API behaviour
# ---------------------------------------------------------------------------
def test_unknown_job_returns_404(client):
    assert client.get("/jobs/does-not-exist").status_code == 404


def test_invalid_policy_json_returns_400(client):
    response = client.post(
        "/jobs",
        files={"file": ("input.zip", three_instance_zip(), "application/zip")},
        data={"policy": "{not json"},
    )
    assert response.status_code == 400


def test_healthz_and_policies(client):
    assert client.get("/healthz").json() == {"status": "ok"}
    policies = client.get("/policies").json()
    assert policies["supported_versions"] == ["1.0"]
    assert "empty" in policies["default_profile"]


# ---------------------------------------------------------------------------
# Crash recovery: interrupted jobs resume on resubmission
# ---------------------------------------------------------------------------
def plant_interrupted_job(
    tmp_path,
    content,
    policy,
    redactions=None,
    *,
    status="queued",
    lease_expires=None,
    owner="dead-worker-1",
):
    """Simulate a job record left behind by a process that died mid-flight.

    The record is written exactly as the live API would have written it up to
    the point of the crash: queued (created but never picked up) or processing
    (executor started, then vanished), with the dead worker's lease attached.
    """
    store = JobStore(str(tmp_path / "jobs.db"))
    input_sha256 = hashlib.sha256(content).hexdigest()
    fp = secret_fingerprint(SECRET)
    job_id = compute_job_id(input_sha256, policy, redactions, fp)
    assert store.create_if_absent(
        job_id, policy, redactions, input_sha256, fp, owner, time.time() + 30
    )
    if status == "processing":
        assert store.begin_processing(
            job_id, owner, lease_expires if lease_expires is not None else time.time() + 30
        )
    return job_id


def resubmit(tmp_path, payload, policy, redactions=None):
    """Start a fresh service instance on the same data dir and resubmit."""
    app = create_app(Settings(data_dir=str(tmp_path), secret=SECRET))
    client = TestClient(app)
    data = {"policy": json.dumps(policy)}
    if redactions is not None:
        data["redactions"] = json.dumps(redactions)
    response = client.post(
        "/jobs",
        files={"file": ("input.zip", payload, "application/zip")},
        data=data,
    )
    return client, response


def test_interrupted_queued_job_resumed_on_resubmit(tmp_path):
    """Process died after recording the job but before executing it."""
    payload = three_instance_zip()
    job_id = plant_interrupted_job(tmp_path, payload, BASE_POLICY, status="queued")

    client, response = resubmit(tmp_path, payload, BASE_POLICY)
    assert response.status_code == 200
    body = response.json()
    assert body["job_id"] == job_id  # original id is reused
    assert "resumed" in body["detail"]

    status = get_job(client, job_id)
    assert status["status"] == "done"
    result = download(client, job_id)
    assert hashlib.sha256(result).hexdigest() == status["result"]["sha256"]
    # the resumed run produces exactly what an uninterrupted run would
    errors, expected, _, _ = anonymize_zip(payload, BASE_POLICY, None, SECRET)
    assert errors == []
    assert result == expected


def test_interrupted_processing_job_resumed_after_lease_expiry(tmp_path):
    """Process died mid-execution; its lease has lapsed by resubmit time."""
    payload = three_instance_zip()
    job_id = plant_interrupted_job(
        tmp_path, payload, BASE_POLICY, status="processing", lease_expires=time.time() - 5
    )

    client, response = resubmit(tmp_path, payload, BASE_POLICY)
    assert response.status_code == 200
    assert response.json()["job_id"] == job_id
    status = get_job(client, job_id)
    assert status["status"] == "done"
    _, expected, _, _ = anonymize_zip(payload, BASE_POLICY, None, SECRET)
    assert download(client, job_id) == expected


def test_restart_invalidates_previous_instance_leases(tmp_path):
    """A fresh service instance on the same DATA_DIR may claim the previous
    instance's in-flight jobs immediately, without waiting out the lease."""
    payload = three_instance_zip()
    # lease still "fresh" (would only expire far in the future) ...
    job_id = plant_interrupted_job(
        tmp_path, payload, BASE_POLICY, status="processing", lease_expires=time.time() + 3600
    )
    # ... but the resubmit goes to a *new* service instance (restart), which
    # invalidates the dead instance's leases at startup
    client, response = resubmit(tmp_path, payload, BASE_POLICY)
    assert response.status_code == 200
    assert response.json()["job_id"] == job_id
    assert get_job(client, job_id)["status"] == "done"


def test_active_job_with_fresh_lease_is_not_taken_over(tmp_path):
    """A live executor's job must not be reclaimed by a resubmission."""
    payload = three_instance_zip()
    app = create_app(Settings(data_dir=str(tmp_path), secret=SECRET))
    client = TestClient(app)
    # plant the record *after* app startup so the startup invalidation does
    # not touch it: this simulates another live instance mid-execution
    job_id = plant_interrupted_job(
        tmp_path, payload, BASE_POLICY, status="processing", lease_expires=time.time() + 300
    )

    response = client.post(
        "/jobs",
        files={"file": ("input.zip", payload, "application/zip")},
        data={"policy": json.dumps(BASE_POLICY)},
    )
    assert response.status_code == 200
    assert response.json()["job_id"] == job_id
    # not claimed, not re-executed: still processing under the original owner
    assert get_job(client, job_id)["status"] == "processing"
    record = JobStore(str(tmp_path / "jobs.db")).get(job_id)
    assert record["lease_owner"] == "dead-worker-1"
    assert record["lease_expires"] > time.time()


def test_resumed_job_runs_with_recorded_inputs(tmp_path):
    """The takeover executes exactly what the record describes: the persisted
    policy/redactions plus the freshly uploaded (hash-verified) ZIP bytes."""
    files = {"img.dcm": make_dcm("1.9.1", "1.9.2", "1.9.3", rows=64, cols=64, pixel_value=200)}
    payload = make_zip(files)
    redactions = [{"scope": "instance", "uid": "1.9.3", "boxes": [[10, 10, 20, 20]], "fill": 0}]
    job_id = plant_interrupted_job(tmp_path, payload, BASE_POLICY, redactions, status="queued")

    client, response = resubmit(tmp_path, payload, BASE_POLICY, redactions)
    assert response.status_code == 200
    assert response.json()["job_id"] == job_id
    status = get_job(client, job_id)
    assert status["status"] == "done"
    assert status["audit"]["summary"]["redaction_boxes_applied"] == 1
    (ds,) = read_output_instances(download(client, job_id)).values()
    assert ds.PixelData[10 * 64 + 10] == 0  # redaction box was applied
    assert ds.PixelData[0] == 200


def test_resubmit_with_mismatched_input_is_rejected(tmp_path):
    """A record whose stored input hash does not match the uploaded bytes must
    never be resumed with those bytes (truncated-id collision defense)."""
    payload = three_instance_zip()
    job_id = plant_interrupted_job(tmp_path, payload, BASE_POLICY, status="queued")
    store = JobStore(str(tmp_path / "jobs.db"))
    with store._conn:
        store._conn.execute(
            "UPDATE jobs SET input_sha256 = ? WHERE job_id = ?", ("0" * 64, job_id)
        )

    _, response = resubmit(tmp_path, payload, BASE_POLICY)
    assert response.status_code == 409
    # and the job was not executed with the wrong input
    assert JobStore(str(tmp_path / "jobs.db")).get(job_id)["status"] == "queued"


def test_interrupted_result_write_leaves_no_partial_output(tmp_path):
    """A crash during result publication must not expose a half-written file:
    the stale temp file is cleaned up and the resumed job downloads complete."""
    payload = three_instance_zip()
    job_id = plant_interrupted_job(
        tmp_path, payload, BASE_POLICY, status="processing", lease_expires=time.time() - 5
    )
    results_dir = tmp_path / "results"
    results_dir.mkdir(exist_ok=True)
    stale_tmp = results_dir / f".{job_id}.1234.tmp"
    stale_tmp.write_bytes(b"half-written-result")

    client, response = resubmit(tmp_path, payload, BASE_POLICY)
    assert response.status_code == 200
    assert get_job(client, job_id)["status"] == "done"
    _, expected, _, _ = anonymize_zip(payload, BASE_POLICY, None, SECRET)
    assert download(client, job_id) == expected
    assert not stale_tmp.exists()  # cleaned up at startup
    # the only artifact at the download path is the complete file
    assert (results_dir / f"{job_id}.zip").read_bytes() == expected


def test_failed_job_resubmission_keeps_existing_semantics(tmp_path):
    """A terminally failed job is not re-executed on resubmission."""
    payload = make_zip({"bad.dcm": make_dcm("1.24.1", "1.24.2", "1.24.3", study_date="20201340")})
    app = create_app(Settings(data_dir=str(tmp_path), secret=SECRET))
    client = TestClient(app)
    job_id = submit(client, payload, BASE_POLICY)
    assert get_job(client, job_id)["status"] == "failed"

    response = client.post(
        "/jobs",
        files={"file": ("input.zip", payload, "application/zip")},
        data={"policy": json.dumps(BASE_POLICY)},
    )
    assert response.status_code == 200
    assert response.json()["job_id"] == job_id
    assert response.json()["status"] == "failed"
    assert get_job(client, job_id)["status"] == "failed"


def test_old_database_is_migrated_with_lease_columns(tmp_path):
    """A SQLite file created by the pre-lease schema gains the lease columns,
    and its orphaned queued row (NULL lease) becomes claimable on resubmit."""
    import sqlite3

    payload = three_instance_zip()
    input_sha256 = hashlib.sha256(payload).hexdigest()
    fp = secret_fingerprint(SECRET)
    job_id = compute_job_id(input_sha256, BASE_POLICY, None, fp)

    db_path = str(tmp_path / "jobs.db")
    conn = sqlite3.connect(db_path)
    conn.execute(
        "CREATE TABLE jobs (job_id TEXT PRIMARY KEY, status TEXT NOT NULL, created_at TEXT,"
        " updated_at TEXT, policy_json TEXT NOT NULL, redactions_json TEXT, input_sha256 TEXT,"
        " result_path TEXT, result_sha256 TEXT, audit_json TEXT, errors_json TEXT)"
    )
    conn.execute(
        "INSERT INTO jobs VALUES (?, 'queued', 't', 't', ?, NULL, ?, NULL, NULL, NULL, NULL)",
        (job_id, json.dumps(BASE_POLICY), input_sha256),
    )
    conn.commit()
    conn.close()

    # pre-lease rows have no secret fingerprint, so scoped dedup cannot match
    # them; attach the current scope as the rotation-aware writer would have
    store = JobStore(db_path)
    assert store.get(job_id)["lease_owner"] is None
    with store._conn:
        store._conn.execute("UPDATE jobs SET secret_fp = ? WHERE job_id = ?", (fp, job_id))

    client, response = resubmit(tmp_path, payload, BASE_POLICY)
    assert response.status_code == 200
    assert response.json()["job_id"] == job_id
    assert get_job(client, job_id)["status"] == "done"


# ---------------------------------------------------------------------------
# Crash recovery across a real process restart (SIGKILL -> restart -> resume)
# ---------------------------------------------------------------------------
def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _wait_ready(port: int, timeout: float = 30.0) -> None:
    import httpx

    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if httpx.get(f"http://127.0.0.1:{port}/healthz", timeout=2).status_code == 200:
                return
        except Exception:
            pass
        time.sleep(0.2)
    raise RuntimeError("server did not become ready")


def _start_server(data_dir, port, secret):
    env = dict(
        os.environ,
        DATA_DIR=str(data_dir),
        ANON_SECRET=secret,
        JOB_LEASE_SECONDS="5",
        JOB_HEARTBEAT_SECONDS="1",
    )
    return subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "app.main:app",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
        ],
        env=env,
        cwd=str(Path(__file__).resolve().parent.parent),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


@pytest.mark.parametrize("instances", [150])
def test_crash_recovery_across_process_restart(tmp_path, instances):
    """End to end: SIGKILL the server mid-job, restart on the same DATA_DIR
    and ANON_SECRET, resubmit verbatim, and get a complete downloadable result
    under the original job id."""
    import httpx

    files = {
        f"inst/{i:04d}.dcm": make_dcm("9.9.1", "9.9.2", f"9.9.3.{i}", instance_number=i)
        for i in range(instances)
    }
    payload = make_zip(files)
    port = _free_port()

    proc = _start_server(tmp_path / "data", port, SECRET)
    try:
        _wait_ready(port)
        resp = httpx.post(
            f"http://127.0.0.1:{port}/jobs",
            files={"file": ("input.zip", payload, "application/zip")},
            data={"policy": json.dumps(BASE_POLICY)},
            timeout=60,
        )
        assert resp.status_code == 202
        job_id = resp.json()["job_id"]
        # resubmitting while the job is actively running reuses the job
        # (HTTP 200) and does not spawn a competing execution
        resp = httpx.post(
            f"http://127.0.0.1:{port}/jobs",
            files={"file": ("input.zip", payload, "application/zip")},
            data={"policy": json.dumps(BASE_POLICY)},
            timeout=60,
        )
        assert resp.status_code == 200
        assert resp.json()["job_id"] == job_id
        # the job must be in flight (not finished) when we kill the server
        status = httpx.get(f"http://127.0.0.1:{port}/jobs/{job_id}", timeout=5).json()
        assert status["status"] in ("queued", "processing"), status
    finally:
        proc.kill()
        proc.wait()

    proc = _start_server(tmp_path / "data", port, SECRET)
    try:
        _wait_ready(port)
        # verbatim resubmission: same id, and the interrupted job is resumed
        resp = httpx.post(
            f"http://127.0.0.1:{port}/jobs",
            files={"file": ("input.zip", payload, "application/zip")},
            data={"policy": json.dumps(BASE_POLICY)},
            timeout=60,
        )
        assert resp.status_code == 200
        assert resp.json()["job_id"] == job_id

        deadline = time.time() + 90
        while True:
            status = httpx.get(f"http://127.0.0.1:{port}/jobs/{job_id}", timeout=5).json()
            if status["status"] == "done":
                break
            assert status["status"] in ("queued", "processing"), status
            assert time.time() < deadline, "job did not recover in time"
            time.sleep(0.5)

        dl = httpx.get(f"http://127.0.0.1:{port}/jobs/{job_id}/download", timeout=30)
        assert dl.status_code == 200
        assert hashlib.sha256(dl.content).hexdigest() == status["result"]["sha256"]
        # byte-identical to what an uninterrupted run would have produced
        errors, expected, _, _ = anonymize_zip(payload, BASE_POLICY, None, SECRET)
        assert errors == []
        assert dl.content == expected
    finally:
        proc.kill()
        proc.wait()
