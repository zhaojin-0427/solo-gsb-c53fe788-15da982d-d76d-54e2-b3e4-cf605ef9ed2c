#!/usr/bin/env python3
"""Generate a deterministic sample DICOM ZIP for trying the API.

Creates ``sample_input.zip`` (default, in the current directory) containing
one study with two series x two instances of synthetic 128x128 16-bit CT
images, complete with fake PHI, a private tag and dates spread over several
days. The UIDs are fixed so examples/redactions.json matches series 1.

Each instance additionally carries:

* a retained multi-level sequence tree
  (``VerifyingObserverSequence`` -> ``OriginalAttributesSequence`` ->
  ``OriginalAttributesSequence``) with PHI, a private tag and a
  ``ReferencedSOPInstanceUID`` at the leaves — demonstrating that tag actions
  and UID remapping recurse into every retained SQ level;
* a ``RequestAttributesSequence`` with PHI nested inside, which the shipped
  ``examples/policy.json`` removes wholesale (its subtree is then neither
  processed nor counted).

The ZIP is written with fixed timestamps/entry order, so regenerating it
yields byte-identical output.

Usage: python scripts/make_sample.py [output.zip] [--instances N]

``--instances N`` generates N instances (default 4) split across the two
series; the default produces exactly the archive described above. Larger
inputs are handy to give a job a multi-second runtime, e.g. when trying out
crash recovery (see README).
"""
from __future__ import annotations

import argparse
import io
import zipfile

from pydicom.dataset import Dataset
from pydicom.dataset import FileDataset, FileMetaDataset
from pydicom.uid import CTImageStorage, ExplicitVRLittleEndian

STUDY_UID = "1.2.826.0.1.3680043.9.7433.1.1"
SERIES_UIDS = [
    ("1.2.826.0.1.3680043.9.7433.1.1.1", "CT HEAD"),
    ("1.2.826.0.1.3680043.9.7433.1.1.2", "CT CHEST"),
]
DATES = [("20200103", "101500"), ("20200103", "101600"), ("20200107", "093000"), ("20200107", "093100")]


def retained_sq_tree(sop_uid: str, all_uids: list):
    """Multi-level SQ tree that survives anonymization (PHI gets recursed into)."""
    referenced_uid = all_uids[(all_uids.index(sop_uid) + 1) % len(all_uids)]
    leaf_ref = Dataset()
    leaf_ref.ReferencedSOPClassUID = CTImageStorage
    leaf_ref.ReferencedSOPInstanceUID = referenced_uid

    leaf = Dataset()
    leaf.PatientName = "Leaf^Patient"
    leaf.InstitutionName = "Leaf Street Clinic"
    leaf.ReferencedSOPSequence = [leaf_ref]

    middle = Dataset()
    middle.PatientName = "History^Patient"
    middle.ReferringPhysicianName = "History^Doctor"
    middle.StudyDescription = "historical study note"
    middle.OriginalAttributesSequence = [leaf]

    top = Dataset()
    top.PatientName = "Observer^Jane"
    top.VerifyingObserverName = "Verifier^Jane"
    top.VerifyingOrganization = "Jane Verification Board"
    top.InstitutionName = "Observer Institute"
    top.add_new(0x00091002, "LO", "observer-private-note")
    top.OriginalAttributesSequence = [middle]
    return [top]


def removed_sq_tree():
    """Nested PHI inside RequestAttributesSequence; policy 1.0 removes this SQ."""
    leaf = Dataset()
    leaf.PatientName = "Request^Leaf"
    leaf.InstitutionName = "Request Clinic"
    middle = Dataset()
    middle.PatientName = "Request^Middle"
    middle.AccessionNumber = "REQ-ACC-0001"
    middle.OriginalAttributesSequence = [leaf]
    top = Dataset()
    top.PatientName = "Request^Top"
    top.RequestingPhysician = "Requesting^Doctor"
    top.OriginalAttributesSequence = [middle]
    return [top]


def make_instance(series_uid, sop_uid, description, date, time, instance_number, all_uids):
    meta = FileMetaDataset()
    meta.MediaStorageSOPClassUID = CTImageStorage
    meta.MediaStorageSOPInstanceUID = sop_uid
    meta.TransferSyntaxUID = ExplicitVRLittleEndian
    meta.ImplementationClassUID = "2.25.1234567890"
    ds = FileDataset("sample", {}, file_meta=meta, preamble=b"\x00" * 128)
    ds.SOPClassUID = CTImageStorage
    ds.SOPInstanceUID = sop_uid
    ds.StudyInstanceUID = STUDY_UID
    ds.SeriesInstanceUID = series_uid
    ds.PatientName = "Doe^John"
    ds.PatientID = "PAT-12345"
    ds.PatientBirthDate = "19750312"
    ds.PatientSex = "M"
    ds.PatientAge = "045Y"
    ds.Modality = "CT"
    ds.StudyDate = date
    ds.StudyTime = time
    ds.SeriesDate = date
    ds.ContentDate = date
    ds.StudyDescription = description
    ds.SeriesDescription = description
    ds.ReferringPhysicianName = "Smith^Alice"
    ds.InstitutionName = "General Hospital"
    ds.AccessionNumber = "ACC-998877"
    ds.StudyID = "S123"
    ds.InstanceNumber = instance_number
    ds.Rows = 128
    ds.Columns = 128
    ds.BitsAllocated = 16
    ds.BitsStored = 16
    ds.HighBit = 15
    ds.SamplesPerPixel = 1
    ds.PhotometricInterpretation = "MONOCHROME2"
    ds.PixelRepresentation = 0
    # synthetic gradient with a bright "annotation" band on the first rows
    pixels = bytearray()
    for row in range(128):
        for col in range(128):
            value = (row * 16 + col) % 2048
            if row < 30:
                value = 4000  # burned-in text area
            pixels += value.to_bytes(2, "little")
    ds.PixelData = bytes(pixels)
    ds.add_new(0x00090010, "LO", "ACME_SCANNER")
    ds.add_new(0x00091001, "LO", "internal-scan-note")
    ds.VerifyingObserverSequence = retained_sq_tree(sop_uid, all_uids)
    ds.RequestAttributesSequence = removed_sq_tree()
    ds.is_little_endian = True
    ds.is_implicit_VR = False
    buf = io.BytesIO()
    ds.save_as(buf, write_like_original=False)
    return buf.getvalue()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate a deterministic sample DICOM ZIP for trying the API."
    )
    parser.add_argument("output", nargs="?", default="sample_input.zip", help="output ZIP path")
    parser.add_argument(
        "--instances",
        type=int,
        default=4,
        help="total number of instances split across the two series (default: 4)",
    )
    args = parser.parse_args()
    if args.instances < 1:
        parser.error("--instances must be >= 1")

    # first series gets the extra instance when the count is odd
    counts = [(args.instances + 1) // 2, args.instances // 2]
    plan = [
        (series_uid, description, [f"{series_uid}.{i}" for i in range(1, counts[idx] + 1)])
        for idx, (series_uid, description) in enumerate(SERIES_UIDS)
    ]
    all_uids = [uid for _, _, uids in plan for uid in uids]

    entries = []
    idx = 0
    for series_idx, (series_uid, description, sop_uids) in enumerate(plan, 1):
        for inst_idx, sop_uid in enumerate(sop_uids, 1):
            date, time = DATES[idx % len(DATES)]
            idx += 1
            payload = make_instance(series_uid, sop_uid, description, date, time, inst_idx, all_uids)
            entries.append((f"series{series_idx}/instance{inst_idx}.dcm", payload))
    with zipfile.ZipFile(args.output, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, payload in entries:
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 0
            info.external_attr = 0o600 << 16
            zf.writestr(info, payload, compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
    print(f"wrote {args.output} ({len(entries)} instances)")
    print(f"  study UID:  {STUDY_UID}")
    for series_uid, description, sop_uids in plan:
        print(f"  series UID: {series_uid} ({description}) -> {len(sop_uids)} instances")


if __name__ == "__main__":
    main()
