"""Core anonymization pipeline.

``anonymize_zip`` is the single entry point. It is all-or-nothing: any
validation error (missing reference, illegal VR, compressed pixels, policy
conflict, ...) aborts the whole job and returns itemized errors; no partial
output archive is ever produced. On success it returns a deterministic output
ZIP plus an audit summary with verifiable SHA-256 hashes.
"""
from __future__ import annotations

import hashlib
import io
import json
import zipfile
from dataclasses import dataclass
from typing import Any, Optional

from pydicom import dcmread
from pydicom.dataelem import RawDataElement
from pydicom.dataset import Dataset
from pydicom.errors import InvalidDicomError
from pydicom.multival import MultiValue
from pydicom.uid import ExplicitVRLittleEndian, ImplicitVRLittleEndian

from . import dicom_ops
from .config import secret_fingerprint
from .policy import canonical_json, compile_actions, policy_sha256, validate_policy

GENERATOR = "dicom-anon-api 1.0.0"

ALLOWED_TRANSFER_SYNTAXES = {str(ImplicitVRLittleEndian), str(ExplicitVRLittleEndian)}
COMPRESSED_PREFIXES = ("1.2.840.10008.1.2.4", "1.2.840.10008.1.2.5")  # JPEG family, RLE
DEFLATED_TS = "1.2.840.10008.1.2.1.99"
BIG_ENDIAN_TS = "1.2.840.10008.1.2.2"


def err(file: Optional[str], code: str, message: str, tag: Optional[str] = None) -> dict:
    item = {"file": file, "code": code, "message": message}
    if tag:
        item["tag"] = tag
    return item


# ---------------------------------------------------------------------------
# Input model
# ---------------------------------------------------------------------------
@dataclass
class Instance:
    zip_path: str
    ds: Dataset
    sop_uid: str
    study_uid: str
    series_uid: str
    patient_key: str
    sort_key: int
    rows: Optional[int]
    columns: Optional[int]
    encoded: bytes = b""


def read_dicom(data: bytes) -> tuple[Optional[Dataset], Optional[str], Optional[str]]:
    """Return (dataset, status, problem). status: 'ok' | 'forced'."""
    try:
        return dcmread(io.BytesIO(data)), "ok", None
    except InvalidDicomError:
        try:
            return dcmread(io.BytesIO(data), force=True), "forced", None
        except Exception:
            return None, None, "not-a-dicom-file"
    except Exception as exc:
        if len(data) > 132 and data[128:132] == b"DICM":
            return None, None, f"corrupt-dicom: {exc}"
        return None, None, "not-a-dicom-file"


def validate_elements(ds: Dataset, name: str) -> list[dict]:
    """Walk every element (recursively) and flag illegal VRs / malformed values.

    Sequences are traversed through their raw item datasets so that an unknown
    VR or malformed value nested inside an SQ item is reported per element
    instead of aborting the whole walk.
    """
    errors: list[dict] = []

    def walk(dataset: Dataset) -> None:
        for tag in list(dataset._dict.keys()):
            raw = dataset._dict[tag]
            is_raw = isinstance(raw, RawDataElement)
            vr = getattr(raw, "VR", None)
            if is_raw and vr not in dicom_ops.VALID_VRS:
                errors.append(
                    err(name, "INVALID_VR", f"element {raw.tag} has unknown VR {vr!r}", tag=str(raw.tag))
                )
                continue
            try:
                elem = dataset[tag]  # force raw -> converted (raises on bad data)
            except Exception as exc:
                errors.append(
                    err(name, "INVALID_DICOM", f"element {raw.tag} cannot be decoded: {exc}", tag=str(raw.tag))
                )
                continue
            if vr in ("DA", "TM", "DT", "UI"):
                values = elem.value if isinstance(elem.value, MultiValue) else [elem.value]
                for value in values:
                    if value is None or str(value) == "":
                        continue
                    problem = dicom_ops.validate_value_format(vr, str(value))
                    if problem:
                        keyword = elem.keyword or str(elem.tag)
                        errors.append(
                            err(
                                name,
                                "INVALID_VALUE",
                                f"{keyword} ({vr}) value {str(value)!r}: {problem}",
                                tag=str(elem.tag),
                            )
                        )
            if elem.VR == "SQ" and elem.value is not None:
                for item in elem.value:
                    walk(item)

    try:
        walk(ds)
    except Exception as exc:
        return [err(name, "INVALID_DICOM", f"cannot iterate dataset elements: {exc}")]
    return errors


def validate_dataset(ds: Dataset, name: str) -> list[dict]:
    errors: list[dict] = []
    ts = None
    if getattr(ds, "file_meta", None) is not None:
        ts = getattr(ds.file_meta, "TransferSyntaxUID", None)
    ts = str(ts) if ts else None
    if ts is None:
        errors.append(err(name, "INVALID_DICOM", "missing TransferSyntaxUID in file meta information"))
    elif ts.startswith(COMPRESSED_PREFIXES) or ts == DEFLATED_TS:
        errors.append(
            err(
                name,
                "COMPRESSED_PIXELS",
                f"compressed transfer syntax {ts} is not supported; "
                "decompress pixel data before submission",
            )
        )
    elif ts not in ALLOWED_TRANSFER_SYNTAXES:
        errors.append(
            err(
                name,
                "UNSUPPORTED_TRANSFER_SYNTAX",
                f"transfer syntax {ts} is not supported "
                "(need Implicit VR or Explicit VR Little Endian)",
            )
        )
    for keyword, label in (
        ("SOPInstanceUID", "SOP Instance UID"),
        ("StudyInstanceUID", "Study Instance UID"),
        ("SeriesInstanceUID", "Series Instance UID"),
        ("SOPClassUID", "SOP Class UID"),
    ):
        value = getattr(ds, keyword, None)
        if value is None or not str(value).strip():
            errors.append(err(name, "MISSING_UID", f"missing required {label} ({keyword})"))
    errors.extend(validate_elements(ds, name))
    return errors


def make_instance(zip_path: str, ds: Dataset) -> Instance:
    try:
        sort_key = int(str(getattr(ds, "InstanceNumber", "")))
    except (TypeError, ValueError):
        sort_key = 2**31 - 1
    rows, cols = getattr(ds, "Rows", None), getattr(ds, "Columns", None)
    return Instance(
        zip_path=zip_path,
        ds=ds,
        sop_uid=str(ds.SOPInstanceUID).strip(),
        study_uid=str(ds.StudyInstanceUID).strip(),
        series_uid=str(ds.SeriesInstanceUID).strip(),
        patient_key=str(getattr(ds, "PatientID", "") or "").strip(),
        sort_key=sort_key,
        rows=int(rows) if rows else None,
        columns=int(cols) if cols else None,
    )


def find_referenced_sop_uids(ds: Dataset) -> list[str]:
    refs: list[str] = []
    for elem in ds.iterall():
        if elem.keyword == "ReferencedSOPInstanceUID" and elem.value:
            values = elem.value if isinstance(elem.value, MultiValue) else [elem.value]
            refs.extend(str(v).strip() for v in values if str(v).strip())
    return refs


# ---------------------------------------------------------------------------
# Redaction rules
# ---------------------------------------------------------------------------
def parse_redactions(redactions: Any) -> tuple[list[dict], list[dict]]:
    rules: list[dict] = []
    errors: list[dict] = []
    if redactions is None:
        return rules, errors
    if not isinstance(redactions, list):
        return [], [err(None, "POLICY_INVALID", "redactions must be a JSON array")]
    for i, rule in enumerate(redactions):
        if not isinstance(rule, dict):
            errors.append(err(None, "POLICY_INVALID", f"redactions[{i}] must be an object"))
            continue
        scope, uid, boxes = rule.get("scope"), rule.get("uid"), rule.get("boxes")
        fill = rule.get("fill", 0)
        ok = True
        if scope not in ("instance", "series", "study"):
            errors.append(
                err(None, "POLICY_INVALID", f"redactions[{i}].scope must be one of instance|series|study")
            )
            ok = False
        if not isinstance(uid, str) or not uid.strip():
            errors.append(err(None, "POLICY_INVALID", f"redactions[{i}].uid must be a non-empty UID string"))
            ok = False
        if not isinstance(boxes, list) or not boxes:
            errors.append(err(None, "POLICY_INVALID", f"redactions[{i}].boxes must be a non-empty array"))
            ok = False
        norm_boxes = []
        if isinstance(boxes, list):
            for b in boxes:
                if not (
                    isinstance(b, list)
                    and len(b) == 4
                    and all(isinstance(v, int) and not isinstance(v, bool) for v in b)
                ):
                    errors.append(
                        err(None, "POLICY_INVALID", f"redactions[{i}] box {b!r} must be [x, y, width, height] integers")
                    )
                    ok = False
                    continue
                x, y, w, h = b
                if x < 0 or y < 0 or w < 1 or h < 1:
                    errors.append(
                        err(None, "POLICY_INVALID", f"redactions[{i}] box {b} has negative origin or non-positive size")
                    )
                    ok = False
                    continue
                norm_boxes.append((x, y, w, h))
        if not isinstance(fill, int) or isinstance(fill, bool) or not 0 <= fill <= 65535:
            errors.append(err(None, "POLICY_INVALID", f"redactions[{i}].fill must be an integer in [0, 65535]"))
            ok = False
        if ok:
            rules.append({"scope": scope, "uid": uid.strip(), "boxes": norm_boxes, "fill": fill})
    return rules, errors


def check_pixel_ready(inst: Instance) -> Optional[dict]:
    ds = inst.ds
    if "PixelData" not in ds:
        return err(inst.zip_path, "PIXEL_DATA_MISSING", "redaction target has no Pixel Data element")
    if inst.rows is None or inst.columns is None:
        return err(inst.zip_path, "PIXEL_DATA_MISSING", "redaction target is missing Rows/Columns")
    spp = int(getattr(ds, "SamplesPerPixel", 1) or 1)
    bits = getattr(ds, "BitsAllocated", None)
    planar = int(getattr(ds, "PlanarConfiguration", 0) or 0)
    if bits is None:
        return err(inst.zip_path, "PIXEL_DATA_MISSING", "redaction target is missing BitsAllocated")
    if dicom_ops.pixel_mode(spp, int(bits), planar) is None:
        return err(
            inst.zip_path,
            "UNSUPPORTED_PIXEL_LAYOUT",
            f"cannot redact SamplesPerPixel={spp}, BitsAllocated={bits}, PlanarConfiguration={planar}; "
            "supported: 8/16-bit grayscale and 8-bit interleaved RGB",
        )
    return None


# ---------------------------------------------------------------------------
# Deterministic packaging
# ---------------------------------------------------------------------------
def build_zip(entries: list[tuple[str, bytes]]) -> bytes:
    """Build a ZIP with fixed timestamps/attributes so output is byte-stable."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        for name, data in entries:
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 0
            info.external_attr = 0o600 << 16
            zf.writestr(info, data, compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
    return buf.getvalue()


# ---------------------------------------------------------------------------
# Main pipeline
# ---------------------------------------------------------------------------
def anonymize_zip(
    zip_bytes: bytes,
    policy: dict,
    redactions: Optional[list],
    secret: str,
) -> tuple[list[dict], Optional[bytes], Optional[dict], list[str]]:
    """Returns (errors, result_zip_bytes, audit, warnings)."""
    warnings: list[str] = []
    errors: list[dict] = validate_policy(policy)
    rules, red_errors = parse_redactions(redactions)
    errors.extend(red_errors)
    if errors:
        return errors, None, None, warnings

    input_sha256 = hashlib.sha256(zip_bytes).hexdigest()
    try:
        zf = zipfile.ZipFile(io.BytesIO(zip_bytes))
    except zipfile.BadZipFile:
        return [err(None, "ZIP_INVALID", "uploaded file is not a valid ZIP archive")], None, None, warnings
    bad_entry = zf.testzip()
    if bad_entry is not None:
        return [err(bad_entry, "ZIP_INVALID", f"ZIP entry {bad_entry!r} failed its CRC check")], None, None, warnings

    # ---- load -------------------------------------------------------------
    instances: list[Instance] = []
    for info in sorted(zf.infolist(), key=lambda i: i.filename):
        if info.is_dir() or info.filename.startswith("__MACOSX"):
            continue
        try:
            data = zf.read(info)
        except Exception as exc:
            errors.append(err(info.filename, "ZIP_INVALID", f"cannot read ZIP entry: {exc}"))
            continue
        ds, status, problem = read_dicom(data)
        if ds is None:
            if problem and problem.startswith("corrupt-dicom"):
                errors.append(err(info.filename, "READ_ERROR", f"file looks like DICOM but cannot be parsed: {problem}"))
            else:
                warnings.append(f"{info.filename}: skipped (not a DICOM file)")
            continue
        if status == "forced":
            warnings.append(f"{info.filename}: missing DICOM preamble; parsed with relaxed reader")
        file_errors = validate_dataset(ds, info.filename)
        if file_errors:
            errors.extend(file_errors)
            continue
        instances.append(make_instance(info.filename, ds))

    if not instances:
        errors.append(err(None, "NO_INSTANCES", "no usable DICOM instances found in the archive"))

    # ---- cross-instance validation ---------------------------------------
    by_sop: dict[str, str] = {}
    for inst in instances:
        other = by_sop.get(inst.sop_uid)
        if other is not None:
            errors.append(
                err(inst.zip_path, "DUPLICATE_INSTANCE", f"SOPInstanceUID {inst.sop_uid} also appears in {other}")
            )
        else:
            by_sop[inst.sop_uid] = inst.zip_path

    if policy.get("strict_references", True):
        sop_set = set(by_sop)
        for inst in instances:
            for ref in find_referenced_sop_uids(inst.ds):
                if ref not in sop_set:
                    errors.append(
                        err(
                            inst.zip_path,
                            "MISSING_REFERENCE",
                            f"referenced SOPInstanceUID {ref} is not present in the archive",
                        )
                    )

    # ---- redaction planning ------------------------------------------------
    plan: dict[str, list[tuple[list, int]]] = {}
    for idx, rule in enumerate(rules):
        if rule["scope"] == "instance":
            targets = [i for i in instances if i.sop_uid == rule["uid"]]
        elif rule["scope"] == "series":
            targets = [i for i in instances if i.series_uid == rule["uid"]]
        else:
            targets = [i for i in instances if i.study_uid == rule["uid"]]
        if not targets:
            errors.append(
                err(
                    None,
                    "REDACTION_TARGET_NOT_FOUND",
                    f"redaction rule {idx}: no instance matches {rule['scope']} UID {rule['uid']}",
                )
            )
            continue
        for target in targets:
            pixel_error = check_pixel_ready(target)
            if pixel_error:
                errors.append(pixel_error)
                continue
            for x, y, w, h in rule["boxes"]:
                if x + w > target.columns or y + h > target.rows:
                    errors.append(
                        err(
                            target.zip_path,
                            "REDACTION_OUT_OF_BOUNDS",
                            f"box [{x}, {y}, {w}, {h}] exceeds image bounds {target.columns}x{target.rows}",
                        )
                    )
            plan.setdefault(target.sop_uid, []).append((rule["boxes"], rule["fill"]))

    if errors:
        return errors, None, None, warnings

    # ---- transform (all-or-nothing, in memory) -----------------------------
    key = hashlib.sha256(f"{secret}|{canonical_json(policy)}".encode("utf-8")).digest()
    secret_fp = secret_fingerprint(secret)
    mapper = dicom_ops.UIDMapper(key)
    actions = compile_actions(policy)
    remove_private = policy.get("remove_private_tags", True)
    shift_cfg = policy.get("date_shift") or {}
    shift_enabled = shift_cfg.get("enabled", True)
    max_days = shift_cfg.get("max_days", 365)
    counters = {
        "tags_removed": 0,
        "tags_emptied": 0,
        "tags_replaced": 0,
        "tags_hashed": 0,
        "private_tags_removed": 0,
        "date_tags_shifted": 0,
        "redaction_boxes_applied": 0,
    }
    offsets: dict[str, Any] = {}
    for inst in instances:
        ds = inst.ds
        # Tag actions run first: a removed/emptied sequence takes its whole
        # subtree away, so UID remapping, private-tag removal and date shifting
        # only see datasets that survive under the same policy.
        dicom_ops.apply_actions(ds, actions, counters, key)
        dicom_ops.remap_uids(ds, mapper)
        if remove_private:
            counters["private_tags_removed"] += dicom_ops.remove_private_tags(ds)
        if shift_enabled:
            offset_key = inst.patient_key or inst.study_uid
            if offset_key not in offsets:
                offsets[offset_key] = dicom_ops.compute_offset(key, offset_key, max_days)
            counters["date_tags_shifted"] += dicom_ops.shift_dates(ds, offsets[offset_key])
        if inst.sop_uid in plan:
            counters["redaction_boxes_applied"] += dicom_ops.redact_pixel_data(ds, plan[inst.sop_uid])
        inst.encoded = dicom_ops.dataset_to_bytes(ds)

    # ---- deterministic Study/Series/Instance packaging ---------------------
    files: list[tuple[str, Instance]] = []
    studies = sorted({i.study_uid for i in instances})
    for study_idx, study_uid in enumerate(studies, 1):
        series_uids = sorted({i.series_uid for i in instances if i.study_uid == study_uid})
        for series_idx, series_uid in enumerate(series_uids, 1):
            members = [i for i in instances if i.study_uid == study_uid and i.series_uid == series_uid]
            members.sort(key=lambda i: (i.sort_key, i.sop_uid))
            for inst_idx, inst in enumerate(members, 1):
                arcname = f"STUDY_{study_idx:04d}/SERIES_{series_idx:04d}/INSTANCE_{inst_idx:05d}.dcm"
                files.append((arcname, inst))

    manifest_files = [
        {
            "path": arcname,
            "sha256": hashlib.sha256(inst.encoded).hexdigest(),
            "study_instance_uid": mapper.map(inst.study_uid),
            "series_instance_uid": mapper.map(inst.series_uid),
            "sop_instance_uid": mapper.map(inst.sop_uid),
        }
        for arcname, inst in files
    ]
    manifest = {
        "format_version": "1.0",
        "generator": GENERATOR,
        "policy_version": policy.get("version"),
        "policy_sha256": policy_sha256(policy),
        "input_sha256": input_sha256,
        "secret_fingerprint": secret_fp,
        "files": manifest_files,
    }
    manifest_bytes = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")
    entries = [("manifest.json", manifest_bytes)] + [(arcname, inst.encoded) for arcname, inst in files]
    result = build_zip(entries)
    result_sha256 = hashlib.sha256(result).hexdigest()

    audit = {
        "generator": GENERATOR,
        "policy_version": policy.get("version"),
        "policy_sha256": policy_sha256(policy),
        "input": {"zip_sha256": input_sha256, "instances": len(instances)},
        "secret_fingerprint": secret_fp,
        "output": {"zip_sha256": result_sha256, "files": manifest_files},
        "summary": {
            "studies": len(studies),
            "series": len({(i.study_uid, i.series_uid) for i in instances}),
            "instances": len(instances),
            "uids_mapped": len(mapper.mapping),
            **counters,
        },
        "date_shift": {
            "enabled": shift_enabled,
            "max_days": max_days,
            "offset_groups": len(offsets),
        },
        "uid_mapping": dict(sorted(mapper.mapping.items())),
        "warnings": warnings,
    }
    return [], result, audit, warnings
