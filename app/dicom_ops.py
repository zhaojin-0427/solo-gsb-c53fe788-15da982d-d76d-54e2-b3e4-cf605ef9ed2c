"""Deterministic DICOM transformation primitives.

Everything in this module is a pure function of (input dataset, policy key):
same input + same policy + same server secret always yields byte-identical
output. UID mapping, date shifting and value hashing are all HMAC-SHA256
derived from a single policy key.
"""
from __future__ import annotations

import hashlib
import hmac
import io
import re
from datetime import datetime, timedelta
from typing import Any, Optional

from PIL import Image
from pydicom.datadict import tag_for_keyword
from pydicom.dataset import Dataset, FileMetaDataset
from pydicom.multival import MultiValue
from pydicom.uid import ExplicitVRLittleEndian

UID_ROOT = "2.25"  # ISO UUID root; mapped UIDs are decimal encodings of 128-bit hashes
IMPLEMENTATION_CLASS_UID = "2.25.80831082754011255466546187597485060871"
IMPLEMENTATION_VERSION_NAME = "DICOMANON10"

VALID_VRS = {
    "AE", "AS", "AT", "CS", "DA", "DS", "DT", "FD", "FL", "IS", "LO", "LT",
    "OB", "OD", "OF", "OL", "OV", "OW", "PN", "SH", "SL", "SQ", "SS", "ST",
    "SV", "TM", "UC", "UI", "UL", "UN", "UR", "US", "UT", "UV",
}

#: UI elements that identify *types*, not *instances* — they must never be remapped.
PRESERVE_UID_KEYWORDS = {
    "SOPClassUID",
    "MediaStorageSOPClassUID",
    "TransferSyntaxUID",
    "ImplementationClassUID",
    "ReferencedSOPClassUID",
    "ReferencedTransferSyntaxUID",
    "CodingSchemeUID",
}

#: (date keyword, time keyword) pairs shifted together so cross-instance
#: deltas are preserved exactly.
DATE_TIME_PAIRS = [
    ("StudyDate", "StudyTime"),
    ("SeriesDate", "SeriesTime"),
    ("AcquisitionDate", "AcquisitionTime"),
    ("ContentDate", "ContentTime"),
    ("InstanceCreationDate", "InstanceCreationTime"),
]
DATETIME_TAGS = ["AcquisitionDateTime"]

_DA_RE = re.compile(r"^\d{8}$")
_TM_RE = re.compile(r"^(\d{2})(\d{2})?(\d{2})?(\.\d{1,6})?$")
_DT_RE = re.compile(r"^\d{4}(\d{2})?(\d{2})?(\d{2})?(\d{2})?(\d{2})?(\.\d{1,6})?([+-]\d{4})?$")
_UI_RE = re.compile(r"^[0-9.]{1,64}$")


class RedactionError(Exception):
    """Raised when pixel redaction cannot be performed."""


# ---------------------------------------------------------------------------
# Value format validation (used to flag illegal VR values in the input)
# ---------------------------------------------------------------------------
def validate_value_format(vr: str, value: str) -> Optional[str]:
    if vr == "DA":
        if not _DA_RE.match(value):
            return "expected format YYYYMMDD"
        try:
            datetime.strptime(value, "%Y%m%d")
        except ValueError:
            return "not a valid calendar date"
    elif vr == "TM":
        m = _TM_RE.match(value)
        if not m:
            return "expected format HH[MM[SS[.FFFFFF]]]"
        hour, minute, second = int(m.group(1)), int(m.group(2) or 0), int(m.group(3) or 0)
        if hour > 23 or minute > 59 or second > 60:
            return "time component out of range"
    elif vr == "DT":
        if not _DT_RE.match(value):
            return "expected format YYYY[MM[DD[HH[MM[SS[.F]]]]]][&ZZXX]"
    elif vr == "UI":
        if not _UI_RE.match(value):
            return "only digits and dots allowed, max 64 characters"
        if value.startswith(".") or value.endswith(".") or ".." in value:
            return "malformed UID"
    return None


# ---------------------------------------------------------------------------
# Deterministic UID mapping
# ---------------------------------------------------------------------------
def _hmac(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


class UIDMapper:
    """Maps any original UID to a deterministic, valid DICOM UID (2.25.<decimal>)."""

    def __init__(self, key: bytes) -> None:
        self._key = key
        self._map: dict[str, str] = {}

    def map(self, uid: str) -> str:
        uid = str(uid).strip()
        if not uid:
            return uid
        mapped = self._map.get(uid)
        if mapped is None:
            number = int.from_bytes(_hmac(self._key, f"UID:{uid}")[:16], "big")
            mapped = f"{UID_ROOT}.{number}"
            self._map[uid] = mapped
        return mapped

    @property
    def mapping(self) -> dict[str, str]:
        return dict(self._map)


def remap_uids(ds: Dataset, mapper: UIDMapper) -> None:
    """Recursively remap every instance-level UI element; class UIDs are preserved."""
    for elem in ds:
        if elem.VR == "UI":
            keyword = elem.keyword
            if keyword in PRESERVE_UID_KEYWORDS or keyword.endswith("ClassUID"):
                continue
            if isinstance(elem.value, MultiValue):
                elem.value = type(elem.value)(mapper.map(v) for v in elem.value if str(v).strip())
            elif elem.value is not None and str(elem.value).strip():
                elem.value = mapper.map(elem.value)
        elif elem.VR == "SQ" and elem.value is not None:
            for item in elem.value:
                remap_uids(item, mapper)


# ---------------------------------------------------------------------------
# Date / time shifting (delta preserving)
# ---------------------------------------------------------------------------
def compute_offset(key: bytes, patient_key: str, max_days: int) -> timedelta:
    """Deterministic per-patient offset: +/-max_days days plus a seconds jitter."""
    digest = _hmac(key, f"DATE:{patient_key}")
    days = int.from_bytes(digest[0:4], "big") % (2 * max_days + 1) - max_days
    seconds = int.from_bytes(digest[4:8], "big") % 86400
    return timedelta(days=days, seconds=seconds)


def _frac_to_micro(frac: Optional[str]) -> int:
    if not frac:
        return 0
    return int(frac[1:].ljust(6, "0"))


def shift_da_tm(da: str, tm: Optional[str], delta: timedelta) -> tuple[str, Optional[str]]:
    base = datetime.strptime(da, "%Y%m%d")
    frac = None
    if tm:
        m = _TM_RE.match(tm)
        if not m:
            raise ValueError(f"invalid TM value {tm!r}")
        frac = m.group(4)
        base = base.replace(
            hour=int(m.group(1)),
            minute=int(m.group(2) or 0),
            second=int(m.group(3) or 0),
            microsecond=_frac_to_micro(frac),
        )
    shifted = base + delta
    new_tm = None
    if tm:
        new_tm = shifted.strftime("%H%M%S")
        if frac:
            new_tm += f".{shifted.microsecond:06d}"
    return shifted.strftime("%Y%m%d"), new_tm


def shift_dt(value: str, delta: timedelta) -> str:
    core, frac, tz = value, "", ""
    m = re.search(r"([+-]\d{4})$", core)
    if m:
        tz, core = m.group(1), core[: m.start()]
    if "." in core:
        core, frac_part = core.split(".", 1)
        frac = "." + frac_part
    digits = core.ljust(14, "0")
    shifted = datetime.strptime(digits, "%Y%m%d%H%M%S") + delta
    return shifted.strftime("%Y%m%d%H%M%S") + frac + tz


def shift_dates(ds: Dataset, delta: timedelta) -> int:
    """Shift all known DA/TM/DT tags by *delta* (recursively). Returns count."""
    count = 0
    for da_kw, tm_kw in DATE_TIME_PAIRS:
        da_elem = ds.get(tag_for_keyword(da_kw))
        if da_elem is None or not str(da_elem.value or "").strip():
            continue
        tm_elem = ds.get(tag_for_keyword(tm_kw)) if tm_kw else None
        tm_value = None
        if tm_elem is not None and str(tm_elem.value or "").strip():
            tm_value = str(tm_elem.value).strip()
        new_da, new_tm = shift_da_tm(str(da_elem.value).strip(), tm_value, delta)
        setattr(ds, da_kw, new_da)
        count += 1
        if tm_value and new_tm:
            setattr(ds, tm_kw, new_tm)
            count += 1
    for kw in DATETIME_TAGS:
        elem = ds.get(tag_for_keyword(kw))
        if elem is not None and str(elem.value or "").strip():
            setattr(ds, kw, shift_dt(str(elem.value).strip(), delta))
            count += 1
    for elem in ds:
        if elem.VR == "SQ" and elem.value is not None:
            for item in elem.value:
                count += shift_dates(item, delta)
    return count


# ---------------------------------------------------------------------------
# Tag actions / private tags
# ---------------------------------------------------------------------------
def hash_value(key: bytes, value: str) -> str:
    return hmac.new(key, f"HASH:{value}".encode("utf-8"), hashlib.sha256).hexdigest()[:16].upper()


def apply_actions(ds: Dataset, actions: dict[str, tuple[str, Any]], counters: dict, key: bytes) -> None:
    """Apply compiled tag actions to *every* dataset level, recursively.

    The same policy covers the top-level dataset and every item dataset that
    survives inside nested sequences (at any depth). When an action removes a
    whole sequence (or empties one), its item datasets are never visited, so
    their children are neither processed nor counted. Each remaining occurrence
    of an actioned tag contributes one to the audit counters.
    """
    for elem in list(ds):
        keyword = elem.keyword
        entry = actions.get(keyword)
        if entry is not None:
            action, value = entry
            if action == "remove":
                del ds[elem.tag]
                counters["tags_removed"] += 1
                continue  # whole subtree is gone: do not descend into it
            if action == "empty":
                counters["tags_emptied"] += 1
                if elem.VR == "SQ":
                    # keep the sequence shell, drop every item (and subtree)
                    setattr(ds, keyword, [])
                    continue
                setattr(ds, keyword, "")
            elif action == "replace":
                setattr(ds, keyword, value)
                counters["tags_replaced"] += 1
            elif action == "hash":
                setattr(ds, keyword, hash_value(key, str(elem.value)))
                counters["tags_hashed"] += 1
        if elem.VR == "SQ" and elem.value is not None:
            for item in elem.value:
                apply_actions(item, actions, counters, key)


def remove_private_tags(ds: Dataset) -> int:
    """Delete all private (odd group) elements, recursively. Returns count."""
    removed = 0
    for elem in list(ds):
        if elem.tag.group % 2 == 1:
            del ds[elem.tag]
            removed += 1
        elif elem.VR == "SQ" and elem.value is not None:
            for item in elem.value:
                removed += remove_private_tags(item)
    return removed


# ---------------------------------------------------------------------------
# Pixel redaction (Pillow-backed)
# ---------------------------------------------------------------------------
def pixel_mode(samples_per_pixel: int, bits_allocated: int, planar_configuration: int) -> Optional[str]:
    """Pillow mode for the supported uncompressed layouts, else None."""
    if samples_per_pixel == 1 and bits_allocated == 8:
        return "L"
    if samples_per_pixel == 1 and bits_allocated == 16:
        return "I;16"  # little-endian 16-bit grayscale
    if samples_per_pixel == 3 and bits_allocated == 8 and planar_configuration == 0:
        return "RGB"
    return None


def redact_pixel_data(ds: Dataset, plan_entries: list[tuple[list[tuple[int, int, int, int]], int]]) -> int:
    """Overwrite every planned box with its fill value, in place.

    ``plan_entries`` is a list of ``(boxes, fill)`` where each box is
    ``(x, y, width, height)`` in pixel coordinates. Returns boxes applied.
    """
    rows, cols = int(ds.Rows), int(ds.Columns)
    spp, bits = int(ds.SamplesPerPixel), int(ds.BitsAllocated)
    frames = int(getattr(ds, "NumberOfFrames", 1) or 1)
    planar = int(getattr(ds, "PlanarConfiguration", 0) or 0)
    mode = pixel_mode(spp, bits, planar)
    if mode is None:
        raise RedactionError(
            f"unsupported pixel layout: SamplesPerPixel={spp}, BitsAllocated={bits}, "
            f"PlanarConfiguration={planar}"
        )
    bytes_per_sample = bits // 8
    frame_len = rows * cols * spp * bytes_per_sample
    raw = bytes(ds.PixelData)
    if len(raw) < frame_len * frames:
        raise RedactionError(
            f"pixel data too short: {len(raw)} bytes, expected at least {frame_len * frames}"
        )
    out = bytearray()
    applied = 0
    for frame in range(frames):
        img = Image.frombytes(mode, (cols, rows), raw[frame * frame_len : (frame + 1) * frame_len])
        for boxes, fill in plan_entries:
            fill_value = (fill, fill, fill) if mode == "RGB" else min(fill, (1 << bits) - 1)
            for x, y, w, h in boxes:
                img.paste(Image.new(mode, (w, h), fill_value), (x, y))
                applied += 1
        out += img.tobytes()
    result = bytes(out)
    if len(result) % 2:  # DICOM requires even-length Pixel Data
        result += b"\x00"
    ds.PixelData = result
    return applied


# ---------------------------------------------------------------------------
# Deterministic encoding
# ---------------------------------------------------------------------------
def dataset_to_bytes(ds: Dataset) -> bytes:
    """Encode a dataset deterministically as Explicit VR Little Endian."""
    meta = FileMetaDataset()
    meta.FileMetaInformationVersion = b"\x00\x01"
    meta.MediaStorageSOPClassUID = str(ds.SOPClassUID)
    meta.MediaStorageSOPInstanceUID = str(ds.SOPInstanceUID)
    meta.TransferSyntaxUID = ExplicitVRLittleEndian
    meta.ImplementationClassUID = IMPLEMENTATION_CLASS_UID
    meta.ImplementationVersionName = IMPLEMENTATION_VERSION_NAME
    ds.file_meta = meta
    ds.preamble = b"\x00" * 128
    ds.is_little_endian = True
    ds.is_implicit_VR = False
    ds.SpecificCharacterSet = "ISO_IR 192"
    buf = io.BytesIO()
    ds.save_as(buf, write_like_original=False)
    return buf.getvalue()
