"""Versioned anonymization policy: schema, defaults and validation.

A policy is a JSON object, e.g.::

    {
      "version": "1.0",
      "salt": "my-research-project",
      "remove_private_tags": true,
      "strict_references": true,
      "date_shift": {"enabled": true, "max_days": 365},
      "tags": {
        "keep":    ["PatientSex"],
        "empty":   ["InstitutionName"],
        "remove":  ["PatientAddress"],
        "hash":    ["PatientID"],
        "replace": {"ReferringPhysicianName": "ANON^MD"}
      }
    }

The built-in default profile (PS3.15 Annex E inspired subset) always applies;
user entries refine it. ``keep`` whitelists a tag from the default profile,
the other actions add or override. Assigning the same tag to two different
actions, protecting a managed tag, or supplying a value that violates the
tag's VR is reported as a policy conflict.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Optional

from pydicom.datadict import dictionary_VR, tag_for_keyword

SUPPORTED_POLICY_VERSIONS = ["1.0"]

# ---------------------------------------------------------------------------
# Default profile (basic de-identification profile subset)
# ---------------------------------------------------------------------------
DEFAULT_EMPTY_KEYWORDS = [
    "PatientName",
    "PatientBirthDate",
    "PatientBirthTime",
    "OtherPatientIDs",
    "OtherPatientNames",
    "PatientMotherBirthName",
    "PatientAddress",
    "PatientTelephoneNumbers",
    "MedicalRecordLocator",
    "EthnicGroup",
    "Occupation",
    "AdditionalPatientHistory",
    "PatientComments",
    "ReferringPhysicianName",
    "ReferringPhysicianAddress",
    "ReferringPhysicianTelephoneNumbers",
    "PhysiciansOfRecord",
    "PerformingPhysicianName",
    "NameOfPhysiciansReadingStudy",
    "OperatorsName",
    "VerifyingObserverName",
    "VerifyingOrganization",
    "InstitutionName",
    "InstitutionAddress",
    "InstitutionalDepartmentName",
    "StationName",
    "RequestingPhysician",
    "RequestingService",
    "AdmissionID",
    "IssuerOfPatientID",
    "ResponsiblePerson",
    "AccessionNumber",
    "StudyID",
    "StudyDescription",
    "SeriesDescription",
    "ProtocolName",
    "DeviceSerialNumber",
]
DEFAULT_HASH_KEYWORDS = ["PatientID"]
DEFAULT_KEEP_KEYWORDS = ["PatientSex", "PatientAge", "PatientSize", "PatientWeight"]

#: Tags the service manages itself; a policy may not touch them.
PROTECTED_KEYWORDS = {
    "SOPClassUID",
    "SOPInstanceUID",
    "StudyInstanceUID",
    "SeriesInstanceUID",
    "TransferSyntaxUID",
    "SpecificCharacterSet",
    "PixelData",
    "Rows",
    "Columns",
    "BitsAllocated",
    "BitsStored",
    "HighBit",
    "SamplesPerPixel",
    "PhotometricInterpretation",
    "PixelRepresentation",
    "PlanarConfiguration",
    "NumberOfFrames",
}

LIST_ACTIONS = ("keep", "empty", "remove", "hash")

# ---------------------------------------------------------------------------
# VR value validation
# ---------------------------------------------------------------------------
_DA_RE = re.compile(r"^\d{8}$")
_TM_RE = re.compile(r"^\d{2}(\d{2})?(\d{2})?(\.\d{1,6})?$")
_DT_RE = re.compile(r"^\d{4}(\d{2})?(\d{2})?(\d{2})?(\d{2})?(\d{2})?(\.\d{1,6})?([+-]\d{4})?$")
_UI_RE = re.compile(r"^[0-9.]{1,64}$")
_IS_RE = re.compile(r"^[+-]?\d{1,12}$")
_DS_RE = re.compile(r"^[+-]?(\d+(\.\d*)?|\.\d+)([eE][+-]?\d+)?$")
_AS_RE = re.compile(r"^\d{3}[DWMY]$")
_CS_RE = re.compile(r"^[A-Z0-9_ ]{0,16}$")
_TEXT_VRS = {"AE", "LO", "LT", "PN", "SH", "ST", "UC", "UR", "UT"}


def validate_vr_value(vr: str, value: Any) -> Optional[str]:
    """Return an error message if *value* is not representable as *vr*."""
    if value is None:
        return "value must not be null"
    if vr in _TEXT_VRS:
        if not isinstance(value, str):
            return "must be a string"
        if any(ord(c) < 32 for c in value):
            return "control characters are not allowed"
        return None
    if vr == "DA":
        if not isinstance(value, str) or not _DA_RE.match(value):
            return "expected YYYYMMDD"
        import datetime as _dt

        try:
            _dt.datetime.strptime(value, "%Y%m%d")
        except ValueError:
            return "not a valid calendar date"
        return None
    if vr == "TM":
        if not isinstance(value, str) or not _TM_RE.match(value):
            return "expected HH[MM[SS[.FFFFFF]]]"
        return None
    if vr == "DT":
        if not isinstance(value, str) or not _DT_RE.match(value):
            return "expected YYYY[MM[DD[HH[MM[SS[.F]]]]]][&ZZXX]"
        return None
    if vr == "UI":
        if not isinstance(value, str) or not _UI_RE.match(value):
            return "digits and dots only, max 64 characters"
        if value.startswith(".") or value.endswith(".") or ".." in value:
            return "malformed UID"
        return None
    if vr == "IS":
        if isinstance(value, int) and not isinstance(value, bool):
            return None
        if isinstance(value, str) and _IS_RE.match(value):
            return None
        return "expected an integer string (max 12 digits)"
    if vr == "DS":
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            return None
        if isinstance(value, str) and _DS_RE.match(value.strip()):
            return None
        return "expected a decimal number"
    if vr == "AS":
        if not isinstance(value, str) or not _AS_RE.match(value):
            return "expected format NNN[DWMY], e.g. 045Y"
        return None
    if vr == "CS":
        if not isinstance(value, str) or not _CS_RE.match(value):
            return "expected up to 16 uppercase chars/digits/underscore"
        return None
    return None


# ---------------------------------------------------------------------------
# Canonicalisation / hashing
# ---------------------------------------------------------------------------
def canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def policy_sha256(policy: dict) -> str:
    return hashlib.sha256(canonical_json(policy).encode("utf-8")).hexdigest()


def _err(code: str, message: str) -> dict:
    return {"file": None, "code": code, "message": message}


# ---------------------------------------------------------------------------
# Policy validation
# ---------------------------------------------------------------------------
def validate_policy(policy: Any) -> list[dict]:
    """Validate a policy document; returns a list of itemized errors."""
    errors: list[dict] = []
    if not isinstance(policy, dict):
        return [_err("POLICY_INVALID", "policy must be a JSON object")]

    version = policy.get("version")
    if version not in SUPPORTED_POLICY_VERSIONS:
        errors.append(
            _err(
                "POLICY_INVALID",
                f"unsupported policy version {version!r}; supported: {SUPPORTED_POLICY_VERSIONS}",
            )
        )

    tags = policy.get("tags", {})
    if tags is None:
        tags = {}
    if not isinstance(tags, dict):
        errors.append(_err("POLICY_INVALID", "tags must be an object"))
        tags = {}

    assignment: dict[str, str] = {}

    def _claim(kw: str, action: str) -> bool:
        """Register keyword -> action; report conflicts. Returns validity."""
        tag = tag_for_keyword(kw)
        if tag is None:
            errors.append(_err("POLICY_INVALID", f"unknown DICOM keyword {kw!r} in tags.{action}"))
            return False
        if kw in PROTECTED_KEYWORDS and action != "keep":
            errors.append(
                _err(
                    "POLICY_CONFLICT",
                    f"tag {kw} is managed by the anonymizer (UID mapping / pixel handling) "
                    f"and cannot be assigned action '{action}'",
                )
            )
            return False
        if dictionary_VR(tag) == "SQ" and action in ("hash", "replace"):
            errors.append(
                _err(
                    "POLICY_CONFLICT",
                    f"tag {kw} is a sequence (SQ); action '{action}' cannot apply to a "
                    "sequence (use 'remove' to drop it or 'empty' to keep an empty sequence)",
                )
            )
            return False
        prev = assignment.get(kw)
        if prev is not None and prev != action:
            errors.append(
                _err("POLICY_CONFLICT", f"tag {kw} is assigned to both '{prev}' and '{action}'")
            )
            return False
        if prev == action:
            errors.append(_err("POLICY_CONFLICT", f"tag {kw} is listed twice in '{action}'"))
            return False
        assignment[kw] = action
        return True

    for action in LIST_ACTIONS:
        kws = tags.get(action, [])
        if not isinstance(kws, list) or not all(isinstance(k, str) for k in kws):
            errors.append(_err("POLICY_INVALID", f"tags.{action} must be a list of DICOM keywords"))
            continue
        for kw in kws:
            _claim(kw, action)

    replace = tags.get("replace", {})
    if not isinstance(replace, dict):
        errors.append(_err("POLICY_INVALID", "tags.replace must be an object of keyword: value"))
        replace = {}
    for kw, value in replace.items():
        if not _claim(kw, "replace"):
            continue
        vr = dictionary_VR(tag_for_keyword(kw))
        msg = validate_vr_value(vr, value)
        if msg:
            errors.append(
                _err("POLICY_CONFLICT", f"replace value for {kw} (VR {vr}) is invalid: {msg}")
            )

    date_shift = policy.get("date_shift", {})
    if date_shift is None:
        date_shift = {}
    if not isinstance(date_shift, dict):
        errors.append(_err("POLICY_INVALID", "date_shift must be an object"))
        date_shift = {}
    max_days = date_shift.get("max_days", 365)
    if not isinstance(max_days, int) or isinstance(max_days, bool) or not 0 <= max_days <= 3650:
        errors.append(_err("POLICY_INVALID", "date_shift.max_days must be an integer in [0, 3650]"))

    for key in ("remove_private_tags", "strict_references"):
        if key in policy and not isinstance(policy[key], bool):
            errors.append(_err("POLICY_INVALID", f"{key} must be a boolean"))
    if "salt" in policy and not isinstance(policy["salt"], str):
        errors.append(_err("POLICY_INVALID", "salt must be a string"))

    return errors


def compile_actions(policy: dict) -> dict[str, tuple[str, Any]]:
    """Resolve the default profile + user overrides into keyword -> (action, value)."""
    actions: dict[str, tuple[str, Any]] = {}
    for kw in DEFAULT_EMPTY_KEYWORDS:
        actions[kw] = ("empty", None)
    for kw in DEFAULT_HASH_KEYWORDS:
        actions[kw] = ("hash", None)

    tags = policy.get("tags") or {}
    for kw in tags.get("keep", []) or []:
        actions.pop(kw, None)  # whitelist: undo any default action
    for kw in tags.get("empty", []) or []:
        actions[kw] = ("empty", None)
    for kw in tags.get("remove", []) or []:
        actions[kw] = ("remove", None)
    for kw in tags.get("hash", []) or []:
        actions[kw] = ("hash", None)
    for kw, value in (tags.get("replace", {}) or {}).items():
        actions[kw] = ("replace", value)
    return actions


def default_profile_doc() -> dict:
    return {
        "empty": DEFAULT_EMPTY_KEYWORDS,
        "hash": DEFAULT_HASH_KEYWORDS,
        "implicit_keep": DEFAULT_KEEP_KEYWORDS,
        "remove_private_tags": True,
        "strict_references": True,
        "date_shift": {"enabled": True, "max_days": 365},
    }
