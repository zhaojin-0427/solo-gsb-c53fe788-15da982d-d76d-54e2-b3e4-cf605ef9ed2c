"""API response models."""
from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel


class ErrorItem(BaseModel):
    file: Optional[str] = None
    code: str
    message: str
    tag: Optional[str] = None


class JobCreated(BaseModel):
    job_id: str
    status: str
    status_url: str
    detail: Optional[str] = None


class ResultInfo(BaseModel):
    sha256: str
    size_bytes: Optional[int] = None
    download_url: str


class JobStatus(BaseModel):
    job_id: str
    status: str  # queued | processing | done | failed
    created_at: str
    updated_at: str
    policy_version: Optional[str] = None
    policy_sha256: str
    input_sha256: str
    #: Fingerprint of the ANON_SECRET scope the job was (or will be) processed
    #: under; null only for legacy rows created before fingerprinted dedup.
    secret_fingerprint: Optional[str] = None
    errors: Optional[list[ErrorItem]] = None
    audit: Optional[dict[str, Any]] = None
    result: Optional[ResultInfo] = None
