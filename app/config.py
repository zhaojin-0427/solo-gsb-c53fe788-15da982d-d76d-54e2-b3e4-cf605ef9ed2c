"""Runtime configuration (environment driven)."""
from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass

#: Default development secret. Override with ANON_SECRET in any real deployment;
#: the secret feeds the HMAC keys behind UID mapping, date shifting and tag
#: hashing, so changing it changes every anonymized output.
DEFAULT_SECRET = "dicom-anon-dev-secret"

#: Domain separation prefix for secret fingerprints. Bumping this version makes
#: every fingerprint (and therefore every fingerprint-scoped job id) change
#: without touching the anonymization key derivation itself.
_FINGERPRINT_PREFIX = b"dicom-anon-secret-fingerprint-v1\n"

#: Number of SHA-256 bytes kept for the fingerprint (hex-encoded in the API).
#: 128 bits is far beyond any practical brute-force/pre-image concern for a
#: deployment-scoped identifier while keeping ids compact.
_FINGERPRINT_BYTES = 16


def secret_fingerprint(secret: str) -> str:
    """Return a non-reversible fingerprint of the configured secret.

    The fingerprint identifies *which* secret scope a job was produced under
    without storing the secret itself: it feeds the idempotent job id and the
    persisted dedup check, so a job anonymized under one ``ANON_SECRET`` is
    never reused as the result of a submission made under another.
    """
    digest = hashlib.sha256(_FINGERPRINT_PREFIX + secret.encode("utf-8")).digest()
    return digest[:_FINGERPRINT_BYTES].hex()


@dataclass(frozen=True)
class Settings:
    data_dir: str
    secret: str
    #: Seconds an executor's lease on a job stays valid without a heartbeat.
    #: A crashed executor stops heartbeating, so its queued/processing jobs
    #: become claimable once the lease lapses (or immediately after a restart,
    #: which invalidates the previous instance's leases outright).
    lease_seconds: float = 30.0
    #: Interval between lease renewals while a job runs.
    heartbeat_seconds: float = 10.0

    @property
    def secret_fp(self) -> str:
        return secret_fingerprint(self.secret)


def get_settings() -> Settings:
    lease = float(os.environ.get("JOB_LEASE_SECONDS", "30"))
    heartbeat = float(os.environ.get("JOB_HEARTBEAT_SECONDS", str(lease / 3)))
    return Settings(
        data_dir=os.environ.get("DATA_DIR", "./data"),
        secret=os.environ.get("ANON_SECRET", DEFAULT_SECRET),
        lease_seconds=lease,
        heartbeat_seconds=heartbeat,
    )
