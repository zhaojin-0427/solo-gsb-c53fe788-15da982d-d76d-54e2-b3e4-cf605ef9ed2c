"""SQLite-backed job store.

Job rows carry an execution *lease* (``lease_owner`` / ``lease_expires``) in
addition to their lifecycle status. The lease is what lets a restarted (or
concurrent) process tell a live executor from a dead one: every state
transition an executor performs is a conditional single-statement UPDATE, so
SQLite itself serializes competing processes and exactly one claimant wins.
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from datetime import datetime, timezone
from typing import Any, Optional

SCHEMA = """
CREATE TABLE IF NOT EXISTS jobs (
    job_id         TEXT PRIMARY KEY,
    status         TEXT NOT NULL,
    created_at     TEXT NOT NULL,
    updated_at     TEXT NOT NULL,
    policy_json    TEXT NOT NULL,
    redactions_json TEXT,
    input_sha256   TEXT NOT NULL,
    secret_fp      TEXT,
    lease_owner    TEXT,
    lease_expires  REAL,
    result_path    TEXT,
    result_sha256  TEXT,
    audit_json     TEXT,
    errors_json    TEXT
);
"""


def _utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class JobStore:
    def __init__(self, db_path: str) -> None:
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock, self._conn:
            self._conn.executescript(SCHEMA)
            self._migrate()

    def _migrate(self) -> None:
        """Upgrade databases created before secret-scoped dedup and leases.

        Pre-rotation rows have no fingerprint. They remain queryable/downloadable
        by their job id, but ``secret_fp IS NULL`` means a fingerprinted lookup
        can never match them, so a legacy result can never be handed out as the
        product of a different secret.

        Rows written before leases existed have ``lease_owner``/``lease_expires``
        NULL; a NULL lease on a queued/processing row is treated as already
        expired, so jobs orphaned by the pre-lease build become resumable too.
        """
        columns = {row["name"] for row in self._conn.execute("PRAGMA table_info(jobs)")}
        if "secret_fp" not in columns:
            self._conn.execute("ALTER TABLE jobs ADD COLUMN secret_fp TEXT")
        if "lease_owner" not in columns:
            self._conn.execute("ALTER TABLE jobs ADD COLUMN lease_owner TEXT")
        if "lease_expires" not in columns:
            self._conn.execute("ALTER TABLE jobs ADD COLUMN lease_expires REAL")

    # ------------------------------------------------------------------
    # Creation / lookup
    # ------------------------------------------------------------------
    def create_if_absent(
        self,
        job_id: str,
        policy: dict,
        redactions: Any,
        input_sha256: str,
        secret_fp: str,
        lease_owner: str,
        lease_expires: float,
    ) -> bool:
        """Insert a queued job already leased to *lease_owner*.

        Returns True iff this call created the row. A False result means a row
        with this primary key already existed (created by a racing process);
        the caller must re-read it and follow the existing-job path.
        """
        now = _utcnow()
        with self._lock, self._conn:
            cur = self._conn.execute(
                "INSERT OR IGNORE INTO jobs (job_id, status, created_at, updated_at, policy_json,"
                " redactions_json, input_sha256, secret_fp, lease_owner, lease_expires)"
                " VALUES (?, 'queued', ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    job_id,
                    now,
                    now,
                    json.dumps(policy),
                    json.dumps(redactions) if redactions is not None else None,
                    input_sha256,
                    secret_fp,
                    lease_owner,
                    lease_expires,
                ),
            )
            return cur.rowcount == 1

    def get(self, job_id: str) -> Optional[dict]:
        with self._lock:
            row = self._conn.execute("SELECT * FROM jobs WHERE job_id = ?", (job_id,)).fetchone()
        return dict(row) if row else None

    def find_scoped(self, job_id: str, secret_fp: str) -> Optional[dict]:
        """Return an existing job only if it was produced under the same secret.

        Matching requires an explicit fingerprint equality; legacy rows with
        ``secret_fp IS NULL`` never match, so they cannot be mistaken for the
        current secret's result even in the face of a truncated-id collision.
        """
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM jobs WHERE job_id = ? AND secret_fp = ?",
                (job_id, secret_fp),
            ).fetchone()
        return dict(row) if row else None

    # ------------------------------------------------------------------
    # Lease arbitration (single-statement conditional UPDATEs)
    # ------------------------------------------------------------------
    def try_claim(self, job_id: str, secret_fp: str, owner: str, lease_expires: float) -> bool:
        """Atomically take over execution rights for an interrupted job.

        Succeeds iff the row is still ``queued`` (no executor ever started) or
        sits in ``processing`` with an expired/absent lease — i.e. the previous
        executor is provably gone. A fresh lease means the job is actively
        being worked on and the claim is refused. Because the UPDATE is one
        statement, concurrent claimants across processes are serialized by
        SQLite and exactly one of them observes ``rowcount == 1``.
        """
        with self._lock, self._conn:
            cur = self._conn.execute(
                "UPDATE jobs SET lease_owner = ?, lease_expires = ?"
                " WHERE job_id = ? AND secret_fp = ?"
                " AND (status = 'queued'"
                "      OR (status = 'processing'"
                "          AND (lease_expires IS NULL OR lease_expires <= ?)))",
                (owner, lease_expires, job_id, secret_fp, time.time()),
            )
            return cur.rowcount == 1

    def begin_processing(self, job_id: str, owner: str, lease_expires: float) -> bool:
        """Flip queued -> processing and refresh the lease, iff *owner* holds it.

        Returns False when the lease was taken over between scheduling and
        execution; the caller must then abort and leave the job to the new
        owner. This is what makes a takeover safe even if the previous owner's
        background task was already queued up.
        """
        with self._lock, self._conn:
            cur = self._conn.execute(
                "UPDATE jobs SET status = 'processing', lease_expires = ?, updated_at = ?"
                " WHERE job_id = ? AND lease_owner = ? AND status IN ('queued', 'processing')",
                (lease_expires, _utcnow(), job_id, owner),
            )
            return cur.rowcount == 1

    def renew_lease(self, job_id: str, owner: str, lease_expires: float) -> bool:
        """Heartbeat: extend the lease while the job runs. False = lease lost."""
        with self._lock, self._conn:
            cur = self._conn.execute(
                "UPDATE jobs SET lease_expires = ?"
                " WHERE job_id = ? AND lease_owner = ? AND status = 'processing'",
                (lease_expires, job_id, owner),
            )
            return cur.rowcount == 1

    def expire_foreign_leases(self, owner: str) -> int:
        """Invalidate every queued/processing lease not held by *owner*.

        Called once at startup: under the single-instance deployment model a
        new process for the same DATA_DIR means the previous instance is gone,
        so its in-flight jobs become claimable immediately instead of only
        after their leases lapse. Live executors are unaffected in practice:
        worst case a wrongly-expired lease is re-acquired by the claimant and
        the deterministic pipeline simply runs twice with identical output.
        """
        with self._lock, self._conn:
            cur = self._conn.execute(
                "UPDATE jobs SET lease_expires = 0"
                " WHERE status IN ('queued', 'processing')"
                " AND (lease_owner IS NULL OR lease_owner != ?)",
                (owner,),
            )
            return cur.rowcount

    # ------------------------------------------------------------------
    # Terminal transitions (lease-guarded)
    # ------------------------------------------------------------------
    def set_failed(self, job_id: str, owner: str, errors: list) -> bool:
        """Mark the job failed, iff *owner* still holds the lease."""
        with self._lock, self._conn:
            cur = self._conn.execute(
                "UPDATE jobs SET status = 'failed', errors_json = ?, updated_at = ?,"
                " lease_owner = NULL, lease_expires = NULL"
                " WHERE job_id = ? AND lease_owner = ? AND status = 'processing'",
                (json.dumps(errors), _utcnow(), job_id, owner),
            )
            return cur.rowcount == 1

    def set_done(self, job_id: str, owner: str, result_path: str, result_sha256: str, audit: dict) -> bool:
        """Mark the job done, iff *owner* still holds the lease.

        The caller must have durably written the result file first: a row is
        only ever marked done after the bytes it points at are complete.
        """
        with self._lock, self._conn:
            cur = self._conn.execute(
                "UPDATE jobs SET status = 'done', result_path = ?, result_sha256 = ?,"
                " audit_json = ?, updated_at = ?, lease_owner = NULL, lease_expires = NULL"
                " WHERE job_id = ? AND lease_owner = ? AND status = 'processing'",
                (result_path, result_sha256, json.dumps(audit), _utcnow(), job_id, owner),
            )
            return cur.rowcount == 1
