"""Background job execution."""
from __future__ import annotations

import hashlib
import os
import threading
import time
from typing import Any, Optional

from .engine import anonymize_zip
from .store import JobStore


def _heartbeat_loop(
    store: JobStore,
    job_id: str,
    owner: str,
    lease_seconds: float,
    interval: float,
    stop: threading.Event,
) -> None:
    """Refresh the lease while the job runs.

    This is what lets other processes distinguish a live executor from a dead
    one: a crashed process stops renewing, so its lease lapses and the job
    becomes claimable. The loop ends when the job finishes or when the lease
    was lost to a takeover (the terminal conditional UPDATE will then refuse
    to publish this executor's outcome anyway).
    """
    if interval <= 0:
        return
    while not stop.wait(interval):
        if not store.renew_lease(job_id, owner, time.time() + lease_seconds):
            return


def _write_result_atomically(results_dir: str, job_id: str, payload: bytes) -> str:
    """Write the result ZIP so a crash can never expose a half-written file.

    The bytes land in a job-private temp file, are fsynced, and are then moved
    onto the download path with an atomic rename: readers only ever see the
    complete file or no file at all. A leftover temp file from a crashed
    executor is cleaned up on the next service start.
    """
    final_path = os.path.join(results_dir, f"{job_id}.zip")
    tmp_path = os.path.join(results_dir, f".{job_id}.{os.getpid()}.tmp")
    with open(tmp_path, "wb") as fh:
        fh.write(payload)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp_path, final_path)
    return final_path


def process_job(
    store: JobStore,
    results_dir: str,
    secret: str,
    job_id: str,
    owner: str,
    lease_seconds: float,
    heartbeat_seconds: float,
    zip_bytes: bytes,
    policy: dict,
    redactions: Optional[list],
) -> None:
    """Run the anonymization pipeline; persist outcome in the job store.

    The pipeline is all-or-nothing: the result file is only written after the
    whole archive has been transformed successfully, so a failed job never
    leaves partial output behind.

    Execution is lease-guarded end to end so an interrupted job can be safely
    resumed by a later process:

    * ``begin_processing`` confirms this executor still holds the lease before
      any work happens (a takeover in the meantime aborts the run);
    * a heartbeat thread keeps the lease fresh while the engine runs;
    * the result ZIP is written atomically (temp file + rename) and the row is
      marked done only afterwards, so a crash mid-write can neither expose a
      truncated file nor mark the job done;
    * terminal updates are conditional on still holding the lease — if the
      job was taken over, the new owner's identical deterministic run is the
      one that gets published.
    """
    if not store.begin_processing(job_id, owner, time.time() + lease_seconds):
        return  # lease lost before work started; the new owner runs the job
    stop = threading.Event()
    heartbeat = threading.Thread(
        target=_heartbeat_loop,
        args=(store, job_id, owner, lease_seconds, heartbeat_seconds, stop),
        name=f"job-heartbeat-{job_id[:8]}",
        daemon=True,
    )
    heartbeat.start()
    try:
        try:
            errors, result, audit, _warnings = anonymize_zip(zip_bytes, policy, redactions, secret)
        except Exception as exc:  # defensive: report, never emit partial output
            store.set_failed(
                job_id,
                owner,
                [{"file": None, "code": "INTERNAL_ERROR", "message": f"{type(exc).__name__}: {exc}"}],
            )
            return
        if errors:
            store.set_failed(job_id, owner, errors)
            return
        assert result is not None and audit is not None
        path = _write_result_atomically(results_dir, job_id, result)
        store.set_done(job_id, owner, path, hashlib.sha256(result).hexdigest(), audit)
    finally:
        stop.set()
