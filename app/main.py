"""FastAPI application: POST /jobs, GET /jobs/{id}, GET /jobs/{id}/download."""
from __future__ import annotations

import hashlib
import json
import os
import socket
import threading
import time
import uuid
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import BackgroundTasks, FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse, JSONResponse

from .config import Settings, get_settings
from .models import JobCreated, JobStatus
from .policy import SUPPORTED_POLICY_VERSIONS, canonical_json, default_profile_doc, policy_sha256
from .store import JobStore
from .worker import process_job

DESCRIPTION = """\
Anonymize multi-series DICOM ZIP archives for research use.

* Deterministic Study/Series/Instance UID mapping (same input + same policy
  => byte-identical output)
* Standard + private PHI removal, delta-preserving date shifting
* Pixel redaction boxes burned into the pixel data, re-encoded output
* Itemized error reporting (missing references, illegal VRs, compressed
  pixels, policy conflicts) with all-or-nothing semantics
* Crash-safe execution: interrupted jobs resume on resubmission under their
  original id
* Audit summary with verifiable SHA-256 hashes
"""


def compute_job_id(
    input_sha256: str, policy: dict, redactions: Optional[list], secret_fp: str
) -> str:
    """Idempotent job id: identical submissions under the same secret scope
    map to the same job.

    The secret fingerprint is part of the id because the anonymized bytes are a
    function of ``ANON_SECRET`` (HMAC UID mapping, date shifting, tag hashing).
    Only a non-reversible fingerprint is ever used, never the secret itself, so
    rotating the secret yields an independent job/audit/result while old job
    ids remain fetchable (they are separate primary keys).
    """
    digest = hashlib.sha256()
    digest.update(b"job-scope-v1\n")
    digest.update(secret_fp.encode("utf-8"))
    digest.update(b"|")
    digest.update(input_sha256.encode("utf-8"))
    digest.update(b"|")
    digest.update(canonical_json(policy).encode("utf-8"))
    digest.update(b"|")
    digest.update(canonical_json(redactions).encode("utf-8"))
    return digest.hexdigest()[:32]


def job_status_payload(record: dict) -> dict:
    policy = json.loads(record["policy_json"])
    payload: dict = {
        "job_id": record["job_id"],
        "status": record["status"],
        "created_at": record["created_at"],
        "updated_at": record["updated_at"],
        "policy_version": policy.get("version"),
        "policy_sha256": policy_sha256(policy),
        "input_sha256": record["input_sha256"],
        "secret_fingerprint": record["secret_fp"],
    }
    if record["status"] == "failed":
        payload["errors"] = json.loads(record["errors_json"] or "[]")
    if record["status"] == "done":
        payload["audit"] = json.loads(record["audit_json"] or "{}")
        size_bytes: Optional[int] = None
        result_path = record["result_path"]
        if result_path and os.path.exists(result_path):
            size_bytes = os.path.getsize(result_path)
        payload["result"] = {
            "sha256": record["result_sha256"],
            "size_bytes": size_bytes,
            "download_url": f"/jobs/{record['job_id']}/download",
        }
    return payload


class _JobRunner:
    """In-process scheduler: at most one running task per job id.

    Cross-process arbitration happens in the store (lease-guarded conditional
    UPDATEs); this registry only prevents duplicate scheduling inside one
    process, where every task shares the same lease owner id.
    """

    def __init__(self, store: JobStore, results_dir: str, settings: Settings, worker_id: str) -> None:
        self._store = store
        self._results_dir = results_dir
        self._settings = settings
        self._worker_id = worker_id
        self._lock = threading.Lock()
        self._running: set[str] = set()

    def maybe_schedule(
        self,
        background_tasks: BackgroundTasks,
        job_id: str,
        content: bytes,
        policy: dict,
        redactions: Optional[list],
    ) -> bool:
        """Queue the job for background execution unless it is already running
        in this process. Returns True iff a new task was scheduled."""
        with self._lock:
            if job_id in self._running:
                return False
            self._running.add(job_id)
        background_tasks.add_task(self._run, job_id, content, policy, redactions)
        return True

    def _run(self, job_id: str, content: bytes, policy: dict, redactions: Optional[list]) -> None:
        try:
            process_job(
                self._store,
                self._results_dir,
                self._settings.secret,
                job_id,
                self._worker_id,
                self._settings.lease_seconds,
                self._settings.heartbeat_seconds,
                content,
                policy,
                redactions,
            )
        finally:
            with self._lock:
                self._running.discard(job_id)


def _remove_stale_tmp_files(results_dir: str) -> None:
    """Drop half-written result temp files left behind by a crashed executor.

    Result files are published via atomic rename, so anything still carrying
    the temp suffix is by definition incomplete and unreachable by clients.
    """
    for name in os.listdir(results_dir):
        if name.startswith(".") and name.endswith(".tmp"):
            try:
                os.remove(os.path.join(results_dir, name))
            except OSError:
                pass


def _instance_heartbeat_loop(
    store: JobStore, worker_id: str, interval: float, stop: threading.Event
) -> None:
    """Keep this instance's liveness registration fresh while it runs.

    Peers sharing the DATA_DIR use the registration to verify whether a lease
    owner is still alive: a registration that stops being renewed means the
    instance is gone, and only then may its leases be invalidated or claimed.
    """
    if interval <= 0:
        return
    while not stop.wait(interval):
        try:
            store.heartbeat_instance(worker_id)
        except Exception:
            return  # store is gone (e.g. test teardown); nothing to renew


def _await_lease_resolution(
    store: JobStore,
    job_id: str,
    secret_fp: str,
    worker_id: str,
    settings: Settings,
    record: dict,
) -> tuple[str, dict]:
    """Arbitrate with a registered peer instance that holds the job's lease.

    Called when a resubmission finds the job leased to another *registered*
    instance and could not claim it outright, so the previous executor's fate
    is not yet decidable. Polls until the situation resolves:

    * ``claimed``  — the lease lapsed or the owner's registration went stale,
      and this process won the atomic takeover (SQLite serializes concurrent
      claimants, so exactly one wins); the caller must (re)schedule execution;
    * ``active``   — the owner proved itself alive: its lease or its liveness
      registration advanced during the wait. The job is being executed and
      must not be preempted;
    * ``terminal`` — the job reached done/failed meanwhile;
    * ``timeout``  — a safety bound was hit; the caller reports the job as-is.

    The wait is naturally bounded: a dead owner stops renewing, so its lease
    lapses (and its registration goes stale) within ``lease_seconds`` of its
    death, at which point the takeover proceeds.
    """
    lease_seconds = settings.lease_seconds
    owner = record["lease_owner"]
    baseline_lease = record["lease_expires"] or 0.0
    baseline_seen = store.instance_last_seen(owner)
    deadline = time.time() + lease_seconds + settings.heartbeat_seconds + 5.0
    while True:
        latest = store.get(job_id)
        if latest is None or latest["status"] in ("done", "failed"):
            return "terminal", (latest or record)
        if store.try_claim(
            job_id, secret_fp, worker_id, time.time() + lease_seconds, lease_seconds
        ):
            return "claimed", store.get(job_id)
        if (latest["lease_expires"] or 0.0) > baseline_lease:
            return "active", latest  # lease renewed: the owner is alive
        if baseline_seen is not None:
            seen = store.instance_last_seen(owner)
            if seen is not None and seen > baseline_seen:
                return "active", latest  # liveness heartbeat advanced: alive
        if time.time() >= deadline:
            return "timeout", latest
        time.sleep(0.5)


def create_app(settings: Optional[Settings] = None) -> FastAPI:
    settings = settings or get_settings()
    os.makedirs(settings.data_dir, exist_ok=True)
    results_dir = os.path.join(settings.data_dir, "results")
    os.makedirs(results_dir, exist_ok=True)
    store = JobStore(os.path.join(settings.data_dir, "jobs.db"))
    # Identity of this service instance for lease arbitration.
    worker_id = f"{socket.gethostname()}-{os.getpid()}-{uuid.uuid4().hex[:12]}"
    # Publish this instance's liveness, then invalidate only leases whose
    # owner is verifiably gone (unregistered or long-silent). Leases of live
    # peer instances sharing this DATA_DIR are left untouched, so a second
    # instance starting up can never preempt jobs that are still executing.
    store.register_instance(worker_id)
    store.expire_foreign_leases(worker_id, settings.lease_seconds)
    _remove_stale_tmp_files(results_dir)
    runner = _JobRunner(store, results_dir, settings, worker_id)

    heartbeat_stop = threading.Event()
    heartbeat = threading.Thread(
        target=_instance_heartbeat_loop,
        args=(store, worker_id, settings.heartbeat_seconds, heartbeat_stop),
        name=f"instance-heartbeat-{worker_id[-12:]}",
        daemon=True,
    )
    heartbeat.start()

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        yield
        # Clean exit: prove this instance is gone (release its in-flight
        # leases and drop its registration) so the next instance's first
        # resubmission recovers its interrupted jobs immediately.
        heartbeat_stop.set()
        store.expire_own_leases(worker_id)
        store.deregister_instance(worker_id)

    app = FastAPI(
        title="DICOM Research Data Anonymization API",
        version="1.0.0",
        description=DESCRIPTION,
        lifespan=lifespan,
    )
    app.state.worker_id = worker_id

    @app.post("/jobs", status_code=202, response_model=JobCreated)
    def create_job(
        background_tasks: BackgroundTasks,
        file: UploadFile = File(..., description="ZIP archive of DICOM instances"),
        policy: str = Form(..., description="Versioned anonymization policy (JSON)"),
        redactions: Optional[str] = Form(None, description="Optional pixel redaction rules (JSON array)"),
    ):
        content = file.file.read()
        if not content:
            raise HTTPException(400, "uploaded file is empty")
        try:
            policy_obj = json.loads(policy)
        except json.JSONDecodeError as exc:
            raise HTTPException(400, f"policy is not valid JSON: {exc}")
        if not isinstance(policy_obj, dict):
            raise HTTPException(400, "policy must be a JSON object")
        redactions_obj = None
        if redactions is not None and redactions.strip():
            try:
                redactions_obj = json.loads(redactions)
            except json.JSONDecodeError as exc:
                raise HTTPException(400, f"redactions is not valid JSON: {exc}")

        input_sha256 = hashlib.sha256(content).hexdigest()
        secret_fp = settings.secret_fp
        job_id = compute_job_id(input_sha256, policy_obj, redactions_obj, secret_fp)

        record = store.find_scoped(job_id, secret_fp)
        if record is None:
            # New job: insert it already leased to this instance, so a crash
            # anywhere after this point leaves a resumable record.
            if store.create_if_absent(
                job_id,
                policy_obj,
                redactions_obj,
                input_sha256,
                secret_fp,
                worker_id,
                time.time() + settings.lease_seconds,
            ):
                runner.maybe_schedule(background_tasks, job_id, content, policy_obj, redactions_obj)
                return JobCreated(job_id=job_id, status="queued", status_url=f"/jobs/{job_id}")
            # Lost a create race with a concurrent process; fall through to
            # the existing-job path with the row that won.
            record = store.find_scoped(job_id, secret_fp)
            if record is None:
                # Same truncated job id under a different secret scope (a
                # legacy unfingerprinted row or a hash collision): it may
                # neither be reused nor overwritten.
                raise HTTPException(
                    409, "job id already exists under a different secret scope; refusing to reuse it"
                )

        if record["input_sha256"] != input_sha256:
            # Defensive: a truncated-id collision must never feed a job inputs
            # that differ from what its record describes.
            raise HTTPException(
                409, "job id collision: existing record describes a different input; refusing to reuse it"
            )

        if record["status"] in ("done", "failed"):
            return JSONResponse(
                status_code=200,
                content={
                    "job_id": job_id,
                    "status": record["status"],
                    "status_url": f"/jobs/{job_id}",
                    "detail": "identical submission already exists; returning the existing job",
                },
            )

        # queued/processing: either still being executed somewhere or
        # interrupted. The store atomically decides which; only the claimant
        # (re)schedules execution.
        current = record
        claimed = store.try_claim(
            job_id,
            secret_fp,
            worker_id,
            time.time() + settings.lease_seconds,
            settings.lease_seconds,
        )
        owner = record["lease_owner"]
        owner_executing = owner == worker_id
        if not claimed and owner and owner != worker_id:
            if store.instance_last_seen(owner) is not None:
                # The lease is held by a registered peer instance. Its fate
                # is not decidable from a single snapshot, so wait for it to
                # resolve: a live peer renews its lease/registration (and
                # keeps the job), a dead one lets the lease lapse, and this
                # request then takes over atomically.
                outcome, current = _await_lease_resolution(
                    store, job_id, secret_fp, worker_id, settings, record
                )
                if outcome == "terminal":
                    return JSONResponse(
                        status_code=200,
                        content={
                            "job_id": job_id,
                            "status": current["status"],
                            "status_url": f"/jobs/{job_id}",
                            "detail": "identical submission already exists; returning the existing job",
                        },
                    )
                if outcome == "claimed":
                    claimed = True
                elif outcome == "active":
                    owner_executing = True
            # Unregistered lease owner (legacy/foreign row): its fate cannot
            # be verified, so nothing is waited out here — the lease lapses on
            # its own and a later resubmission takes over atomically.
        resumed = False
        if claimed:
            # Execute with the persisted policy/redactions so the resumed job
            # runs exactly what its record describes; the freshly uploaded ZIP
            # bytes (sha256 verified against the record above) supply the
            # input the record never stored.
            record_policy = json.loads(record["policy_json"])
            record_redactions = (
                json.loads(record["redactions_json"]) if record["redactions_json"] else None
            )
            resumed = runner.maybe_schedule(
                background_tasks, job_id, content, record_policy, record_redactions
            )
        if resumed:
            detail = "existing job was interrupted; execution resumed under the original job id"
        elif owner_executing:
            detail = (
                "identical submission already exists and is still being executed; "
                "returning the existing job"
            )
        else:
            detail = "identical submission already exists; returning the existing job"
        return JSONResponse(
            status_code=200,
            content={
                "job_id": job_id,
                "status": current["status"],
                "status_url": f"/jobs/{job_id}",
                "detail": detail,
            },
        )

    @app.get("/jobs/{job_id}", response_model=JobStatus)
    def get_job(job_id: str):
        record = store.get(job_id)
        if not record:
            raise HTTPException(404, "job not found")
        return job_status_payload(record)

    @app.get("/jobs/{job_id}/download")
    def download_result(job_id: str):
        record = store.get(job_id)
        if not record:
            raise HTTPException(404, "job not found")
        if record["status"] != "done":
            raise HTTPException(409, f"job status is '{record['status']}'; no result available")
        if not record["result_path"] or not os.path.exists(record["result_path"]):
            raise HTTPException(410, "job result file is no longer available on this server")
        return FileResponse(
            record["result_path"],
            media_type="application/zip",
            filename=f"anonymized-{job_id}.zip",
        )

    @app.get("/policies")
    def list_policies():
        return {
            "supported_versions": SUPPORTED_POLICY_VERSIONS,
            "default_profile": default_profile_doc(),
            "redactions_schema": {
                "type": "array",
                "items": {
                    "scope": "instance | series | study",
                    "uid": "SOP/series/study Instance UID to target",
                    "boxes": "[[x, y, width, height], ...] in pixel coordinates",
                    "fill": "optional integer fill value 0..65535 (default 0)",
                },
            },
        }

    @app.get("/healthz")
    def healthz():
        return {"status": "ok"}

    return app


app = create_app()
