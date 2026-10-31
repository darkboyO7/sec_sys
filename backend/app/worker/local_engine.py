"""
Local Subprocess Worker Execution Engine.
Wraps the SubprocessWorkerRunner for isolated, Windows-native subprocess execution.
Preserves Win32 Job Objects, sanitized environment without secrets, process tree killing,
and provides seamless compatibility with the BaseWorkerExecutionEngine interface.
"""
import os
import sys
import logging
from typing import Dict, Any, List, Optional, Callable
from datetime import datetime, timezone
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.base import utc_now
from app.models.assessment import AssessmentJob, AssessmentStatus
from app.models.worker_node import WorkerNode, WorkerStatus, WorkerType
from app.services.scanner_adapters.base import AdapterResult
from app.worker.ipc_schemas import WorkerIPCRequest
from app.worker.execution_interface import (
    BaseWorkerExecutionEngine,
    WorkerRegistrationRequest,
    WorkerHeartbeatRequest,
)
from app.worker.worker_registry import worker_registry

logger = logging.getLogger(__name__)


class LocalSubprocessWorkerEngine(BaseWorkerExecutionEngine):
    """
    Local Windows/POSIX subprocess worker engine.
    Supervises child processes via SubprocessWorkerRunner.
    """

    def __init__(self, worker_id: Optional[str] = None):
        from app.services.subprocess_worker_runner import SubprocessWorkerRunner
        self.worker_id = worker_id or f"worker-local-{os.getpid()}"
        self.runner = SubprocessWorkerRunner()
        self.active_jobs: Dict[str, int] = {}  # job_id -> pid
        self._session_token: Optional[str] = None
        self._registered = False

    def ensure_registered(self, db: Session) -> None:
        """Idempotently registers this local engine with the worker registry."""
        if self._registered and self._session_token:
            return

        import socket
        hostname = socket.gethostname()
        auth_token = settings.WORKER_REGISTRATION_SECRET or settings.SECRET_KEY

        req = WorkerRegistrationRequest(
            worker_id=self.worker_id,
            worker_type="LOCAL_SUBPROCESS",
            hostname=hostname,
            pid=os.getpid(),
            concurrency_slots=settings.WORKER_MAX_CONCURRENT_JOBS,
            capabilities=["local_fixture_adapter", "nmap", "zap", "custom_scanner"],
            auth_token=auth_token,
            metadata={"platform": sys.platform, "python_version": sys.version.split()[0]},
        )
        resp = worker_registry.register_worker(req, db)
        self._session_token = resp.session_token
        self._registered = True

    def claim_job(
        self,
        worker_id: Optional[str] = None,
        capabilities: Optional[List[str]] = None,
        db: Optional[Session] = None,
    ) -> Optional[AssessmentJob]:
        """
        Atomically claims a queued job for this local worker engine.
        Uses skip-locked on PostgreSQL or atomic conditional update on SQLite.
        """
        if not db:
            from app.core.database import SessionLocal
            db_session = SessionLocal()
            try:
                return self.claim_job(worker_id=worker_id, capabilities=capabilities, db=db_session)
            finally:
                db_session.close()

        w_id = worker_id or self.worker_id
        self.ensure_registered(db)
        now = utc_now()

        dialect_name = getattr(db.bind.dialect, "name", "sqlite") if (db.bind and hasattr(db.bind, "dialect")) else "sqlite"

        if dialect_name == "postgresql":
            query = (
                db.query(AssessmentJob)
                .filter(AssessmentJob.status == AssessmentStatus.QUEUED)
            )
            if capabilities:
                query = query.filter(AssessmentJob.adapter_name.in_(capabilities))

            job = query.order_by(AssessmentJob.created_at.asc()).with_for_update(skip_locked=True).first()
            if not job:
                return None

            job.status = AssessmentStatus.PREFLIGHT
            job.claimed_by = w_id
            job.preflight_at = now
            job.heartbeat_at = now
            job.progress_pct = 10
            db.commit()
            db.refresh(job)
            return job
        else:
            # SQLite / Generic atomic conditional update
            query = db.query(AssessmentJob).filter(AssessmentJob.status == AssessmentStatus.QUEUED)
            if capabilities:
                query = query.filter(AssessmentJob.adapter_name.in_(capabilities))

            candidate = query.order_by(AssessmentJob.created_at.asc()).first()
            if not candidate:
                return None

            rows = (
                db.query(AssessmentJob)
                .filter(
                    AssessmentJob.id == candidate.id,
                    AssessmentJob.status == AssessmentStatus.QUEUED,
                )
                .update(
                    {
                        AssessmentJob.status: AssessmentStatus.PREFLIGHT,
                        AssessmentJob.claimed_by: w_id,
                        AssessmentJob.preflight_at: now,
                        AssessmentJob.heartbeat_at: now,
                        AssessmentJob.progress_pct: 10,
                    },
                    synchronize_session="fetch",
                )
            )
            db.commit()
            if rows > 0:
                db.refresh(candidate)
                return candidate
            return None

    def execute_job(
        self,
        request: WorkerIPCRequest,
        cancellation_check: Optional[Callable[[], bool]] = None,
        on_spawn: Optional[Callable[[int], None]] = None,
    ) -> AdapterResult:
        """
        Executes a job payload via SubprocessWorkerRunner.
        """
        def handle_spawn(pid: int):
            self.active_jobs[request.job_id] = pid
            if on_spawn:
                on_spawn(pid)

        try:
            result = self.runner.run_job(
                request=request,
                cancellation_check=cancellation_check,
                on_spawn=handle_spawn,
            )
            return result
        finally:
            if request.job_id in self.active_jobs:
                del self.active_jobs[request.job_id]

    def heartbeat(
        self,
        worker_id: Optional[str] = None,
        active_job_ids: Optional[List[str]] = None,
        db: Optional[Session] = None,
    ) -> Dict[str, Any]:
        """
        Records heartbeat with worker registry.
        """
        if not db:
            from app.core.database import SessionLocal
            db_session = SessionLocal()
            try:
                return self.heartbeat(worker_id=worker_id, active_job_ids=active_job_ids, db=db_session)
            finally:
                db_session.close()

        w_id = worker_id or self.worker_id
        self.ensure_registered(db)

        jobs = active_job_ids if active_job_ids is not None else list(self.active_jobs.keys())
        req = WorkerHeartbeatRequest(
            worker_id=w_id,
            session_token=self._session_token or "",
            active_job_ids=jobs,
            system_metrics={"active_jobs": len(jobs)},
        )
        resp = worker_registry.record_heartbeat(req, db)
        return resp.model_dump()

    def cancel_job(
        self,
        job_id: str,
        reason: str = "Operator requested cancellation",
        db: Optional[Session] = None,
    ) -> bool:
        """
        Cancels an active job and terminates child process if local.
        """
        pid = self.active_jobs.get(job_id)
        if pid:
            from app.services.subprocess_worker_runner import terminate_process_tree
            terminate_process_tree(pid)
            if job_id in self.active_jobs:
                del self.active_jobs[job_id]

        if db:
            job = db.query(AssessmentJob).filter(AssessmentJob.id == job_id).first()
            if job and job.status not in (AssessmentStatus.COMPLETED, AssessmentStatus.FAILED, AssessmentStatus.CANCELLED):
                job.status = AssessmentStatus.CANCELLED
                job.error_message = reason
                job.completed_at = utc_now()
                db.commit()
                return True
        return True

    def report_outcome(
        self,
        job_id: str,
        worker_id: Optional[str] = None,
        result: Optional[AdapterResult] = None,
        db: Optional[Session] = None,
    ) -> bool:
        """
        Reports execution outcome.
        """
        if job_id in self.active_jobs:
            del self.active_jobs[job_id]
        return True

    def get_worker_health(self) -> Dict[str, Any]:
        """
        Returns status of local subprocess worker engine.
        """
        return {
            "worker_id": self.worker_id,
            "engine_type": "LOCAL_SUBPROCESS",
            "active_processes_count": len(self.active_jobs),
            "active_pids": list(self.active_jobs.values()),
            "last_spawned_pid": self.runner.last_spawned_pid,
            "status": "HEALTHY",
        }
