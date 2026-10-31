"""
Worker Registry & Lifecycle Coordination Service.
Manages authenticated worker node registration, HMAC token verification,
heartbeat tracking, dead worker lease scavenging, and dead-letter queue routing.
"""
import hmac
import hashlib
import time
import logging
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime, timezone, timedelta
from sqlalchemy.orm import Session
from sqlalchemy import text, or_

from app.core.config import settings
from app.models.base import utc_now
from app.models.worker_node import WorkerNode, WorkerStatus, WorkerType
from app.models.assessment import AssessmentJob, AssessmentStatus
from app.worker.execution_interface import (
    WorkerRegistrationRequest,
    WorkerRegistrationResponse,
    WorkerHeartbeatRequest,
    WorkerHeartbeatResponse,
    WorkerNodeSummary,
    DeadLetterJobRecord,
)

logger = logging.getLogger(__name__)


class WorkerAuthenticationError(Exception):
    """Raised when worker token or session identity cannot be verified."""
    pass


class WorkerRegistry:
    """
    Central registry for worker node identity, capacity, and health.
    Enforces fail-closed token verification and atomic lease scavenging.
    """

    def __init__(self):
        # Ephemeral session token store: worker_id -> session_token
        self._session_tokens: Dict[str, str] = {}
        # In-memory fast cache of active worker heartbeats: worker_id -> timestamp
        self._heartbeat_cache: Dict[str, float] = {}

    def _get_signing_key(self) -> bytes:
        """Derives the HMAC signing secret for worker authentication."""
        secret = settings.WORKER_REGISTRATION_SECRET or settings.SECRET_KEY
        return secret.encode("utf-8")

    def generate_token_hash(self, token: str) -> str:
        """Computes SHA-256 digest of raw token for storage."""
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    def generate_session_token(self, worker_id: str) -> str:
        """Generates an HMAC-authenticated session token for a worker."""
        key = self._get_signing_key()
        msg = f"{worker_id}:{time.time()}".encode("utf-8")
        return hmac.new(key, msg, hashlib.sha256).hexdigest()

    def verify_registration_token(self, raw_token: str) -> bool:
        """
        Verifies that the raw registration token matches the cluster secret.
        Fails closed on mismatch.
        """
        expected_secret = settings.WORKER_REGISTRATION_SECRET or settings.SECRET_KEY
        if not raw_token or not expected_secret:
            return False
        return hmac.compare_digest(raw_token.strip(), expected_secret.strip())

    def verify_session_token(self, worker_id: str, session_token: str) -> bool:
        """Validates that the provided session token matches the active session."""
        if not worker_id or not session_token:
            return False
        cached = self._session_tokens.get(worker_id)
        if cached and hmac.compare_digest(cached, session_token):
            return True
        return False

    def register_worker(
        self,
        req: WorkerRegistrationRequest,
        db: Session,
    ) -> WorkerRegistrationResponse:
        """
        Registers a worker node after verifying its authentication token.
        Fails closed if the token is invalid.
        """
        if not self.verify_registration_token(req.auth_token):
            logger.warning(f"Worker registration rejected: unauthorized token for worker_id='{req.worker_id}'")
            raise WorkerAuthenticationError("Unauthorized worker registration: invalid authentication token.")

        session_token = self.generate_session_token(req.worker_id)
        self._session_tokens[req.worker_id] = session_token
        self._heartbeat_cache[req.worker_id] = time.time()

        now = utc_now()
        token_hash = self.generate_token_hash(req.auth_token)

        node = db.query(WorkerNode).filter(WorkerNode.worker_id == req.worker_id).first()
        if not node:
            w_type = WorkerType.LOCAL_SUBPROCESS if req.worker_type == "LOCAL_SUBPROCESS" else WorkerType.DISTRIBUTED_NODE
            node = WorkerNode(
                worker_id=req.worker_id,
                worker_type=w_type,
                hostname=req.hostname,
                pid=req.pid,
                status=WorkerStatus.ONLINE,
                concurrency_slots=req.concurrency_slots,
                active_jobs_count=0,
                capabilities=req.capabilities,
                registered_at=now,
                last_heartbeat_at=now,
                auth_token_hash=token_hash,
                metadata_json=req.metadata,
            )
            db.add(node)
        else:
            node.hostname = req.hostname
            node.pid = req.pid
            node.status = WorkerStatus.ONLINE
            node.concurrency_slots = req.concurrency_slots
            node.capabilities = req.capabilities
            node.last_heartbeat_at = now
            node.auth_token_hash = token_hash
            node.metadata_json = req.metadata

        db.commit()
        db.refresh(node)

        logger.info(f"Worker '{req.worker_id}' ({req.worker_type}) successfully registered on host '{req.hostname}'.")
        return WorkerRegistrationResponse(
            success=True,
            worker_id=req.worker_id,
            status=node.status.value,
            session_token=session_token,
            heartbeat_interval_seconds=settings.WORKER_HEARTBEAT_INTERVAL_SECONDS,
            message="Worker registered successfully.",
        )

    def record_heartbeat(
        self,
        req: WorkerHeartbeatRequest,
        db: Session,
    ) -> WorkerHeartbeatResponse:
        """
        Updates worker heartbeat timestamp and identifies canceled jobs.
        """
        if not self.verify_session_token(req.worker_id, req.session_token):
            raise WorkerAuthenticationError("Invalid or expired worker session token.")

        self._heartbeat_cache[req.worker_id] = time.time()
        now = utc_now()

        node = db.query(WorkerNode).filter(WorkerNode.worker_id == req.worker_id).first()
        if not node:
            raise WorkerAuthenticationError(f"Worker '{req.worker_id}' not found in registry.")

        node.last_heartbeat_at = now
        node.active_jobs_count = len(req.active_job_ids)
        if node.status == WorkerStatus.DEAD or node.status == WorkerStatus.OFFLINE:
            node.status = WorkerStatus.ONLINE

        canceled_jobs: List[str] = []
        if req.active_job_ids:
            # Check if any of these jobs were flagged for cancellation
            canceled = db.query(AssessmentJob.id).filter(
                AssessmentJob.id.in_(req.active_job_ids),
                AssessmentJob.status.in_([AssessmentStatus.CANCELLATION_REQUESTED, AssessmentStatus.CANCELLED]),
            ).all()
            canceled_jobs = [c[0] for c in canceled]

            # Update heartbeat on active jobs claimed by this worker
            db.query(AssessmentJob).filter(
                AssessmentJob.id.in_(req.active_job_ids),
                AssessmentJob.claimed_by == req.worker_id,
            ).update({AssessmentJob.heartbeat_at: now}, synchronize_session=False)

        db.commit()

        return WorkerHeartbeatResponse(
            acknowledged=True,
            worker_id=req.worker_id,
            status=node.status.value,
            canceled_job_ids=canceled_jobs,
            reclaim_required=False,
        )

    def reclaim_stale_leases(
        self,
        db: Session,
        timeout_seconds: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Scavenges dead worker leases and reconciles orphaned jobs.
        Re-queues jobs if retryable; transitions to DEAD_LETTER if retries exhausted.
        """
        timeout = timeout_seconds or settings.WORKER_HEARTBEAT_TIMEOUT_SECONDS
        cutoff = utc_now() - timedelta(seconds=timeout)
        now = utc_now()

        # 1. Detect dead worker nodes
        dead_workers = db.query(WorkerNode).filter(
            WorkerNode.status.in_([WorkerStatus.ONLINE, WorkerStatus.BUSY]),
            WorkerNode.last_heartbeat_at < cutoff,
        ).all()

        dead_worker_ids = []
        for worker in dead_workers:
            worker.status = WorkerStatus.DEAD
            dead_worker_ids.append(worker.worker_id)
            if worker.worker_id in self._session_tokens:
                del self._session_tokens[worker.worker_id]
            if worker.worker_id in self._heartbeat_cache:
                del self._heartbeat_cache[worker.worker_id]

        # 2. Find orphaned jobs claimed by dead workers or whose heartbeat expired
        orphaned_query = db.query(AssessmentJob).filter(
            AssessmentJob.status.in_([AssessmentStatus.PREFLIGHT, AssessmentStatus.RUNNING]),
            or_(
                AssessmentJob.heartbeat_at < cutoff,
                AssessmentJob.heartbeat_at.is_(None),
                AssessmentJob.claimed_by.in_(dead_worker_ids) if dead_worker_ids else False,
            ),
        )
        orphaned_jobs = orphaned_query.all()

        requeued_count = 0
        dead_letter_count = 0
        details: List[str] = []

        for job in orphaned_jobs:
            if job.retry_count < job.max_retries:
                # Requeue for retry
                job.retry_count += 1
                job.attempt_count += 1
                job.status = AssessmentStatus.QUEUED
                job.claimed_by = None
                job.heartbeat_at = None
                job.error_message = f"Orphaned worker lease expired (no heartbeat > {timeout}s). Re-queued for retry {job.retry_count}/{job.max_retries}."
                requeued_count += 1
                details.append(f"Job {job.id} re-queued (retry {job.retry_count}/{job.max_retries}).")
            else:
                # Retries exhausted: transition to DEAD_LETTER
                job.status = AssessmentStatus.DEAD_LETTER
                job.dead_letter_reason = f"Worker heartbeat timeout exceeded and retry limit ({job.max_retries}) exhausted."
                job.dead_letter_at = now
                job.error_message = f"Dead-letter: worker lease expired after {job.retry_count} retries."
                dead_letter_count += 1
                details.append(f"Job {job.id} transitioned to DEAD_LETTER.")

        db.commit()

        return {
            "dead_workers_identified": len(dead_worker_ids),
            "dead_worker_ids": dead_worker_ids,
            "orphaned_jobs_processed": len(orphaned_jobs),
            "requeued_count": requeued_count,
            "dead_letter_count": dead_letter_count,
            "details": details,
        }

    def list_nodes(self, db: Session) -> List[WorkerNodeSummary]:
        """Returns summary of all registered worker nodes and their liveness."""
        timeout = settings.WORKER_HEARTBEAT_TIMEOUT_SECONDS
        cutoff = utc_now() - timedelta(seconds=timeout)
        nodes = db.query(WorkerNode).all()
        summaries = []
        for n in nodes:
            is_alive = n.last_heartbeat_at >= cutoff and n.status != WorkerStatus.DEAD
            summaries.append(
                WorkerNodeSummary(
                    id=n.id,
                    worker_id=n.worker_id,
                    worker_type=n.worker_type.value,
                    hostname=n.hostname,
                    pid=n.pid,
                    status=n.status.value,
                    concurrency_slots=n.concurrency_slots,
                    active_jobs_count=n.active_jobs_count,
                    capabilities=n.capabilities or [],
                    registered_at=n.registered_at.isoformat(),
                    last_heartbeat_at=n.last_heartbeat_at.isoformat(),
                    is_alive=is_alive,
                )
            )
        return summaries

    def list_dead_letter_jobs(self, db: Session, limit: int = 50) -> List[DeadLetterJobRecord]:
        """Lists jobs currently in DEAD_LETTER state."""
        jobs = (
            db.query(AssessmentJob)
            .filter(AssessmentJob.status == AssessmentStatus.DEAD_LETTER)
            .order_by(AssessmentJob.dead_letter_at.desc())
            .limit(limit)
            .all()
        )
        return [
            DeadLetterJobRecord(
                job_id=j.id,
                project_id=j.project_id,
                target_input=j.target_input,
                adapter_name=j.adapter_name,
                attempt_count=j.attempt_count,
                retry_count=j.retry_count,
                max_retries=j.max_retries,
                dead_letter_reason=j.dead_letter_reason,
                dead_letter_at=j.dead_letter_at.isoformat() if j.dead_letter_at else None,
                failure_category=j.failure_category,
                error_message=j.error_message,
            )
            for j in jobs
        ]

    def replay_dead_letter_job(self, job_id: str, db: Session) -> bool:
        """
        Replays a dead-letter job by resetting its status to QUEUED and clearing retry counts.
        """
        job = db.query(AssessmentJob).filter(
            AssessmentJob.id == job_id,
            AssessmentJob.status == AssessmentStatus.DEAD_LETTER,
        ).first()
        if not job:
            return False

        job.status = AssessmentStatus.QUEUED
        job.retry_count = 0
        job.dead_letter_reason = None
        job.dead_letter_at = None
        job.error_message = None
        job.claimed_by = None
        job.heartbeat_at = None
        db.commit()
        return True


worker_registry = WorkerRegistry()
