"""
Distributed Worker Registry & Dead-Letter Queue API.
Supports authenticated worker node registration, heartbeat pings,
lease scavenging, worker telemetry, and dead-letter job inspection/replay.
"""
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.api.deps import get_current_user, require_system_roles
from app.models.user import User, SystemRole
from app.worker.execution_interface import (
    WorkerRegistrationRequest,
    WorkerRegistrationResponse,
    WorkerHeartbeatRequest,
    WorkerHeartbeatResponse,
    WorkerNodeSummary,
    DeadLetterJobRecord,
)
from app.worker.worker_registry import worker_registry, WorkerAuthenticationError

router = APIRouter()


@router.post("/register", response_model=WorkerRegistrationResponse)
def register_worker(
    req: WorkerRegistrationRequest,
    db: Session = Depends(get_db),
):
    """
    Registers a worker node in the execution cluster using an HMAC authentication token.
    Fails closed if the token does not match the cluster secret.
    """
    try:
        return worker_registry.register_worker(req, db)
    except WorkerAuthenticationError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e),
        )


@router.post("/heartbeat", response_model=WorkerHeartbeatResponse)
def worker_heartbeat(
    req: WorkerHeartbeatRequest,
    db: Session = Depends(get_db),
):
    """
    Processes worker node heartbeat, renews lease, and returns cancellation commands.
    """
    try:
        return worker_registry.record_heartbeat(req, db)
    except WorkerAuthenticationError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e),
        )


class JobBindingVerifyRequest(BaseModel):
    job_id: str = Field(min_length=1, max_length=100)
    worker_id: str = Field(min_length=1, max_length=100)
    session_token: str = Field(min_length=1, max_length=256)


@router.post("/verify-job-binding")
def verify_worker_job_binding(
    req: JobBindingVerifyRequest,
    db: Session = Depends(get_db),
):
    """
    Enforces that:
    1. The worker session token is authentic and not expired.
    2. The target job was claimed exclusively by this worker.
    3. The job is in an active execution state.
    4. The job scope snapshot digest is valid and untampered.
    Fails closed with 401 or 403 on any violation.
    """
    valid, err_msg, job = worker_registry.verify_job_execution_binding(
        job_id=req.job_id,
        worker_id=req.worker_id,
        session_token=req.session_token,
        db=db,
    )
    if not valid:
        err_lower = (err_msg or "").lower()
        if "ownership" in err_lower or "scope" in err_lower:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=err_msg)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=err_msg)

    return {
        "valid": True,
        "job_id": req.job_id,
        "worker_id": req.worker_id,
        "status": job.status.value,
        "message": "Worker job execution binding verified successfully.",
    }


@router.get("/nodes", response_model=List[WorkerNodeSummary])
def list_worker_nodes(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_system_roles([
        SystemRole.ADMIN,
        SystemRole.SECURITY_LEAD,
        SystemRole.AUDITOR,
    ])),
):
    """
    Lists registered worker nodes, their types, capabilities, and liveness.
    """
    return worker_registry.list_nodes(db)


@router.post("/reclaim-stale-leases")
def reclaim_stale_worker_leases(
    timeout_seconds: Optional[int] = Query(None, description="Override timeout threshold in seconds"),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_system_roles([SystemRole.ADMIN, SystemRole.SECURITY_LEAD])),
):
    """
    Scavenges dead worker leases and reconciles orphaned jobs.
    Re-queues retryable jobs and routes exhausted jobs to the dead-letter queue.
    """
    return worker_registry.reclaim_stale_leases(db, timeout_seconds=timeout_seconds)


@router.get("/dead-letter", response_model=List[DeadLetterJobRecord])
def list_dead_letter_jobs(
    limit: int = Query(50, ge=1, le=500),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_system_roles([
        SystemRole.ADMIN,
        SystemRole.SECURITY_LEAD,
        SystemRole.AUDITOR,
    ])),
):
    """
    Retrieves jobs routed to the dead-letter queue for operator inspection.
    """
    return worker_registry.list_dead_letter_jobs(db, limit=limit)


@router.post("/dead-letter/{job_id}/replay")
def replay_dead_letter_job(
    job_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_system_roles([SystemRole.ADMIN, SystemRole.SECURITY_LEAD])),
):
    """
    Replays a dead-letter job by re-queuing it with cleared retry counters.
    """
    success = worker_registry.replay_dead_letter_job(job_id, db)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Dead-letter job '{job_id}' not found.",
        )
    return {"success": True, "job_id": job_id, "status": "QUEUED", "message": "Job re-queued successfully."}
