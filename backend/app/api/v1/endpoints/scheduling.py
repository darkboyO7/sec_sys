"""
Intelligent Assessment Scheduling, Risk-Based Prioritization & Resource-Aware Orchestration Endpoints (Prompt 34).
REST APIs for assessment queues, priority calculation previews, worker dispatch, lease recovery,
reassessment triggers, cancellation, and scheduling policy governance.
"""
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.exceptions import (
    NotFoundError,
    ValidationError,
    AuthorizationError,
)
from app.models.user import User, SystemRole
from app.models.project import ProjectRole
from app.models.scheduling import (
    QueueItemStatus,
    PriorityBand,
    EligibilityStatus,
    SchedulerDecisionType,
    TriggerSourceType,
    AssessmentQueueItem,
    SchedulerDecisionRecord,
)
from app.schemas.scheduling import (
    QueueItemCreate,
    QueueItemResponse,
    QueueItemPreviewRequest,
    QueueItemPreviewResponse,
    TriggerAssessmentRequest,
    DispatchResultResponse,
    LeaseRecoveryResponse,
    SchedulerCapacityResponse,
    SchedulerDecisionResponse,
    SchedulerPolicyUpdate,
    SchedulerPolicyResponse,
)
from app.services.scheduling_service import SchedulingService
from app.api.deps import get_current_user, verify_project_access, require_system_roles

router = APIRouter()


# ---------------------------------------------------------------------------
# Assessment Queue Management Endpoints
# ---------------------------------------------------------------------------

@router.get("/projects/{project_id}/scheduling/queue", response_model=List[QueueItemResponse], tags=["Intelligent Scheduling"])
def list_queue_items(
    project_id: str,
    status_filter: Optional[QueueItemStatus] = Query(None, alias="status"),
    priority_band: Optional[PriorityBand] = Query(None),
    target: Optional[str] = Query(None),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """List scheduled and queued assessments with deterministic priority rankings."""
    verify_project_access(project_id, current_user, db, [ProjectRole.VIEWER])

    query = db.query(AssessmentQueueItem).filter(AssessmentQueueItem.project_id == project_id)
    if status_filter:
        query = query.filter(AssessmentQueueItem.status == status_filter)
    if priority_band:
        query = query.filter(AssessmentQueueItem.priority_band == priority_band)
    if target:
        query = query.filter(AssessmentQueueItem.target_input.contains(target))

    items = query.order_by(
        AssessmentQueueItem.priority_score.desc(),
        AssessmentQueueItem.created_at.asc(),
    ).offset(skip).limit(limit).all()

    return items


@router.get("/projects/{project_id}/scheduling/queue/{queue_id}", response_model=QueueItemResponse, tags=["Intelligent Scheduling"])
def get_queue_item(
    project_id: str,
    queue_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Retrieve full details of a single assessment queue item, including factor breakdown and lease."""
    verify_project_access(project_id, current_user, db, [ProjectRole.VIEWER])

    item = db.query(AssessmentQueueItem).filter(
        AssessmentQueueItem.project_id == project_id,
        AssessmentQueueItem.id == queue_id,
    ).first()
    if not item:
        raise HTTPException(status_code=404, detail="Queue item not found.")
    return item


@router.post("/projects/{project_id}/scheduling/enqueue", response_model=QueueItemResponse, status_code=status.HTTP_201_CREATED, tags=["Intelligent Scheduling"])
def enqueue_assessment_request(
    project_id: str,
    request: QueueItemCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Enqueue an authorized assessment workload.
    Calculates deterministic priority, enforces defensive boundaries, and deduplicates identical active tasks.
    """
    verify_project_access(project_id, current_user, db, [ProjectRole.TESTER])

    try:
        queue_item = SchedulingService.enqueue_assessment(
            db=db,
            project_id=project_id,
            user_id=current_user.id,
            request=request,
            trigger_source="MANUAL_DISPATCH",
        )
        return queue_item
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/projects/{project_id}/scheduling/preview", response_model=QueueItemPreviewResponse, tags=["Intelligent Scheduling"])
def preview_assessment_scheduling(
    project_id: str,
    request: QueueItemPreviewRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Preview eligibility status, priority factors, and explanation without reserving capacity or altering state.
    """
    verify_project_access(project_id, current_user, db, [ProjectRole.VIEWER])

    preview = SchedulingService.preview_assessment(
        db=db,
        project_id=project_id,
        target_input=request.target_input,
        adapter_name=request.adapter_name or "local_fixture_adapter",
    )
    return preview


@router.post("/projects/{project_id}/scheduling/queue/{queue_id}/cancel", response_model=QueueItemResponse, tags=["Intelligent Scheduling"])
def cancel_queue_item(
    project_id: str,
    queue_id: str,
    reason: Optional[str] = Query("Operator cancelled assessment"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Request persistent, auditable cancellation of a queued or running assessment."""
    verify_project_access(project_id, current_user, db, [ProjectRole.TESTER])

    try:
        cancelled_item = SchedulingService.request_cancellation(
            db=db,
            project_id=project_id,
            queue_id=queue_id,
            user_id=current_user.id,
            reason=reason,
        )
        return cancelled_item
    except NotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))


# ---------------------------------------------------------------------------
# Worker Dispatch & Concurrency Orchestration Endpoints
# ---------------------------------------------------------------------------

@router.post("/projects/{project_id}/scheduling/dispatch-next", response_model=DispatchResultResponse, tags=["Intelligent Scheduling"])
def dispatch_next_job(
    project_id: str,
    worker_id: Optional[str] = Query("worker-local"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Dispatch next highest effective priority eligible job adhering to concurrency limits and anti-starvation aging.
    Revalidates eligibility immediately before claiming.
    """
    verify_project_access(project_id, current_user, db, [ProjectRole.TESTER])

    dispatched, msg, item, job_id = SchedulingService.dispatch_next_eligible(
        db=db,
        project_id=project_id,
        worker_id=worker_id or "worker-local",
    )

    return DispatchResultResponse(
        dispatched=dispatched,
        message=msg,
        queue_item=item,
        job_id=job_id,
    )


@router.post("/projects/{project_id}/scheduling/recover-stale", response_model=LeaseRecoveryResponse, tags=["Intelligent Scheduling"])
def recover_stale_worker_leases(
    project_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Audit and recover abandoned worker leases, applying bounded backoff or dead-lettering."""
    verify_project_access(project_id, current_user, db, [ProjectRole.LEAD])

    res = SchedulingService.recover_stale_leases(db, project_id)
    return res


# ---------------------------------------------------------------------------
# Reassessment Triggers & Automated Operations
# ---------------------------------------------------------------------------

@router.post("/projects/{project_id}/scheduling/trigger", response_model=QueueItemResponse, tags=["Intelligent Scheduling"])
def trigger_automated_reassessment(
    project_id: str,
    req: TriggerAssessmentRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Submit an automated reassessment trigger event (exposure drift, new finding, failed retest).
    Applies cooldown periods and coalesces duplicates to prevent assessment storms.
    """
    verify_project_access(project_id, current_user, db, [ProjectRole.TESTER])

    try:
        item = SchedulingService.handle_reassessment_trigger(
            db=db,
            project_id=project_id,
            user_id=current_user.id,
            trigger_source=req.trigger_source,
            target_input=req.target_input,
            adapter_name=req.adapter_name or "local_fixture_adapter",
            metadata=req.metadata,
        )
        return item
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))


# ---------------------------------------------------------------------------
# Capacity, Decision Audit Ledger & Policy Endpoints
# ---------------------------------------------------------------------------

@router.get("/projects/{project_id}/scheduling/capacity", response_model=SchedulerCapacityResponse, tags=["Intelligent Scheduling"])
def get_scheduler_capacity(
    project_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Retrieve real-time worker capacity, slot allocations, and queue depth metrics."""
    verify_project_access(project_id, current_user, db, [ProjectRole.VIEWER])

    cap = SchedulingService.get_capacity_summary(db, project_id)
    return cap


@router.get("/projects/{project_id}/scheduling/decisions", response_model=List[SchedulerDecisionResponse], tags=["Intelligent Scheduling"])
def list_scheduler_decisions(
    project_id: str,
    decision_type: Optional[SchedulerDecisionType] = Query(None),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Inspect append-only scheduler decision ledger for prioritization and capacity transparency."""
    verify_project_access(project_id, current_user, db, [ProjectRole.VIEWER])

    query = db.query(SchedulerDecisionRecord).filter(SchedulerDecisionRecord.project_id == project_id)
    if decision_type:
        query = query.filter(SchedulerDecisionRecord.decision_type == decision_type)

    decisions = query.order_by(SchedulerDecisionRecord.created_at.desc()).offset(skip).limit(limit).all()
    return decisions


@router.get("/projects/{project_id}/scheduling/policy", response_model=SchedulerPolicyResponse, tags=["Intelligent Scheduling"])
def get_scheduler_policy(
    project_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Retrieve project-level scheduling and concurrency policy limits."""
    verify_project_access(project_id, current_user, db, [ProjectRole.VIEWER])

    policy = SchedulingService.get_or_create_policy(db, project_id)
    return policy


@router.put("/projects/{project_id}/scheduling/policy", response_model=SchedulerPolicyResponse, tags=["Intelligent Scheduling"])
def update_scheduler_policy(
    project_id: str,
    updates: SchedulerPolicyUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Update scheduling policy limits, worker concurrency, and anti-starvation aging rate."""
    verify_project_access(project_id, current_user, db, [ProjectRole.LEAD])

    policy = SchedulingService.update_policy(db, project_id, updates)
    return policy
