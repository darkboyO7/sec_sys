from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.core.database import get_db
from app.models.user import User, SystemRole
from app.models.project import ProjectRole, ProjectMember
from app.models.orchestration import (
    OrchestrationState,
    OrchestrationEventRecord,
    OrchestrationWorkflowRecord,
    AdaptiveOptimizationRecord,
    DependencyInvalidationRecord,
)
from app.api.deps import get_current_user, verify_project_access
from app.schemas.orchestration import (
    EventIngestRequest,
    EventRead,
    WorkflowRead,
    WorkflowActionRequest,
    WorkflowActionResponse,
    OrchestrationDashboardRead,
    AdaptiveOptimizationRead,
    DependencyInvalidationRead,
)
from app.services.event_processing_service import EventProcessingService
from app.services.autonomous_orchestration_engine import (
    AutonomousOrchestrationEngine,
    OrchestrationAuthorizationError,
    OrchestrationTransitionError,
)
from app.services.adaptive_optimization_service import AdaptiveOptimizationService
from app.services.dependency_invalidation_service import DependencyInvalidationService
from app.models.base import utc_now

router = APIRouter()


def _get_project_role(project_id: str, user: User, db: Session) -> ProjectRole:
    if user.system_role == SystemRole.ADMIN:
        return ProjectRole.ADMIN
    member = db.query(ProjectMember).filter(
        ProjectMember.project_id == project_id,
        ProjectMember.user_id == user.id,
    ).first()
    if not member:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not a member of this project.")
    return member.role


# ------------------------------------------------------------------------------
# Orchestration Dashboard
# ------------------------------------------------------------------------------
@router.get(
    "/{project_id}/dashboard",
    response_model=OrchestrationDashboardRead,
    status_code=status.HTTP_200_OK,
    summary="Get complete autonomous orchestration control plane dashboard",
)
def get_orchestration_dashboard(
    project_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    verify_project_access(project_id, current_user, db)

    workflows = (
        db.query(OrchestrationWorkflowRecord)
        .filter(OrchestrationWorkflowRecord.project_id == project_id)
        .order_by(desc(OrchestrationWorkflowRecord.updated_at))
        .limit(20)
        .all()
    )

    events = (
        db.query(OrchestrationEventRecord)
        .filter(OrchestrationEventRecord.project_id == project_id)
        .order_by(desc(OrchestrationEventRecord.received_at))
        .limit(10)
        .all()
    )

    pending_approvals = [w for w in workflows if w.state == OrchestrationState.AWAITING_APPROVAL]
    active_workflows = [w for w in workflows if w.state in (
        OrchestrationState.ACTION_RUNNING,
        OrchestrationState.ACTION_QUEUED,
        OrchestrationState.DECISION_PENDING,
    )]
    suspended_count = len([w for w in workflows if w.state == OrchestrationState.SUSPENDED])
    failed_count = len([w for w in workflows if w.state == OrchestrationState.FAILED])
    completed_count = len([w for w in workflows if w.state == OrchestrationState.COMPLETED])

    return {
        "project_id": project_id,
        "timestamp": utc_now().isoformat(),
        "summary": {
            "total_workflows": len(workflows),
            "active_workflows": len(active_workflows),
            "pending_approvals": len(pending_approvals),
            "suspended_workflows": suspended_count,
            "failed_workflows": failed_count,
            "completed_workflows": completed_count,
        },
        "active_workflows": workflows[:10],
        "recent_events": events,
        "pending_approvals": pending_approvals,
    }


# ------------------------------------------------------------------------------
# Ingest Event
# ------------------------------------------------------------------------------
@router.post(
    "/{project_id}/events",
    response_model=EventRead,
    status_code=status.HTTP_201_CREATED,
    summary="Ingest an operational event into the autonomous orchestration pipeline",
)
def ingest_event(
    project_id: str,
    req: EventIngestRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    verify_project_access(project_id, current_user, db)
    user_role = _get_project_role(project_id, current_user, db)

    if user_role == ProjectRole.VIEWER and current_user.system_role != SystemRole.ADMIN:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="VIEWER role cannot trigger operational events.")

    event, is_new, msg = EventProcessingService.ingest_event(
        db=db,
        project_id=project_id,
        event_type=req.event_type,
        target_resource=req.target_resource,
        payload=req.payload,
        event_source=req.event_source,
    )

    # If new work, automatically launch orchestration cycle
    if is_new:
        workflow = AutonomousOrchestrationEngine.create_or_resume_workflow(
            db=db,
            project_id=project_id,
            event=event,
        )
        AutonomousOrchestrationEngine.execute_workflow_cycle(
            db=db,
            workflow_id=workflow.id,
            worker_id=f"api-{current_user.id[:8]}",
        )

    return event


# ------------------------------------------------------------------------------
# Workflows List & Detail
# ------------------------------------------------------------------------------
@router.get(
    "/{project_id}/workflows",
    response_model=List[WorkflowRead],
    status_code=status.HTTP_200_OK,
    summary="List orchestration workflows",
)
def list_workflows(
    project_id: str,
    state: Optional[OrchestrationState] = None,
    limit: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    verify_project_access(project_id, current_user, db)
    query = db.query(OrchestrationWorkflowRecord).filter(OrchestrationWorkflowRecord.project_id == project_id)
    if state:
        query = query.filter(OrchestrationWorkflowRecord.state == state)
    return query.order_by(desc(OrchestrationWorkflowRecord.updated_at)).limit(limit).all()


@router.get(
    "/{project_id}/workflows/{workflow_id}",
    response_model=WorkflowRead,
    status_code=status.HTTP_200_OK,
    summary="Get workflow details by ID",
)
def get_workflow(
    project_id: str,
    workflow_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    verify_project_access(project_id, current_user, db)
    wf = (
        db.query(OrchestrationWorkflowRecord)
        .filter(
            OrchestrationWorkflowRecord.id == workflow_id,
            OrchestrationWorkflowRecord.project_id == project_id,
        )
        .first()
    )
    if not wf:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Workflow not found.")
    return wf


# ------------------------------------------------------------------------------
# Operator Actions: Approve, Reject, Suspend, Resume, Retry
# ------------------------------------------------------------------------------
@router.post(
    "/{project_id}/workflows/{workflow_id}/approve",
    response_model=WorkflowActionResponse,
    status_code=status.HTTP_200_OK,
    summary="Approve a pending workflow",
)
def approve_workflow(
    project_id: str,
    workflow_id: str,
    req: WorkflowActionRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    verify_project_access(project_id, current_user, db)
    user_role = _get_project_role(project_id, current_user, db)

    try:
        wf = AutonomousOrchestrationEngine.approve_workflow(
            db=db,
            workflow_id=workflow_id,
            user=current_user,
            user_role=user_role,
            notes=req.notes or "",
        )
        # Execute approved action
        AutonomousOrchestrationEngine.execute_workflow_cycle(
            db=db,
            workflow_id=wf.id,
            worker_id=f"operator-{current_user.id[:8]}",
        )
        return {
            "workflow_id": wf.id,
            "state": wf.state,
            "message": "Workflow approved and execution triggered.",
        }
    except (OrchestrationAuthorizationError, OrchestrationTransitionError) as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))


@router.post(
    "/{project_id}/workflows/{workflow_id}/reject",
    response_model=WorkflowActionResponse,
    status_code=status.HTTP_200_OK,
    summary="Reject a pending workflow",
)
def reject_workflow(
    project_id: str,
    workflow_id: str,
    req: WorkflowActionRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    verify_project_access(project_id, current_user, db)
    user_role = _get_project_role(project_id, current_user, db)

    try:
        wf = AutonomousOrchestrationEngine.reject_workflow(
            db=db,
            workflow_id=workflow_id,
            user=current_user,
            user_role=user_role,
            reason=req.notes or "Rejected by operator",
        )
        return {
            "workflow_id": wf.id,
            "state": wf.state,
            "message": "Workflow rejected.",
        }
    except OrchestrationTransitionError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post(
    "/{project_id}/workflows/{workflow_id}/suspend",
    response_model=WorkflowActionResponse,
    status_code=status.HTTP_200_OK,
    summary="Suspend an active workflow",
)
def suspend_workflow(
    project_id: str,
    workflow_id: str,
    req: WorkflowActionRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    verify_project_access(project_id, current_user, db)
    try:
        wf = AutonomousOrchestrationEngine.suspend_workflow(
            db=db,
            workflow_id=workflow_id,
            user=current_user,
            reason=req.notes or "Operator suspension",
        )
        return {
            "workflow_id": wf.id,
            "state": wf.state,
            "message": "Workflow suspended.",
        }
    except OrchestrationTransitionError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post(
    "/{project_id}/workflows/{workflow_id}/resume",
    response_model=WorkflowActionResponse,
    status_code=status.HTTP_200_OK,
    summary="Resume a suspended workflow",
)
def resume_workflow(
    project_id: str,
    workflow_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    verify_project_access(project_id, current_user, db)
    try:
        wf = AutonomousOrchestrationEngine.resume_workflow(
            db=db,
            workflow_id=workflow_id,
            user=current_user,
        )
        AutonomousOrchestrationEngine.execute_workflow_cycle(
            db=db,
            workflow_id=wf.id,
            worker_id=f"operator-{current_user.id[:8]}",
        )
        return {
            "workflow_id": wf.id,
            "state": wf.state,
            "message": "Workflow resumed and executed.",
        }
    except (OrchestrationAuthorizationError, OrchestrationTransitionError) as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))


@router.post(
    "/{project_id}/workflows/{workflow_id}/retry",
    response_model=WorkflowActionResponse,
    status_code=status.HTTP_200_OK,
    summary="Retry a failed workflow",
)
def retry_workflow(
    project_id: str,
    workflow_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    verify_project_access(project_id, current_user, db)
    try:
        wf = AutonomousOrchestrationEngine.retry_workflow(
            db=db,
            workflow_id=workflow_id,
            user=current_user,
        )
        AutonomousOrchestrationEngine.execute_workflow_cycle(
            db=db,
            workflow_id=wf.id,
            worker_id=f"operator-{current_user.id[:8]}",
        )
        return {
            "workflow_id": wf.id,
            "state": wf.state,
            "message": "Workflow retry initiated.",
        }
    except (OrchestrationAuthorizationError, OrchestrationTransitionError) as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))


# ------------------------------------------------------------------------------
# Optimizations and Invalidations
# ------------------------------------------------------------------------------
@router.get(
    "/{project_id}/optimizations",
    response_model=List[AdaptiveOptimizationRead],
    status_code=status.HTTP_200_OK,
    summary="List evaluated adaptive optimization records",
)
def list_optimizations(
    project_id: str,
    limit: int = Query(10, ge=1, le=50),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    verify_project_access(project_id, current_user, db)
    return AdaptiveOptimizationService.list_optimizations(db=db, project_id=project_id, limit=limit)


@router.get(
    "/{project_id}/invalidations",
    response_model=List[DependencyInvalidationRead],
    status_code=status.HTTP_200_OK,
    summary="List dependency invalidation records",
)
def list_invalidations(
    project_id: str,
    limit: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    verify_project_access(project_id, current_user, db)
    return (
        db.query(DependencyInvalidationRecord)
        .filter(DependencyInvalidationRecord.project_id == project_id)
        .order_by(desc(DependencyInvalidationRecord.created_at))
        .limit(limit)
        .all()
    )
