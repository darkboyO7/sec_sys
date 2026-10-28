from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.user import User
from app.models.project import ProjectRole
from app.models.decision import DecisionLedgerType
from app.models.notification import NotificationStatus
from app.api.deps import get_current_user, verify_project_access

from app.schemas.operations import (
    PolicyRead,
    PolicyUpdateRequest,
    EmergencySuspendRequest,
    DecisionLedgerRead,
    DecisionLedgerListResponse,
    NotificationRead,
    NotificationListResponse,
    NotificationProviderStatusRead,
    SLOConfigRead,
    SLOConfigUpdateRequest,
    OperationsDashboardRead,
    LifecycleTransitionRequest,
    LifecycleTransitionResponse,
)
from app.services.policy_engine import PolicyEngineService
from app.services.decision_ledger_service import DecisionLedgerService
from app.services.notification_service import NotificationService
from app.services.operational_metrics_service import OperationalMetricsService
from app.services.unified_operations_service import UnifiedOperationsService

router = APIRouter()


# ------------------------------------------------------------------------------
# Dashboard Endpoint
# ------------------------------------------------------------------------------
@router.get(
    "/{project_id}/dashboard",
    response_model=OperationsDashboardRead,
    status_code=status.HTTP_200_OK,
    summary="Get complete unified operations overview and health dashboard",
)
def get_operations_dashboard(
    project_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    verify_project_access(project_id, current_user, db)
    return UnifiedOperationsService.get_operations_dashboard(db=db, project_id=project_id)


# ------------------------------------------------------------------------------
# Policy Engine Endpoints
# ------------------------------------------------------------------------------
@router.get(
    "/{project_id}/policy",
    response_model=PolicyRead,
    status_code=status.HTTP_200_OK,
    summary="Get active autonomous security policy",
)
def get_policy(
    project_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    verify_project_access(project_id, current_user, db)
    return PolicyEngineService.get_or_create_policy(db=db, project_id=project_id, creator=current_user)


@router.put(
    "/{project_id}/policy",
    response_model=PolicyRead,
    status_code=status.HTTP_200_OK,
    summary="Update autonomous security policy configuration (Requires LEAD role)",
)
def update_policy(
    project_id: str,
    payload: PolicyUpdateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    verify_project_access(project_id, current_user, db, required_project_roles=[ProjectRole.LEAD])
    update_data = {k: v for k, v in payload.model_dump().items() if v is not None}
    return PolicyEngineService.update_policy(
        db=db,
        project_id=project_id,
        update_data=update_data,
        actor=current_user,
    )


@router.post(
    "/{project_id}/policy/emergency-suspend",
    response_model=PolicyRead,
    status_code=status.HTTP_200_OK,
    summary="Trigger emergency kill-switch to suspend autonomous operations (Requires LEAD role)",
)
def emergency_suspend_policy(
    project_id: str,
    payload: EmergencySuspendRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    verify_project_access(project_id, current_user, db, required_project_roles=[ProjectRole.LEAD])
    return PolicyEngineService.emergency_suspend(
        db=db,
        project_id=project_id,
        reason=payload.reason,
        actor=current_user,
    )


@router.post(
    "/{project_id}/policy/resume",
    response_model=PolicyRead,
    status_code=status.HTTP_200_OK,
    summary="Resume autonomous operations following emergency suspension (Requires LEAD role)",
)
def resume_policy(
    project_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    verify_project_access(project_id, current_user, db, required_project_roles=[ProjectRole.LEAD])
    return PolicyEngineService.resume_autonomy(
        db=db,
        project_id=project_id,
        actor=current_user,
    )


# ------------------------------------------------------------------------------
# Decision Ledger Endpoints
# ------------------------------------------------------------------------------
@router.get(
    "/{project_id}/decision-ledger",
    response_model=DecisionLedgerListResponse,
    status_code=status.HTTP_200_OK,
    summary="Query auditable security decision ledger records",
)
def get_decision_ledger(
    project_id: str,
    decision_type: Optional[DecisionLedgerType] = Query(None),
    decision_outcome: Optional[str] = Query(None),
    target_type: Optional[str] = Query(None),
    target_id: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    verify_project_access(project_id, current_user, db)
    return DecisionLedgerService.query_ledger(
        db=db,
        project_id=project_id,
        decision_type=decision_type,
        decision_outcome=decision_outcome,
        target_type=target_type,
        target_id=target_id,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/{project_id}/decision-ledger/{target_id}/trail",
    response_model=List[DecisionLedgerRead],
    status_code=status.HTTP_200_OK,
    summary="Get complete historical decision trail for a specific target entity",
)
def get_target_decision_trail(
    project_id: str,
    target_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    verify_project_access(project_id, current_user, db)
    return DecisionLedgerService.get_audit_trail_for_entity(
        db=db,
        project_id=project_id,
        target_id=target_id,
    )


# ------------------------------------------------------------------------------
# Notification Endpoints
# ------------------------------------------------------------------------------
@router.get(
    "/{project_id}/notifications",
    response_model=NotificationListResponse,
    status_code=status.HTTP_200_OK,
    summary="Query security notifications and delivery statuses",
)
def get_notifications(
    project_id: str,
    notification_status: Optional[NotificationStatus] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    verify_project_access(project_id, current_user, db)
    return NotificationService.get_notifications(
        db=db,
        project_id=project_id,
        status=notification_status,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/{project_id}/notifications/provider-status",
    response_model=NotificationProviderStatusRead,
    status_code=status.HTTP_200_OK,
    summary="Get honest notification delivery provider configuration status",
)
def get_notification_provider_status(
    project_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    verify_project_access(project_id, current_user, db)
    return NotificationService.get_notification_provider_status(db=db, project_id=project_id)


@router.post(
    "/{project_id}/notifications/retry-failed",
    response_model=List[NotificationRead],
    status_code=status.HTTP_200_OK,
    summary="Retry transiently failed notifications within retry budget (Requires LEAD role)",
)
def retry_failed_notifications(
    project_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    verify_project_access(project_id, current_user, db, required_project_roles=[ProjectRole.LEAD])
    return NotificationService.retry_failed_notifications(db=db, project_id=project_id)


# ------------------------------------------------------------------------------
# Operational SLO Endpoints
# ------------------------------------------------------------------------------
@router.get(
    "/{project_id}/slo-metrics",
    status_code=status.HTTP_200_OK,
    summary="Calculate comprehensive operational SLO adherence metrics",
)
def get_slo_metrics(
    project_id: str,
    window_days: int = Query(30, ge=1, le=365),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    verify_project_access(project_id, current_user, db)
    return OperationalMetricsService.calculate_operational_slos(
        db=db,
        project_id=project_id,
        window_days=window_days,
    )


@router.get(
    "/{project_id}/slo-config",
    response_model=SLOConfigRead,
    status_code=status.HTTP_200_OK,
    summary="Get project-specific SLO target objectives and alert thresholds",
)
def get_slo_config(
    project_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    verify_project_access(project_id, current_user, db)
    return OperationalMetricsService.get_or_create_slo_config(db=db, project_id=project_id)


@router.put(
    "/{project_id}/slo-config",
    response_model=SLOConfigRead,
    status_code=status.HTTP_200_OK,
    summary="Update project-specific SLO target thresholds (Requires LEAD role)",
)
def update_slo_config(
    project_id: str,
    payload: SLOConfigUpdateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    verify_project_access(project_id, current_user, db, required_project_roles=[ProjectRole.LEAD])
    update_data = {k: v for k, v in payload.model_dump().items() if v is not None}
    return OperationalMetricsService.update_slo_config(
        db=db,
        project_id=project_id,
        update_data=update_data,
    )


# ------------------------------------------------------------------------------
# Lifecycle Transition Endpoint
# ------------------------------------------------------------------------------
@router.post(
    "/{project_id}/lifecycle-transition/{finding_id}",
    response_model=LifecycleTransitionResponse,
    status_code=status.HTTP_200_OK,
    summary="Execute a verified finding lifecycle state transition",
)
def execute_lifecycle_transition(
    project_id: str,
    finding_id: str,
    payload: LifecycleTransitionRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    verify_project_access(project_id, current_user, db, required_project_roles=[ProjectRole.LEAD, ProjectRole.TESTER])
    return UnifiedOperationsService.execute_lifecycle_transition(
        db=db,
        project_id=project_id,
        finding_id=finding_id,
        action=payload.action,
        actor=current_user,
        notes=payload.notes or "",
    )
