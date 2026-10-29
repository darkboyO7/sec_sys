"""
VAPT Platform — Reliable Security Alerting & Notification Management Endpoints (Prompt 31).
Exposes alert lifecycle, transactional outbox dispatch, dead-letter replay,
and maintenance window management.
"""
from typing import Optional, List
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, Query, HTTPException, status
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.api.deps import get_current_user, require_system_roles
from app.models.user import User, SystemRole
from app.models.notification import (
    AlertLifecycleStatus,
    NotificationSeverity,
)
from app.schemas.alerting import (
    AlertListResponse,
    AlertResponse,
    AlertActionRequest,
    AlertAssignmentRequest,
    OutboxStatusResponse,
    MaintenanceWindowCreateRequest,
    MaintenanceWindowResponse,
)
from app.services.alerting_service import alerting_service

router = APIRouter()


@router.get("", response_model=AlertListResponse, summary="List Security Alerts")
def list_alerts(
    project_id: str = Query(..., description="Project ID to retrieve alerts for"),
    lifecycle_status: Optional[AlertLifecycleStatus] = Query(None, description="Filter by alert lifecycle status"),
    severity: Optional[NotificationSeverity] = Query(None, description="Filter by severity"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Lists operational security alerts with server-side pagination, filters, and count metrics."""
    return alerting_service.get_alerts(
        db=db,
        project_id=project_id,
        lifecycle_status=lifecycle_status,
        severity=severity,
        limit=limit,
        offset=offset,
    )


@router.get("/outbox/status", response_model=OutboxStatusResponse, summary="Get Event Outbox Operational Status")
def get_outbox_status(
    project_id: Optional[str] = Query(None, description="Optional project ID filter"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Returns transactional outbox backlog, retry counts, dead-letter state, and delivery health."""
    return alerting_service.get_outbox_status(db=db, project_id=project_id)


@router.post("/outbox/process", summary="Trigger Outbox Event Dispatch Batch")
def process_outbox_batch(
    batch_size: int = Query(50, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_system_roles([
            SystemRole.ADMIN,
            SystemRole.SECURITY_LEAD,
            SystemRole.SECURITY_TESTER,
        ])
    ),
):
    """Processes pending events from the transactional outbox with bounded exponential backoff."""
    return alerting_service.process_outbox(db=db, batch_size=batch_size)


@router.post("/outbox/{event_id}/replay", summary="Replay Dead-Letter Event")
def replay_dead_letter_event(
    event_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_system_roles([
            SystemRole.ADMIN,
            SystemRole.SECURITY_LEAD,
        ])
    ),
):
    """Resets a dead-letter event to PENDING and schedules immediate retry."""
    success = alerting_service.replay_dead_letter_event(db=db, event_id=event_id)
    if not success:
        raise HTTPException(status_code=404, detail="Dead-letter event not found or not in DEAD_LETTER status")
    return {"status": "REPLAY_SCHEDULED", "event_id": event_id}


@router.get("/maintenance-windows", response_model=List[MaintenanceWindowResponse], summary="List Maintenance Windows")
def list_maintenance_windows(
    project_id: str = Query(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Lists scheduled maintenance windows for the project."""
    return alerting_service.list_maintenance_windows(db=db, project_id=project_id)


@router.post("/maintenance-windows", response_model=MaintenanceWindowResponse, summary="Create Maintenance Window")
def create_maintenance_window(
    payload: MaintenanceWindowCreateRequest,
    project_id: str = Query(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_system_roles([
            SystemRole.ADMIN,
            SystemRole.SECURITY_LEAD,
        ])
    ),
):
    """Creates a maintenance window to explainably suppress non-critical notification delivery."""
    try:
        start_dt = datetime.fromisoformat(payload.start_time.replace("Z", "+00:00"))
        end_dt = datetime.fromisoformat(payload.end_time.replace("Z", "+00:00"))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid ISO timestamp format: {str(e)}")

    if end_dt <= start_dt:
        raise HTTPException(status_code=400, detail="End time must be after start time")

    mw = alerting_service.create_maintenance_window(
        db=db,
        project_id=project_id,
        title=payload.title,
        reason=payload.reason,
        start_time=start_dt,
        end_time=end_dt,
        suppress_critical=payload.suppress_critical,
        user_id=current_user.id,
    )
    return MaintenanceWindowResponse(
        id=mw.id,
        project_id=mw.project_id,
        title=mw.title,
        reason=mw.reason,
        start_time=mw.start_time.isoformat(),
        end_time=mw.end_time.isoformat(),
        suppress_critical=mw.suppress_critical,
        is_currently_active=mw.start_time <= datetime.now(timezone.utc) <= mw.end_time,
        created_at=mw.created_at.isoformat(),
    )


@router.get("/{alert_id}", response_model=AlertResponse, summary="Get Security Alert Details")
def get_alert(
    alert_id: str,
    project_id: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Retrieves full alert record with delivery attempts and lifecycle history."""
    alert = alerting_service.get_alert_by_id(db=db, alert_id=alert_id, project_id=project_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert record not found")

    return AlertResponse(
        id=alert.id,
        project_id=alert.project_id,
        event_type=alert.event_type,
        severity=alert.severity,
        title=alert.title,
        summary=alert.summary,
        lifecycle_status=alert.lifecycle_status,
        delivery_status=alert.status,
        assigned_to_id=alert.assigned_to_id,
        acknowledged_at=alert.acknowledged_at.isoformat() if alert.acknowledged_at else None,
        acknowledged_by_id=alert.acknowledged_by_id,
        resolved_at=alert.resolved_at.isoformat() if alert.resolved_at else None,
        resolved_by_id=alert.resolved_by_id,
        reopened_at=alert.reopened_at.isoformat() if alert.reopened_at else None,
        escalated_at=alert.escalated_at.isoformat() if alert.escalated_at else None,
        correlation_id=alert.correlation_id,
        causation_id=alert.causation_id,
        idempotency_key=alert.idempotency_key,
        schema_version=alert.schema_version,
        suppression_reason=alert.suppression_reason,
        retry_count=alert.retry_count,
        max_retries=alert.max_retries,
        last_attempt_at=alert.last_attempt_at.isoformat() if alert.last_attempt_at else None,
        error_message=alert.error_message,
        delivery_attempts_count=len(alert.delivery_attempts) if alert.delivery_attempts else 0,
        created_at=alert.created_at.isoformat(),
        updated_at=alert.updated_at.isoformat(),
    )


@router.post("/{alert_id}/acknowledge", summary="Acknowledge Security Alert")
def acknowledge_alert(
    alert_id: str,
    payload: AlertActionRequest = AlertActionRequest(),
    project_id: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_system_roles([
            SystemRole.ADMIN,
            SystemRole.SECURITY_LEAD,
            SystemRole.SECURITY_TESTER,
        ])
    ),
):
    """Transitions an alert to ACKNOWLEDGED state."""
    alert = alerting_service.acknowledge_alert(
        db=db,
        alert_id=alert_id,
        user_id=current_user.id,
        project_id=project_id,
    )
    if not alert:
        raise HTTPException(status_code=404, detail="Alert record not found")
    return {"status": "ACKNOWLEDGED", "alert_id": alert_id, "acknowledged_by": current_user.email}


@router.post("/{alert_id}/assign", summary="Assign Security Alert")
def assign_alert(
    alert_id: str,
    payload: AlertAssignmentRequest,
    project_id: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_system_roles([
            SystemRole.ADMIN,
            SystemRole.SECURITY_LEAD,
        ])
    ),
):
    """Assigns an alert to a designated operator."""
    alert = alerting_service.assign_alert(
        db=db,
        alert_id=alert_id,
        assigned_to_id=payload.assigned_to_id,
        user_id=current_user.id,
        project_id=project_id,
    )
    if not alert:
        raise HTTPException(status_code=404, detail="Alert record not found")
    return {"status": "ASSIGNED", "alert_id": alert_id, "assigned_to_id": payload.assigned_to_id}


@router.post("/{alert_id}/resolve", summary="Resolve Security Alert")
def resolve_alert(
    alert_id: str,
    payload: AlertActionRequest = AlertActionRequest(),
    project_id: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_system_roles([
            SystemRole.ADMIN,
            SystemRole.SECURITY_LEAD,
        ])
    ),
):
    """Transitions an alert to RESOLVED state."""
    alert = alerting_service.resolve_alert(
        db=db,
        alert_id=alert_id,
        user_id=current_user.id,
        project_id=project_id,
    )
    if not alert:
        raise HTTPException(status_code=404, detail="Alert record not found")
    return {"status": "RESOLVED", "alert_id": alert_id, "resolved_by": current_user.email}


@router.post("/{alert_id}/reopen", summary="Reopen Security Alert")
def reopen_alert(
    alert_id: str,
    payload: AlertActionRequest = AlertActionRequest(),
    project_id: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_system_roles([
            SystemRole.ADMIN,
            SystemRole.SECURITY_LEAD,
        ])
    ),
):
    """Transitions a resolved alert back to REOPENED state."""
    alert = alerting_service.reopen_alert(
        db=db,
        alert_id=alert_id,
        user_id=current_user.id,
        project_id=project_id,
    )
    if not alert:
        raise HTTPException(status_code=404, detail="Alert record not found")
    return {"status": "REOPENED", "alert_id": alert_id, "reopened_by": current_user.email}
