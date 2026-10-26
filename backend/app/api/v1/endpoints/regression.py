from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Request, Query
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.user import User
from app.models.regression import (
    RegressionAlert,
    RegressionBaseline,
    AlertStatus,
    AlertSeverity,
)
from app.schemas.regression import (
    RegressionAlertRead,
    RegressionBaselineCreate,
    RegressionBaselineRead,
    AlertAcknowledgeRequest,
    AlertResolveRequest,
    RegressionEvaluationResponse,
)
from app.services.regression_service import RegressionDetectionService
from app.api.deps import get_current_user, verify_project_access, get_client_ip
from app.models.base import utc_now

router = APIRouter()


@router.post(
    "/projects/{project_id}/regressions/evaluate",
    response_model=RegressionEvaluationResponse,
    status_code=status.HTTP_200_OK,
    summary="Evaluate project regressions and generate change intelligence alerts",
)
def evaluate_regressions(
    project_id: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    verify_project_access(project_id, current_user, db)
    client_ip = get_client_ip(request)

    try:
        active_alerts = RegressionDetectionService.evaluate_project_regressions(
            project_id=project_id,
            db=db,
            actor=current_user,
            client_ip=client_ip,
        )
        return RegressionEvaluationResponse(
            project_id=project_id,
            evaluated_at=utc_now(),
            alerts_generated=len(active_alerts),
            active_alerts_count=len(active_alerts),
            alerts=[RegressionAlertRead.model_validate(a) for a in active_alerts],
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.get(
    "/projects/{project_id}/regressions/alerts",
    response_model=List[RegressionAlertRead],
    summary="List regression alerts for project",
)
def list_regression_alerts(
    project_id: str,
    status_filter: Optional[AlertStatus] = Query(None, description="Filter by status (ACTIVE, ACKNOWLEDGED, RESOLVED, DISMISSED)"),
    severity_filter: Optional[AlertSeverity] = Query(None, description="Filter by severity"),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    verify_project_access(project_id, current_user, db)
    query = db.query(RegressionAlert).filter(RegressionAlert.project_id == project_id)
    if status_filter:
        query = query.filter(RegressionAlert.status == status_filter)
    if severity_filter:
        query = query.filter(RegressionAlert.severity == severity_filter)

    return (
        query.order_by(RegressionAlert.created_at.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )


@router.post(
    "/projects/{project_id}/regressions/alerts/{alert_id}/acknowledge",
    response_model=RegressionAlertRead,
    summary="Acknowledge a regression alert",
)
def acknowledge_alert(
    project_id: str,
    alert_id: str,
    body: AlertAcknowledgeRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    verify_project_access(project_id, current_user, db)
    client_ip = get_client_ip(request)
    try:
        return RegressionDetectionService.acknowledge_alert(
            project_id=project_id,
            alert_id=alert_id,
            user=current_user,
            db=db,
            notes=body.notes,
            client_ip=client_ip,
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.post(
    "/projects/{project_id}/regressions/alerts/{alert_id}/resolve",
    response_model=RegressionAlertRead,
    summary="Resolve or dismiss a regression alert",
)
def resolve_alert(
    project_id: str,
    alert_id: str,
    body: AlertResolveRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    verify_project_access(project_id, current_user, db)
    client_ip = get_client_ip(request)
    try:
        return RegressionDetectionService.resolve_alert(
            project_id=project_id,
            alert_id=alert_id,
            resolution_notes=body.resolution_notes,
            user=current_user,
            db=db,
            dismiss=body.dismiss,
            client_ip=client_ip,
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.get(
    "/projects/{project_id}/regressions/baseline",
    response_model=RegressionBaselineRead,
    summary="Get active regression baseline configuration",
)
def get_active_baseline(
    project_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    verify_project_access(project_id, current_user, db)
    return RegressionDetectionService.get_or_create_active_baseline(project_id, db)


@router.post(
    "/projects/{project_id}/regressions/baseline",
    response_model=RegressionBaselineRead,
    status_code=status.HTTP_201_CREATED,
    summary="Configure active regression baseline",
)
def configure_baseline(
    project_id: str,
    body: RegressionBaselineCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    verify_project_access(project_id, current_user, db)

    # Deactivate existing baselines
    existing = db.query(RegressionBaseline).filter(RegressionBaseline.project_id == project_id).all()
    for b in existing:
        b.is_active = False

    new_baseline = RegressionBaseline(
        project_id=project_id,
        snapshot_id=body.snapshot_id,
        name=body.name,
        is_active=True,
        risk_score_threshold_delta=body.risk_score_threshold_delta,
        evidence_stale_days=body.evidence_stale_days,
    )
    db.add(new_baseline)
    db.commit()
    db.refresh(new_baseline)
    return new_baseline
