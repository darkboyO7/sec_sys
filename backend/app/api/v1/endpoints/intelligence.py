from typing import Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.user import User, SystemRole
from app.models.project import ProjectRole, ProjectMember
from app.api.deps import get_current_user, verify_project_access
from app.schemas.intelligence import (
    ProjectIntelligenceSummaryResponse,
    CoverageAuditResponse,
    AdaptivePlanResponse,
    AdaptivePlanCreateRequest,
    ExecutePlanCheckRequest,
)
from app.services.security_intelligence_service import SecurityIntelligenceService
from app.models.decision import ChangeType, AdaptiveAssessmentPlanRecord, PlanStatus

router = APIRouter()


@router.get("/projects/{project_id}/intelligence/overview", response_model=ProjectIntelligenceSummaryResponse)
def get_project_intelligence_summary(
    project_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Returns unified evidence-backed security intelligence across risk, assets, attack paths,
    remediation verifications, adaptive planning, and learning pipeline telemetry.
    """
    verify_project_access(project_id, current_user, db)
    try:
        summary = SecurityIntelligenceService.get_project_intelligence_summary(db=db, project_id=project_id)
        return summary
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.get("/projects/{project_id}/intelligence/coverage", response_model=CoverageAuditResponse)
def audit_assessment_coverage(
    project_id: str,
    stale_days: int = 14,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Identifies assets and scope targets that have stale or missing assessment coverage.
    """
    verify_project_access(project_id, current_user, db)
    return SecurityIntelligenceService.audit_assessment_coverage(
        db=db,
        project_id=project_id,
        stale_days_threshold=stale_days,
    )


@router.get("/projects/{project_id}/intelligence/plans/latest", response_model=Optional[AdaptivePlanResponse])
def get_latest_adaptive_plan(
    project_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Retrieves the most recent active or generated adaptive assessment plan.
    """
    verify_project_access(project_id, current_user, db)
    plan = (
        db.query(AdaptiveAssessmentPlanRecord)
        .filter(
            AdaptiveAssessmentPlanRecord.project_id == project_id,
            AdaptiveAssessmentPlanRecord.status.in_([PlanStatus.GENERATED, PlanStatus.PARTIALLY_EXECUTED, PlanStatus.COMPLETED]),
        )
        .order_by(AdaptiveAssessmentPlanRecord.created_at.desc())
        .first()
    )
    if not plan:
        return None

    return {
        "id": plan.id,
        "project_id": plan.project_id,
        "plan_name": plan.plan_name,
        "status": plan.status.value,
        "scan_budget": plan.scan_budget,
        "total_recommended": plan.total_recommended,
        "total_skipped": plan.total_skipped,
        "recommended_checks": plan.recommended_checks,
        "skipped_checks": plan.skipped_checks,
        "execution_summary": plan.execution_summary or {},
        "created_at": plan.created_at.isoformat() if plan.created_at else "",
        "updated_at": plan.updated_at.isoformat() if plan.updated_at else "",
    }


@router.post("/projects/{project_id}/intelligence/plans/generate", response_model=AdaptivePlanResponse)
def generate_adaptive_plan(
    project_id: str,
    req: AdaptivePlanCreateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Synthesizes a new Evidence-Driven Adaptive Assessment Plan respecting scan budget and scope.
    """
    verify_project_access(project_id, current_user, db)
    plan = SecurityIntelligenceService.generate_adaptive_assessment_plan(
        db=db,
        project_id=project_id,
        scan_budget=req.scan_budget,
        creator=current_user,
    )
    return {
        "id": plan.id,
        "project_id": plan.project_id,
        "plan_name": plan.plan_name,
        "status": plan.status.value,
        "scan_budget": plan.scan_budget,
        "total_recommended": plan.total_recommended,
        "total_skipped": plan.total_skipped,
        "recommended_checks": plan.recommended_checks,
        "skipped_checks": plan.skipped_checks,
        "execution_summary": plan.execution_summary or {},
        "created_at": plan.created_at.isoformat() if plan.created_at else "",
        "updated_at": plan.updated_at.isoformat() if plan.updated_at else "",
    }


@router.post("/projects/{project_id}/intelligence/plans/{plan_id}/execute")
def execute_planned_check(
    project_id: str,
    plan_id: str,
    req: ExecutePlanCheckRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Executes a recommended check from an adaptive plan under real-time scope enforcement.
    """
    verify_project_access(project_id, current_user, db)
    client_ip = request.client.host if request.client else None
    try:
        result = SecurityIntelligenceService.execute_planned_check(
            db=db,
            project_id=project_id,
            plan_id=plan_id,
            check_id=req.check_id,
            actor=current_user,
            client_ip=client_ip,
        )
        return result
    except PermissionError as pe:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(pe))
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ve))


@router.post("/projects/{project_id}/intelligence/changes/record")
def record_posture_change(
    project_id: str,
    payload: Dict[str, Any],
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Records an observed posture change with event-storm throttling and deduplication.
    """
    verify_project_access(project_id, current_user, db)
    change_type_str = payload.get("change_type", "CONFIG_CHANGED")
    try:
        c_type = ChangeType(change_type_str)
    except ValueError:
        c_type = ChangeType.CONFIG_CHANGED

    result = SecurityIntelligenceService.record_posture_change_with_throttle(
        db=db,
        project_id=project_id,
        change_type=c_type,
        target_resource=payload.get("target_resource", ""),
        title=payload.get("title", "Observed Posture Change"),
        previous_state=payload.get("previous_state", {}),
        new_state=payload.get("new_state", {}),
        evidence_summary=payload.get("evidence_summary", "Environmental telemetry event"),
        confidence=float(payload.get("confidence", 1.0)),
    )
    return result
