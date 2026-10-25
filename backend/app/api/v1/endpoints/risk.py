from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Request, Query
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.core.database import get_db
from app.models.user import User, SystemRole
from app.models.project import ProjectRole
from app.models.risk import RiskAssessment, RiskPriority, RemediationRecommendation, RecommendationStatus
from app.models.finding import VulnerabilityFinding, FindingLifecycleStatus
from app.schemas.risk import (
    RiskAssessmentRead,
    RiskSummaryResponse,
    AttackPathRequest,
    AttackPathAnalysisResponse,
    RemediationRecommendationRead,
    RemediationReviewRequest,
)
from app.services.contextual_risk_service import ContextualRiskService
from app.services.attack_path_service import AttackPathAnalysisService
from app.services.remediation_service import RemediationPrioritizationService
from app.api.deps import get_current_user, verify_project_access, get_client_ip

router = APIRouter()


@router.get("/projects/{project_id}/risk/summary", response_model=RiskSummaryResponse)
def get_project_risk_summary(
    project_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Returns an aggregated risk intelligence summary for a project:
    distribution by priority, average contextual risk score, and counts of active critical issues.
    """
    verify_project_access(project_id, current_user, db)

    # Active non-superseded assessments
    active_assessments = (
        db.query(RiskAssessment)
        .filter(
            RiskAssessment.project_id == project_id,
            RiskAssessment.is_superseded.is_(False),
        )
        .all()
    )

    by_priority: dict = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "INFORMATIONAL": 0,
    }
    scores = []
    for a in active_assessments:
        p_val = a.priority.value if hasattr(a.priority, "value") else str(a.priority)
        by_priority[p_val] = by_priority.get(p_val, 0) + 1
        scores.append(a.score)

    total = len(active_assessments)
    avg_score = round(sum(scores) / total, 1) if total > 0 else 0.0
    highest_score = max(scores) if scores else 0.0

    # Unresolved findings count
    unresolved_count = (
        db.query(func.count(VulnerabilityFinding.id))
        .filter(
            VulnerabilityFinding.project_id == project_id,
            VulnerabilityFinding.status.notin_([
                FindingLifecycleStatus.VERIFIED_CLOSED,
                FindingLifecycleStatus.FALSE_POSITIVE,
            ]),
        )
        .scalar()
        or 0
    )

    return RiskSummaryResponse(
        total_assessed=total,
        by_priority=by_priority,
        average_score=avg_score,
        highest_score=highest_score,
        critical_count=by_priority.get("CRITICAL", 0),
        high_count=by_priority.get("HIGH", 0),
        unresolved_risk_count=unresolved_count,
    )


@router.get("/projects/{project_id}/risk/assessments", response_model=List[RiskAssessmentRead])
def list_risk_assessments(
    project_id: str,
    priority: Optional[RiskPriority] = Query(None, description="Filter by risk priority"),
    asset_id: Optional[str] = Query(None, description="Filter by asset ID"),
    include_superseded: bool = Query(False, description="Whether to include historical superseded assessments"),
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    List contextual risk assessments for findings in a project with pagination and filters.
    """
    verify_project_access(project_id, current_user, db)

    query = db.query(RiskAssessment).filter(RiskAssessment.project_id == project_id)

    if not include_superseded:
        query = query.filter(RiskAssessment.is_superseded.is_(False))

    if priority:
        query = query.filter(RiskAssessment.priority == priority)

    if asset_id:
        query = query.filter(RiskAssessment.asset_id == asset_id)

    return (
        query.order_by(RiskAssessment.score.desc(), RiskAssessment.calculated_at.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )


@router.get("/projects/{project_id}/risk/findings/{finding_id}", response_model=RiskAssessmentRead)
def get_or_assess_finding_risk(
    project_id: str,
    finding_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Retrieve or calculate the current active contextual risk assessment for a specific finding.
    """
    verify_project_access(project_id, current_user, db)

    assessment = (
        db.query(RiskAssessment)
        .filter(
            RiskAssessment.project_id == project_id,
            RiskAssessment.finding_id == finding_id,
            RiskAssessment.is_superseded.is_(False),
        )
        .first()
    )
    if not assessment:
        # Auto-assess if not yet calculated
        try:
            assessment = ContextualRiskService.assess_and_persist_finding_risk(
                project_id=project_id,
                finding_id=finding_id,
                db=db,
                actor=current_user,
            )
        except ValueError as e:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))

    return assessment


@router.post("/projects/{project_id}/risk/findings/{finding_id}/assess", response_model=RiskAssessmentRead)
def recalculate_finding_risk(
    project_id: str,
    finding_id: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Force a fresh recalculation of a finding's contextual risk score and persist it.
    Requires project membership.
    """
    verify_project_access(project_id, current_user, db)

    try:
        client_ip = get_client_ip(request)
        return ContextualRiskService.assess_and_persist_finding_risk(
            project_id=project_id,
            finding_id=finding_id,
            db=db,
            force_recalculate=True,
            actor=current_user,
            client_ip=client_ip,
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.post("/projects/{project_id}/risk/recalculate")
def recalculate_all_project_risks(
    project_id: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Batch recalculate contextual risk assessments for all findings in a project.
    Requires Project LEAD or System ADMIN.
    """
    verify_project_access(
        project_id,
        current_user,
        db,
        required_project_roles=[ProjectRole.LEAD],
    )

    client_ip = get_client_ip(request)
    count = ContextualRiskService.recalculate_project_risks(
        project_id=project_id,
        db=db,
        actor=current_user,
        client_ip=client_ip,
    )
    return {"message": f"Successfully recalculated risk assessments for {count} findings.", "recalculated_count": count}


@router.post("/projects/{project_id}/graph/paths/analyze", response_model=AttackPathAnalysisResponse)
def analyze_attack_paths(
    project_id: str,
    req: AttackPathRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Execute bounded, cycle-safe attack path analysis through the project's knowledge graph.
    Returns categorized paths (VERIFIED, MIXED_EVIDENCE, HYPOTHETICAL) with cumulative confidence.
    """
    verify_project_access(project_id, current_user, db)

    try:
        return AttackPathAnalysisService.analyze_attack_paths(
            project_id=project_id,
            db=db,
            start_node_id=req.start_node_id,
            target_node_id=req.target_node_id,
            finding_id=req.finding_id,
            max_depth=req.max_depth,
            max_paths=req.max_paths,
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.get("/projects/{project_id}/remediations", response_model=List[RemediationRecommendationRead])
def list_remediation_recommendations(
    project_id: str,
    status_filter: Optional[RecommendationStatus] = Query(None, description="Filter by review status"),
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    List remediation recommendations for the project with optional status filter.
    """
    verify_project_access(project_id, current_user, db)

    query = db.query(RemediationRecommendation).filter(RemediationRecommendation.project_id == project_id)
    if status_filter:
        query = query.filter(RemediationRecommendation.status == status_filter)

    return (
        query.order_by(RemediationRecommendation.created_at.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )


@router.get("/projects/{project_id}/remediations/findings/{finding_id}", response_model=RemediationRecommendationRead)
def get_or_generate_finding_remediation(
    project_id: str,
    finding_id: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Retrieve or generate defensive remediation recommendation for a specific finding.
    """
    verify_project_access(project_id, current_user, db)

    try:
        client_ip = get_client_ip(request)
        return RemediationPrioritizationService.generate_or_get_recommendation(
            project_id=project_id,
            finding_id=finding_id,
            db=db,
            actor=current_user,
            client_ip=client_ip,
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.post("/projects/{project_id}/remediations/{recommendation_id}/review", response_model=RemediationRecommendationRead)
def review_remediation_recommendation(
    project_id: str,
    recommendation_id: str,
    review_req: RemediationReviewRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Review a remediation recommendation (APPROVE, DEFER, REJECT).
    Requires Project LEAD or System ADMIN to approve recommendations marked requires_approval.
    """
    verify_project_access(project_id, current_user, db)
    reviewer_role = None
    if current_user.system_role == SystemRole.ADMIN:
        reviewer_role = ProjectRole.LEAD
    else:
        from app.models.project import ProjectMember
        member = (
            db.query(ProjectMember)
            .filter(ProjectMember.project_id == project_id, ProjectMember.user_id == current_user.id)
            .first()
        )
        reviewer_role = member.role if member else None

    client_ip = get_client_ip(request)
    try:
        return RemediationPrioritizationService.review_recommendation(
            project_id=project_id,
            recommendation_id=recommendation_id,
            new_status=review_req.status,
            reviewer=current_user,
            reviewer_role=reviewer_role,
            review_notes=review_req.review_notes,
            db=db,
            client_ip=client_ip,
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except PermissionError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
