from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Request, Query
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.core.database import get_db
from app.models.user import User
from app.models.project import ProjectRole
from app.models.drift import (
    ExposureDriftRecord,
    ReassessmentProposal,
    DriftType,
    DriftMateriality,
    ReassessmentStatus,
)
from app.models.asset import Asset
from app.schemas.drift import (
    ExposureDriftRecordRead,
    ReassessmentProposalRead,
    ProposalRejectionRequest,
    ProjectDriftOverviewResponse,
)
from app.schemas.assessment import AssessmentJobResponse
from app.services.continuous_change_intelligence_service import ContinuousChangeIntelligenceService
from app.services.reassessment_planner_service import ReassessmentPlannerService
from app.api.deps import get_current_user, verify_project_access

router = APIRouter()


@router.get("/projects/{project_id}/drift/overview", response_model=ProjectDriftOverviewResponse)
def get_project_drift_overview(
    project_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Retrieve project-level exposure drift metrics, observation freshness distributions,
    and governance gap alerts (Prompt 20).
    """
    verify_project_access(project_id, current_user, db)
    return ContinuousChangeIntelligenceService.get_project_drift_overview(project_id, db)


@router.get("/projects/{project_id}/drift/records", response_model=List[ExposureDriftRecordRead])
def list_exposure_drift_records(
    project_id: str,
    materiality: Optional[DriftMateriality] = Query(None),
    drift_type: Optional[DriftType] = Query(None),
    asset_id: Optional[str] = Query(None),
    reassessment_recommended: Optional[bool] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    List chronological exposure drift records for a project with materiality and type filters.
    """
    verify_project_access(project_id, current_user, db)

    query = db.query(ExposureDriftRecord).filter(ExposureDriftRecord.project_id == project_id)

    if materiality:
        query = query.filter(ExposureDriftRecord.materiality == materiality)
    if drift_type:
        query = query.filter(ExposureDriftRecord.drift_type == drift_type)
    if asset_id:
        query = query.filter(ExposureDriftRecord.asset_id == asset_id)
    if reassessment_recommended is not None:
        query = query.filter(ExposureDriftRecord.reassessment_recommended == reassessment_recommended)

    return (
        query.order_by(ExposureDriftRecord.detected_at.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )


@router.get("/projects/{project_id}/drift/proposals", response_model=List[ReassessmentProposalRead])
def list_reassessment_proposals(
    project_id: str,
    status_filter: Optional[ReassessmentStatus] = Query(None, alias="status"),
    asset_id: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    List policy-constrained reassessment proposals generated from material exposure drift.
    """
    verify_project_access(project_id, current_user, db)

    query = db.query(ReassessmentProposal).filter(ReassessmentProposal.project_id == project_id)

    if status_filter:
        query = query.filter(ReassessmentProposal.status == status_filter)
    if asset_id:
        query = query.filter(ReassessmentProposal.asset_id == asset_id)

    return (
        query.order_by(ReassessmentProposal.created_at.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )


@router.post("/projects/{project_id}/drift/proposals/{proposal_id}/approve", response_model=AssessmentJobResponse)
def approve_reassessment_proposal(
    project_id: str,
    proposal_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Approve and queue an assessment job for a reassessment proposal (Prompt 20 / Section 5).
    Requires Project LEAD or System ADMIN. Revalidates scope at execution boundary.
    """
    project = verify_project_access(
        project_id,
        current_user,
        db,
        required_project_roles=[ProjectRole.LEAD],
    )

    # Get user role in project
    from app.models.project import ProjectMember
    pm = db.query(ProjectMember).filter(ProjectMember.project_id == project_id, ProjectMember.user_id == current_user.id).first()
    actor_role = pm.role if pm else None

    try:
        job = ReassessmentPlannerService.approve_and_queue_reassessment(
            project_id=project_id,
            proposal_id=proposal_id,
            actor=current_user,
            actor_role=actor_role,
            db=db,
        )
        db.commit()
        db.refresh(job)
        return job
    except PermissionError as pe:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(pe))
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ve))


@router.post("/projects/{project_id}/drift/proposals/{proposal_id}/reject", response_model=ReassessmentProposalRead)
def reject_reassessment_proposal(
    project_id: str,
    proposal_id: str,
    reject_in: ProposalRejectionRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Reject a reassessment proposal with mandatory operator justification.
    Requires Project LEAD or System ADMIN.
    """
    verify_project_access(
        project_id,
        current_user,
        db,
        required_project_roles=[ProjectRole.LEAD],
    )

    try:
        proposal = ReassessmentPlannerService.reject_reassessment(
            project_id=project_id,
            proposal_id=proposal_id,
            actor=current_user,
            rejection_reason=reject_in.rejection_reason,
            db=db,
        )
        db.commit()
        db.refresh(proposal)
        return proposal
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ve))
