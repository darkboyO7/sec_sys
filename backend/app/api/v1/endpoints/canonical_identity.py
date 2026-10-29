from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.api.deps import (
    get_db,
    get_current_user,
    verify_project_access,
)
from app.models.user import User
from app.models.project import ProjectRole
from app.models.canonical_asset import (
    AssetDeduplicationProposal,
    AssetDataQualityIssue,
    DataQualityIssueStatus,
)
from app.schemas.canonical_asset import (
    ResolutionRequest,
    ResolutionResponse,
    DryRunImpactResponse,
    ProposeDeduplicationRequest,
    ReviewDeduplicationRequest,
    DeduplicationProposalResponse,
    DataQualityIssueResponse,
    ResolveIssueRequest,
)
from app.services.canonical_identity_service import CanonicalIdentityService

router = APIRouter()


@router.post(
    "/{project_id}/asset-identity/resolve",
    response_model=ResolutionResponse,
    summary="Confidence-aware entity resolution against project canonical assets",
)
def resolve_entity(
    project_id: str,
    payload: ResolutionRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    verify_project_access(project_id, current_user, db, [ProjectRole.LEAD, ProjectRole.TESTER, ProjectRole.VIEWER])
    result = CanonicalIdentityService.resolve_entity(
        db=db,
        project_id=project_id,
        candidate_target=payload.candidate_target,
        attributes=payload.attributes,
    )
    return result.to_dict()


@router.post(
    "/{project_id}/asset-identity/deduplication/dry-run",
    response_model=DryRunImpactResponse,
    summary="Evaluate dry-run impact report for merging source asset into target asset",
)
def evaluate_dry_run(
    project_id: str,
    source_asset_id: str,
    target_asset_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    verify_project_access(project_id, current_user, db, [ProjectRole.LEAD, ProjectRole.TESTER])
    try:
        impact = CanonicalIdentityService.evaluate_dry_run_impact(
            db=db,
            project_id=project_id,
            source_asset_id=source_asset_id,
            target_asset_id=target_asset_id,
        )
        return impact
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.get(
    "/{project_id}/asset-identity/deduplication/proposals",
    response_model=List[DeduplicationProposalResponse],
    summary="List reviewable deduplication proposals for project",
)
def list_proposals(
    project_id: str,
    status_filter: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    verify_project_access(project_id, current_user, db, [ProjectRole.LEAD, ProjectRole.TESTER, ProjectRole.VIEWER])
    query = db.query(AssetDeduplicationProposal).filter(AssetDeduplicationProposal.project_id == project_id)
    if status_filter:
        query = query.filter(AssetDeduplicationProposal.status == status_filter)
    return query.order_by(AssetDeduplicationProposal.created_at.desc()).all()


@router.post(
    "/{project_id}/asset-identity/deduplication/proposals",
    response_model=DeduplicationProposalResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Propose deduplication merge requiring Lead/Admin review",
)
def propose_deduplication(
    project_id: str,
    payload: ProposeDeduplicationRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    verify_project_access(project_id, current_user, db, [ProjectRole.LEAD, ProjectRole.TESTER])
    try:
        proposal = CanonicalIdentityService.propose_deduplication(
            db=db,
            project_id=project_id,
            source_asset_id=payload.source_asset_id,
            target_asset_id=payload.target_asset_id,
            proposed_by_id=current_user.id,
            rationale=payload.rationale,
            confidence=payload.confidence or 0.90,
        )
        return proposal
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post(
    "/{project_id}/asset-identity/deduplication/proposals/{proposal_id}/approve",
    response_model=DeduplicationProposalResponse,
    summary="Approve and execute deduplication merge (Lead only)",
)
def approve_proposal(
    project_id: str,
    proposal_id: str,
    payload: ReviewDeduplicationRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    verify_project_access(project_id, current_user, db, [ProjectRole.LEAD])
    return CanonicalIdentityService.approve_deduplication(
        db=db,
        project_id=project_id,
        proposal_id=proposal_id,
        reviewer_id=current_user.id,
        review_comments=payload.comments,
    )


@router.post(
    "/{project_id}/asset-identity/deduplication/proposals/{proposal_id}/reject",
    response_model=DeduplicationProposalResponse,
    summary="Reject deduplication merge (Lead only)",
)
def reject_proposal(
    project_id: str,
    proposal_id: str,
    payload: ReviewDeduplicationRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    verify_project_access(project_id, current_user, db, [ProjectRole.LEAD])
    return CanonicalIdentityService.reject_deduplication(
        db=db,
        project_id=project_id,
        proposal_id=proposal_id,
        reviewer_id=current_user.id,
        review_comments=payload.comments,
    )


@router.post(
    "/{project_id}/asset-identity/deduplication/proposals/{proposal_id}/revert",
    response_model=DeduplicationProposalResponse,
    summary="Revert previously approved deduplication merge (Split Workflow - Lead only)",
)
def revert_proposal(
    project_id: str,
    proposal_id: str,
    payload: ReviewDeduplicationRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    verify_project_access(project_id, current_user, db, [ProjectRole.LEAD])
    return CanonicalIdentityService.revert_deduplication(
        db=db,
        project_id=project_id,
        proposal_id=proposal_id,
        revert_user_id=current_user.id,
        reversal_notes=payload.comments,
    )


@router.post(
    "/{project_id}/asset-identity/data-quality/audit",
    response_model=List[DataQualityIssueResponse],
    summary="Trigger comprehensive data quality audit across project inventory",
)
def run_data_quality_audit(
    project_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    verify_project_access(project_id, current_user, db, [ProjectRole.LEAD, ProjectRole.TESTER])
    return CanonicalIdentityService.run_data_quality_audit(db=db, project_id=project_id)


@router.get(
    "/{project_id}/asset-identity/data-quality/issues",
    response_model=List[DataQualityIssueResponse],
    summary="List data quality issues identified in project inventory",
)
def list_data_quality_issues(
    project_id: str,
    status_filter: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    verify_project_access(project_id, current_user, db, [ProjectRole.LEAD, ProjectRole.TESTER, ProjectRole.VIEWER])
    query = db.query(AssetDataQualityIssue).filter(AssetDataQualityIssue.project_id == project_id)
    if status_filter:
        query = query.filter(AssetDataQualityIssue.status == status_filter)
    return query.order_by(AssetDataQualityIssue.detected_at.desc()).all()


@router.post(
    "/{project_id}/asset-identity/data-quality/issues/{issue_id}/status",
    response_model=DataQualityIssueResponse,
    summary="Update resolution status of a data quality issue",
)
def update_issue_status(
    project_id: str,
    issue_id: str,
    payload: ResolveIssueRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    verify_project_access(project_id, current_user, db, [ProjectRole.LEAD, ProjectRole.TESTER])
    new_status = DataQualityIssueStatus(payload.status)
    return CanonicalIdentityService.resolve_data_quality_issue(
        db=db,
        project_id=project_id,
        issue_id=issue_id,
        new_status=new_status,
    )
