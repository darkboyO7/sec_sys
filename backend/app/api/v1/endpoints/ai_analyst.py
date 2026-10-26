from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Request, Query
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.user import User
from app.models.project import ProjectRole
from app.models.ai_analyst import AIAnalystDraft, AIDraftType, AIDraftStatus
from app.schemas.ai_analyst import (
    AIDraftResponse,
    ExplainFindingRequest,
    DraftRemediationRequest,
    SummarizeAttackPathRequest,
    DraftReviewRequest,
)
from app.services.ai_analyst_service import AIAnalystService
from app.api.deps import get_current_user, verify_project_access, get_client_ip

router = APIRouter()


@router.post(
    "/projects/{project_id}/ai-analyst/explain-finding/{finding_id}",
    response_model=AIDraftResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Generate evidence-grounded AI explanation for a vulnerability finding",
)
def explain_finding(
    project_id: str,
    finding_id: str,
    request: Request,
    payload: ExplainFindingRequest = ExplainFindingRequest(),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    verify_project_access(project_id, current_user, db)
    client_ip = get_client_ip(request)

    try:
        draft = AIAnalystService.explain_finding(
            project_id=project_id,
            finding_id=finding_id,
            db=db,
            actor=current_user,
            include_mitre=payload.include_mitre_mapping,
            include_controls=payload.include_defensive_controls,
            client_ip=client_ip,
        )
        return draft
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.post(
    "/projects/{project_id}/ai-analyst/draft-remediation/{finding_id}",
    response_model=AIDraftResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Draft an advisory remediation plan for a vulnerability finding",
)
def draft_remediation(
    project_id: str,
    finding_id: str,
    request: Request,
    payload: DraftRemediationRequest = DraftRemediationRequest(),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    verify_project_access(project_id, current_user, db)
    client_ip = get_client_ip(request)

    try:
        draft = AIAnalystService.draft_remediation_plan(
            project_id=project_id,
            finding_id=finding_id,
            db=db,
            actor=current_user,
            operational_constraints=payload.operational_constraints,
            client_ip=client_ip,
        )
        return draft
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.post(
    "/projects/{project_id}/ai-analyst/summarize-assessment/{job_id}",
    response_model=AIDraftResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Generate an AI assessment execution and findings summary",
)
def summarize_assessment(
    project_id: str,
    job_id: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    verify_project_access(project_id, current_user, db)
    client_ip = get_client_ip(request)

    try:
        draft = AIAnalystService.summarize_assessment(
            project_id=project_id,
            job_id=job_id,
            db=db,
            actor=current_user,
            client_ip=client_ip,
        )
        return draft
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.post(
    "/projects/{project_id}/ai-analyst/summarize-attack-path",
    response_model=AIDraftResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Generate an AI advisory summary of active attack paths and choke points",
)
def summarize_attack_path(
    project_id: str,
    request: Request,
    payload: SummarizeAttackPathRequest = SummarizeAttackPathRequest(),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    verify_project_access(project_id, current_user, db)
    client_ip = get_client_ip(request)

    try:
        draft = AIAnalystService.summarize_attack_path(
            project_id=project_id,
            path_id=payload.path_id,
            db=db,
            actor=current_user,
            client_ip=client_ip,
        )
        return draft
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post(
    "/projects/{project_id}/ai-analyst/drafts/{draft_id}/review",
    response_model=AIDraftResponse,
    status_code=status.HTTP_200_OK,
    summary="Review and approve/reject an AI advisory draft (Analyst Lead/Tester gate)",
)
def review_draft(
    project_id: str,
    draft_id: str,
    payload: DraftReviewRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    verify_project_access(
        project_id,
        current_user,
        db,
        required_project_roles=[ProjectRole.LEAD, ProjectRole.TESTER],
    )
    client_ip = get_client_ip(request)

    try:
        draft = AIAnalystService.review_draft(
            project_id=project_id,
            draft_id=draft_id,
            approved=payload.approved,
            review_notes=payload.review_notes,
            reviewer=current_user,
            db=db,
            client_ip=client_ip,
        )
        return draft
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.get(
    "/projects/{project_id}/ai-analyst/drafts",
    response_model=List[AIDraftResponse],
    status_code=status.HTTP_200_OK,
    summary="List all AI analyst decision-support drafts for a project",
)
def list_drafts(
    project_id: str,
    draft_type: Optional[AIDraftType] = Query(None, description="Filter by draft type"),
    status_filter: Optional[AIDraftStatus] = Query(None, alias="status", description="Filter by status"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    verify_project_access(project_id, current_user, db)

    query = db.query(AIAnalystDraft).filter(AIAnalystDraft.project_id == project_id)
    if draft_type:
        query = query.filter(AIAnalystDraft.draft_type == draft_type)
    if status_filter:
        query = query.filter(AIAnalystDraft.status == status_filter)

    return query.order_by(AIAnalystDraft.created_at.desc()).all()


@router.get(
    "/projects/{project_id}/ai-analyst/drafts/{draft_id}",
    response_model=AIDraftResponse,
    status_code=status.HTTP_200_OK,
    summary="Get single AI analyst decision-support draft details",
)
def get_draft(
    project_id: str,
    draft_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    verify_project_access(project_id, current_user, db)

    draft = (
        db.query(AIAnalystDraft)
        .filter(AIAnalystDraft.id == draft_id, AIAnalystDraft.project_id == project_id)
        .first()
    )
    if not draft:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Draft '{draft_id}' not found.")
    return draft
