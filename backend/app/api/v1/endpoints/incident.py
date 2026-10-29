from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.user import User
from app.models.project import ProjectRole
from app.models.incident import (
    IncidentCase,
    CaseSeverity,
    CaseStatus,
    RelationshipType,
    CorrelationType,
)
from app.schemas.incident import (
    CreateCaseRequest,
    LinkAssetRequest,
    LinkFindingRequest,
    AttachEvidenceRequest,
    TransitionStatusRequest,
    AddCaseNoteRequest,
    IncidentCaseSummary,
    IncidentCaseDetail,
    CorrelationExplanationResponse,
    TimelineEventResponse,
)
from app.services.incident_service import IncidentInvestigationService
from app.api.deps import get_current_user, verify_project_access

router = APIRouter()


@router.post(
    "/projects/{project_id}/incidents/cases",
    response_model=IncidentCaseDetail,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new security incident investigation case",
)
def create_incident_case(
    project_id: str,
    payload: CreateCaseRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Initializes an evidence-preserving security incident case (Prompt 39 Req 1, 2).
    """
    verify_project_access(
        project_id,
        current_user,
        db,
        required_project_roles=[ProjectRole.LEAD, ProjectRole.TESTER],
    )
    sev = CaseSeverity.MEDIUM
    if payload.severity:
        try:
            sev = CaseSeverity(payload.severity)
        except ValueError:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Invalid severity: {payload.severity}")

    try:
        case = IncidentInvestigationService.create_case(
            db=db,
            project_id=project_id,
            title=payload.title,
            description=payload.description,
            severity=sev,
            lead_investigator_id=payload.lead_investigator_id,
            assigned_team=payload.assigned_team,
            actor=current_user,
        )
        return case
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.get(
    "/projects/{project_id}/incidents/cases",
    response_model=List[IncidentCaseSummary],
    status_code=status.HTTP_200_OK,
    summary="List security incident cases for project",
)
def list_incident_cases(
    project_id: str,
    status_filter: Optional[str] = Query(None, alias="status", description="Filter by case status"),
    severity_filter: Optional[str] = Query(None, alias="severity", description="Filter by case severity"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    verify_project_access(
        project_id,
        current_user,
        db,
        required_project_roles=[ProjectRole.LEAD, ProjectRole.TESTER, ProjectRole.VIEWER],
    )
    query = db.query(IncidentCase).filter(IncidentCase.project_id == project_id)
    if status_filter:
        query = query.filter(IncidentCase.status == status_filter)
    if severity_filter:
        query = query.filter(IncidentCase.severity == severity_filter)

    cases = query.order_by(IncidentCase.opened_at.desc()).all()
    return cases


@router.get(
    "/projects/{project_id}/incidents/cases/{case_id}",
    response_model=IncidentCaseDetail,
    status_code=status.HTTP_200_OK,
    summary="Get full incident case details with linked assets, findings, and evidence",
)
def get_incident_case(
    project_id: str,
    case_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    verify_project_access(
        project_id,
        current_user,
        db,
        required_project_roles=[ProjectRole.LEAD, ProjectRole.TESTER, ProjectRole.VIEWER],
    )
    case = (
        db.query(IncidentCase)
        .filter(IncidentCase.id == case_id, IncidentCase.project_id == project_id)
        .first()
    )
    if not case:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="IncidentCase not found.")
    return case


@router.post(
    "/projects/{project_id}/incidents/cases/{case_id}/assets",
    status_code=status.HTTP_201_CREATED,
    summary="Link an asset to the incident case with explicit relationship classification",
)
def link_asset_to_case(
    project_id: str,
    case_id: str,
    payload: LinkAssetRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    verify_project_access(
        project_id,
        current_user,
        db,
        required_project_roles=[ProjectRole.LEAD, ProjectRole.TESTER],
    )
    rel = RelationshipType.OBSERVED_CORRELATION
    if payload.relationship_type:
        try:
            rel = RelationshipType(payload.relationship_type)
        except ValueError:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Invalid relationship_type: {payload.relationship_type}")

    try:
        link = IncidentInvestigationService.link_asset_to_case(
            db=db,
            project_id=project_id,
            case_id=case_id,
            asset_id=payload.asset_id,
            relationship_type=rel,
            confidence=payload.confidence or 0.5,
            is_contradictory=payload.is_contradictory or False,
            notes=payload.notes,
            actor=current_user,
        )
        return {"status": "SUCCESS", "link_id": link.id}
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post(
    "/projects/{project_id}/incidents/cases/{case_id}/findings",
    status_code=status.HTTP_201_CREATED,
    summary="Link a vulnerability finding with causation vs temporal correlation classification",
)
def link_finding_to_case(
    project_id: str,
    case_id: str,
    payload: LinkFindingRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    verify_project_access(
        project_id,
        current_user,
        db,
        required_project_roles=[ProjectRole.LEAD, ProjectRole.TESTER],
    )
    corr = CorrelationType.PROBABLE_CORRELATION
    if payload.correlation_type:
        try:
            corr = CorrelationType(payload.correlation_type)
        except ValueError:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Invalid correlation_type: {payload.correlation_type}")

    try:
        link = IncidentInvestigationService.link_finding_to_case(
            db=db,
            project_id=project_id,
            case_id=case_id,
            finding_id=payload.finding_id,
            correlation_type=corr,
            confidence=payload.confidence or 0.5,
            rationale=payload.rationale,
            actor=current_user,
        )
        return {"status": "SUCCESS", "link_id": link.id}
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post(
    "/projects/{project_id}/incidents/cases/{case_id}/evidence",
    status_code=status.HTTP_201_CREATED,
    summary="Attach an immutable evidence snapshot to the case",
)
def attach_evidence_snapshot(
    project_id: str,
    case_id: str,
    payload: AttachEvidenceRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    verify_project_access(
        project_id,
        current_user,
        db,
        required_project_roles=[ProjectRole.LEAD, ProjectRole.TESTER],
    )
    try:
        ev = IncidentInvestigationService.attach_evidence_snapshot(
            db=db,
            project_id=project_id,
            case_id=case_id,
            evidence_summary=payload.evidence_summary,
            finding_evidence_id=payload.finding_evidence_id,
            is_contradictory=payload.is_contradictory or False,
            provenance_details=payload.provenance_details,
            actor=current_user,
        )
        return {"status": "SUCCESS", "evidence_id": ev.id, "digest": ev.evidence_digest}
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post(
    "/projects/{project_id}/incidents/cases/{case_id}/transition",
    response_model=IncidentCaseDetail,
    status_code=status.HTTP_200_OK,
    summary="Transition case status with mandatory reason and Separation of Duties",
)
def transition_case_status(
    project_id: str,
    case_id: str,
    payload: TransitionStatusRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    verify_project_access(
        project_id,
        current_user,
        db,
        required_project_roles=[ProjectRole.LEAD, ProjectRole.TESTER],
    )
    try:
        to_st = CaseStatus(payload.to_status)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Invalid to_status: {payload.to_status}")

    try:
        case = IncidentInvestigationService.transition_case_status(
            db=db,
            project_id=project_id,
            case_id=case_id,
            to_status=to_st,
            reason=payload.reason,
            actor=current_user,
            closure_summary=payload.closure_summary,
            reopening_rationale=payload.reopening_rationale,
            root_cause_hypothesis=payload.root_cause_hypothesis,
            is_containment_verified=payload.is_containment_verified,
        )
        return case
    except PermissionError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post(
    "/projects/{project_id}/incidents/cases/{case_id}/notes",
    status_code=status.HTTP_201_CREATED,
    summary="Add an analyst observation, alternative hypothesis, or task log",
)
def add_case_note(
    project_id: str,
    case_id: str,
    payload: AddCaseNoteRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    verify_project_access(
        project_id,
        current_user,
        db,
        required_project_roles=[ProjectRole.LEAD, ProjectRole.TESTER],
    )
    try:
        note = IncidentInvestigationService.add_case_note(
            db=db,
            project_id=project_id,
            case_id=case_id,
            content=payload.content,
            note_type=payload.note_type or "ANALYST_OBSERVATION",
            is_alternative_hypothesis=payload.is_alternative_hypothesis or False,
            actor=current_user,
        )
        return {"status": "SUCCESS", "note_id": note.id}
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.get(
    "/projects/{project_id}/incidents/cases/{case_id}/correlations",
    response_model=CorrelationExplanationResponse,
    status_code=status.HTTP_200_OK,
    summary="Get explainable breakdown separating confirmed causal links from temporal correlations",
)
def explain_case_correlations(
    project_id: str,
    case_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    verify_project_access(
        project_id,
        current_user,
        db,
        required_project_roles=[ProjectRole.LEAD, ProjectRole.TESTER, ProjectRole.VIEWER],
    )
    try:
        breakdown = IncidentInvestigationService.explain_correlations(
            db=db,
            project_id=project_id,
            case_id=case_id,
        )
        return breakdown
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.get(
    "/projects/{project_id}/incidents/cases/{case_id}/timeline",
    response_model=List[TimelineEventResponse],
    status_code=status.HTTP_200_OK,
    summary="Retrieve unified chronological case timeline with provenance",
)
def get_case_timeline(
    project_id: str,
    case_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    verify_project_access(
        project_id,
        current_user,
        db,
        required_project_roles=[ProjectRole.LEAD, ProjectRole.TESTER, ProjectRole.VIEWER],
    )
    try:
        events = IncidentInvestigationService.get_case_timeline(
            db=db,
            project_id=project_id,
            case_id=case_id,
        )
        return events
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
