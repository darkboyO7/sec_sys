"""
Compliance Intelligence, Security Baselines & Configuration Drift Governance Endpoints (Prompt 33).
REST APIs for controls, profiles, evaluations, drift tracking, and controlled exceptions.
"""
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status, Request
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.exceptions import (
    NotFoundError,
    ConflictError,
    ValidationError,
    AuthorizationError,
)
from app.models.user import User, SystemRole
from app.models.project import ProjectRole
from app.models.compliance import (
    ComplianceEvaluationStatus,
    ComplianceExceptionStatus,
    ComplianceDriftType,
)
from app.schemas.compliance import (
    ComplianceControlCreate,
    ComplianceControlResponse,
    BaselineProfileCreate,
    BaselineProfileUpdate,
    BaselineProfileResponse,
    ComplianceEvaluationRequest,
    ComplianceEvaluationRunResponse,
    ComplianceComparisonResponse,
    ComplianceDriftEventResponse,
    ComplianceExceptionCreate,
    ComplianceExceptionReview,
    ComplianceExceptionResponse,
)
from app.services.compliance_service import ComplianceService
from app.api.deps import get_current_user, verify_project_access, require_system_roles

router = APIRouter()


# ---------------------------------------------------------------------------
# Global Security Controls Catalog Endpoints
# ---------------------------------------------------------------------------
@router.get("/compliance/controls", response_model=List[ComplianceControlResponse], tags=["Compliance Intelligence"])
def list_compliance_controls(
    category: Optional[str] = Query(None),
    framework: Optional[str] = Query(None),
    is_active: Optional[bool] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List normalized security requirements from the versioned control catalog."""
    return ComplianceService.list_controls(db, category=category, framework=framework, is_active=is_active)


@router.get("/compliance/controls/{control_id}", response_model=ComplianceControlResponse, tags=["Compliance Intelligence"])
def get_compliance_control(
    control_id: str,
    version: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Retrieve a specific security control and its requirement metadata."""
    try:
        return ComplianceService.get_control(db, control_id=control_id, version=version)
    except NotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.post("/compliance/controls", response_model=ComplianceControlResponse, status_code=status.HTTP_201_CREATED, tags=["Compliance Intelligence"])
def create_compliance_control(
    payload: ComplianceControlCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_system_roles([SystemRole.ADMIN])),
):
    """Create or publish a new version of a security control. Requires Admin."""
    try:
        return ComplianceService.create_or_update_control(db, payload.model_dump())
    except ConflictError as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))
    except ValidationError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


# ---------------------------------------------------------------------------
# Project-Scoped Baseline Profiles & Evaluation Endpoints
# ---------------------------------------------------------------------------
@router.get("/projects/{project_id}/compliance/baselines", response_model=List[BaselineProfileResponse], tags=["Compliance Intelligence"])
def list_project_baseline_profiles(
    project_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List versioned security baseline profiles configured for a project."""
    verify_project_access(project_id, current_user, db)
    return ComplianceService.list_profiles(db, project_id=project_id)


@router.get("/projects/{project_id}/compliance/baselines/{profile_id}", response_model=BaselineProfileResponse, tags=["Compliance Intelligence"])
def get_project_baseline_profile(
    project_id: str,
    profile_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Retrieve details of a specific baseline profile."""
    verify_project_access(project_id, current_user, db)
    try:
        return ComplianceService.get_profile(db, project_id=project_id, profile_id=profile_id)
    except NotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.post("/projects/{project_id}/compliance/baselines", response_model=BaselineProfileResponse, status_code=status.HTTP_201_CREATED, tags=["Compliance Intelligence"])
def create_project_baseline_profile(
    project_id: str,
    payload: BaselineProfileCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Create a new versioned baseline profile. Requires Project Lead or Admin."""
    verify_project_access(project_id, current_user, db, required_project_roles=[ProjectRole.LEAD])
    try:
        return ComplianceService.create_profile(db, project_id=project_id, data=payload.model_dump(), user_id=current_user.id)
    except ConflictError as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))
    except ValidationError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.put("/projects/{project_id}/compliance/baselines/{profile_id}", response_model=BaselineProfileResponse, tags=["Compliance Intelligence"])
def update_project_baseline_profile(
    project_id: str,
    profile_id: str,
    payload: BaselineProfileUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Update baseline profile configuration parameters or controls. Requires Project Lead or Admin."""
    verify_project_access(project_id, current_user, db, required_project_roles=[ProjectRole.LEAD])
    try:
        return ComplianceService.update_profile(db, project_id=project_id, profile_id=profile_id, data=payload.model_dump(exclude_unset=True))
    except NotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.post("/projects/{project_id}/compliance/evaluate", response_model=ComplianceEvaluationRunResponse, status_code=status.HTTP_201_CREATED, tags=["Compliance Intelligence"])
def evaluate_compliance_baseline(
    project_id: str,
    payload: ComplianceEvaluationRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Executes a deterministic compliance evaluation comparing authorized evidence
    against the selected baseline profile. Never infers PASS from missing evidence.
    """
    verify_project_access(project_id, current_user, db)
    try:
        run = ComplianceService.evaluate_baseline(
            db=db,
            project_id=project_id,
            baseline_profile_id=payload.baseline_profile_id,
            assessment_id=payload.assessment_id,
            asset_ids=payload.asset_ids,
            evaluator_user_id=current_user.id,
        )
        prof = ComplianceService.get_profile(db, project_id, run.baseline_profile_id)
        resp = ComplianceEvaluationRunResponse.model_validate(run)
        resp.baseline_profile_key = prof.profile_key
        resp.baseline_profile_version = prof.version
        return resp
    except NotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except ValidationError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.get("/projects/{project_id}/compliance/evaluations", response_model=List[ComplianceEvaluationRunResponse], tags=["Compliance Intelligence"])
def list_compliance_evaluations(
    project_id: str,
    baseline_profile_id: Optional[str] = Query(None),
    limit: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List historical baseline evaluation runs for auditability and drift tracking."""
    verify_project_access(project_id, current_user, db)
    runs = ComplianceService.list_evaluation_runs(db, project_id=project_id, baseline_profile_id=baseline_profile_id, limit=limit)
    response_list = []
    for r in runs:
        prof = ComplianceService.get_profile(db, project_id, r.baseline_profile_id)
        item = ComplianceEvaluationRunResponse.model_validate(r)
        item.baseline_profile_key = prof.profile_key
        item.baseline_profile_version = prof.version
        response_list.append(item)
    return response_list


@router.get("/projects/{project_id}/compliance/evaluations/{run_id}", response_model=ComplianceEvaluationRunResponse, tags=["Compliance Intelligence"])
def get_compliance_evaluation(
    project_id: str,
    run_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Retrieve full details, evidence references, and control outcomes for an evaluation run."""
    verify_project_access(project_id, current_user, db)
    try:
        run = ComplianceService.get_evaluation_run(db, project_id=project_id, run_id=run_id)
        prof = ComplianceService.get_profile(db, project_id, run.baseline_profile_id)
        resp = ComplianceEvaluationRunResponse.model_validate(run)
        resp.baseline_profile_key = prof.profile_key
        resp.baseline_profile_version = prof.version
        return resp
    except NotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.get("/projects/{project_id}/compliance/compare", response_model=ComplianceComparisonResponse, tags=["Compliance Intelligence"])
def compare_compliance_evaluations(
    project_id: str,
    run_a: str = Query(..., description="Prior or baseline evaluation run ID"),
    run_b: str = Query(..., description="Target or newer evaluation run ID"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Compare two evaluation runs to analyze security posture regressions and improvements."""
    verify_project_access(project_id, current_user, db)
    try:
        return ComplianceService.compare_runs(db, project_id=project_id, run_id_a=run_a, run_id_b=run_b)
    except NotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.get("/projects/{project_id}/compliance/drift", response_model=List[ComplianceDriftEventResponse], tags=["Compliance Intelligence"])
def list_compliance_drift_events(
    project_id: str,
    control_id: Optional[str] = Query(None),
    drift_type: Optional[ComplianceDriftType] = Query(None),
    limit: int = Query(50, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List detected security baseline and evidence drift events."""
    verify_project_access(project_id, current_user, db)
    return ComplianceService.list_drift_events(db, project_id=project_id, control_id=control_id, drift_type=drift_type, limit=limit)


# ---------------------------------------------------------------------------
# Controlled Exception Management with Separation of Duties
# ---------------------------------------------------------------------------
@router.get("/projects/{project_id}/compliance/exceptions", response_model=List[ComplianceExceptionResponse], tags=["Compliance Intelligence"])
def list_compliance_exceptions(
    project_id: str,
    control_id: Optional[str] = Query(None),
    status: Optional[ComplianceExceptionStatus] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List project baseline exceptions and their approval/expiry status."""
    verify_project_access(project_id, current_user, db)
    return ComplianceService.list_exceptions(db, project_id=project_id, control_id=control_id, status=status)


@router.post("/projects/{project_id}/compliance/exceptions", response_model=ComplianceExceptionResponse, status_code=status.HTTP_201_CREATED, tags=["Compliance Intelligence"])
def request_compliance_exception(
    project_id: str,
    payload: ComplianceExceptionCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Submit a time-bounded baseline exception request with business justification."""
    verify_project_access(project_id, current_user, db)
    try:
        return ComplianceService.request_exception(
            db=db,
            project_id=project_id,
            control_id=payload.control_id,
            justification=payload.justification,
            risk_assessment=payload.risk_assessment,
            compensating_controls=payload.compensating_controls,
            expires_at=payload.expires_at,
            requester_id=current_user.id,
            asset_id=payload.asset_id,
        )
    except (ValidationError, NotFoundError) as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post("/projects/{project_id}/compliance/exceptions/{exception_id}/review", response_model=ComplianceExceptionResponse, tags=["Compliance Intelligence"])
def review_compliance_exception(
    project_id: str,
    exception_id: str,
    payload: ComplianceExceptionReview,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Approve or reject a baseline exception.
    Enforces Separation of Duties: Requester cannot approve their own exception.
    Requires Project Lead or Admin.
    """
    verify_project_access(project_id, current_user, db, required_project_roles=[ProjectRole.LEAD])
    try:
        return ComplianceService.review_exception(
            db=db,
            project_id=project_id,
            exception_id=exception_id,
            approved=payload.approved,
            reviewer_id=current_user.id,
            review_notes=payload.review_notes,
        )
    except AuthorizationError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    except NotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except ValidationError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post("/projects/{project_id}/compliance/exceptions/{exception_id}/revoke", response_model=ComplianceExceptionResponse, tags=["Compliance Intelligence"])
def revoke_compliance_exception(
    project_id: str,
    exception_id: str,
    notes: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Revoke an approved exception. Requires Project Lead or Admin."""
    verify_project_access(project_id, current_user, db, required_project_roles=[ProjectRole.LEAD])
    try:
        return ComplianceService.revoke_exception(
            db=db,
            project_id=project_id,
            exception_id=exception_id,
            revoker_id=current_user.id,
            notes=notes,
        )
    except NotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
