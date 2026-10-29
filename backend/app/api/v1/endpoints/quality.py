"""
Detection Quality & Intelligence Validation API Endpoints (Prompt 19).
Exposes operational quality metrics, deterministic fixture benchmarks,
full evidence provenance, and governed epistemic validation transitions.
"""

from typing import Dict, Any, List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Request, Query
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.user import User, SystemRole
from app.models.project import ProjectRole, ProjectMember
from app.models.finding import (
    VulnerabilityFinding,
    FindingValidationStatus,
)
from app.schemas.finding import (
    FindingValidationTransitionRequest,
    ValidationTransitionRead,
    VulnerabilityFindingDetail,
)
from app.services.detection_quality_service import DetectionQualityService
from app.services.finding_validation_service import FindingValidationService
from app.services.validation_fixture_framework import DeterministicFixtureFramework
from app.api.deps import get_current_user, verify_project_access, get_client_ip
from app.api.v1.endpoints.findings import _format_finding_detail, _get_user_project_role

router = APIRouter()


@router.get("/projects/{project_id}/quality/overview")
def get_project_quality_overview(
    project_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Returns comprehensive detection quality metrics, validation status distributions,
    and disclosed mathematical denominators for a project.
    """
    verify_project_access(project_id, current_user, db)
    try:
        return DetectionQualityService.calculate_project_quality_metrics(project_id, db)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.get("/projects/{project_id}/quality/fixtures")
def get_fixture_benchmarks(
    project_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Executes and returns deterministic benchmark results against all four controlled
    fixture scenarios: positive_exposed, negative_clean, unavailable, and ambiguous.
    Reports ground truth, precision, recall, FPR, FNR, and disclosed denominators.
    """
    verify_project_access(project_id, current_user, db)

    scenarios = ["positive_exposed", "negative_clean", "unavailable", "ambiguous"]
    results = {}
    for sc in scenarios:
        results[sc] = DeterministicFixtureFramework.run_benchmark_scenario(sc)

    return {
        "project_id": project_id,
        "framework_version": DeterministicFixtureFramework.VERSION,
        "benchmark_scenarios": results,
    }


@router.get("/projects/{project_id}/quality/adapters/{adapter_name}")
def get_adapter_quality_benchmark(
    project_id: str,
    adapter_name: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Returns historical detection quality, corroboration, and false-positive rates
    produced by a specific scanner adapter.
    """
    verify_project_access(project_id, current_user, db)
    return DetectionQualityService.calculate_adapter_benchmark_metrics(adapter_name, db)


@router.get("/projects/{project_id}/quality/findings/{finding_id}/provenance")
def get_finding_provenance(
    project_id: str,
    finding_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Returns full cryptographic provenance, raw observation lineage, SHA-256 evidence
    payload integrity verification, and validation history for a finding.
    """
    verify_project_access(project_id, current_user, db)
    try:
        return DetectionQualityService.get_finding_provenance(finding_id, db)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.post("/projects/{project_id}/findings/{finding_id}/validation", response_model=VulnerabilityFindingDetail)
def transition_finding_validation(
    project_id: str,
    finding_id: str,
    payload: FindingValidationTransitionRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Governed Epistemic Validation Transition (Prompt 19).
    Transitions a finding through the 9-state validation lifecycle with RBAC gates,
    cryptographic evidence requirements, minimum justification checks, and immutable transition audit.
    """
    verify_project_access(project_id, current_user, db)

    finding = (
        db.query(VulnerabilityFinding)
        .filter(
            VulnerabilityFinding.id == finding_id,
            VulnerabilityFinding.project_id == project_id,
        )
        .first()
    )
    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Finding '{finding_id}' not found in project '{project_id}'.",
        )

    # Validate target status
    try:
        target_status = FindingValidationStatus(payload.to_status)
    except ValueError:
        valid_states = [s.value for s in FindingValidationStatus]
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid validation status '{payload.to_status}'. Valid states: {valid_states}",
        )

    actor_role = _get_user_project_role(project_id, current_user, db)
    client_ip = get_client_ip(request)

    updated = FindingValidationService.transition_validation_status(
        finding=finding,
        to_status=target_status,
        validation_method=payload.validation_method,
        actor=current_user,
        actor_role=actor_role,
        reason=payload.reason,
        db=db,
        evidence_ref=payload.evidence_ref,
        client_ip=client_ip,
        is_ai_generated=payload.is_ai_generated,
    )
    db.commit()

    return _format_finding_detail(updated, db)
