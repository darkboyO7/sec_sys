from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Request, Query
from sqlalchemy.orm import Session
from sqlalchemy import func, or_

from app.core.database import get_db
from app.models.user import User, SystemRole
from app.models.project import ProjectRole, ProjectMember
from app.models.finding import (
    FindingLifecycleStatus,
    VulnerabilityFinding,
    FindingTransition,
)
from app.models.assessment import (
    FindingSeverity,
    FindingConfidence,
    AssessmentFinding,
)
from app.schemas.finding import (
    VulnerabilityFindingRead,
    VulnerabilityFindingDetail,
    FindingTransitionRead,
    FindingTransitionRequest,
    AcceptRiskRequest,
    FalsePositiveRequest,
    ProposeRemediationRequest,
    FindingStatsResponse,
)
from app.services.finding_lifecycle_service import FindingLifecycleService
from app.api.deps import get_current_user, verify_project_access, get_client_ip

router = APIRouter()


def _get_user_project_role(project_id: str, user: User, db: Session) -> Optional[ProjectRole]:
    """Helper to retrieve project role for a user; returns None if user is an admin without explicit membership."""
    membership = (
        db.query(ProjectMember)
        .filter(ProjectMember.project_id == project_id, ProjectMember.user_id == user.id)
        .first()
    )
    return membership.role if membership else None


def _format_finding_detail(finding: VulnerabilityFinding, db: Session) -> VulnerabilityFindingDetail:
    """Helper to attach transition history and observation provenance to a finding detail response."""
    transitions = (
        db.query(FindingTransition)
        .filter(FindingTransition.finding_id == finding.id)
        .order_by(FindingTransition.created_at.desc())
        .all()
    )

    # Gather distinct job IDs from observations
    obs_jobs = (
        db.query(AssessmentFinding.job_id)
        .filter(AssessmentFinding.canonical_finding_id == finding.id)
        .distinct()
        .all()
    )
    job_ids = [row[0] for row in obs_jobs]

    # Count attached evidence across observations
    total_evidence = (
        db.query(func.count(AssessmentFinding.id))
        .join(AssessmentFinding.evidence_items)
        .filter(AssessmentFinding.canonical_finding_id == finding.id)
        .scalar()
        or 0
    )

    detail_data = VulnerabilityFindingRead.model_validate(finding).model_dump()
    detail_data["transitions"] = [FindingTransitionRead.model_validate(t) for t in transitions]
    detail_data["observation_job_ids"] = job_ids
    detail_data["evidence_count"] = total_evidence
    return VulnerabilityFindingDetail(**detail_data)


@router.get("/projects/{project_id}/findings", response_model=List[VulnerabilityFindingRead])
def list_project_findings(
    project_id: str,
    status_filter: Optional[FindingLifecycleStatus] = Query(None, alias="status"),
    severity_filter: Optional[FindingSeverity] = Query(None, alias="severity"),
    target_filter: Optional[str] = Query(None, alias="target"),
    has_contradictions: Optional[bool] = Query(None),
    search: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    List tracked vulnerability findings for a project with rich filtering.
    """
    verify_project_access(project_id, current_user, db)

    # Ensure any overdue accepted risks are reliably transitioned before query
    expired = FindingLifecycleService.sweep_expired_accepted_risks(project_id, db)
    if expired > 0:
        db.commit()

    query = db.query(VulnerabilityFinding).filter(VulnerabilityFinding.project_id == project_id)

    if status_filter:
        query = query.filter(VulnerabilityFinding.status == status_filter)
    if severity_filter:
        query = query.filter(VulnerabilityFinding.severity == severity_filter)
    if target_filter:
        query = query.filter(VulnerabilityFinding.target_value.ilike(f"%{target_filter.strip()}%"))
    if has_contradictions is not None:
        query = query.filter(VulnerabilityFinding.has_contradictions == has_contradictions)
    if search:
        search_term = f"%{search.strip()}%"
        query = query.filter(
            or_(
                VulnerabilityFinding.title.ilike(search_term),
                VulnerabilityFinding.description.ilike(search_term),
                VulnerabilityFinding.vuln_id.ilike(search_term),
                VulnerabilityFinding.target_value.ilike(search_term),
            )
        )

    return (
        query.order_by(
            VulnerabilityFinding.severity.desc(),
            VulnerabilityFinding.last_observed_at.desc(),
        )
        .offset(offset)
        .limit(limit)
        .all()
    )


@router.get("/projects/{project_id}/findings/stats", response_model=FindingStatsResponse)
def get_finding_statistics(
    project_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Retrieve aggregated metrics across all 13 finding lifecycle states,
    severities, unresolved items, and contradictory evidence signals.
    """
    verify_project_access(project_id, current_user, db)

    # Ensure any overdue accepted risks are reliably transitioned before aggregating
    expired = FindingLifecycleService.sweep_expired_accepted_risks(project_id, db)
    if expired > 0:
        db.commit()

    findings = db.query(VulnerabilityFinding).filter(VulnerabilityFinding.project_id == project_id).all()

    by_status = {s.value: 0 for s in FindingLifecycleStatus}
    by_severity = {s.value: 0 for s in FindingSeverity}
    reopened_count = 0
    accepted_risk_count = 0
    contradiction_count = 0
    unresolved_count = 0

    unresolved_statuses = {
        FindingLifecycleStatus.DETECTED,
        FindingLifecycleStatus.NEEDS_VALIDATION,
        FindingLifecycleStatus.CONFIRMED,
        FindingLifecycleStatus.INCONCLUSIVE,
        FindingLifecycleStatus.REOPENED,
        FindingLifecycleStatus.REMEDIATION_PROPOSED,
        FindingLifecycleStatus.REMEDIATION_APPROVED,
        FindingLifecycleStatus.REMEDIATION_ATTEMPTED,
        FindingLifecycleStatus.REMEDIATED_PENDING_VERIFICATION,
        FindingLifecycleStatus.EXPIRED,
    }

    for f in findings:
        by_status[f.status.value] = by_status.get(f.status.value, 0) + 1
        by_severity[f.severity.value] = by_severity.get(f.severity.value, 0) + 1

        if f.status in unresolved_statuses:
            unresolved_count += 1
        if f.status == FindingLifecycleStatus.REOPENED:
            reopened_count += 1
        if f.status == FindingLifecycleStatus.ACCEPTED_RISK:
            accepted_risk_count += 1
        if f.has_contradictions:
            contradiction_count += 1

    return FindingStatsResponse(
        total=len(findings),
        by_status=by_status,
        by_severity=by_severity,
        unresolved_count=unresolved_count,
        reopened_count=reopened_count,
        accepted_risk_count=accepted_risk_count,
        contradiction_count=contradiction_count,
    )


@router.post("/projects/{project_id}/findings/sweep-expired-risks")
def sweep_expired_risks(
    project_id: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Evaluates all ACCEPTED_RISK findings in the project and transitions
    overdue items whose expiration date has elapsed to EXPIRED.
    Requires Project LEAD or System ADMIN.
    """
    verify_project_access(
        project_id,
        current_user,
        db,
        required_project_roles=[ProjectRole.LEAD],
    )
    client_ip = get_client_ip(request)
    expired_count = FindingLifecycleService.sweep_expired_accepted_risks(
        project_id=project_id,
        db=db,
        actor=current_user,
        client_ip=client_ip,
    )
    db.commit()
    return {"status": "success", "expired_count": expired_count}


@router.get("/projects/{project_id}/findings/{finding_id}", response_model=VulnerabilityFindingDetail)
def get_finding_detail(
    project_id: str,
    finding_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Retrieve full details for a finding, including its complete state transition provenance
    and linked assessment jobs.
    """
    verify_project_access(project_id, current_user, db)

    # Ensure any overdue accepted risks are reliably transitioned
    expired = FindingLifecycleService.sweep_expired_accepted_risks(project_id, db)
    if expired > 0:
        db.commit()

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
            detail="Finding not found in specified project",
        )

    return _format_finding_detail(finding, db)


@router.post("/projects/{project_id}/findings/{finding_id}/transition", response_model=VulnerabilityFindingDetail)
def transition_finding(
    project_id: str,
    finding_id: str,
    transition_in: FindingTransitionRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Transition a finding to a new state in the 13-state lifecycle.
    Validates legal state machine transitions and requires explicit rationale.
    """
    verify_project_access(project_id, current_user, db)

    # Ensure any overdue accepted risks are reliably transitioned
    expired = FindingLifecycleService.sweep_expired_accepted_risks(project_id, db)
    if expired > 0:
        db.commit()

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
            detail="Finding not found in specified project",
        )

    actor_role = _get_user_project_role(project_id, current_user, db)
    client_ip = get_client_ip(request)

    updated_finding = FindingLifecycleService.transition_finding(
        finding=finding,
        to_status=transition_in.to_status,
        actor=current_user,
        actor_role=actor_role,
        reason=transition_in.reason,
        db=db,
        client_ip=client_ip,
        expires_at=transition_in.expires_at,
        compensating_controls=transition_in.compensating_controls,
        verification_job_id=transition_in.verification_job_id,
        verification_notes=transition_in.verification_notes,
        remediation_notes=transition_in.remediation_notes,
        assigned_to_id=transition_in.assigned_to_id,
    )
    db.commit()

    return _format_finding_detail(updated_finding, db)


@router.post("/projects/{project_id}/findings/{finding_id}/accept-risk", response_model=VulnerabilityFindingDetail)
def accept_finding_risk(
    project_id: str,
    finding_id: str,
    risk_in: AcceptRiskRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Dedicated endpoint to record an ACCEPTED_RISK disposition.
    Requires Project LEAD or System ADMIN, future expiration date, and documented compensating controls.
    """
    verify_project_access(
        project_id,
        current_user,
        db,
        required_project_roles=[ProjectRole.LEAD],
    )

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
            detail="Finding not found in specified project",
        )

    actor_role = _get_user_project_role(project_id, current_user, db)
    client_ip = get_client_ip(request)

    updated = FindingLifecycleService.transition_finding(
        finding=finding,
        to_status=FindingLifecycleStatus.ACCEPTED_RISK,
        actor=current_user,
        actor_role=actor_role,
        reason=risk_in.reason,
        db=db,
        client_ip=client_ip,
        expires_at=risk_in.expires_at,
        compensating_controls=risk_in.compensating_controls,
    )
    db.commit()

    return _format_finding_detail(updated, db)


@router.post("/projects/{project_id}/findings/{finding_id}/false-positive", response_model=VulnerabilityFindingDetail)
def mark_finding_false_positive(
    project_id: str,
    finding_id: str,
    fp_in: FalsePositiveRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Dedicated endpoint to record a FALSE_POSITIVE disposition.
    Requires Project LEAD or System ADMIN, and detailed justification.
    """
    verify_project_access(
        project_id,
        current_user,
        db,
        required_project_roles=[ProjectRole.LEAD],
    )

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
            detail="Finding not found in specified project",
        )

    actor_role = _get_user_project_role(project_id, current_user, db)
    client_ip = get_client_ip(request)

    updated = FindingLifecycleService.transition_finding(
        finding=finding,
        to_status=FindingLifecycleStatus.FALSE_POSITIVE,
        actor=current_user,
        actor_role=actor_role,
        reason=fp_in.reason,
        db=db,
        client_ip=client_ip,
    )
    db.commit()

    return _format_finding_detail(updated, db)


@router.post("/projects/{project_id}/findings/{finding_id}/propose-remediation", response_model=VulnerabilityFindingDetail)
def propose_remediation(
    project_id: str,
    finding_id: str,
    rem_in: ProposeRemediationRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Dedicated endpoint to submit a proposed remediation and optional assignee.
    Transitions finding to REMEDIATION_PROPOSED.
    """
    verify_project_access(project_id, current_user, db)

    # Ensure any overdue accepted risks are reliably transitioned
    expired = FindingLifecycleService.sweep_expired_accepted_risks(project_id, db)
    if expired > 0:
        db.commit()

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
            detail="Finding not found in specified project",
        )

    actor_role = _get_user_project_role(project_id, current_user, db)
    client_ip = get_client_ip(request)

    updated = FindingLifecycleService.transition_finding(
        finding=finding,
        to_status=FindingLifecycleStatus.REMEDIATION_PROPOSED,
        actor=current_user,
        actor_role=actor_role,
        reason=f"Remediation plan proposed: {rem_in.remediation_notes}",
        db=db,
        client_ip=client_ip,
        remediation_notes=rem_in.remediation_notes,
        assigned_to_id=rem_in.assigned_to_id,
    )
    db.commit()

    return _format_finding_detail(updated, db)
