from datetime import datetime, timezone
from typing import List
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.models.user import User, SystemRole
from app.models.project import ProjectRole
from app.models.scope import ScopeTarget, ScopeExclusion, TargetType, AuthorizationStatus
from app.schemas.scope import (
    ScopeTargetCreate,
    ScopeTargetResponse,
    ScopeTargetAuthorizeRequest,
    ScopeTargetRevokeRequest,
    ScopeExclusionCreate,
    ScopeExclusionResponse,
    ScopeValidationRequest,
    ScopeValidationResponse,
)
from app.services.scope_engine import ScopeEngine, ScopeTargetParseException
from app.services.audit_service import AuditService
from app.services.governance_service import ProjectGovernanceService
from app.api.deps import get_current_user, verify_project_access, get_client_ip

router = APIRouter()


# ------------------------------------------------------------------------------
# Scope Targets (Registration & Authorization Life-cycle)
# ------------------------------------------------------------------------------

@router.get("/projects/{project_id}/targets", response_model=List[ScopeTargetResponse])
def list_scope_targets(
    project_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List all registered scope targets for a project along with their authorization status."""
    verify_project_access(project_id, current_user, db)
    return db.query(ScopeTarget).filter(ScopeTarget.project_id == project_id).all()


@router.post("/projects/{project_id}/targets", response_model=ScopeTargetResponse, status_code=status.HTTP_201_CREATED)
def register_scope_target(
    project_id: str,
    target_in: ScopeTargetCreate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Register a candidate scope target.
    CRITICAL SECURITY INVARIANT:
    Registration does NOT grant authorization to scan or assess.
    New targets are created strictly in PENDING status.
    """
    client_ip = get_client_ip(request)
    verify_project_access(project_id, current_user, db, required_project_roles=[ProjectRole.LEAD, ProjectRole.TESTER])

    # Validate and normalize target syntax
    try:
        target_type, normalized_val = ScopeEngine.normalize_target(target_in.target_value)
    except ScopeTargetParseException as e:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(e))

    # Check for existing target in the same project
    existing = (
        db.query(ScopeTarget)
        .filter(ScopeTarget.project_id == project_id, ScopeTarget.target_value == normalized_val)
        .first()
    )
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Target '{normalized_val}' is already registered in this project (status: {existing.authorization_status.value})",
        )

    scope_target = ScopeTarget(
        project_id=project_id,
        target_type=target_type,
        target_value=normalized_val,
        description=target_in.description or "",
        authorization_status=AuthorizationStatus.PENDING,
        authorization_evidence="",
        created_by_id=current_user.id,
    )
    db.add(scope_target)
    db.commit()
    db.refresh(scope_target)

    AuditService.record_event(
        db=db,
        action="SCOPE_TARGET_REGISTER",
        target_type="scope_target",
        target_id=scope_target.id,
        project_id=project_id,
        actor_id=current_user.id,
        actor_email=current_user.email,
        outcome="SUCCESS",
        ip_address=client_ip,
        details={
            "target_type": target_type.value,
            "target_value": normalized_val,
            "initial_status": AuthorizationStatus.PENDING.value,
        },
    )

    return scope_target


@router.post("/projects/{project_id}/targets/{target_id}/authorize", response_model=ScopeTargetResponse)
def authorize_scope_target(
    project_id: str,
    target_id: str,
    auth_in: ScopeTargetAuthorizeRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Explicitly grant authorization for an assessment scope target.
    Requires project LEAD or system ADMIN / SECURITY_LEAD role.
    Must supply verifiable evidence (ROE doc, ticket number, authorization hash).
    """
    client_ip = get_client_ip(request)
    verify_project_access(project_id, current_user, db, required_project_roles=[ProjectRole.LEAD])

    scope_target = (
        db.query(ScopeTarget)
        .filter(ScopeTarget.project_id == project_id, ScopeTarget.id == target_id)
        .first()
    )
    if not scope_target:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scope target not found")

    # Separation of Duties (SoD) verification: Target creator cannot authorize their own target
    policy = ProjectGovernanceService.get_or_create_policy(db, project_id)
    if scope_target.created_by_id == current_user.id:
        if policy.enforce_separation_of_duties and not policy.allow_self_approval_override:
            AuditService.record_event(
                db=db,
                action="SCOPE_TARGET_AUTHORIZE_DENIED_SOD",
                target_type="scope_target",
                target_id=scope_target.id,
                project_id=project_id,
                actor_id=current_user.id,
                actor_email=current_user.email,
                outcome="DENIED",
                ip_address=client_ip,
                details={
                    "target_value": scope_target.target_value,
                    "reason": "Separation of Duties violation: Requester attempted self-authorization.",
                },
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Separation of Duties violation: The creator of a scope target cannot authorize their own target. An independent Project LEAD or Administrator must authorize it.",
            )
        elif policy.allow_self_approval_override:
            AuditService.record_event(
                db=db,
                action="SCOPE_TARGET_SELF_AUTHORIZATION_OVERRIDE",
                target_type="scope_target",
                target_id=scope_target.id,
                project_id=project_id,
                actor_id=current_user.id,
                actor_email=current_user.email,
                outcome="SUCCESS",
                ip_address=client_ip,
                details={
                    "target_value": scope_target.target_value,
                    "notes": "Single-operator mode exception: Scope target creator self-authorized.",
                },
            )

    now = datetime.now(timezone.utc)
    if auth_in.expires_at:
        exp = auth_in.expires_at
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        if exp <= now:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Expiration time must be in the future")

    scope_target.authorization_status = AuthorizationStatus.AUTHORIZED
    scope_target.authorization_evidence = auth_in.evidence.strip()
    scope_target.authorized_by_id = current_user.id
    scope_target.authorized_at = now
    scope_target.expires_at = auth_in.expires_at
    scope_target.revocation_reason = None
    scope_target.revoked_by_id = None
    scope_target.revoked_at = None

    db.commit()
    db.refresh(scope_target)

    AuditService.record_event(
        db=db,
        action="SCOPE_TARGET_AUTHORIZE",
        target_type="scope_target",
        target_id=scope_target.id,
        project_id=project_id,
        actor_id=current_user.id,
        actor_email=current_user.email,
        outcome="SUCCESS",
        ip_address=client_ip,
        details={
            "target_value": scope_target.target_value,
            "evidence": scope_target.authorization_evidence,
            "expires_at": scope_target.expires_at.isoformat() if scope_target.expires_at else None,
        },
    )

    return scope_target


@router.post("/projects/{project_id}/targets/{target_id}/revoke", response_model=ScopeTargetResponse)
def revoke_scope_target(
    project_id: str,
    target_id: str,
    revoke_in: ScopeTargetRevokeRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Revoke authorization for a scope target.
    Requires project LEAD or system ADMIN.
    """
    client_ip = get_client_ip(request)
    verify_project_access(project_id, current_user, db, required_project_roles=[ProjectRole.LEAD])

    scope_target = (
        db.query(ScopeTarget)
        .filter(ScopeTarget.project_id == project_id, ScopeTarget.id == target_id)
        .first()
    )
    if not scope_target:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scope target not found")

    # Invalidate any active approvals for this revoked target
    ProjectGovernanceService.invalidate_approvals_for_resource(
        db=db,
        project_id=project_id,
        resource_type="ScopeTarget",
        resource_id=target_id,
        reason=f"Scope target revoked: {revoke_in.reason.strip()}",
    )

    now = datetime.now(timezone.utc)
    scope_target.authorization_status = AuthorizationStatus.REVOKED
    scope_target.revocation_reason = revoke_in.reason.strip()
    scope_target.revoked_by_id = current_user.id
    scope_target.revoked_at = now

    db.commit()
    db.refresh(scope_target)

    AuditService.record_event(
        db=db,
        action="SCOPE_TARGET_REVOKE",
        target_type="scope_target",
        target_id=scope_target.id,
        project_id=project_id,
        actor_id=current_user.id,
        actor_email=current_user.email,
        outcome="SUCCESS",
        ip_address=client_ip,
        details={
            "target_value": scope_target.target_value,
            "revocation_reason": scope_target.revocation_reason,
        },
    )

    return scope_target


# ------------------------------------------------------------------------------
# Scope Exclusions (Preemptive Out-of-Scope Rules)
# ------------------------------------------------------------------------------

@router.get("/projects/{project_id}/exclusions", response_model=List[ScopeExclusionResponse])
def list_scope_exclusions(
    project_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List all scope exclusions registered for a project."""
    verify_project_access(project_id, current_user, db)
    return db.query(ScopeExclusion).filter(ScopeExclusion.project_id == project_id).all()


@router.post("/projects/{project_id}/exclusions", response_model=ScopeExclusionResponse, status_code=status.HTTP_201_CREATED)
def add_scope_exclusion(
    project_id: str,
    excl_in: ScopeExclusionCreate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Add an exclusion rule.
    Exclusions preemptively deny access even if covered by an authorized broader range.
    """
    client_ip = get_client_ip(request)
    verify_project_access(project_id, current_user, db, required_project_roles=[ProjectRole.LEAD, ProjectRole.TESTER])

    try:
        excl_type, normalized_val = ScopeEngine.normalize_target(excl_in.target_value)
    except ScopeTargetParseException as e:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(e))

    existing = (
        db.query(ScopeExclusion)
        .filter(ScopeExclusion.project_id == project_id, ScopeExclusion.target_value == normalized_val)
        .first()
    )
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Exclusion '{normalized_val}' already exists in this project",
        )

    exclusion = ScopeExclusion(
        project_id=project_id,
        target_type=excl_type,
        target_value=normalized_val,
        reason=excl_in.reason.strip(),
        created_by_id=current_user.id,
    )
    db.add(exclusion)
    db.commit()
    db.refresh(exclusion)

    AuditService.record_event(
        db=db,
        action="SCOPE_EXCLUSION_ADD",
        target_type="scope_exclusion",
        target_id=exclusion.id,
        project_id=project_id,
        actor_id=current_user.id,
        actor_email=current_user.email,
        outcome="SUCCESS",
        ip_address=client_ip,
        details={
            "target_type": excl_type.value,
            "target_value": normalized_val,
            "reason": exclusion.reason,
        },
    )

    return exclusion


@router.delete("/projects/{project_id}/exclusions/{exclusion_id}", status_code=status.HTTP_204_NO_CONTENT)
def remove_scope_exclusion(
    project_id: str,
    exclusion_id: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Remove an exclusion rule. Requires project LEAD or system ADMIN."""
    client_ip = get_client_ip(request)
    verify_project_access(project_id, current_user, db, required_project_roles=[ProjectRole.LEAD])

    exclusion = (
        db.query(ScopeExclusion)
        .filter(ScopeExclusion.project_id == project_id, ScopeExclusion.id == exclusion_id)
        .first()
    )
    if not exclusion:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scope exclusion not found")

    target_val = exclusion.target_value
    db.delete(exclusion)
    db.commit()

    AuditService.record_event(
        db=db,
        action="SCOPE_EXCLUSION_REMOVE",
        target_type="scope_exclusion",
        target_id=exclusion_id,
        project_id=project_id,
        actor_id=current_user.id,
        actor_email=current_user.email,
        outcome="SUCCESS",
        ip_address=client_ip,
        details={"target_value": target_val},
    )

    return None


# ------------------------------------------------------------------------------
# Non-invasive Scope Validation Console
# ------------------------------------------------------------------------------

@router.post("/projects/{project_id}/validate", response_model=ScopeValidationResponse)
def validate_target_scope(
    project_id: str,
    val_in: ScopeValidationRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Non-invasive evaluation of candidate target against project authorization rules.
    DOES NOT initiate network probes, DNS lookups, or port scans.
    Strictly evaluates rules in memory and fails closed.
    """
    client_ip = get_client_ip(request)
    verify_project_access(project_id, current_user, db)

    evaluation = ScopeEngine.validate_target_in_scope(
        db=db,
        project_id=project_id,
        target=val_in.target,
    )

    # Log validation audit entry
    AuditService.record_event(
        db=db,
        action="SCOPE_TARGET_VALIDATION",
        target_type="scope_target",
        project_id=project_id,
        actor_id=current_user.id,
        actor_email=current_user.email,
        outcome="SUCCESS" if evaluation["is_authorized"] else "DENIED",
        ip_address=client_ip,
        details={
            "queried_target": val_in.target,
            "normalized_target": evaluation["normalized_target"],
            "decision": evaluation["status"],
            "reason": evaluation["reason"],
        },
    )

    return ScopeValidationResponse(
        target=val_in.target,
        normalized_target=evaluation["normalized_target"],
        is_authorized=evaluation["is_authorized"],
        status=evaluation["status"],
        reason=evaluation["reason"],
        matched_rule=evaluation["matched_rule"],
        matched_exclusion=evaluation["matched_exclusion"],
        evaluated_at=datetime.now(timezone.utc),
    )
