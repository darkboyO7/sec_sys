from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Set, Any
from sqlalchemy.orm import Session
from fastapi import HTTPException, status

from app.models.finding import (
    FindingLifecycleStatus,
    VulnerabilityFinding,
    FindingTransition,
)
from app.models.user import User, SystemRole
from app.models.project import ProjectRole
from app.models.base import utc_now
from app.services.audit_service import AuditService


class InvalidFindingTransitionError(HTTPException):
    def __init__(self, detail: str):
        super().__init__(status_code=status.HTTP_400_BAD_REQUEST, detail=detail)


class FindingAuthorizationError(HTTPException):
    def __init__(self, detail: str):
        super().__init__(status_code=status.HTTP_403_FORBIDDEN, detail=detail)


class FindingLifecycleService:
    """
    Domain service governing the 13-state finding lifecycle.
    Enforces deterministic state transitions, reviewer attribution,
    and audit trails for false positives, risk acceptances, and closures.
    """

    ALLOWED_TRANSITIONS: Dict[FindingLifecycleStatus, Set[FindingLifecycleStatus]] = {
        FindingLifecycleStatus.DETECTED: {
            FindingLifecycleStatus.NEEDS_VALIDATION,
            FindingLifecycleStatus.CONFIRMED,
            FindingLifecycleStatus.FALSE_POSITIVE,
            FindingLifecycleStatus.INCONCLUSIVE,
            FindingLifecycleStatus.ACCEPTED_RISK,
        },
        FindingLifecycleStatus.NEEDS_VALIDATION: {
            FindingLifecycleStatus.CONFIRMED,
            FindingLifecycleStatus.FALSE_POSITIVE,
            FindingLifecycleStatus.INCONCLUSIVE,
            FindingLifecycleStatus.ACCEPTED_RISK,
        },
        FindingLifecycleStatus.CONFIRMED: {
            FindingLifecycleStatus.REMEDIATION_PROPOSED,
            FindingLifecycleStatus.ACCEPTED_RISK,
            FindingLifecycleStatus.FALSE_POSITIVE,
            FindingLifecycleStatus.NEEDS_VALIDATION,
        },
        FindingLifecycleStatus.FALSE_POSITIVE: {
            FindingLifecycleStatus.REOPENED,
            FindingLifecycleStatus.NEEDS_VALIDATION,
        },
        FindingLifecycleStatus.INCONCLUSIVE: {
            FindingLifecycleStatus.CONFIRMED,
            FindingLifecycleStatus.FALSE_POSITIVE,
            FindingLifecycleStatus.NEEDS_VALIDATION,
            FindingLifecycleStatus.ACCEPTED_RISK,
        },
        FindingLifecycleStatus.REMEDIATION_PROPOSED: {
            FindingLifecycleStatus.REMEDIATION_APPROVED,
            FindingLifecycleStatus.CONFIRMED,
            FindingLifecycleStatus.ACCEPTED_RISK,
        },
        FindingLifecycleStatus.REMEDIATION_APPROVED: {
            FindingLifecycleStatus.REMEDIATION_ATTEMPTED,
            FindingLifecycleStatus.REMEDIATION_PROPOSED,
            FindingLifecycleStatus.ACCEPTED_RISK,
        },
        FindingLifecycleStatus.REMEDIATION_ATTEMPTED: {
            FindingLifecycleStatus.REMEDIATED_PENDING_VERIFICATION,
            FindingLifecycleStatus.REMEDIATION_APPROVED,
            FindingLifecycleStatus.CONFIRMED,
        },
        FindingLifecycleStatus.REMEDIATED_PENDING_VERIFICATION: {
            FindingLifecycleStatus.VERIFIED_CLOSED,
            FindingLifecycleStatus.REOPENED,
            FindingLifecycleStatus.CONFIRMED,
        },
        FindingLifecycleStatus.VERIFIED_CLOSED: {
            FindingLifecycleStatus.REOPENED,
        },
        FindingLifecycleStatus.REOPENED: {
            FindingLifecycleStatus.CONFIRMED,
            FindingLifecycleStatus.NEEDS_VALIDATION,
            FindingLifecycleStatus.REMEDIATION_PROPOSED,
            FindingLifecycleStatus.ACCEPTED_RISK,
        },
        FindingLifecycleStatus.ACCEPTED_RISK: {
            FindingLifecycleStatus.EXPIRED,
            FindingLifecycleStatus.REOPENED,
            FindingLifecycleStatus.CONFIRMED,
            FindingLifecycleStatus.REMEDIATION_PROPOSED,
            FindingLifecycleStatus.NEEDS_VALIDATION,
        },
        FindingLifecycleStatus.EXPIRED: {
            FindingLifecycleStatus.NEEDS_VALIDATION,
            FindingLifecycleStatus.ACCEPTED_RISK,
            FindingLifecycleStatus.CONFIRMED,
            FindingLifecycleStatus.REMEDIATION_PROPOSED,
        },
    }

    @classmethod
    def can_transition(
        cls, from_status: FindingLifecycleStatus, to_status: FindingLifecycleStatus
    ) -> bool:
        if from_status == to_status:
            return False
        return to_status in cls.ALLOWED_TRANSITIONS.get(from_status, set())

    @classmethod
    def validate_transition(
        cls,
        finding: VulnerabilityFinding,
        to_status: FindingLifecycleStatus,
        actor: User,
        actor_role: Optional[ProjectRole],
        reason: str,
        expires_at: Optional[datetime] = None,
        compensating_controls: Optional[str] = None,
        verification_job_id: Optional[str] = None,
        verification_notes: Optional[str] = None,
    ) -> None:
        """
        Validates whether a transition from finding.status to to_status is legally permitted
        and satisfies all field, reason, and role constraints.
        """
        from_status = finding.status

        # 1. Check legal state machine transition
        if not cls.can_transition(from_status, to_status):
            raise InvalidFindingTransitionError(
                f"Illegal finding lifecycle transition from '{from_status.value}' to '{to_status.value}'."
            )

        # 2. Check reason requirement
        cleaned_reason = (reason or "").strip()
        if len(cleaned_reason) < 5:
            raise InvalidFindingTransitionError(
                "A transition rationale of at least 5 characters is required."
            )

        is_lead_or_admin = (actor.system_role == SystemRole.ADMIN) or (
            actor_role in (ProjectRole.LEAD,)
        )

        # 3. Special rules for FALSE_POSITIVE
        if to_status == FindingLifecycleStatus.FALSE_POSITIVE:
            if not is_lead_or_admin:
                raise FindingAuthorizationError(
                    "Only a Project LEAD or System ADMIN can classify a finding as FALSE_POSITIVE."
                )
            if len(cleaned_reason) < 10:
                raise InvalidFindingTransitionError(
                    "A detailed justification of at least 10 characters is required for FALSE_POSITIVE dispositions."
                )

        # 4. Special rules for ACCEPTED_RISK
        if to_status == FindingLifecycleStatus.ACCEPTED_RISK:
            if not is_lead_or_admin:
                raise FindingAuthorizationError(
                    "Only a Project LEAD or System ADMIN can mark a finding as ACCEPTED_RISK."
                )
            if len(cleaned_reason) < 10:
                raise InvalidFindingTransitionError(
                    "A comprehensive business justification of at least 10 characters is required for ACCEPTED_RISK."
                )
            if not expires_at:
                raise InvalidFindingTransitionError(
                    "A mandatory expiration date ('expires_at') is required for ACCEPTED_RISK."
                )
            now = utc_now()
            # Must be strictly in the future
            if expires_at <= now:
                raise InvalidFindingTransitionError(
                    "The risk acceptance expiration date must be in the future."
                )
            # Max 365 days in future
            if expires_at > now + timedelta(days=366):
                raise InvalidFindingTransitionError(
                    "Risk acceptance cannot exceed 365 days from today."
                )
            if not compensating_controls or len(compensating_controls.strip()) < 5:
                raise InvalidFindingTransitionError(
                    "Documented compensating controls (at least 5 characters) are required for ACCEPTED_RISK."
                )

        # 5. Special rules for VERIFIED_CLOSED
        if to_status == FindingLifecycleStatus.VERIFIED_CLOSED:
            notes = (verification_notes or "").strip()
            if not verification_job_id and len(notes) < 10:
                raise InvalidFindingTransitionError(
                    "Verification closure requires either a valid assessment verification job ID or detailed verification notes (>= 10 chars)."
                )

    @classmethod
    def transition_finding(
        cls,
        finding: VulnerabilityFinding,
        to_status: FindingLifecycleStatus,
        actor: User,
        actor_role: Optional[ProjectRole],
        reason: str,
        db: Session,
        client_ip: Optional[str] = None,
        expires_at: Optional[datetime] = None,
        compensating_controls: Optional[str] = None,
        verification_job_id: Optional[str] = None,
        verification_notes: Optional[str] = None,
        remediation_notes: Optional[str] = None,
        assigned_to_id: Optional[str] = None,
    ) -> VulnerabilityFinding:
        """
        Executes a validated lifecycle transition, persists provenance metadata,
        creates a transition audit record, and writes to the audit ledger.
        """
        cls.validate_transition(
            finding=finding,
            to_status=to_status,
            actor=actor,
            actor_role=actor_role,
            reason=reason,
            expires_at=expires_at,
            compensating_controls=compensating_controls,
            verification_job_id=verification_job_id,
            verification_notes=verification_notes,
        )

        from_status = finding.status
        now = utc_now()

        # Update specific fields based on target state
        if to_status == FindingLifecycleStatus.FALSE_POSITIVE:
            finding.false_positive_at = now
            finding.false_positive_by_id = actor.id
            finding.false_positive_reason = reason.strip()

        elif to_status == FindingLifecycleStatus.ACCEPTED_RISK:
            finding.risk_accepted_at = now
            finding.risk_accepted_by_id = actor.id
            finding.risk_accepted_reason = reason.strip()
            finding.risk_accepted_expires_at = expires_at
            finding.compensating_controls = (compensating_controls or "").strip()

        elif to_status == FindingLifecycleStatus.VERIFIED_CLOSED:
            finding.verified_at = now
            finding.verified_by_id = actor.id
            finding.verification_job_id = verification_job_id
            finding.verification_notes = (verification_notes or reason).strip()

        elif to_status == FindingLifecycleStatus.REMEDIATION_PROPOSED:
            if remediation_notes:
                finding.remediation_notes = remediation_notes.strip()
            if assigned_to_id:
                finding.assigned_to_id = assigned_to_id

        # Update finding status
        finding.status = to_status
        finding.updated_at = now

        # Create transition history record
        transition_record = FindingTransition(
            finding_id=finding.id,
            from_status=from_status,
            to_status=to_status,
            actor_id=actor.id,
            reason=reason.strip(),
            metadata_snapshot={
                "actor_email": actor.email,
                "actor_role": actor_role.value if actor_role else None,
                "severity": finding.severity.value,
                "confidence": finding.confidence.value,
                "target": finding.target_value,
                "has_contradictions": finding.has_contradictions,
            },
            created_at=now,
        )
        db.add(transition_record)
        db.flush()

        # Write immutable audit log
        AuditService.log(
            db=db,
            action="FINDING_STATE_TRANSITION",
            actor_id=actor.id,
            target_resource=f"finding:{finding.id}",
            project_id=finding.project_id,
            client_ip=client_ip,
            details={
                "finding_id": finding.id,
                "from_status": from_status.value,
                "to_status": to_status.value,
                "reason": reason.strip(),
                "actor_email": actor.email,
            },
        )

        return finding

    @classmethod
    def sweep_expired_accepted_risks(
        cls,
        project_id: str,
        db: Session,
        actor: Optional[User] = None,
        client_ip: Optional[str] = None,
    ) -> int:
        """
        Sweeps all ACCEPTED_RISK findings in a project whose risk_accepted_expires_at <= utc_now().
        Automatically transitions them to EXPIRED.
        Returns the number of expired findings transitioned.
        """
        now = utc_now()
        overdue_findings = (
            db.query(VulnerabilityFinding)
            .filter(
                VulnerabilityFinding.project_id == project_id,
                VulnerabilityFinding.status == FindingLifecycleStatus.ACCEPTED_RISK,
                VulnerabilityFinding.risk_accepted_expires_at <= now,
            )
            .all()
        )

        expired_count = 0
        for f in overdue_findings:
            from_status = f.status
            f.status = FindingLifecycleStatus.EXPIRED
            f.updated_at = now

            transition_record = FindingTransition(
                finding_id=f.id,
                from_status=from_status,
                to_status=FindingLifecycleStatus.EXPIRED,
                actor_id=actor.id if actor else None,
                reason="Scheduled risk acceptance period has expired without authorized renewal.",
                metadata_snapshot={
                    "automated": True,
                    "expired_at": now.isoformat(),
                    "original_expiration": f.risk_accepted_expires_at.isoformat()
                    if f.risk_accepted_expires_at
                    else None,
                },
                created_at=now,
            )
            db.add(transition_record)

            AuditService.log(
                db=db,
                action="FINDING_RISK_EXPIRED",
                actor_id=actor.id if actor else None,
                target_resource=f"finding:{f.id}",
                project_id=project_id,
                client_ip=client_ip,
                details={
                    "finding_id": f.id,
                    "target": f.target_value,
                    "vuln_id": f.vuln_id,
                    "expired_at": now.isoformat(),
                },
            )
            expired_count += 1

        db.flush()
        return expired_count
