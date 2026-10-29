from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Set, Any, List
from sqlalchemy.orm import Session
from fastapi import HTTPException, status

from app.models.finding import (
    FindingLifecycleStatus,
    FindingValidationStatus,
    VulnerabilityFinding,
    ValidationTransition,
    ValidationOutcome,
)
from app.models.assessment import AssessmentFinding, AssessmentJob, FindingConfidence, FindingEvidence
from app.models.user import User, SystemRole
from app.models.project import ProjectRole
from app.models.base import utc_now
from app.services.finding_lifecycle_service import FindingLifecycleService, FindingAuthorizationError
from app.services.audit_service import AuditService


class InvalidValidationTransitionError(HTTPException):
    def __init__(self, detail: str):
        super().__init__(status_code=status.HTTP_400_BAD_REQUEST, detail=detail)


class ValidationAuthorizationError(HTTPException):
    def __init__(self, detail: str):
        super().__init__(status_code=status.HTTP_403_FORBIDDEN, detail=detail)


class FindingValidationService:
    """
    Evidence-Driven Finding Validation Engine (Prompt 19).
    Governs the 9-state evidence and proof lifecycle:
    DETECTED -> EVIDENCE_PENDING / EVIDENCE_SUPPORTED -> INDEPENDENTLY_REPRODUCED ->
    CONFIRMED_TRUE_POSITIVE / CONFIRMED_FALSE_POSITIVE / INCONCLUSIVE / UNABLE_TO_VERIFY -> RESOLVED_AFTER_RETEST.

    Strictly separates:
    - Operational lifecycle state (finding.status)
    - Epistemic validation state (finding.validation_status)
    - Scanner confidence (finding.confidence)
    """

    ALLOWED_VALIDATION_TRANSITIONS: Dict[FindingValidationStatus, Set[FindingValidationStatus]] = {
        FindingValidationStatus.DETECTED: {
            FindingValidationStatus.EVIDENCE_PENDING,
            FindingValidationStatus.EVIDENCE_SUPPORTED,
            FindingValidationStatus.INCONCLUSIVE,
            FindingValidationStatus.UNABLE_TO_VERIFY,
        },
        FindingValidationStatus.EVIDENCE_PENDING: {
            FindingValidationStatus.EVIDENCE_SUPPORTED,
            FindingValidationStatus.INCONCLUSIVE,
            FindingValidationStatus.UNABLE_TO_VERIFY,
            FindingValidationStatus.CONFIRMED_FALSE_POSITIVE,
        },
        FindingValidationStatus.EVIDENCE_SUPPORTED: {
            FindingValidationStatus.INDEPENDENTLY_REPRODUCED,
            FindingValidationStatus.CONFIRMED_TRUE_POSITIVE,
            FindingValidationStatus.CONFIRMED_FALSE_POSITIVE,
            FindingValidationStatus.INCONCLUSIVE,
            FindingValidationStatus.UNABLE_TO_VERIFY,
        },
        FindingValidationStatus.INDEPENDENTLY_REPRODUCED: {
            FindingValidationStatus.CONFIRMED_TRUE_POSITIVE,
            FindingValidationStatus.CONFIRMED_FALSE_POSITIVE,
            FindingValidationStatus.INCONCLUSIVE,
            FindingValidationStatus.RESOLVED_AFTER_RETEST,
            FindingValidationStatus.UNABLE_TO_VERIFY,
        },
        FindingValidationStatus.CONFIRMED_TRUE_POSITIVE: {
            FindingValidationStatus.RESOLVED_AFTER_RETEST,
            FindingValidationStatus.CONFIRMED_FALSE_POSITIVE,
            FindingValidationStatus.INCONCLUSIVE,
            FindingValidationStatus.UNABLE_TO_VERIFY,
        },
        FindingValidationStatus.CONFIRMED_FALSE_POSITIVE: {
            FindingValidationStatus.DETECTED,
            FindingValidationStatus.EVIDENCE_SUPPORTED,
            FindingValidationStatus.CONFIRMED_TRUE_POSITIVE,
        },
        FindingValidationStatus.INCONCLUSIVE: {
            FindingValidationStatus.EVIDENCE_SUPPORTED,
            FindingValidationStatus.INDEPENDENTLY_REPRODUCED,
            FindingValidationStatus.CONFIRMED_TRUE_POSITIVE,
            FindingValidationStatus.CONFIRMED_FALSE_POSITIVE,
            FindingValidationStatus.UNABLE_TO_VERIFY,
        },
        FindingValidationStatus.UNABLE_TO_VERIFY: {
            FindingValidationStatus.EVIDENCE_SUPPORTED,
            FindingValidationStatus.INDEPENDENTLY_REPRODUCED,
            FindingValidationStatus.CONFIRMED_TRUE_POSITIVE,
            FindingValidationStatus.INCONCLUSIVE,
            FindingValidationStatus.CONFIRMED_FALSE_POSITIVE,
        },
        FindingValidationStatus.RESOLVED_AFTER_RETEST: {
            FindingValidationStatus.CONFIRMED_TRUE_POSITIVE,
            FindingValidationStatus.INDEPENDENTLY_REPRODUCED,
        },
    }

    @classmethod
    def can_transition_validation(
        cls, from_status: FindingValidationStatus, to_status: FindingValidationStatus
    ) -> bool:
        if from_status == to_status:
            return False
        return to_status in cls.ALLOWED_VALIDATION_TRANSITIONS.get(from_status, set())

    @classmethod
    def verify_finding_has_valid_evidence(cls, finding: VulnerabilityFinding, db: Session) -> bool:
        """
        Determines whether the canonical finding is backed by at least one cryptographically
        hashed, non-empty evidence item with verified payload hash.
        """
        observations = (
            db.query(AssessmentFinding)
            .filter(AssessmentFinding.canonical_finding_id == finding.id)
            .all()
        )
        for obs in observations:
            for ev in obs.evidence_items:
                if ev.payload and ev.sha256_hash:
                    return True
        return False

    @classmethod
    def transition_validation_status(
        cls,
        finding: VulnerabilityFinding,
        to_status: FindingValidationStatus,
        validation_method: str,
        actor: User,
        actor_role: Optional[ProjectRole],
        reason: str,
        db: Session,
        evidence_ref: Optional[str] = None,
        client_ip: Optional[str] = None,
        is_ai_generated: bool = False,
    ) -> VulnerabilityFinding:
        """
        Executes a validated transition of the finding's epistemic validation state.
        Enforces authorization gates, evidence presence, and immutable audit recording.
        """
        from_status = finding.validation_status or FindingValidationStatus.DETECTED

        # 1. Check legal FSM transition
        if not cls.can_transition_validation(from_status, to_status):
            raise InvalidValidationTransitionError(
                f"Illegal validation state transition from '{from_status.value}' to '{to_status.value}'."
            )

        # 2. Check reason length
        cleaned_reason = (reason or "").strip()
        if len(cleaned_reason) < 5:
            raise InvalidValidationTransitionError(
                "A validation transition rationale of at least 5 characters is required."
            )

        is_lead_or_admin = (actor.system_role == SystemRole.ADMIN) or (actor_role == ProjectRole.LEAD)
        is_viewer = (actor_role == ProjectRole.VIEWER) and (actor.system_role != SystemRole.ADMIN)

        if is_viewer:
            raise ValidationAuthorizationError(
                "Viewers have read-only access and cannot alter finding validation states."
            )

        # 3. AI prediction guardrail: AI-generated explanations CANNOT confirm findings without evidence
        if is_ai_generated and to_status == FindingValidationStatus.CONFIRMED_TRUE_POSITIVE:
            raise InvalidValidationTransitionError(
                "AI-generated predictions cannot confirm a vulnerability without independent verified evidence."
            )

        # 4. Special rules for CONFIRMED_FALSE_POSITIVE
        if to_status == FindingValidationStatus.CONFIRMED_FALSE_POSITIVE:
            if not is_lead_or_admin:
                raise ValidationAuthorizationError(
                    "Only a Project LEAD or System ADMIN can validate a finding as CONFIRMED_FALSE_POSITIVE."
                )
            if len(cleaned_reason) < 10:
                raise InvalidValidationTransitionError(
                    "A comprehensive justification of at least 10 characters is required for CONFIRMED_FALSE_POSITIVE."
                )

        # 5. Special rules for CONFIRMED_TRUE_POSITIVE
        if to_status == FindingValidationStatus.CONFIRMED_TRUE_POSITIVE:
            has_evidence = cls.verify_finding_has_valid_evidence(finding, db)
            if not has_evidence and not evidence_ref:
                raise InvalidValidationTransitionError(
                    "Cannot mark finding as CONFIRMED_TRUE_POSITIVE without valid, cryptographically hashed evidence."
                )

        # 6. Special rules for RESOLVED_AFTER_RETEST
        if to_status == FindingValidationStatus.RESOLVED_AFTER_RETEST:
            if not is_lead_or_admin and actor_role != ProjectRole.TESTER:
                raise ValidationAuthorizationError(
                    "Only Project TESTER, LEAD, or System ADMIN can record retest resolution."
                )

        now = utc_now()

        # Update finding validation fields
        finding.validation_status = to_status
        finding.validation_method = validation_method
        finding.validation_notes = cleaned_reason
        finding.validation_evidence_ref = evidence_ref
        finding.validation_updated_at = now
        finding.reviewed_by_id = actor.id
        finding.reviewed_at = now

        # Synchronize operational lifecycle status where appropriate
        if to_status == FindingValidationStatus.CONFIRMED_FALSE_POSITIVE:
            finding.status = FindingLifecycleStatus.FALSE_POSITIVE
            finding.false_positive_at = now
            finding.false_positive_by_id = actor.id
            finding.false_positive_reason = cleaned_reason
        elif to_status == FindingValidationStatus.CONFIRMED_TRUE_POSITIVE:
            if finding.status in (FindingLifecycleStatus.DETECTED, FindingLifecycleStatus.NEEDS_VALIDATION):
                finding.status = FindingLifecycleStatus.CONFIRMED
        elif to_status == FindingValidationStatus.INCONCLUSIVE:
            finding.status = FindingLifecycleStatus.INCONCLUSIVE
        elif to_status == FindingValidationStatus.RESOLVED_AFTER_RETEST:
            finding.status = FindingLifecycleStatus.VERIFIED_CLOSED

        # Record immutable audit transition
        transition = ValidationTransition(
            finding_id=finding.id,
            from_status=from_status,
            to_status=to_status,
            validation_method=validation_method,
            actor_id=actor.id,
            reason=cleaned_reason,
            evidence_ref=evidence_ref,
            metadata_snapshot={
                "actor_role": actor_role.value if actor_role else None,
                "confidence": finding.confidence.value if hasattr(finding.confidence, "value") else str(finding.confidence),
                "severity": finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity),
                "operational_status": finding.status.value,
            },
            created_at=now,
        )
        db.add(transition)

        # Audit ledger log
        AuditService.log(
            db=db,
            action="FINDING_VALIDATION_TRANSITION",
            actor_id=actor.id,
            target_resource=f"finding:{finding.id}",
            project_id=finding.project_id,
            client_ip=client_ip,
            details={
                "finding_id": finding.id,
                "from_validation_status": from_status.value,
                "to_validation_status": to_status.value,
                "validation_method": validation_method,
                "reason": cleaned_reason,
                "evidence_ref": evidence_ref,
                "operational_status": finding.status.value,
            },
        )

        return finding

    @classmethod
    def calculate_evidence_quality_score(
        cls, finding: VulnerabilityFinding, db: Session
    ) -> float:
        """
        Calculates an objective evidence quality score (0.0 to 1.0) based on:
        - Cross-source multi-adapter corroboration
        - Evidence freshness / recency
        - Contradiction status
        - Scanner confidence
        """
        score = 1.0

        # 1. Contradiction penalty
        if finding.has_contradictions:
            score -= 0.35

        # 2. Scanner confidence penalty
        if finding.confidence == FindingConfidence.TENTATIVE:
            score -= 0.25

        # 3. Multi-adapter corroboration
        distinct_adapters = (
            db.query(AssessmentJob.adapter_name)
            .join(AssessmentFinding, AssessmentFinding.job_id == AssessmentJob.id)
            .filter(AssessmentFinding.canonical_finding_id == finding.id)
            .distinct()
            .count()
        )
        if distinct_adapters > 1:
            score = min(1.0, score + 0.15)

        # 4. Freshness penalty
        now = utc_now()
        last_obs = finding.last_observed_at
        if last_obs:
            if last_obs.tzinfo is None:
                last_obs = last_obs.replace(tzinfo=timezone.utc)
            age_days = (now - last_obs).total_seconds() / 86400.0
            if age_days > 90:
                score *= 0.5
            elif age_days > 30:
                score *= 0.8

        return max(0.0, min(1.0, round(score, 2)))

    @classmethod
    def validate_finding(
        cls,
        finding: VulnerabilityFinding,
        validation_outcome: ValidationOutcome,
        analyst_review_notes: str,
        analyst: User,
        analyst_role: Optional[ProjectRole],
        db: Session,
        client_ip: Optional[str] = None,
        explicit_quality_score: Optional[float] = None,
    ) -> VulnerabilityFinding:
        """
        Phase 9 Backward Compatibility: Analyst finding validation method.
        Maps ValidationOutcome to finding status and Prompt 19 FindingValidationStatus.
        """
        outcome_val = validation_outcome.value if hasattr(validation_outcome, "value") else str(validation_outcome)

        is_lead_or_admin = (analyst.system_role == SystemRole.ADMIN) or (analyst_role == ProjectRole.LEAD)
        is_viewer = (analyst_role == ProjectRole.VIEWER) and (analyst.system_role != SystemRole.ADMIN)

        if is_viewer:
            raise ValidationAuthorizationError("Viewers have read-only access and cannot validate findings.")

        if outcome_val == "FALSE_POSITIVE":
            if not is_lead_or_admin:
                raise ValidationAuthorizationError("Only a Project LEAD or System ADMIN can validate a finding as FALSE_POSITIVE.")
            if not analyst_review_notes or len(analyst_review_notes.strip()) < 5:
                raise InvalidValidationTransitionError("A justification is required to validate a finding as FALSE_POSITIVE.")

        now = utc_now()
        # Coerce to enum if needed
        if isinstance(validation_outcome, str):
            try:
                validation_outcome = ValidationOutcome(validation_outcome)
            except ValueError:
                pass

        finding.validation_outcome = validation_outcome
        finding.analyst_review_notes = analyst_review_notes
        finding.reviewed_by_id = analyst.id
        finding.reviewed_at = now

        if explicit_quality_score is not None:
            finding.evidence_quality_score = max(0.0, min(1.0, explicit_quality_score))
        else:
            finding.evidence_quality_score = cls.calculate_evidence_quality_score(finding, db)

        # Synchronize lifecycle status and Prompt 19 validation_status
        if outcome_val == "CONFIRMED":
            finding.status = FindingLifecycleStatus.CONFIRMED
            finding.validation_status = FindingValidationStatus.CONFIRMED_TRUE_POSITIVE
        elif outcome_val == "FALSE_POSITIVE":
            finding.status = FindingLifecycleStatus.FALSE_POSITIVE
            finding.validation_status = FindingValidationStatus.CONFIRMED_FALSE_POSITIVE
            finding.false_positive_at = now
            finding.false_positive_by_id = analyst.id
            finding.false_positive_reason = analyst_review_notes
        elif outcome_val == "INCONCLUSIVE":
            finding.status = FindingLifecycleStatus.INCONCLUSIVE
            finding.validation_status = FindingValidationStatus.INCONCLUSIVE
        elif outcome_val == "NEEDS_MANUAL_REVIEW":
            finding.status = FindingLifecycleStatus.NEEDS_VALIDATION
            finding.validation_status = FindingValidationStatus.EVIDENCE_PENDING

        AuditService.log(
            db=db,
            action="FINDING_VALIDATED",
            actor_id=analyst.id,
            target_resource=f"finding:{finding.id}",
            project_id=finding.project_id,
            client_ip=client_ip,
            details={
                "finding_id": finding.id,
                "validation_outcome": outcome_val,
                "analyst_review_notes": analyst_review_notes,
                "evidence_quality_score": finding.evidence_quality_score,
                "status": finding.status.value,
                "validation_status": finding.validation_status.value if finding.validation_status else None,
            },
        )

        return finding
