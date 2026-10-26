from datetime import datetime, timezone, timedelta
from typing import Optional
from sqlalchemy.orm import Session
from fastapi import HTTPException, status

from app.models.finding import (
    FindingLifecycleStatus,
    VulnerabilityFinding,
    ValidationOutcome,
)
from app.models.assessment import AssessmentFinding, AssessmentJob, FindingConfidence
from app.models.user import User, SystemRole
from app.models.project import ProjectRole
from app.models.base import utc_now
from app.services.finding_lifecycle_service import FindingLifecycleService, FindingAuthorizationError
from app.services.audit_service import AuditService


class FindingValidationService:
    """
    Phase 9: Advanced Finding Validation Service.
    Enforces analyst review governance, tracks confidence and evidence quality,
    evaluates cross-source correlation, and maintains validation outcomes.
    """

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
        validation_outcome: str,
        analyst_review_notes: str,
        analyst: User,
        analyst_role: Optional[ProjectRole],
        db: Session,
        client_ip: Optional[str] = None,
        explicit_quality_score: Optional[float] = None,
    ) -> VulnerabilityFinding:
        """
        Validates a finding with analyst attribution, updates the lifecycle if appropriate,
        and records immutable audit logs.
        """
        # Validate outcome enum
        valid_outcomes = {o.value for o in ValidationOutcome}
        if validation_outcome not in valid_outcomes:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid validation outcome '{validation_outcome}'. Must be one of {sorted(valid_outcomes)}",
            )

        now = utc_now()
        quality_score = (
            explicit_quality_score
            if explicit_quality_score is not None
            else cls.calculate_evidence_quality_score(finding, db)
        )

        # Handle lifecycle status synchronization based on outcome
        if validation_outcome == ValidationOutcome.FALSE_POSITIVE.value:
            # Requires LEAD or ADMIN
            is_admin = analyst.system_role == SystemRole.ADMIN
            is_lead = analyst_role == ProjectRole.LEAD
            if not (is_admin or is_lead):
                raise FindingAuthorizationError(
                    "Only Project LEAD or System ADMIN can validate finding as FALSE_POSITIVE."
                )
            if finding.status != FindingLifecycleStatus.FALSE_POSITIVE:
                FindingLifecycleService.transition_finding(
                    finding=finding,
                    to_status=FindingLifecycleStatus.FALSE_POSITIVE,
                    actor=analyst,
                    actor_role=analyst_role,
                    reason=f"Analyst validated as FALSE_POSITIVE: {analyst_review_notes}",
                    db=db,
                    client_ip=client_ip,
                )
        elif validation_outcome == ValidationOutcome.CONFIRMED.value:
            if finding.status in (
                FindingLifecycleStatus.DETECTED,
                FindingLifecycleStatus.NEEDS_VALIDATION,
                FindingLifecycleStatus.INCONCLUSIVE,
                FindingLifecycleStatus.REOPENED,
            ):
                FindingLifecycleService.transition_finding(
                    finding=finding,
                    to_status=FindingLifecycleStatus.CONFIRMED,
                    actor=analyst,
                    actor_role=analyst_role,
                    reason=f"Analyst validated as CONFIRMED: {analyst_review_notes}",
                    db=db,
                    client_ip=client_ip,
                )
        elif validation_outcome == ValidationOutcome.NEEDS_MANUAL_REVIEW.value:
            if finding.status == FindingLifecycleStatus.DETECTED:
                FindingLifecycleService.transition_finding(
                    finding=finding,
                    to_status=FindingLifecycleStatus.NEEDS_VALIDATION,
                    actor=analyst,
                    actor_role=analyst_role,
                    reason=f"Analyst flagged for manual review: {analyst_review_notes}",
                    db=db,
                    client_ip=client_ip,
                )
        elif validation_outcome == ValidationOutcome.INCONCLUSIVE.value:
            if finding.status in (
                FindingLifecycleStatus.DETECTED,
                FindingLifecycleStatus.NEEDS_VALIDATION,
            ):
                FindingLifecycleService.transition_finding(
                    finding=finding,
                    to_status=FindingLifecycleStatus.INCONCLUSIVE,
                    actor=analyst,
                    actor_role=analyst_role,
                    reason=f"Analyst marked evidence inconclusive: {analyst_review_notes}",
                    db=db,
                    client_ip=client_ip,
                )

        # Store analyst validation metadata
        finding.validation_outcome = validation_outcome
        finding.analyst_review_notes = analyst_review_notes
        finding.reviewed_by_id = analyst.id
        finding.reviewed_at = now
        finding.evidence_quality_score = quality_score
        finding.updated_at = now

        AuditService.log(
            db=db,
            action="FINDING_VALIDATED",
            actor_id=analyst.id,
            target_resource=f"finding:{finding.id}",
            project_id=finding.project_id,
            client_ip=client_ip,
            details={
                "finding_id": finding.id,
                "validation_outcome": validation_outcome,
                "evidence_quality_score": quality_score,
                "analyst_review_notes": analyst_review_notes,
                "new_lifecycle_status": finding.status.value,
            },
        )

        return finding
