import hashlib
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session
from sqlalchemy import desc, and_

from app.models.drift import (
    ExposureDriftRecord,
    ReassessmentProposal,
    ReassessmentPriority,
    ReassessmentStatus,
    DriftMateriality,
)
from app.models.asset import Asset, AssetStatus
from app.models.assessment import AssessmentJob, AssessmentStatus
from app.models.user import User, SystemRole
from app.models.project import ProjectRole
from app.models.base import utc_now
from app.services.scope_engine import ScopeEngine
from app.services.audit_service import AuditService


class ReassessmentPlannerService:
    """
    Policy-Constrained Reassessment Planner (Prompt 20 / Section 5).
    Translates material exposure drift into prioritized, scope-validated reassessment proposals.
    Enforces:
    - Zero authorization escalation: target MUST be in active authorized scope.
    - Scope revalidation at execution boundary.
    - Deterministic deduplication to prevent scheduling storms.
    - Failure loop avoidance: defers reassessment if target repeatedly failed without environment changes.
    - Human approval enforcement for restricted or production assets.
    """

    @classmethod
    def plan_reassessments_for_drift(
        cls,
        project_id: str,
        drift_record: ExposureDriftRecord,
        db: Session,
    ) -> Optional[ReassessmentProposal]:
        """
        Evaluates an individual material drift record and creates a policy-constrained reassessment proposal.
        """
        if not drift_record.reassessment_recommended:
            return None
        if drift_record.materiality != DriftMateriality.MATERIAL:
            return None

        now = utc_now()
        target = drift_record.target_resource

        # 1. Authoritative Scope Validation Check
        scope_eval = ScopeEngine.validate_target_in_scope(
            db=db,
            project_id=project_id,
            target=target,
            now=now,
        )

        is_authorized = scope_eval.get("is_authorized", False)

        # 2. Priority Determination based on drift type and confidence
        priority = ReassessmentPriority.MEDIUM
        requires_human_approval = False

        if drift_record.drift_type.value in ["NEW_AUTHORIZED_ASSET", "SECURITY_CONFIG_CHANGED"]:
            priority = ReassessmentPriority.HIGH
        elif drift_record.drift_type.value in ["SERVICE_ADDED", "IP_ASSOCIATION_CHANGED"]:
            priority = ReassessmentPriority.HIGH

        asset = db.query(Asset).filter(Asset.id == drift_record.asset_id).first() if drift_record.asset_id else None
        if asset:
            if asset.criticality.value in ["CRITICAL", "HIGH"]:
                priority = ReassessmentPriority.CRITICAL
                requires_human_approval = True
            if asset.environment == "PRODUCTION":
                requires_human_approval = True

        # 3. Check for previous repeated failures on this target (prevent retry storm)
        recent_failed_jobs = (
            db.query(AssessmentJob)
            .filter(
                AssessmentJob.project_id == project_id,
                AssessmentJob.target_input == target,
                AssessmentJob.status == AssessmentStatus.FAILED,
                AssessmentJob.created_at >= now - timedelta(hours=6),
            )
            .count()
        )

        initial_status = ReassessmentStatus.PROPOSED
        if not is_authorized:
            initial_status = ReassessmentStatus.REJECTED
        elif recent_failed_jobs >= 3:
            initial_status = ReassessmentStatus.DEFERRED

        # 4. Deterministic Dedup Key
        dedup_seed = f"{project_id}:{target}:{drift_record.drift_type.value}"
        dedup_key = hashlib.sha256(dedup_seed.encode("utf-8")).hexdigest()

        # Check existing active proposal with identical dedup key
        existing_proposal = (
            db.query(ReassessmentProposal)
            .filter(
                ReassessmentProposal.project_id == project_id,
                ReassessmentProposal.dedup_key == dedup_key,
                ReassessmentProposal.status.in_([
                    ReassessmentStatus.PROPOSED,
                    ReassessmentStatus.APPROVED,
                    ReassessmentStatus.QUEUED,
                ]),
            )
            .first()
        )

        if existing_proposal:
            # Equivalent reassessment proposal already pending
            return existing_proposal

        rationale = (
            f"Reassessment proposed due to material exposure drift ({drift_record.drift_type.value}): "
            f"{drift_record.title}. {drift_record.materiality_reason}"
        )
        if not is_authorized:
            rationale += f" [BLOCKED: Scope validation failed - {scope_eval.get('reason')}]."
        elif initial_status == ReassessmentStatus.DEFERRED:
            rationale += " [DEFERRED: Target experienced 3+ repeated failures in last 6 hours]."

        proposal = ReassessmentProposal(
            project_id=project_id,
            asset_id=drift_record.asset_id,
            drift_record_id=drift_record.id,
            target_input=target,
            adapter_name="live_network_auditor_adapter",
            fixture_profile="LIVE_WEB_SECURITY_AUDIT",
            priority=priority,
            status=initial_status,
            rationale=rationale,
            scope_authorized=is_authorized,
            scope_validation_details=scope_eval,
            requires_human_approval=requires_human_approval,
            dedup_key=dedup_key,
            rejection_reason=scope_eval.get("reason") if not is_authorized else None,
            created_at=now,
            updated_at=now,
        )
        db.add(proposal)
        db.flush()

        AuditService.log(
            db=db,
            action="REASSESSMENT_PROPOSAL_CREATED",
            target_resource=target,
            project_id=project_id,
            details={
                "proposal_id": proposal.id,
                "drift_record_id": drift_record.id,
                "priority": priority.value,
                "status": initial_status.value,
                "requires_approval": requires_human_approval,
            },
        )
        return proposal

    @classmethod
    def approve_and_queue_reassessment(
        cls,
        project_id: str,
        proposal_id: str,
        actor: User,
        actor_role: Optional[ProjectRole],
        db: Session,
    ) -> AssessmentJob:
        """
        Approves and creates an execution-ready assessment job for a reassessment proposal.
        Re-validates scope and authorization at the exact moment of execution.
        """
        proposal = (
            db.query(ReassessmentProposal)
            .filter(
                ReassessmentProposal.id == proposal_id,
                ReassessmentProposal.project_id == project_id,
            )
            .first()
        )
        if not proposal:
            raise ValueError("Reassessment proposal not found.")

        if proposal.status not in [ReassessmentStatus.PROPOSED, ReassessmentStatus.DEFERRED]:
            raise ValueError(f"Proposal cannot be approved in state '{proposal.status.value}'.")

        # RBAC Check
        is_lead_or_admin = (actor.system_role == SystemRole.ADMIN) or (actor_role == ProjectRole.LEAD)
        if proposal.requires_human_approval and not is_lead_or_admin:
            raise PermissionError("Approval requires Project LEAD or System ADMIN authority.")

        now = utc_now()

        # Strict execution-boundary scope re-validation
        scope_eval = ScopeEngine.validate_target_in_scope(
            db=db,
            project_id=project_id,
            target=proposal.target_input,
            now=now,
        )
        if not scope_eval.get("is_authorized"):
            proposal.status = ReassessmentStatus.REJECTED
            proposal.rejection_reason = f"Execution blocked: Scope revoked or target excluded ({scope_eval.get('reason')})."
            proposal.updated_at = now
            db.flush()
            raise PermissionError(f"Target is no longer authorized: {scope_eval.get('reason')}")

        # Create scheduled assessment job
        job = AssessmentJob(
            project_id=project_id,
            name=f"Reassessment: {proposal.target_input}",
            target_input=proposal.target_input,
            adapter_name=proposal.adapter_name,
            fixture_profile=proposal.fixture_profile,
            status=AssessmentStatus.QUEUED,
            created_by_id=actor.id,
            job_metadata={
                "trigger": "EXPOSURE_DRIFT_REASSESSMENT",
                "proposal_id": proposal.id,
                "drift_record_id": proposal.drift_record_id,
                "priority": proposal.priority.value,
            },
            created_at=now,
            updated_at=now,
        )
        db.add(job)
        db.flush()

        # Update proposal state
        proposal.status = ReassessmentStatus.QUEUED
        proposal.approved_by_id = actor.id
        proposal.approved_at = now
        proposal.scheduled_job_id = job.id
        proposal.updated_at = now
        db.flush()

        AuditService.log(
            db=db,
            action="REASSESSMENT_PROPOSAL_APPROVED",
            target_resource=proposal.target_input,
            actor_id=actor.id,
            project_id=project_id,
            details={
                "proposal_id": proposal.id,
                "job_id": job.id,
            },
        )
        return job

    @classmethod
    def reject_reassessment(
        cls,
        project_id: str,
        proposal_id: str,
        actor: User,
        rejection_reason: str,
        db: Session,
    ) -> ReassessmentProposal:
        """Rejects a reassessment proposal with documented operator justification."""
        proposal = (
            db.query(ReassessmentProposal)
            .filter(
                ReassessmentProposal.id == proposal_id,
                ReassessmentProposal.project_id == project_id,
            )
            .first()
        )
        if not proposal:
            raise ValueError("Reassessment proposal not found.")

        now = utc_now()
        proposal.status = ReassessmentStatus.REJECTED
        proposal.rejection_reason = rejection_reason or "Rejected by operator."
        proposal.updated_at = now
        db.flush()

        AuditService.log(
            db=db,
            action="REASSESSMENT_PROPOSAL_REJECTED",
            target_resource=proposal.target_input,
            actor_id=actor.id,
            project_id=project_id,
            details={
                "proposal_id": proposal.id,
                "rejection_reason": rejection_reason,
            },
        )
        return proposal
