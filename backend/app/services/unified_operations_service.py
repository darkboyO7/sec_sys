from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.models.decision import (
    AutonomousPolicyRecord,
    SecurityDecisionLedgerRecord,
    DecisionLedgerType,
    PlanStatus,
    AdaptiveAssessmentPlanRecord,
)
from app.models.assessment import (
    AssessmentJob,
    AssessmentStatus,
    FindingSeverity,
)
from app.models.finding import (
    VulnerabilityFinding,
    FindingLifecycleStatus,
)
from app.models.asset import Asset
from app.models.risk import RemediationRecommendation, RecommendationStatus
from app.models.verification import RemediationVerification, VerificationOutcome
from app.models.notification import NotificationRecord, NotificationStatus
from app.models.user import User
from app.models.base import utc_now

from app.services.policy_engine import PolicyEngineService
from app.services.decision_ledger_service import DecisionLedgerService
from app.services.notification_service import NotificationService
from app.services.operational_metrics_service import OperationalMetricsService
from app.services.security_intelligence_service import SecurityIntelligenceService


class UnifiedOperationsService:
    """
    Unified Autonomous Security Operations Lifecycle Coordinator (Prompt 11 / Section 1).
    Orchestrates and integrates:
    - Discovery -> Assessment -> Evidence -> Prioritization -> Remediation -> Retesting -> Closure.
    - Policy evaluation at every decision boundary.
    - Auditable security decision ledger persistence.
    - Honest operational SLO reporting and notifications.
    """

    @classmethod
    def get_operations_dashboard(
        cls,
        db: Session,
        project_id: str,
    ) -> Dict[str, Any]:
        """
        Synthesizes the complete operational dashboard for operators.
        """
        now = utc_now()
        policy = PolicyEngineService.get_or_create_policy(db=db, project_id=project_id)
        slos = OperationalMetricsService.calculate_operational_slos(db=db, project_id=project_id, now=now)

        # Active jobs
        jobs = (
            db.query(AssessmentJob)
            .filter(AssessmentJob.project_id == project_id)
            .order_by(desc(AssessmentJob.created_at))
            .limit(10)
            .all()
        )
        running_jobs = len([j for j in jobs if j.status in (AssessmentStatus.RUNNING, AssessmentStatus.PREFLIGHT)])
        queued_jobs = len([j for j in jobs if j.status == AssessmentStatus.QUEUED])
        failed_jobs = len([j for j in jobs if j.status in (AssessmentStatus.FAILED, AssessmentStatus.CANCELLED)])

        # Findings
        findings = db.query(VulnerabilityFinding).filter(VulnerabilityFinding.project_id == project_id).all()
        critical_count = len([f for f in findings if f.severity == FindingSeverity.CRITICAL and f.status != FindingLifecycleStatus.VERIFIED_CLOSED])
        high_count = len([f for f in findings if f.severity == FindingSeverity.HIGH and f.status != FindingLifecycleStatus.VERIFIED_CLOSED])

        # Pending approvals
        pending_recs = (
            db.query(RemediationRecommendation)
            .filter(
                RemediationRecommendation.project_id == project_id,
                RemediationRecommendation.status == RecommendationStatus.PENDING_REVIEW,
            )
            .count()
        )

        # Recent decision ledger records
        ledger = DecisionLedgerService.query_ledger(db=db, project_id=project_id, limit=5)

        # Recent notifications
        notifications = NotificationService.get_notifications(db=db, project_id=project_id, limit=5)
        provider_status = NotificationService.get_notification_provider_status(db=db, project_id=project_id)

        return {
            "project_id": project_id,
            "timestamp": now.isoformat(),
            "policy": {
                "version": policy.policy_version,
                "is_active": policy.is_active,
                "is_suspended": policy.is_suspended,
                "suspension_reason": policy.suspension_reason,
                "intensity": policy.intensity.value,
                "daily_budget": {
                    "max": policy.max_daily_budget,
                    "spent": policy.daily_budget_spent,
                    "remaining": max(0, policy.max_daily_budget - policy.daily_budget_spent),
                },
                "max_concurrency": policy.max_concurrency,
                "consecutive_failures": policy.consecutive_failures,
            },
            "operations_summary": {
                "active_jobs": running_jobs,
                "queued_jobs": queued_jobs,
                "failed_recent_jobs": failed_jobs,
                "critical_findings": critical_count,
                "high_findings": high_count,
                "pending_remediation_approvals": pending_recs,
            },
            "slo_health": {
                "overall_health_pct": slos.get("overall_health_pct"),
                "slos": slos.get("slos", {}),
            },
            "recent_decisions": ledger.get("records", []),
            "recent_notifications": notifications.get("records", []),
            "notification_provider": provider_status,
        }

    @classmethod
    def execute_lifecycle_transition(
        cls,
        db: Session,
        project_id: str,
        finding_id: str,
        action: str,  # "AUTHORIZE_RETEST", "CLOSE_FINDING", "REOPEN_FINDING"
        actor: Optional[User] = None,
        notes: str = "",
    ) -> Dict[str, Any]:
        """
        Executes a controlled lifecycle state transition with policy validation and ledger logging.
        """
        finding = (
            db.query(VulnerabilityFinding)
            .filter(
                VulnerabilityFinding.id == finding_id,
                VulnerabilityFinding.project_id == project_id,
            )
            .first()
        )
        if not finding:
            raise ValueError(f"Finding '{finding_id}' not found in project '{project_id}'.")

        policy_eval = PolicyEngineService.evaluate_action_permission(
            db=db,
            project_id=project_id,
            action_type=action,
            target_resource=finding.target_value,
        )

        if not policy_eval.get("allowed"):
            DecisionLedgerService.record_decision(
                db=db,
                project_id=project_id,
                decision_type=DecisionLedgerType.POLICY_EVALUATION,
                decision_outcome="DENIED",
                initiating_event=f"LIFECYCLE_ACTION:{action}",
                target_type="FINDING",
                target_id=finding.id,
                target_resource=finding.target_value,
                policy_version=policy_eval.get("policy_version", "v1.0.0"),
                reason=policy_eval.get("reason", "Action denied by policy."),
                actor_id=actor.id if actor else None,
            )
            return {
                "success": False,
                "finding_id": finding.id,
                "error": policy_eval.get("reason"),
            }

        prev_status = finding.status.value

        if action == "CLOSE_FINDING":
            finding.status = FindingLifecycleStatus.VERIFIED_CLOSED
            decision_type = DecisionLedgerType.FINDING_RESOLVED
            reason = f"Finding marked closed by {actor.email if actor else 'SYSTEM'}. Notes: {notes}"
        elif action == "REOPEN_FINDING":
            finding.status = FindingLifecycleStatus.REOPENED
            finding.recurrence_count += 1
            decision_type = DecisionLedgerType.FINDING_REOPENED
            reason = f"Finding reopened by {actor.email if actor else 'SYSTEM'}. Notes: {notes}"
        else:
            decision_type = DecisionLedgerType.FINDING_PRIORITIZED
            reason = f"Finding lifecycle updated. Action: {action}. Notes: {notes}"

        finding.updated_at = utc_now()
        db.commit()

        # Record ledger entry
        DecisionLedgerService.record_decision(
            db=db,
            project_id=project_id,
            decision_type=decision_type,
            decision_outcome="SUCCESS",
            initiating_event=f"LIFECYCLE_ACTION:{action}",
            target_type="FINDING",
            target_id=finding.id,
            target_resource=finding.target_value,
            policy_version=policy_eval.get("policy_version", "v1.0.0"),
            reason=reason,
            details={"previous_status": prev_status, "new_status": finding.status.value, "notes": notes},
            actor_id=actor.id if actor else None,
        )

        return {
            "success": True,
            "finding_id": finding.id,
            "previous_status": prev_status,
            "current_status": finding.status.value,
        }
