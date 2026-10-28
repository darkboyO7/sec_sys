from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session

from app.models.decision import (
    AutonomousPolicyRecord,
    AutonomyIntensity,
    DecisionLedgerType,
    SecurityDecisionLedgerRecord,
)
from app.models.scope import ScopeTarget, AuthorizationStatus
from app.models.user import User
from app.models.base import utc_now
from app.services.scope_engine import ScopeEngine


class PolicyEngineService:
    """
    Policy-Based Autonomy Engine (Prompt 11 / Section 2).
    Enforces project policies governing:
    - Permitted assessment adapters and scopes
    - Scan intensity, concurrency, rate limits, and time windows
    - Daily execution budgets and failure thresholds
    - Emergency kill-switch suspension and resumption
    - Remediation approval requirements
    """

    DEFAULT_PERMITTED_ADAPTERS = [
        "live_network_auditor_adapter",
        "web_adapter",
    ]

    DEFAULT_PERMITTED_REMEDIATIONS = [
        "APPLY_SAFE_HEADER_CONFIG",
        "DISABLE_INSECURE_CIPHERS",
        "UPDATE_CONTAINER_IMAGE_TAG",
    ]

    @classmethod
    def get_or_create_policy(
        cls,
        db: Session,
        project_id: str,
        creator: Optional[User] = None,
    ) -> AutonomousPolicyRecord:
        """
        Fetches the active policy for a project or initializes secure-by-default policy.
        """
        policy = (
            db.query(AutonomousPolicyRecord)
            .filter(AutonomousPolicyRecord.project_id == project_id)
            .first()
        )
        if not policy:
            now = utc_now()
            policy = AutonomousPolicyRecord(
                project_id=project_id,
                policy_version="v1.0.0",
                is_active=True,
                is_suspended=False,
                permitted_assessment_types=cls.DEFAULT_PERMITTED_ADAPTERS,
                intensity=AutonomyIntensity.NORMAL,
                max_concurrency=2,
                rate_limit_rps=10.0,
                permitted_time_windows=[],  # Empty means all hours permitted
                max_daily_budget=20,
                daily_budget_spent=0,
                last_budget_reset_at=now,
                permitted_remediation_actions=cls.DEFAULT_PERMITTED_REMEDIATIONS,
                require_approval_for_disruptive=True,
                require_approval_for_remediation=True,
                max_retries=2,
                failure_threshold=3,
                consecutive_failures=0,
                created_by_id=creator.id if creator else None,
            )
            db.add(policy)
            db.commit()
            db.refresh(policy)
        else:
            cls._check_and_reset_daily_budget(db=db, policy=policy)

        return policy

    @classmethod
    def update_policy(
        cls,
        db: Session,
        project_id: str,
        update_data: Dict[str, Any],
        actor: Optional[User] = None,
    ) -> AutonomousPolicyRecord:
        """
        Updates policy parameters with version increment and audit ledger record.
        """
        policy = cls.get_or_create_policy(db=db, project_id=project_id, creator=actor)
        now = utc_now()

        # Version bump e.g. v1.0.0 -> v1.0.1
        try:
            parts = policy.policy_version.replace("v", "").split(".")
            minor = int(parts[-1]) + 1
            new_version = f"v{parts[0]}.{parts[1]}.{minor}"
        except Exception:
            new_version = "v1.1.0"

        for k, v in update_data.items():
            if hasattr(policy, k) and k not in ("id", "project_id", "created_at"):
                setattr(policy, k, v)

        policy.policy_version = new_version
        policy.updated_at = now

        # Record policy update in decision ledger
        cls._record_ledger_entry(
            db=db,
            project_id=project_id,
            decision_type=DecisionLedgerType.POLICY_EVALUATION,
            decision_outcome="POLICY_UPDATED",
            initiating_event="OPERATOR_CONFIGURATION",
            target_type="POLICY",
            target_id=policy.id,
            target_resource=f"policy:{project_id}",
            policy_version=new_version,
            reason=f"Policy updated to {new_version} by {actor.email if actor else 'SYSTEM'}.",
            details={"updated_fields": list(update_data.keys())},
            actor_id=actor.id if actor else None,
        )

        db.commit()
        db.refresh(policy)
        return policy

    @classmethod
    def emergency_suspend(
        cls,
        db: Session,
        project_id: str,
        reason: str,
        actor: Optional[User] = None,
    ) -> AutonomousPolicyRecord:
        """
        Emergency kill switch: immediately suspends all autonomous execution.
        """
        policy = cls.get_or_create_policy(db=db, project_id=project_id, creator=actor)
        now = utc_now()

        policy.is_suspended = True
        policy.suspension_reason = reason
        policy.suspended_at = now
        policy.suspended_by_id = actor.id if actor else None
        policy.updated_at = now

        cls._record_ledger_entry(
            db=db,
            project_id=project_id,
            decision_type=DecisionLedgerType.AUTONOMY_SUSPENDED,
            decision_outcome="SUSPENDED",
            initiating_event="EMERGENCY_KILL_SWITCH",
            target_type="POLICY",
            target_id=policy.id,
            target_resource=f"project:{project_id}",
            policy_version=policy.policy_version,
            reason=f"Autonomous operations suspended: {reason}",
            details={"suspended_by": actor.email if actor else "SYSTEM", "timestamp": now.isoformat()},
            actor_id=actor.id if actor else None,
        )

        db.commit()
        db.refresh(policy)
        return policy

    @classmethod
    def resume_autonomy(
        cls,
        db: Session,
        project_id: str,
        actor: Optional[User] = None,
    ) -> AutonomousPolicyRecord:
        """
        Resumes autonomous execution following emergency suspension.
        """
        policy = cls.get_or_create_policy(db=db, project_id=project_id, creator=actor)
        now = utc_now()

        policy.is_suspended = False
        policy.suspension_reason = None
        policy.suspended_at = None
        policy.suspended_by_id = None
        policy.consecutive_failures = 0
        policy.updated_at = now

        cls._record_ledger_entry(
            db=db,
            project_id=project_id,
            decision_type=DecisionLedgerType.AUTONOMY_RESUMED,
            decision_outcome="RESUMED",
            initiating_event="OPERATOR_RESUME",
            target_type="POLICY",
            target_id=policy.id,
            target_resource=f"project:{project_id}",
            policy_version=policy.policy_version,
            reason=f"Autonomous operations resumed by {actor.email if actor else 'SYSTEM'}.",
            details={"resumed_by": actor.email if actor else "SYSTEM", "timestamp": now.isoformat()},
            actor_id=actor.id if actor else None,
        )

        db.commit()
        db.refresh(policy)
        return policy

    @classmethod
    def evaluate_action_permission(
        cls,
        db: Session,
        project_id: str,
        action_type: str,
        target_resource: str,
        adapter_name: Optional[str] = None,
        is_remediation: bool = False,
        remediation_action: Optional[str] = None,
        is_disruptive: bool = False,
        now: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        """
        Preflight policy evaluation:
        Determines whether a security operation may proceed autonomously, requires approval, or is denied.
        """
        if now is None:
            now = utc_now()

        policy = cls.get_or_create_policy(db=db, project_id=project_id)

        # 1. Emergency Suspension Check
        if policy.is_suspended:
            reason = f"Autonomous operations currently suspended for project: {policy.suspension_reason or 'No reason provided'}."
            return {
                "allowed": False,
                "requires_approval": False,
                "denial_category": "SUSPENDED",
                "policy_version": policy.policy_version,
                "reason": reason,
            }

        # 2. Scope & Target Authorization Check (Fail-closed)
        scope_eval = ScopeEngine.validate_target_in_scope(
            db=db,
            project_id=project_id,
            target=target_resource,
            now=now,
        )
        if not scope_eval.get("is_authorized"):
            reason = f"Target '{target_resource}' is outside authorized scope: {scope_eval.get('reason')}."
            return {
                "allowed": False,
                "requires_approval": False,
                "denial_category": "OUT_OF_SCOPE",
                "policy_version": policy.policy_version,
                "reason": reason,
            }

        # 3. Permitted Assessment Types Check
        if adapter_name and adapter_name not in policy.permitted_assessment_types:
            reason = f"Adapter '{adapter_name}' is not in policy permitted adapters: {policy.permitted_assessment_types}."
            return {
                "allowed": False,
                "requires_approval": False,
                "denial_category": "ADAPTER_DISALLOWED",
                "policy_version": policy.policy_version,
                "reason": reason,
            }

        # 4. Daily Budget Check
        cls._check_and_reset_daily_budget(db=db, policy=policy, now=now)
        if policy.daily_budget_spent >= policy.max_daily_budget:
            reason = f"Daily execution budget exhausted ({policy.daily_budget_spent}/{policy.max_daily_budget} actions spent today)."
            return {
                "allowed": False,
                "requires_approval": False,
                "denial_category": "BUDGET_EXCEEDED",
                "policy_version": policy.policy_version,
                "reason": reason,
            }

        # 5. Time Window Restriction Check
        if policy.permitted_time_windows:
            current_hour = now.hour
            in_window = any(
                w.get("start_hour", 0) <= current_hour < w.get("end_hour", 24)
                for w in policy.permitted_time_windows
            )
            if not in_window:
                reason = f"Current UTC hour {current_hour} is outside permitted time windows: {policy.permitted_time_windows}."
                return {
                    "allowed": False,
                    "requires_approval": False,
                    "denial_category": "TIME_WINDOW_RESTRICTION",
                    "policy_version": policy.policy_version,
                    "reason": reason,
                }

        # 6. Failure Threshold Check
        if policy.consecutive_failures >= policy.failure_threshold:
            # Auto-suspend
            cls.emergency_suspend(
                db=db,
                project_id=project_id,
                reason=f"Consecutive failure threshold ({policy.failure_threshold}) exceeded.",
            )
            return {
                "allowed": False,
                "requires_approval": False,
                "denial_category": "FAILURE_THRESHOLD_EXCEEDED",
                "policy_version": policy.policy_version,
                "reason": f"Automatic suspension: {policy.consecutive_failures} consecutive execution failures observed.",
            }

        # 7. Remediation & Disruptive Action Gate
        if is_remediation:
            if remediation_action and remediation_action not in policy.permitted_remediation_actions:
                return {
                    "allowed": True,
                    "requires_approval": True,
                    "approval_reason": f"Remediation action '{remediation_action}' is not on the automated permit list.",
                    "policy_version": policy.policy_version,
                    "reason": "Approval required: remediation action requires operator authorization.",
                }
            if policy.require_approval_for_remediation:
                return {
                    "allowed": True,
                    "requires_approval": True,
                    "approval_reason": "Policy enforces operator approval for all remediation actions.",
                    "policy_version": policy.policy_version,
                    "reason": "Approval required: remediation approval policy active.",
                }

        if is_disruptive and policy.require_approval_for_disruptive:
            return {
                "allowed": True,
                "requires_approval": True,
                "approval_reason": "Action classified as disruptive/destructive; policy requires explicit approval.",
                "policy_version": policy.policy_version,
                "reason": "Approval required: disruptive action policy active.",
            }

        # Permitted to proceed autonomously
        return {
            "allowed": True,
            "requires_approval": False,
            "policy_version": policy.policy_version,
            "reason": "Action fully authorized under active autonomous security policy.",
        }

    @classmethod
    def record_execution_outcome(
        cls,
        db: Session,
        project_id: str,
        success: bool,
        budget_cost: int = 1,
    ) -> None:
        """
        Updates budget spend and consecutive failure tracking following execution.
        """
        policy = cls.get_or_create_policy(db=db, project_id=project_id)
        if success:
            policy.consecutive_failures = 0
        else:
            policy.consecutive_failures += 1

        policy.daily_budget_spent += budget_cost
        policy.updated_at = utc_now()
        db.commit()

    @classmethod
    def _check_and_reset_daily_budget(
        cls,
        db: Session,
        policy: AutonomousPolicyRecord,
        now: Optional[datetime] = None,
    ) -> None:
        """
        Resets daily budget spent if 24 hours have elapsed since last reset.
        """
        if now is None:
            now = utc_now()

        last_reset = policy.last_budget_reset_at
        if last_reset.tzinfo is None:
            last_reset = last_reset.replace(tzinfo=timezone.utc)

        if (now - last_reset) >= timedelta(days=1):
            policy.daily_budget_spent = 0
            policy.last_budget_reset_at = now
            db.commit()

    @classmethod
    def _record_ledger_entry(
        cls,
        db: Session,
        project_id: str,
        decision_type: DecisionLedgerType,
        decision_outcome: str,
        initiating_event: str,
        target_type: str,
        target_id: Optional[str],
        target_resource: Optional[str],
        policy_version: str,
        reason: str,
        evidence_references: Optional[List[Dict[str, Any]]] = None,
        details: Optional[Dict[str, Any]] = None,
        actor_id: Optional[str] = None,
    ) -> SecurityDecisionLedgerRecord:
        """
        Internal helper to record immutable ledger entries.
        """
        entry = SecurityDecisionLedgerRecord(
            project_id=project_id,
            decision_type=decision_type,
            decision_outcome=decision_outcome,
            initiating_event=initiating_event,
            target_type=target_type,
            target_id=target_id,
            target_resource=target_resource,
            policy_version=policy_version,
            reason=reason,
            evidence_references=evidence_references or [],
            details=details or {},
            actor_id=actor_id,
        )
        db.add(entry)
        return entry
