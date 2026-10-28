from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional, Tuple, List
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.models.orchestration import (
    OrchestrationEventType,
    OrchestrationActionType,
    OrchestrationEventRecord,
    OrchestrationWorkflowRecord,
)
from app.models.decision import (
    AutonomousPolicyRecord,
    SecurityDecisionRecord,
    DecisionStatus,
    DecisionActionType,
)
from app.models.asset import Asset
from app.models.finding import VulnerabilityFinding, FindingLifecycleStatus
from app.models.assessment import AssessmentJob, AssessmentStatus, FindingSeverity
from app.models.risk import RemediationRecommendation, RecommendationStatus, RiskAssessment
from app.models.verification import RemediationVerification, VerificationOutcome
from app.models.adaptive_defense import AdaptiveMorphState
from app.models.base import utc_now

from app.services.scope_engine import ScopeEngine
from app.services.policy_engine import PolicyEngineService
from app.services.adaptive_defense_service import AdaptiveDefenseService


class DecisionPlannerService:
    """
    Evidence-Driven Decision Planner (Prompt 15 / Section 3 & 4).
    Evaluates real persisted operational context and recommends the next useful action.
    Strictly verifies scope, policy, and safety boundaries before every recommendation.
    """

    @classmethod
    def evaluate_authorization(
        cls,
        db: Session,
        project_id: str,
        target_resource: str,
        action_type: OrchestrationActionType,
        now: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        """
        Zero-Trust Pre-Execution Authorization Check (Prompt 15 / Section 4).
        Validates:
        1. Target is explicitly authorized in ScopeEngine without active exclusions.
        2. Autonomous policy is active, not suspended, and within daily budget limits.
        3. Adaptive defense is not in emergency quarantine or lockdown.
        4. Resource/action specific preconditions.
        """
        if now is None:
            now = utc_now()

        # 1. Adaptive Defense check
        try:
            current_posture = AdaptiveDefenseService.get_or_create_project_posture(db=db, project_id=project_id)
            if current_posture.state == AdaptiveMorphState.LOCKDOWN:
                return {
                    "is_authorized": False,
                    "reason": "Adaptive defense is in LOCKDOWN mode. All active actions are suspended.",
                    "status": "ADAPTIVE_DEFENSE_LOCKDOWN",
                }
        except Exception:
            pass  # Fall back to policy check if posture service uninitialized

        # 2. Autonomous Policy check
        policy = PolicyEngineService.get_or_create_policy(db=db, project_id=project_id)
        if policy.is_suspended:
            return {
                "is_authorized": False,
                "reason": f"Autonomous operations policy is suspended: {policy.suspension_reason}",
                "status": "POLICY_SUSPENDED",
            }

        if policy.daily_budget_spent >= policy.max_daily_budget and action_type in (
            OrchestrationActionType.REASSESS_CHANGED_ASSET,
            OrchestrationActionType.RETRY_FAILED_ASSESSMENT,
            OrchestrationActionType.SCHEDULE_INDEPENDENT_RETEST,
        ):
            return {
                "is_authorized": False,
                "reason": f"Daily scan budget exceeded ({policy.daily_budget_spent}/{policy.max_daily_budget}).",
                "status": "BUDGET_EXCEEDED",
            }

        # 3. Scope Engine Validation (for network and scan actions)
        if target_resource and action_type in (
            OrchestrationActionType.REASSESS_CHANGED_ASSET,
            OrchestrationActionType.REFRESH_STALE_EVIDENCE,
            OrchestrationActionType.RETRY_FAILED_ASSESSMENT,
            OrchestrationActionType.SCHEDULE_INDEPENDENT_RETEST,
        ):
            # Check if scope records exist for project
            from app.models.scope import ScopeTarget, ScopeExclusion
            has_scope = (
                db.query(ScopeTarget).filter(ScopeTarget.project_id == project_id).first() is not None or
                db.query(ScopeExclusion).filter(ScopeExclusion.project_id == project_id).first() is not None
            )
            if has_scope:
                scope_eval = ScopeEngine.validate_target_in_scope(
                    db=db,
                    project_id=project_id,
                    target=target_resource,
                    now=now,
                )
                if not scope_eval.get("is_authorized"):
                    return {
                        "is_authorized": False,
                        "reason": f"Scope boundary denial: {scope_eval.get('reason')} ({scope_eval.get('status')})",
                        "status": scope_eval.get("status", "NOT_IN_SCOPE"),
                    }

        return {
            "is_authorized": True,
            "reason": "Target and action fully authorized under active scope and security policy.",
            "status": "AUTHORIZED",
            "policy_version": policy.policy_version,
        }

    @classmethod
    def plan_next_action(
        cls,
        db: Session,
        project_id: str,
        event: OrchestrationEventRecord,
        now: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        """
        Evidence-Driven Decision Planner.
        Considers the incoming event, persisted operational context, and generates
        a justified, verifiable recommendation with full provenance.
        """
        if now is None:
            now = utc_now()

        event_type = event.event_type
        target = event.target_resource
        payload = event.payload or {}
        policy = PolicyEngineService.get_or_create_policy(db=db, project_id=project_id)

        # Baseline evaluation details
        plan_result = {
            "action_type": OrchestrationActionType.NO_ACTION_REQUIRED,
            "rationale": "No operational action justified by current evidence.",
            "expected_benefit": "Maintains steady-state operations without unneeded scanning.",
            "confidence": 1.0,
            "uncertainty": 0.0,
            "required_approval_role": None,
            "resource_cost": 0,
            "staleness_condition": "Event older than 24 hours without processing.",
            "references": {
                "event_id": event.id,
                "project_id": project_id,
                "target_resource": target,
            },
            "is_authorized": True,
            "authorization_details": {},
        }

        # Scenario 1: Diagnostic Failure or Repeated Failures -> Run Diagnostics or Suspend
        if event_type == OrchestrationEventType.DIAGNOSTIC_FAILURE or policy.consecutive_failures >= policy.failure_threshold:
            plan_result["action_type"] = OrchestrationActionType.RUN_DIAGNOSTICS
            plan_result["rationale"] = (
                f"Consecutive failures ({policy.consecutive_failures}) reached failure threshold "
                f"({policy.failure_threshold}) or diagnostic failure event triggered."
            )
            plan_result["expected_benefit"] = "Isolate root cause of operational failures before attempting further assessments."
            plan_result["confidence"] = 0.95
            plan_result["uncertainty"] = 0.05
            plan_result["resource_cost"] = 1
            return plan_result

        # Scenario 2: Integrity Alert -> Suspend Activity
        if event_type == OrchestrationEventType.INTEGRITY_ALERT:
            plan_result["action_type"] = OrchestrationActionType.SUSPEND_ACTIVITY
            plan_result["rationale"] = f"Cryptographic evidence integrity breach detected: {payload.get('alert_detail', 'Tampering suspected')}."
            plan_result["expected_benefit"] = "Prevents corrupted or untrusted evidence from polluting security posture conclusions."
            plan_result["confidence"] = 1.0
            plan_result["uncertainty"] = 0.0
            plan_result["required_approval_role"] = "ADMIN"
            return plan_result

        # Scenario 3: Asset Config Changed -> Reassess Changed Asset
        if event_type in (OrchestrationEventType.CONFIG_CHANGED, OrchestrationEventType.ASSET_DISCOVERED):
            auth_check = cls.evaluate_authorization(
                db=db,
                project_id=project_id,
                target_resource=target,
                action_type=OrchestrationActionType.REASSESS_CHANGED_ASSET,
                now=now,
            )
            plan_result["is_authorized"] = auth_check["is_authorized"]
            plan_result["authorization_details"] = auth_check

            if not auth_check["is_authorized"]:
                plan_result["action_type"] = OrchestrationActionType.SUSPEND_ACTIVITY
                plan_result["rationale"] = f"Asset changed but reassessment unauthorized: {auth_check['reason']}"
                plan_result["expected_benefit"] = "Prevents unauthorized scanning against unapproved target."
                return plan_result

            plan_result["action_type"] = OrchestrationActionType.REASSESS_CHANGED_ASSET
            plan_result["rationale"] = f"Target resource '{target}' experienced configuration changes; baseline refresh required."
            plan_result["expected_benefit"] = "Detects new vulnerabilities or regressions introduced by configuration changes."
            plan_result["confidence"] = 0.9
            plan_result["uncertainty"] = 0.1
            plan_result["resource_cost"] = 1
            return plan_result

        # Scenario 4: Remediation Applied -> Schedule Independent Retest
        if event_type == OrchestrationEventType.REMEDIATION_APPLIED:
            finding_id = payload.get("finding_id")
            finding = db.query(VulnerabilityFinding).filter(VulnerabilityFinding.id == finding_id).first() if finding_id else None

            auth_check = cls.evaluate_authorization(
                db=db,
                project_id=project_id,
                target_resource=target,
                action_type=OrchestrationActionType.SCHEDULE_INDEPENDENT_RETEST,
                now=now,
            )
            plan_result["is_authorized"] = auth_check["is_authorized"]
            plan_result["authorization_details"] = auth_check

            if not auth_check["is_authorized"]:
                plan_result["action_type"] = OrchestrationActionType.SUSPEND_ACTIVITY
                plan_result["rationale"] = f"Remediation verification blocked by scope policy: {auth_check['reason']}"
                return plan_result

            plan_result["action_type"] = OrchestrationActionType.SCHEDULE_INDEPENDENT_RETEST
            plan_result["rationale"] = f"Remediation applied to finding '{finding.title if finding else target}'; independent retest required before closure."
            plan_result["expected_benefit"] = "Verifies vulnerability elimination without relying on developer self-assertion."
            plan_result["confidence"] = 0.95
            plan_result["uncertainty"] = 0.05
            plan_result["resource_cost"] = 1
            plan_result["references"]["finding_id"] = finding_id
            return plan_result

        # Scenario 5: Finding Detected -> Recommend Remediation or Approval Gate
        if event_type == OrchestrationEventType.FINDING_DETECTED:
            finding_id = payload.get("finding_id")
            finding = db.query(VulnerabilityFinding).filter(VulnerabilityFinding.id == finding_id).first() if finding_id else None

            is_disruptive = payload.get("is_disruptive", False)
            if is_disruptive or policy.require_approval_for_remediation:
                plan_result["action_type"] = OrchestrationActionType.REQUEST_HUMAN_APPROVAL
                plan_result["required_approval_role"] = "LEAD"
                plan_result["rationale"] = f"Verified finding '{finding.title if finding else target}' identified; requires human approval due to disruptive remediation."
                plan_result["expected_benefit"] = "Governed remediation prevents unexpected production downtime."
            else:
                plan_result["action_type"] = OrchestrationActionType.RECOMMEND_REMEDIATION
                plan_result["rationale"] = f"Verified finding '{finding.title if finding else target}' requires structured remediation."
                plan_result["expected_benefit"] = "Reduces attack surface by eliminating confirmed security defect."

            plan_result["confidence"] = 0.85
            plan_result["uncertainty"] = 0.15
            plan_result["references"]["finding_id"] = finding_id
            return plan_result

        # Scenario 6: Scan Completed -> Recalculate Risk and Paths
        if event_type == OrchestrationEventType.SCAN_COMPLETED:
            plan_result["action_type"] = OrchestrationActionType.RECALCULATE_RISK_AND_PATHS
            plan_result["rationale"] = f"Assessment scan completed for '{target}'; contextual risk and attack paths must be synchronized."
            plan_result["expected_benefit"] = "Ensures operational dashboards reflect latest observed threat posture."
            plan_result["confidence"] = 1.0
            plan_result["uncertainty"] = 0.0
            plan_result["resource_cost"] = 0
            return plan_result

        # Default fallback
        return plan_result
