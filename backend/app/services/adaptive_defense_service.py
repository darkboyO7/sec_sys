from typing import List, Dict, Any, Optional, Tuple
from sqlalchemy.orm import Session

from app.models.project import Project
from app.models.finding import VulnerabilityFinding, FindingLifecycleStatus
from app.models.assessment import FindingSeverity
from app.models.risk import RemediationRecommendation
from app.models.verification import RemediationVerification, VerificationOutcome
from app.models.regression import RegressionAlert, AlertStatus
from app.models.adaptive_defense import (
    AdaptiveMorphState,
    AdaptiveTransitionTrigger,
    MorphStatePosture,
    MorphStateHistory,
)
from app.models.user import User
from app.models.base import utc_now
from app.services.audit_service import AuditService


LEGAL_TRANSITIONS: Dict[AdaptiveMorphState, List[AdaptiveMorphState]] = {
    AdaptiveMorphState.NORMAL: [
        AdaptiveMorphState.ELEVATED_MONITORING,
        AdaptiveMorphState.INVESTIGATION_REQUIRED,
        AdaptiveMorphState.MANUAL_REVIEW_REQUIRED,
    ],
    AdaptiveMorphState.ELEVATED_MONITORING: [
        AdaptiveMorphState.NORMAL,
        AdaptiveMorphState.INVESTIGATION_REQUIRED,
        AdaptiveMorphState.CONTAINMENT_RECOMMENDED,
        AdaptiveMorphState.MANUAL_REVIEW_REQUIRED,
    ],
    AdaptiveMorphState.INVESTIGATION_REQUIRED: [
        AdaptiveMorphState.NORMAL,
        AdaptiveMorphState.CONTAINMENT_RECOMMENDED,
        AdaptiveMorphState.RECOVERY_IN_PROGRESS,
        AdaptiveMorphState.MANUAL_REVIEW_REQUIRED,
    ],
    AdaptiveMorphState.CONTAINMENT_RECOMMENDED: [
        AdaptiveMorphState.RECOVERY_IN_PROGRESS,
        AdaptiveMorphState.INVESTIGATION_REQUIRED,
        AdaptiveMorphState.MANUAL_REVIEW_REQUIRED,
    ],
    AdaptiveMorphState.RECOVERY_IN_PROGRESS: [
        AdaptiveMorphState.RECOVERY_VERIFICATION_REQUIRED,
        AdaptiveMorphState.INVESTIGATION_REQUIRED,
        AdaptiveMorphState.MANUAL_REVIEW_REQUIRED,
    ],
    AdaptiveMorphState.RECOVERY_VERIFICATION_REQUIRED: [
        AdaptiveMorphState.RECOVERY_COMPLETE,
        AdaptiveMorphState.INVESTIGATION_REQUIRED,
        AdaptiveMorphState.MANUAL_REVIEW_REQUIRED,
    ],
    AdaptiveMorphState.RECOVERY_COMPLETE: [
        AdaptiveMorphState.NORMAL,
        AdaptiveMorphState.MANUAL_REVIEW_REQUIRED,
    ],
    AdaptiveMorphState.MANUAL_REVIEW_REQUIRED: [
        AdaptiveMorphState.NORMAL,
        AdaptiveMorphState.ELEVATED_MONITORING,
        AdaptiveMorphState.INVESTIGATION_REQUIRED,
        AdaptiveMorphState.CONTAINMENT_RECOMMENDED,
        AdaptiveMorphState.RECOVERY_IN_PROGRESS,
        AdaptiveMorphState.RECOVERY_VERIFICATION_REQUIRED,
        AdaptiveMorphState.RECOVERY_COMPLETE,
    ],
}

STATE_CADENCE_MAP: Dict[AdaptiveMorphState, float] = {
    AdaptiveMorphState.NORMAL: 1.0,
    AdaptiveMorphState.ELEVATED_MONITORING: 2.0,
    AdaptiveMorphState.INVESTIGATION_REQUIRED: 3.0,
    AdaptiveMorphState.CONTAINMENT_RECOMMENDED: 4.0,
    AdaptiveMorphState.RECOVERY_IN_PROGRESS: 2.0,
    AdaptiveMorphState.RECOVERY_VERIFICATION_REQUIRED: 3.0,
    AdaptiveMorphState.RECOVERY_COMPLETE: 1.0,
    AdaptiveMorphState.MANUAL_REVIEW_REQUIRED: 0.5,
}


class AdaptiveDefenseService:
    """
    Morph-State Adaptive Defense and Recovery Controller (Phase 20).
    Governs finite state transitions based strictly on provenance-backed,
    empirical operational signals without autonomous live disruption.
    """

    @classmethod
    def get_or_create_project_posture(
        cls,
        project_id: str,
        db: Session,
    ) -> MorphStatePosture:
        """Retrieves or provisions the initial default NORMAL posture for a project."""
        posture = (
            db.query(MorphStatePosture)
            .filter(MorphStatePosture.project_id == project_id)
            .first()
        )
        if posture:
            return posture

        posture = MorphStatePosture(
            project_id=project_id,
            current_state=AdaptiveMorphState.NORMAL,
            previous_state=None,
            state_version=1,
            kill_switch_active=False,
            monitoring_cadence_multiplier=1.0,
            active_recommendations=[
                {"action": "STANDARD_MONITORING", "description": "Baseline passive scanning cadence active."}
            ],
            recovery_prerequisites=[],
            last_transition_at=utc_now(),
            last_evaluated_at=utc_now(),
        )
        db.add(posture)
        db.flush()

        history = MorphStateHistory(
            posture_id=posture.id,
            from_state=AdaptiveMorphState.NORMAL,
            to_state=AdaptiveMorphState.NORMAL,
            trigger=AdaptiveTransitionTrigger.INITIAL_PROVISIONING,
            evidence_rationale="Initial baseline posture established.",
        )
        db.add(history)
        db.commit()
        db.refresh(posture)
        return posture

    @classmethod
    def execute_transition(
        cls,
        posture: MorphStatePosture,
        target_state: AdaptiveMorphState,
        trigger: AdaptiveTransitionTrigger,
        rationale: str,
        db: Session,
        actor: Optional[User] = None,
        recommendations: Optional[List[Dict[str, Any]]] = None,
        recovery_prerequisites: Optional[List[Dict[str, Any]]] = None,
        client_ip: Optional[str] = None,
    ) -> MorphStatePosture:
        """Executes a governed state transition, recording immutable history and updating cadence."""
        if target_state != posture.current_state:
            # Validate legal transition unless triggered by Kill Switch
            if trigger != AdaptiveTransitionTrigger.KILL_SWITCH_ENGAGED:
                allowed = LEGAL_TRANSITIONS.get(posture.current_state, [])
                if target_state not in allowed:
                    raise ValueError(
                        f"Illegal posture transition from {posture.current_state.value} to {target_state.value}."
                    )

            posture.previous_state = posture.current_state
            posture.current_state = target_state
            posture.state_version += 1
            posture.last_transition_at = utc_now()

            # Record immutable audit history
            history = MorphStateHistory(
                posture_id=posture.id,
                from_state=posture.previous_state,
                to_state=target_state,
                trigger=trigger,
                evidence_rationale=rationale,
                triggered_by_id=actor.id if actor else None,
            )
            db.add(history)

        posture.monitoring_cadence_multiplier = STATE_CADENCE_MAP.get(target_state, 1.0)
        if recommendations is not None:
            posture.active_recommendations = recommendations
        if recovery_prerequisites is not None:
            posture.recovery_prerequisites = recovery_prerequisites
        posture.last_evaluated_at = utc_now()

        AuditService.log(
            db=db,
            action="ADAPTIVE_POSTURE_TRANSITION",
            actor_id=actor.id if actor else None,
            target_resource=f"posture:{posture.id}",
            project_id=posture.project_id,
            client_ip=client_ip,
            details={
                "current_state": posture.current_state.value,
                "previous_state": posture.previous_state.value if posture.previous_state else None,
                "trigger": trigger.value,
                "cadence_multiplier": posture.monitoring_cadence_multiplier,
            },
        )
        db.commit()
        db.refresh(posture)
        return posture

    @classmethod
    def evaluate_adaptive_posture(
        cls,
        project_id: str,
        db: Session,
        actor: Optional[User] = None,
        client_ip: Optional[str] = None,
    ) -> MorphStatePosture:
        """
        Empirically evaluates operational signals (findings, verifications, regression alerts)
        and deterministically drives the adaptive morph-state posture.
        """
        posture = cls.get_or_create_project_posture(project_id, db)

        # 1. Kill Switch override enforcement
        if posture.kill_switch_active:
            return posture

        # 2. Gather verified operational signals
        active_findings = (
            db.query(VulnerabilityFinding)
            .filter(
                VulnerabilityFinding.project_id == project_id,
                VulnerabilityFinding.status.in_([
                    FindingLifecycleStatus.CONFIRMED,
                    FindingLifecycleStatus.DETECTED,
                    FindingLifecycleStatus.REOPENED,
                ]),
            )
            .all()
        )
        critical_count = sum(
            1 for f in active_findings
            if (f.severity.value if hasattr(f.severity, "value") else str(f.severity)) == "CRITICAL"
        )
        high_count = sum(
            1 for f in active_findings
            if (f.severity.value if hasattr(f.severity, "value") else str(f.severity)) == "HIGH"
        )

        active_alerts = (
            db.query(RegressionAlert)
            .filter(
                RegressionAlert.project_id == project_id,
                RegressionAlert.status == AlertStatus.ACTIVE,
            )
            .all()
        )

        recent_verifications = (
            db.query(RemediationVerification)
            .filter(RemediationVerification.project_id == project_id)
            .order_by(RemediationVerification.verified_at.desc())
            .limit(5)
            .all()
        )
        failed_verification = any(v.outcome == VerificationOutcome.STILL_VULNERABLE for v in recent_verifications)

        # 3. Deterministic State Progression Logic
        recs = []
        prereqs = []

        if failed_verification:
            target_state = AdaptiveMorphState.INVESTIGATION_REQUIRED
            trigger = AdaptiveTransitionTrigger.VERIFICATION_FAILED
            rationale = "Recent remediation verification probe failed (STILL_VULNERABLE). Immediate triage required."
            recs = [{"action": "RETEST_FAILURE_ANALYSIS", "priority": "HIGH", "description": "Review failed verification probe telemetry."}]
            prereqs = [{"condition": "ROOT_CAUSE_REVISION", "status": "PENDING"}]

        elif critical_count >= 2:
            target_state = AdaptiveMorphState.CONTAINMENT_RECOMMENDED
            trigger = AdaptiveTransitionTrigger.CRITICAL_FINDING_DETECTED
            rationale = f"Detected {critical_count} active unmitigated CRITICAL vulnerabilities. Recommending perimeter containment."
            recs = [
                {"action": "NETWORK_ISOLATION_PROPOSAL", "priority": "CRITICAL", "description": "Review defensive containment plan for exposed targets."},
                {"action": "ELEVATE_LOGGING", "priority": "HIGH", "description": "Enable full request header audit logging on ingress gateways."},
            ]
            prereqs = [{"condition": "CONTAINMENT_PLAN_APPROVAL", "status": "PENDING"}]

        elif critical_count == 1 or len(active_alerts) > 0:
            target_state = AdaptiveMorphState.INVESTIGATION_REQUIRED
            trigger = (
                AdaptiveTransitionTrigger.REGRESSION_ALERT_RAISED
                if len(active_alerts) > 0
                else AdaptiveTransitionTrigger.CRITICAL_FINDING_DETECTED
            )
            rationale = f"Elevated exposure: {critical_count} critical findings and {len(active_alerts)} active regression alerts."
            recs = [{"action": "TRIAGE_REGRESSIONS", "priority": "HIGH", "description": "Acknowledge and assign regression alerts."}]

        elif high_count > 0:
            target_state = AdaptiveMorphState.ELEVATED_MONITORING
            trigger = AdaptiveTransitionTrigger.CRITICAL_FINDING_DETECTED
            rationale = f"Identified {high_count} HIGH severity findings. Elevating passive monitoring frequency."
            recs = [{"action": "INCREASE_PASSIVE_CADENCE", "multiplier": 2.0, "description": "Execute passive header checks twice daily."}]

        else:
            # Baseline normal
            target_state = AdaptiveMorphState.NORMAL
            trigger = AdaptiveTransitionTrigger.POSTURE_CLEARED
            rationale = "Zero unmitigated critical or high findings. Posture restored to baseline NORMAL."
            recs = [{"action": "STANDARD_CADENCE", "multiplier": 1.0, "description": "Standard monitoring cadence active."}]

        # Check if direct transition is allowed from current state
        allowed = LEGAL_TRANSITIONS.get(posture.current_state, [])
        if target_state != posture.current_state and target_state in allowed:
            return cls.execute_transition(
                posture=posture,
                target_state=target_state,
                trigger=trigger,
                rationale=rationale,
                db=db,
                actor=actor,
                recommendations=recs,
                recovery_prerequisites=prereqs,
                client_ip=client_ip,
            )

        # Update recommendations in place if state remains unchanged
        posture.active_recommendations = recs
        posture.recovery_prerequisites = prereqs
        posture.last_evaluated_at = utc_now()
        db.commit()
        db.refresh(posture)
        return posture

    @classmethod
    def engage_kill_switch(
        cls,
        project_id: str,
        reason: str,
        user: User,
        db: Session,
        client_ip: Optional[str] = None,
    ) -> MorphStatePosture:
        """
        Emergency Kill Switch.
        Immediately locks the project into MANUAL_REVIEW_REQUIRED and halts
        all automated escalation and cadence multipliers.
        """
        posture = cls.get_or_create_project_posture(project_id, db)
        clean_reason = (reason or "").strip()
        if len(clean_reason) < 3:
            raise ValueError("Kill switch reason is required (minimum 3 characters).")

        posture.kill_switch_active = True
        posture.kill_switch_engaged_at = utc_now()
        posture.kill_switch_engaged_by_id = user.id
        posture.kill_switch_reason = clean_reason

        posture = cls.execute_transition(
            posture=posture,
            target_state=AdaptiveMorphState.MANUAL_REVIEW_REQUIRED,
            trigger=AdaptiveTransitionTrigger.KILL_SWITCH_ENGAGED,
            rationale=f"EMERGENCY KILL SWITCH ENGAGED by {user.email}: {clean_reason}",
            db=db,
            actor=user,
            recommendations=[{"action": "HALT_AUTOMATION", "status": "ALL_ESCALATIONS_PAUSED"}],
            client_ip=client_ip,
        )
        return posture

    @classmethod
    def disengage_kill_switch(
        cls,
        project_id: str,
        justification: str,
        user: User,
        db: Session,
        client_ip: Optional[str] = None,
    ) -> MorphStatePosture:
        """
        Disengages Emergency Kill Switch and restores operational baseline.
        Requires Lead or Admin role.
        """
        posture = cls.get_or_create_project_posture(project_id, db)
        if not posture.kill_switch_active:
            raise ValueError("Kill switch is not currently active for this project.")

        clean_just = (justification or "").strip()
        if len(clean_just) < 3:
            raise ValueError("Disengagement justification is required (minimum 3 characters).")

        posture.kill_switch_active = False
        posture.kill_switch_reason = None

        posture = cls.execute_transition(
            posture=posture,
            target_state=AdaptiveMorphState.NORMAL,
            trigger=AdaptiveTransitionTrigger.KILL_SWITCH_DISENGAGED,
            rationale=f"KILL SWITCH DISENGAGED by {user.email}: {clean_just}",
            db=db,
            actor=user,
            client_ip=client_ip,
        )
        return posture

    @classmethod
    def transition_manually(
        cls,
        project_id: str,
        target_state: AdaptiveMorphState,
        justification: str,
        user: User,
        db: Session,
        client_ip: Optional[str] = None,
    ) -> MorphStatePosture:
        """Enforces governed manual transition by an authorized Lead or Admin."""
        posture = cls.get_or_create_project_posture(project_id, db)
        clean_just = (justification or "").strip()
        if len(clean_just) < 3:
            raise ValueError("Manual transition justification is required (minimum 3 characters).")

        return cls.execute_transition(
            posture=posture,
            target_state=target_state,
            trigger=AdaptiveTransitionTrigger.MANUAL_OVERRIDE,
            rationale=f"Manual transition by {user.email}: {clean_just}",
            db=db,
            actor=user,
            client_ip=client_ip,
        )
