from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session

from app.models.decision import (
    SecurityDecisionRecord,
    PostureChangeRecord,
    DecisionActionType,
    DecisionStatus,
    ChangeType,
)
from app.models.finding import VulnerabilityFinding, FindingLifecycleStatus
from app.models.risk import RemediationRecommendation, RecommendationStatus
from app.models.scope import ScopeTarget, AuthorizationStatus
from app.models.user import User
from app.models.project import ProjectRole
from app.models.assessment import AssessmentJob, AssessmentStatus, FindingSeverity, FindingConfidence
from app.services.scope_engine import ScopeEngine
from app.services.assessment_engine import AssessmentExecutionEngine
from app.services.remediation_service import RemediationPrioritizationService
from app.services.remediation_verification_service import RemediationVerificationService, VerificationOutcome
from app.services.contextual_risk_service import ContextualRiskService
from app.services.attack_path_service import AttackPathService
from app.services.learning_service import PredictionLedgerService
from app.services.audit_service import AuditService


class SecurityDecisionService:
    """
    Autonomous Security Decision and Closed-Loop Orchestration Engine.
    Continuously evaluates evidence, prioritizes actions, enforces governance gates,
    and executes verified defensive security workflows.
    """

    @classmethod
    def evaluate_and_propose_decisions(
        cls,
        db: Session,
        project_id: str,
    ) -> List[SecurityDecisionRecord]:
        """
        Closed-Loop Evaluation Phase:
        Inspects findings, changes, risk scores, and remediation states to synthesize
        prioritized actionable decisions. Deduplicates against existing pending decisions.
        """
        proposed: List[SecurityDecisionRecord] = []

        existing_pending = {
            (d.action_type, d.target_id): d
            for d in db.query(SecurityDecisionRecord)
            .filter(
                SecurityDecisionRecord.project_id == project_id,
                SecurityDecisionRecord.status.in_([DecisionStatus.PROPOSED, DecisionStatus.APPROVED]),
            )
            .all()
        }

        # ----------------------------------------------------------------------
        # Rule 1: High-Risk Unmitigated Finding -> PRIORITIZE_REMEDIATION
        # ----------------------------------------------------------------------
        critical_findings = (
            db.query(VulnerabilityFinding)
            .filter(
                VulnerabilityFinding.project_id == project_id,
                VulnerabilityFinding.severity.in_([FindingSeverity.CRITICAL, FindingSeverity.HIGH]),
                VulnerabilityFinding.status.in_([FindingLifecycleStatus.DETECTED, FindingLifecycleStatus.CONFIRMED, FindingLifecycleStatus.REOPENED]),
            )
            .all()
        )

        for finding in critical_findings:
            key = (DecisionActionType.PRIORITIZE_REMEDIATION, finding.id)
            if key not in existing_pending:
                rec = RemediationPrioritizationService.generate_or_get_recommendation(
                    project_id=project_id,
                    finding_id=finding.id,
                    db=db,
                )
                decision = SecurityDecisionRecord(
                    project_id=project_id,
                    action_type=DecisionActionType.PRIORITIZE_REMEDIATION,
                    status=DecisionStatus.PROPOSED,
                    title=f"Prioritize Remediation: {finding.title}",
                    triggering_observation=f"Active {finding.severity.value} finding '{finding.title}' discovered on {finding.target_value}.",
                    evidence_considered={
                        "finding_id": finding.id,
                        "severity": finding.severity.value,
                        "target_value": finding.target_value,
                        "vuln_id": finding.vuln_id,
                        "recommendation_id": rec.id if rec else None,
                    },
                    selected_action=f"Generate defense playbook and submit change authorization ticket for '{finding.title}'.",
                    rationale=f"{finding.severity.value} vulnerability exposes attack surfaces; remediation playbook is available.",
                    confidence=0.95,
                    uncertainty=0.05,
                    target_id=finding.id,
                    target_resource=finding.target_value,
                    required_approval_role="LEAD",
                )
                db.add(decision)
                proposed.append(decision)

        # ----------------------------------------------------------------------
        # Rule 2: Approved Remediation Awaiting Retest -> VERIFY_APPLIED_FIX
        # ----------------------------------------------------------------------
        approved_recs = (
            db.query(RemediationRecommendation)
            .filter(
                RemediationRecommendation.project_id == project_id,
                RemediationRecommendation.status == RecommendationStatus.APPROVED,
            )
            .all()
        )

        for rec in approved_recs:
            key = (DecisionActionType.VERIFY_APPLIED_FIX, rec.finding_id)
            if key not in existing_pending:
                finding = db.query(VulnerabilityFinding).filter(VulnerabilityFinding.id == rec.finding_id).first()
                if finding and finding.status != FindingLifecycleStatus.VERIFIED_CLOSED:
                    decision = SecurityDecisionRecord(
                        project_id=project_id,
                        action_type=DecisionActionType.VERIFY_APPLIED_FIX,
                        status=DecisionStatus.PROPOSED,
                        title=f"Verify Remediation: {rec.title}",
                        triggering_observation=f"Remediation change approved for finding '{finding.title}'.",
                        evidence_considered={"finding_id": finding.id, "recommendation_id": rec.id},
                        selected_action=f"Dispatch targeted independent re-test probe against {finding.target_value} to verify resolution.",
                        rationale="Independent verification is mandatory before closing any finding.",
                        confidence=0.9,
                        uncertainty=0.1,
                        target_id=finding.id,
                        target_resource=finding.target_value,
                        required_approval_role=None,  # Safe read-only verification probe
                    )
                    db.add(decision)
                    proposed.append(decision)

        # ----------------------------------------------------------------------
        # Rule 3: Changed Configuration or New Asset -> REASSESS_CHANGED_ASSET
        # ----------------------------------------------------------------------
        recent_changes = (
            db.query(PostureChangeRecord)
            .filter(
                PostureChangeRecord.project_id == project_id,
                PostureChangeRecord.change_type.in_([ChangeType.CONFIG_CHANGED, ChangeType.NEW_ASSET]),
                PostureChangeRecord.is_confirmed.is_(True),
            )
            .order_by(PostureChangeRecord.created_at.desc())
            .limit(5)
            .all()
        )

        for change in recent_changes:
            key = (DecisionActionType.REASSESS_CHANGED_ASSET, change.target_resource)
            if key not in existing_pending:
                decision = SecurityDecisionRecord(
                    project_id=project_id,
                    action_type=DecisionActionType.REASSESS_CHANGED_ASSET,
                    status=DecisionStatus.PROPOSED,
                    title=f"Reassess Changed Target: {change.target_resource}",
                    triggering_observation=change.title,
                    evidence_considered={"change_id": change.id, "previous_state": change.previous_state, "new_state": change.new_state},
                    selected_action=f"Schedule non-intrusive re-assessment for modified target '{change.target_resource}'.",
                    rationale="Configuration change detected; environment security baseline must be refreshed.",
                    confidence=0.85,
                    uncertainty=0.15,
                    target_id=change.target_resource,
                    target_resource=change.target_resource,
                    required_approval_role=None,  # Passive read-only audit
                )
                db.add(decision)
                proposed.append(decision)

        if proposed:
            db.commit()
            for d in proposed:
                db.refresh(d)

        return proposed

    @classmethod
    def execute_decision(
        cls,
        db: Session,
        project_id: str,
        decision_id: str,
        actor: Optional[User] = None,
        actor_role: Optional[ProjectRole] = None,
        force: bool = False,
    ) -> SecurityDecisionRecord:
        """
        Closed-Loop Execution Phase:
        Executes an approved or safe decision, enforces execution-boundary scope authorization,
        measures posture improvement before vs after, and records audit telemetry.
        """
        decision = (
            db.query(SecurityDecisionRecord)
            .filter(
                SecurityDecisionRecord.id == decision_id,
                SecurityDecisionRecord.project_id == project_id,
            )
            .first()
        )
        if not decision:
            raise ValueError(f"Security decision '{decision_id}' not found in project '{project_id}'.")

        # Governance Check: Gated decisions require Lead approval
        if decision.required_approval_role and decision.status != DecisionStatus.APPROVED and not force:
            if actor_role != ProjectRole.LEAD:
                raise PermissionError(f"Decision '{decision.title}' requires explicit {decision.required_approval_role} approval.")

        # Baseline risk measurement before execution
        initial_risk = ContextualRiskService.assess_and_persist_finding_risk(
            project_id=project_id,
            finding_id=decision.target_id,
            db=db,
        ) if decision.target_id and db.query(VulnerabilityFinding).filter(VulnerabilityFinding.id == decision.target_id).first() else None
        initial_risk_score = initial_risk.score if initial_risk else 0.0

        outcome_payload: Dict[str, Any] = {}
        now = datetime.now(timezone.utc)

        # ----------------------------------------------------------------------
        # DISPATCH 1: REASSESS_CHANGED_ASSET
        # ----------------------------------------------------------------------
        if decision.action_type == DecisionActionType.REASSESS_CHANGED_ASSET:
            target = decision.target_resource or decision.target_id
            scope_eval = ScopeEngine.validate_target_in_scope(db=db, project_id=project_id, target=target, now=now)
            if not scope_eval["is_authorized"]:
                decision.status = DecisionStatus.REJECTED
                decision.execution_outcome = {"error": f"Execution boundary denied: {scope_eval['reason']}"}
                db.commit()
                return decision

            job = AssessmentExecutionEngine.create_job(
                db=db,
                project_id=project_id,
                created_by_id=actor.id if actor else None,
                target_input=target,
                adapter_name="live_network_auditor_adapter",
                config={"profile": "LIVE_WEB_SECURITY_AUDIT", "allow_loopback": True},
            )
            claimed = AssessmentExecutionEngine.preflight_and_claim_job(db=db, job_id=job.id)
            completed_job = AssessmentExecutionEngine.execute_claimed_job(db=db, job_id=job.id)
            decision.job_id = completed_job.id
            outcome_payload = {
                "job_id": completed_job.id,
                "status": completed_job.status.value,
                "findings_count": len(completed_job.findings),
            }
            decision.status = DecisionStatus.EXECUTED

        # ----------------------------------------------------------------------
        # DISPATCH 2: VERIFY_APPLIED_FIX
        # ----------------------------------------------------------------------
        elif decision.action_type == DecisionActionType.VERIFY_APPLIED_FIX:
            finding = db.query(VulnerabilityFinding).filter(VulnerabilityFinding.id == decision.target_id).first()
            if not finding:
                decision.status = DecisionStatus.INCONCLUSIVE
                outcome_payload = {"error": "Target finding not found."}
            else:
                verification = RemediationVerificationService.execute_automated_retest(
                    project_id=project_id,
                    finding_id=finding.id,
                    adapter_name="live_network_auditor_adapter",
                    config={"profile": "LIVE_HTTP_HEADERS", "allow_loopback": True},
                    notes="Autonomous verification probe dispatched by Closed-Loop Decision Engine",
                    verifier=actor,
                    verifier_role=actor_role or ProjectRole.LEAD,
                    db=db,
                )
                decision.status = DecisionStatus.EXECUTED
                outcome_payload = {
                    "verification_id": verification.id,
                    "outcome": verification.outcome.value,
                    "target": finding.target_value,
                }

        # ----------------------------------------------------------------------
        # DISPATCH 3: PRIORITIZE_REMEDIATION
        # ----------------------------------------------------------------------
        elif decision.action_type == DecisionActionType.PRIORITIZE_REMEDIATION:
            rec = RemediationPrioritizationService.generate_or_get_recommendation(
                project_id=project_id,
                finding_id=decision.target_id,
                db=db,
            )
            decision.status = DecisionStatus.EXECUTED
            outcome_payload = {
                "recommendation_id": rec.id,
                "guidance_title": rec.title,
                "status": rec.status.value,
            }

        # ----------------------------------------------------------------------
        # DISPATCH 4: RECALCULATE_RISK_AND_PATHS
        # ----------------------------------------------------------------------
        elif decision.action_type == DecisionActionType.RECALCULATE_RISK_AND_PATHS:
            risk_summary = ContextualRiskService.recalculate_project_risks(project_id=project_id, db=db)
            paths = AttackPathService.analyze_attack_paths(project_id=project_id, db=db)
            decision.status = DecisionStatus.EXECUTED
            outcome_payload = {
                "recalculated_count": risk_summary.get("total_assessed", 0),
                "attack_paths_count": len(paths.get("attack_paths", [])),
            }

        else:
            decision.status = DecisionStatus.EXECUTED
            outcome_payload = {"action": decision.selected_action, "result": "Action acknowledged and logged."}

        # Measure posture improvement after execution
        post_risk = ContextualRiskService.assess_and_persist_finding_risk(
            project_id=project_id,
            finding_id=decision.target_id,
            db=db,
        ) if decision.target_id and db.query(VulnerabilityFinding).filter(VulnerabilityFinding.id == decision.target_id).first() else None
        post_risk_score = post_risk.score if post_risk else 0.0

        delta_risk = initial_risk_score - post_risk_score
        decision.executed_at = now
        decision.execution_outcome = outcome_payload
        decision.posture_improvement_measured = {
            "initial_risk_score": initial_risk_score,
            "post_risk_score": post_risk_score,
            "risk_reduction": round(delta_risk, 2),
            "improved": delta_risk > 0,
        }

        # Audit ledger event
        AuditService.record_event(
            db=db,
            action="SECURITY_DECISION_EXECUTED",
            target_type="security_decision",
            target_id=decision.id,
            project_id=project_id,
            actor_id=actor.id if actor else None,
            outcome="SUCCESS",
            details={
                "action_type": decision.action_type.value,
                "decision_title": decision.title,
                "outcome": outcome_payload,
                "posture_improvement": decision.posture_improvement_measured,
            },
        )

        db.commit()
        db.refresh(decision)
        return decision

    @classmethod
    def get_closed_loop_overview(
        cls,
        db: Session,
        project_id: str,
    ) -> Dict[str, Any]:
        """
        Synthesizes active operational telemetry across the closed loop:
        Posture changes, proposed decisions, executed outcomes, and verified improvements.
        """
        from app.models.adaptive_defense import MorphStatePosture

        posture = db.query(MorphStatePosture).filter(MorphStatePosture.project_id == project_id).first()
        active_posture_str = posture.current_state.value if posture else "NORMAL"

        total_changes = db.query(PostureChangeRecord).filter(PostureChangeRecord.project_id == project_id).count()
        recent_changes = (
            db.query(PostureChangeRecord)
            .filter(PostureChangeRecord.project_id == project_id)
            .order_by(PostureChangeRecord.created_at.desc())
            .limit(10)
            .all()
        )

        all_decisions = db.query(SecurityDecisionRecord).filter(SecurityDecisionRecord.project_id == project_id).all()
        proposed = [d for d in all_decisions if d.status == DecisionStatus.PROPOSED]
        executed = [d for d in all_decisions if d.status == DecisionStatus.EXECUTED]
        verified_improvements = [
            d for d in executed
            if d.posture_improvement_measured and d.posture_improvement_measured.get("improved") is True
        ]

        return {
            "project_id": project_id,
            "active_posture": active_posture_str,
            "total_posture_changes": total_changes,
            "unresolved_changes": len([c for c in recent_changes if c.change_type in (ChangeType.NEW_FINDING, ChangeType.RECURRING_FINDING)]),
            "proposed_decisions_count": len(proposed),
            "executed_decisions_count": len(executed),
            "verified_improvements_count": len(verified_improvements),
            "recent_changes": recent_changes,
            "pending_decisions": proposed,
        }
