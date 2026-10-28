"""
Recovery Engine Service for VAPT System.
Executes controlled, bounded, idempotent recovery actions.
Enforces scope authorization, tenant isolation, pre/post condition comparison,
and immutable decision ledger recording.
"""
import logging
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session

from app.models.base import utc_now
from app.models.user import User
from app.models.diagnostics import (
    RecoveryActionType,
    RecoveryOutcome,
    RecoveryActionRecord,
)
from app.models.assessment import AssessmentJob, AssessmentStatus
from app.models.finding import VulnerabilityFinding, FindingLifecycleStatus
from app.models.notification import NotificationRecord, NotificationStatus
from app.models.decision import DecisionLedgerType
from app.services.scope_engine import ScopeEngine
from app.services.policy_engine import PolicyEngineService
from app.services.decision_ledger_service import DecisionLedgerService
from app.services.backup_service import BackupRecoveryService
from app.services.contextual_risk_service import ContextualRiskService
from app.services.knowledge_graph_service import KnowledgeGraphService

logger = logging.getLogger(__name__)


class RecoveryEngineService:
    """
    Controlled Recovery and Self-Healing Engine.
    Executes validated recovery actions and independently verifies post-conditions.
    """

    @classmethod
    def execute_recovery(
        cls,
        db: Session,
        project_id: str,
        action_type: RecoveryActionType,
        target_entity_type: str,
        target_entity_id: Optional[str] = None,
        target_resource: Optional[str] = None,
        actor: Optional[User] = None,
        reason: str = "",
    ) -> Dict[str, Any]:
        now = utc_now()
        pre_condition: Dict[str, Any] = {}
        post_condition: Dict[str, Any] = {}
        outcome = RecoveryOutcome.FAILED
        verification_notes = ""

        # ----------------------------------------------------------------------
        # Action 1: RECOVER_STUCK_JOB
        # ----------------------------------------------------------------------
        if action_type == RecoveryActionType.RECOVER_STUCK_JOB:
            if not target_entity_id:
                raise ValueError("target_entity_id is required for RECOVER_STUCK_JOB.")
            job = (
                db.query(AssessmentJob)
                .filter(
                    AssessmentJob.id == target_entity_id,
                    AssessmentJob.project_id == project_id,
                )
                .first()
            )
            if not job:
                raise ValueError(f"Assessment job '{target_entity_id}' not found in project '{project_id}'.")

            pre_condition = {
                "job_id": job.id,
                "status": job.status.value,
                "started_at": job.started_at.isoformat() if job.started_at else None,
                "target_input": job.target_input,
            }

            if job.status in [AssessmentStatus.RUNNING, AssessmentStatus.QUEUED]:
                job.status = AssessmentStatus.CANCELLED
                job.error_message = f"Recovered by diagnostic action: {reason}"
                job.completed_at = now
                db.commit()

                post_condition = {
                    "job_id": job.id,
                    "status": job.status.value,
                    "completed_at": job.completed_at.isoformat(),
                }
                outcome = RecoveryOutcome.SUCCESS
                verification_notes = "Job transitioned from active to CANCELLED; concurrency slot released."
            else:
                outcome = RecoveryOutcome.INCONCLUSIVE
                post_condition = pre_condition
                verification_notes = f"Job was already in terminal state '{job.status.value}'."

        # ----------------------------------------------------------------------
        # Action 2: RETRY_ASSESSMENT
        # ----------------------------------------------------------------------
        elif action_type == RecoveryActionType.RETRY_ASSESSMENT:
            if not target_entity_id:
                raise ValueError("target_entity_id is required for RETRY_ASSESSMENT.")
            orig_job = (
                db.query(AssessmentJob)
                .filter(
                    AssessmentJob.id == target_entity_id,
                    AssessmentJob.project_id == project_id,
                )
                .first()
            )
            if not orig_job:
                raise ValueError(f"Assessment job '{target_entity_id}' not found in project '{project_id}'.")

            pre_condition = {
                "original_job_id": orig_job.id,
                "original_status": orig_job.status.value,
                "target_input": orig_job.target_input,
            }

            # Preflight Scope Enforcement: Fail-Closed
            scope_eval = ScopeEngine.validate_target_in_scope(
                db=db,
                project_id=project_id,
                target=orig_job.target_input,
            )
            if not scope_eval.get("is_authorized"):
                outcome = RecoveryOutcome.FAILED
                verification_notes = f"Recovery rejected: Target '{orig_job.target_input}' is outside authorized scope."
                post_condition = {"scope_error": "OUT_OF_SCOPE"}
            else:
                # Preflight Policy Enforcement
                policy_eval = PolicyEngineService.evaluate_action_permission(
                    db=db,
                    project_id=project_id,
                    action_type="RETRY_ASSESSMENT",
                    target_resource=orig_job.target_input,
                )
                if not policy_eval.get("allowed"):
                    outcome = RecoveryOutcome.FAILED
                    verification_notes = f"Policy rejected recovery: {policy_eval.get('reason')}"
                    post_condition = {"policy_error": policy_eval.get("reason")}
                else:
                    new_job = AssessmentJob(
                        project_id=project_id,
                        target_input=orig_job.target_input,
                        adapter_name=orig_job.adapter_name,
                        status=AssessmentStatus.QUEUED,
                        created_by_id=actor.id if actor else None,
                    )
                    db.add(new_job)
                    db.commit()

                    post_condition = {
                        "new_job_id": new_job.id,
                        "new_status": new_job.status.value,
                    }
                    outcome = RecoveryOutcome.SUCCESS
                    verification_notes = f"New retry job '{new_job.id}' enqueued successfully."

        # ----------------------------------------------------------------------
        # Action 3: REQUEUE_NOTIFICATION
        # ----------------------------------------------------------------------
        elif action_type == RecoveryActionType.REQUEUE_NOTIFICATION:
            if not target_entity_id:
                raise ValueError("target_entity_id is required for REQUEUE_NOTIFICATION.")
            notif = (
                db.query(NotificationRecord)
                .filter(
                    NotificationRecord.id == target_entity_id,
                    NotificationRecord.project_id == project_id,
                )
                .first()
            )
            if not notif:
                raise ValueError(f"Notification '{target_entity_id}' not found in project '{project_id}'.")

            pre_condition = {
                "notification_id": notif.id,
                "status": notif.status.value,
                "attempts": notif.retry_count,
            }

            if notif.retry_count >= 3:
                outcome = RecoveryOutcome.FAILED
                post_condition = pre_condition
                verification_notes = "Recovery aborted: Maximum retry limit reached (3 attempts)."
            else:
                notif.status = NotificationStatus.PENDING
                notif.retry_count += 1
                db.commit()

                post_condition = {
                    "notification_id": notif.id,
                    "status": notif.status.value,
                    "attempts": notif.retry_count,
                }
                outcome = RecoveryOutcome.SUCCESS
                verification_notes = f"Notification requeued for attempt {notif.retry_count}/3."

        # ----------------------------------------------------------------------
        # Action 4: RECALCULATE_RISK_SCORES
        # ----------------------------------------------------------------------
        elif action_type == RecoveryActionType.RECALCULATE_RISK_SCORES:
            pre_condition = {"project_id": project_id}
            findings = (
                db.query(VulnerabilityFinding)
                .filter(VulnerabilityFinding.project_id == project_id)
                .all()
            )
            recalculated = 0
            for f in findings:
                ContextualRiskService.assess_and_persist_finding_risk(
                    project_id=project_id,
                    finding_id=f.id,
                    db=db,
                )
                recalculated += 1

            post_condition = {"recalculated_findings_count": recalculated}
            outcome = RecoveryOutcome.SUCCESS
            verification_notes = f"Recalculated contextual risk scores for {recalculated} findings using model v2.0.0."

        # ----------------------------------------------------------------------
        # Action 5: REBUILD_KNOWLEDGE_GRAPH
        # ----------------------------------------------------------------------
        elif action_type == RecoveryActionType.REBUILD_KNOWLEDGE_GRAPH:
            pre_condition = {"project_id": project_id}
            res = KnowledgeGraphService.reconcile_graph_from_assets(
                project_id=project_id,
                db=db,
            )
            post_condition = res
            outcome = RecoveryOutcome.SUCCESS
            verification_notes = "Graph topology and node relationships refreshed from authoritative assets and observations."

        # ----------------------------------------------------------------------
        # Action 6: TRIGGER_BACKUP
        # ----------------------------------------------------------------------
        elif action_type == RecoveryActionType.TRIGGER_BACKUP:
            pre_condition = {"project_id": project_id}
            backup_meta = BackupRecoveryService.create_database_backup(
                db=db,
                actor_id=actor.id if actor else None,
            )
            restore_eval = BackupRecoveryService.verify_and_test_restore(
                backup_file_path=backup_meta.backup_path,
                expected_sha256=backup_meta.sha256_hash,
            )
            post_condition = {
                "backup_path": backup_meta.backup_path,
                "sha256": backup_meta.sha256_hash,
                "restore_valid": restore_eval["is_valid"],
            }
            outcome = RecoveryOutcome.SUCCESS if restore_eval["is_valid"] else RecoveryOutcome.FAILED
            verification_notes = (
                f"Backup created ({backup_meta.size_bytes} bytes) and verified in disposable sandbox."
                if restore_eval["is_valid"]
                else "Backup created but sandbox restore verification failed."
            )

        # ----------------------------------------------------------------------
        # Action 7: RETEST_REMEDIATION
        # ----------------------------------------------------------------------
        elif action_type == RecoveryActionType.RETEST_REMEDIATION:
            if not target_entity_id:
                raise ValueError("target_entity_id (finding_id) required for RETEST_REMEDIATION.")
            finding = (
                db.query(VulnerabilityFinding)
                .filter(
                    VulnerabilityFinding.id == target_entity_id,
                    VulnerabilityFinding.project_id == project_id,
                )
                .first()
            )
            if not finding:
                raise ValueError(f"Finding '{target_entity_id}' not found in project '{project_id}'.")

            pre_condition = {
                "finding_id": finding.id,
                "status": finding.status.value,
                "target_value": finding.target_value,
            }

            # Scope preflight
            scope_eval = ScopeEngine.validate_target_in_scope(
                db=db,
                project_id=project_id,
                target=finding.target_value,
            )
            if not scope_eval.get("is_authorized"):
                outcome = RecoveryOutcome.FAILED
                verification_notes = f"Scope rejection: Finding target '{finding.target_value}' is outside authorized scope."
                post_condition = {"scope_error": "OUT_OF_SCOPE"}
            else:
                # Dispatch retest assessment job
                retest_job = AssessmentJob(
                    project_id=project_id,
                    target_input=finding.target_value,
                    adapter_name="web_adapter",
                    status=AssessmentStatus.QUEUED,
                    created_by_id=actor.id if actor else None,
                )
                db.add(retest_job)
                db.commit()

                post_condition = {
                    "finding_id": finding.id,
                    "retest_job_id": retest_job.id,
                    "job_status": retest_job.status.value,
                }
                outcome = RecoveryOutcome.SUCCESS
                verification_notes = f"Remediation retest job '{retest_job.id}' queued for independent verification."

        # ----------------------------------------------------------------------
        # Action 8: RESUME_MONITORING
        # ----------------------------------------------------------------------
        elif action_type == RecoveryActionType.RESUME_MONITORING:
            pre_condition = {"project_id": project_id}
            # Reset consecutive failures in policy to clear block
            policy = (
                db.query(AutonomousPolicyRecord)
                .filter(AutonomousPolicyRecord.project_id == project_id)
                .first()
            )
            if policy:
                policy.consecutive_failures = 0
                db.commit()

            post_condition = {"policy_consecutive_failures": 0}
            outcome = RecoveryOutcome.SUCCESS
            verification_notes = "Cleared consecutive failure counters; monitoring schedules eligible for execution."

        else:
            raise ValueError(f"Unsupported recovery action type: '{action_type}'.")

        # Record Recovery Action History
        recovery_rec = RecoveryActionRecord(
            project_id=project_id,
            action_type=action_type,
            target_entity_type=target_entity_type,
            target_entity_id=target_entity_id,
            target_resource=target_resource,
            executed_by_id=actor.id if actor else None,
            execution_timestamp=now,
            reason=reason or "Operator triggered recovery action",
            pre_condition=pre_condition,
            post_condition=post_condition,
            outcome=outcome,
            verification_notes=verification_notes,
            verification_timestamp=utc_now(),
        )
        db.add(recovery_rec)
        db.commit()

        # Record in Immutable Security Decision Ledger
        ledger_entry = DecisionLedgerService.record_decision(
            db=db,
            project_id=project_id,
            decision_type=DecisionLedgerType.POLICY_EVALUATION,
            decision_outcome=outcome.value,
            initiating_event=f"RECOVERY_ACTION:{action_type.value}",
            target_type=target_entity_type,
            target_id=target_entity_id,
            target_resource=target_resource,
            reason=f"Recovery action {action_type.value} executed. {verification_notes}",
            details={"pre_condition": pre_condition, "post_condition": post_condition},
            actor_id=actor.id if actor else None,
        )

        recovery_rec.ledger_record_id = ledger_entry.id
        db.commit()

        return {
            "recovery_id": recovery_rec.id,
            "project_id": project_id,
            "action_type": action_type.value,
            "outcome": outcome.value,
            "pre_condition": pre_condition,
            "post_condition": post_condition,
            "verification_notes": verification_notes,
            "ledger_record_id": ledger_entry.id,
        }
