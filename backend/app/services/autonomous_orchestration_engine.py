import traceback
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional, Tuple, List
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.models.orchestration import (
    OrchestrationState,
    OrchestrationEventType,
    OrchestrationActionType,
    OutcomeMeasurementStatus,
    EventProcessingStatus,
    OrchestrationEventRecord,
    OrchestrationWorkflowRecord,
)
from app.models.user import User, SystemRole
from app.models.project import ProjectRole
from app.models.finding import VulnerabilityFinding, FindingLifecycleStatus
from app.models.assessment import AssessmentJob, AssessmentStatus
from app.models.base import utc_now

from app.services.orchestration_state_machine import (
    OrchestrationStateMachine,
    OrchestrationTransitionError,
    ConcurrencyLockError,
)
from app.services.event_processing_service import EventProcessingService
from app.services.decision_planner_service import DecisionPlannerService
from app.services.dependency_invalidation_service import DependencyInvalidationService
from app.services.closed_loop_measurement_service import ClosedLoopMeasurementService
from app.services.policy_engine import PolicyEngineService


class OrchestrationAuthorizationError(Exception):
    """Raised when an unauthorized operator attempts workflow mutation."""
    pass


class AutonomousOrchestrationEngine:
    """
    Unified Autonomous Security Orchestration Engine (Prompt 15 / Section 1-8).
    Closed-loop orchestration:
    Event -> Context -> Decision Plan -> Approval Gate -> Action Execution -> Verification -> Outcome Measurement.
    """

    @classmethod
    def create_or_resume_workflow(
        cls,
        db: Session,
        project_id: str,
        event: OrchestrationEventRecord,
        now: Optional[datetime] = None,
    ) -> OrchestrationWorkflowRecord:
        """Creates a new workflow tied to an incoming event or retrieves existing."""
        if now is None:
            now = utc_now()

        existing = (
            db.query(OrchestrationWorkflowRecord)
            .filter(
                OrchestrationWorkflowRecord.project_id == project_id,
                OrchestrationWorkflowRecord.trigger_event_id == event.id,
            )
            .first()
        )
        if existing:
            return existing

        workflow = OrchestrationWorkflowRecord(
            project_id=project_id,
            state=OrchestrationState.EVENT_RECEIVED,
            trigger_event_id=event.id,
            workflow_type=event.event_type.value,
            target_resource=event.target_resource,
            context_data={"event_payload": event.payload or {}},
            attempt_count=0,
            max_retries=3,
            created_at=now,
            updated_at=now,
        )
        db.add(workflow)
        db.commit()
        db.refresh(workflow)
        return workflow

    @classmethod
    def execute_workflow_cycle(
        cls,
        db: Session,
        workflow_id: str,
        worker_id: str = "orchestrator-worker",
        now: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        """
        Executes an end-to-end orchestration cycle for a workflow.
        Guarantees concurrency isolation, state validation, and closed-loop measurement.
        """
        if now is None:
            now = utc_now()

        workflow = db.query(OrchestrationWorkflowRecord).filter(OrchestrationWorkflowRecord.id == workflow_id).first()
        if not workflow:
            raise ValueError(f"Workflow '{workflow_id}' not found.")

        # 1. Acquire Concurrency Lease
        OrchestrationStateMachine.acquire_lock(
            workflow=workflow,
            worker_id=worker_id,
            lease_seconds=60,
            now=now,
        )
        db.commit()

        try:
            # 2. Gather Context (EVENT_RECEIVED -> CONTEXT_GATHERED)
            if workflow.state == OrchestrationState.EVENT_RECEIVED:
                initial_snapshot = ClosedLoopMeasurementService.capture_project_posture_snapshot(
                    db=db, project_id=workflow.project_id
                )
                context = dict(workflow.context_data or {})
                context["initial_snapshot"] = initial_snapshot
                workflow.context_data = context

                OrchestrationStateMachine.transition(
                    workflow=workflow,
                    target_state=OrchestrationState.CONTEXT_GATHERED,
                    now=now,
                )
                db.commit()

            # 3. Decision Planning (CONTEXT_GATHERED -> DECISION_PENDING)
            if workflow.state == OrchestrationState.CONTEXT_GATHERED:
                event = db.query(OrchestrationEventRecord).filter(OrchestrationEventRecord.id == workflow.trigger_event_id).first()
                if not event:
                    event = OrchestrationEventRecord(
                        project_id=workflow.project_id,
                        event_type=OrchestrationEventType.MANUAL_TRIGGER,
                        target_resource=workflow.target_resource,
                        dedup_key="manual",
                        received_at=now,
                    )

                plan = DecisionPlannerService.plan_next_action(
                    db=db,
                    project_id=workflow.project_id,
                    event=event,
                    now=now,
                )

                workflow.recommended_action = plan["action_type"]
                workflow.action_rationale = plan["rationale"]
                workflow.confidence = plan["confidence"]
                workflow.uncertainty = plan["uncertainty"]
                workflow.required_approval_role = plan.get("required_approval_role")

                OrchestrationStateMachine.transition(
                    workflow=workflow,
                    target_state=OrchestrationState.DECISION_PENDING,
                    now=now,
                )
                db.commit()

            # 4. Handle Decision
            if workflow.state == OrchestrationState.DECISION_PENDING:
                rec_action = workflow.recommended_action

                # Branch A: Human Approval Required
                if workflow.required_approval_role and not workflow.approved_at:
                    OrchestrationStateMachine.transition(
                        workflow=workflow,
                        target_state=OrchestrationState.AWAITING_APPROVAL,
                        now=now,
                    )
                    db.commit()
                    return {
                        "workflow_id": workflow.id,
                        "state": workflow.state.value,
                        "message": f"Workflow requires approval from role '{workflow.required_approval_role}'.",
                    }

                # Branch B: Suspend Activity
                if rec_action == OrchestrationActionType.SUSPEND_ACTIVITY:
                    OrchestrationStateMachine.transition(
                        workflow=workflow,
                        target_state=OrchestrationState.SUSPENDED,
                        reason=workflow.action_rationale,
                        now=now,
                    )
                    if workflow.trigger_event:
                        EventProcessingService.mark_event_processed(db=db, event=workflow.trigger_event, now=now)
                    db.commit()
                    return {
                        "workflow_id": workflow.id,
                        "state": workflow.state.value,
                        "message": f"Workflow suspended: {workflow.suspension_reason}",
                    }

                # Branch C: No Action Required
                if rec_action == OrchestrationActionType.NO_ACTION_REQUIRED:
                    OrchestrationStateMachine.transition(
                        workflow=workflow,
                        target_state=OrchestrationState.COMPLETED,
                        reason="No further security action required for this event.",
                        now=now,
                    )
                    if workflow.trigger_event:
                        EventProcessingService.mark_event_processed(db=db, event=workflow.trigger_event, now=now)
                    db.commit()
                    return {
                        "workflow_id": workflow.id,
                        "state": workflow.state.value,
                        "message": "Workflow completed with no action required.",
                    }

                # Branch D: Action Ready to Queue
                # Zero-Trust Scope & Authorization Validation before Queueing
                auth_check = DecisionPlannerService.evaluate_authorization(
                    db=db,
                    project_id=workflow.project_id,
                    target_resource=workflow.target_resource,
                    action_type=rec_action,
                    now=now,
                )
                if not auth_check["is_authorized"]:
                    OrchestrationStateMachine.transition(
                        workflow=workflow,
                        target_state=OrchestrationState.FAILED,
                        reason=f"Authorization rejected at queue boundary: {auth_check['reason']}",
                        failure_category=auth_check.get("status", "AUTHORIZATION_DENIED"),
                        now=now,
                    )
                    if workflow.trigger_event:
                        EventProcessingService.mark_event_failed(db=db, event=workflow.trigger_event, reason=auth_check['reason'], now=now)
                    db.commit()
                    return {
                        "workflow_id": workflow.id,
                        "state": workflow.state.value,
                        "message": workflow.failure_reason,
                    }

                OrchestrationStateMachine.transition(
                    workflow=workflow,
                    target_state=OrchestrationState.ACTION_QUEUED,
                    now=now,
                )
                db.commit()

            # 5. Execute Action (ACTION_QUEUED -> ACTION_RUNNING)
            if workflow.state == OrchestrationState.ACTION_QUEUED:
                # Re-validate authorization at execution boundary
                auth_check = DecisionPlannerService.evaluate_authorization(
                    db=db,
                    project_id=workflow.project_id,
                    target_resource=workflow.target_resource,
                    action_type=workflow.recommended_action,
                    now=now,
                )
                if not auth_check["is_authorized"]:
                    OrchestrationStateMachine.transition(
                        workflow=workflow,
                        target_state=OrchestrationState.FAILED,
                        reason=f"Execution boundary denial: {auth_check['reason']}",
                        failure_category=auth_check.get("status", "AUTHORIZATION_REVOKED"),
                        now=now,
                    )
                    if workflow.trigger_event:
                        EventProcessingService.mark_event_failed(db=db, event=workflow.trigger_event, reason=auth_check['reason'], now=now)
                    db.commit()
                    return {
                        "workflow_id": workflow.id,
                        "state": workflow.state.value,
                        "message": workflow.failure_reason,
                    }

                OrchestrationStateMachine.transition(
                    workflow=workflow,
                    target_state=OrchestrationState.ACTION_RUNNING,
                    now=now,
                )
                workflow.attempt_count += 1
                db.commit()

                # Action Execution Simulation / Integration
                execution_result = {
                    "action": workflow.recommended_action.value if workflow.recommended_action else "UNKNOWN",
                    "status": "COMPLETED",
                    "target": workflow.target_resource,
                    "attempt": workflow.attempt_count,
                    "executed_at": now.isoformat(),
                }

                # 6. Verify Outcome (ACTION_RUNNING -> VERIFYING_OUTCOME)
                OrchestrationStateMachine.transition(
                    workflow=workflow,
                    target_state=OrchestrationState.VERIFYING_OUTCOME,
                    partial_results={"execution_result": execution_result},
                    now=now,
                )
                db.commit()

                initial_snapshot = (workflow.context_data or {}).get("initial_snapshot", {})
                ClosedLoopMeasurementService.evaluate_and_record_outcome(
                    db=db,
                    workflow=workflow,
                    initial_snapshot=initial_snapshot,
                    execution_result=execution_result,
                    verification_id=workflow.verification_id,
                    now=now,
                )

                # 7. Complete Workflow (VERIFYING_OUTCOME -> COMPLETED)
                OrchestrationStateMachine.transition(
                    workflow=workflow,
                    target_state=OrchestrationState.COMPLETED,
                    now=now,
                )

                if workflow.trigger_event:
                    EventProcessingService.mark_event_processed(db=db, event=workflow.trigger_event, now=now)

                db.commit()

            return {
                "workflow_id": workflow.id,
                "state": workflow.state.value,
                "outcome_status": workflow.outcome_status.value if workflow.outcome_status else None,
                "recommended_action": workflow.recommended_action.value if workflow.recommended_action else None,
                "message": "Workflow cycle executed successfully.",
            }

        finally:
            OrchestrationStateMachine.release_lock(workflow=workflow, worker_id=worker_id)
            db.commit()

    @classmethod
    def approve_workflow(
        cls,
        db: Session,
        workflow_id: str,
        user: User,
        user_role: ProjectRole,
        notes: str = "",
        now: Optional[datetime] = None,
    ) -> OrchestrationWorkflowRecord:
        """
        Operator Approval Gate: Approves a workflow in AWAITING_APPROVAL.
        Enforces least-privilege RBAC.
        """
        if now is None:
            now = utc_now()

        workflow = db.query(OrchestrationWorkflowRecord).filter(OrchestrationWorkflowRecord.id == workflow_id).first()
        if not workflow:
            raise ValueError(f"Workflow '{workflow_id}' not found.")

        if workflow.state != OrchestrationState.AWAITING_APPROVAL:
            raise OrchestrationTransitionError(
                f"Workflow '{workflow_id}' is in state '{workflow.state.value}'. Only AWAITING_APPROVAL can be approved."
            )

        required_role = workflow.required_approval_role or "LEAD"
        is_lead_or_admin = (
            user.system_role == SystemRole.ADMIN or
            user_role in (ProjectRole.LEAD,)
        )

        if required_role in ("LEAD", "ADMIN") and not is_lead_or_admin:
            raise OrchestrationAuthorizationError(
                f"User '{user.email}' with role '{user_role.value}' cannot approve workflow requiring '{required_role}'."
            )

        workflow.approved_by_id = user.id
        workflow.approved_at = now

        context = dict(workflow.context_data or {})
        context["approval_notes"] = notes
        workflow.context_data = context

        OrchestrationStateMachine.transition(
            workflow=workflow,
            target_state=OrchestrationState.ACTION_QUEUED,
            reason=f"Approved by {user.email}: {notes}",
            now=now,
        )
        db.commit()
        db.refresh(workflow)
        return workflow

    @classmethod
    def reject_workflow(
        cls,
        db: Session,
        workflow_id: str,
        user: User,
        user_role: ProjectRole,
        reason: str = "Rejected by operator",
        now: Optional[datetime] = None,
    ) -> OrchestrationWorkflowRecord:
        """Operator Rejection Gate: Rejects a workflow in AWAITING_APPROVAL."""
        if now is None:
            now = utc_now()

        workflow = db.query(OrchestrationWorkflowRecord).filter(OrchestrationWorkflowRecord.id == workflow_id).first()
        if not workflow:
            raise ValueError(f"Workflow '{workflow_id}' not found.")

        if workflow.state != OrchestrationState.AWAITING_APPROVAL:
            raise OrchestrationTransitionError(
                f"Workflow '{workflow_id}' is in state '{workflow.state.value}'. Only AWAITING_APPROVAL can be rejected."
            )

        OrchestrationStateMachine.transition(
            workflow=workflow,
            target_state=OrchestrationState.COMPLETED,
            reason=f"Rejected by operator {user.email}: {reason}",
            now=now,
        )
        if workflow.trigger_event:
            EventProcessingService.mark_event_processed(db=db, event=workflow.trigger_event, now=now)

        db.commit()
        db.refresh(workflow)
        return workflow

    @classmethod
    def suspend_workflow(
        cls,
        db: Session,
        workflow_id: str,
        user: User,
        reason: str = "Operator suspended workflow",
        now: Optional[datetime] = None,
    ) -> OrchestrationWorkflowRecord:
        """Suspends an active or queued workflow."""
        if now is None:
            now = utc_now()

        workflow = db.query(OrchestrationWorkflowRecord).filter(OrchestrationWorkflowRecord.id == workflow_id).first()
        if not workflow:
            raise ValueError(f"Workflow '{workflow_id}' not found.")

        OrchestrationStateMachine.transition(
            workflow=workflow,
            target_state=OrchestrationState.SUSPENDED,
            reason=f"Operator {user.email} suspended: {reason}",
            now=now,
        )
        db.commit()
        db.refresh(workflow)
        return workflow

    @classmethod
    def resume_workflow(
        cls,
        db: Session,
        workflow_id: str,
        user: User,
        now: Optional[datetime] = None,
    ) -> OrchestrationWorkflowRecord:
        """Resumes a suspended workflow after re-validating safety conditions."""
        if now is None:
            now = utc_now()

        workflow = db.query(OrchestrationWorkflowRecord).filter(OrchestrationWorkflowRecord.id == workflow_id).first()
        if not workflow:
            raise ValueError(f"Workflow '{workflow_id}' not found.")

        if workflow.state != OrchestrationState.SUSPENDED:
            raise OrchestrationTransitionError(
                f"Cannot resume workflow in status '{workflow.state.value}'. Only SUSPENDED workflows can be resumed."
            )

        # Re-check authorization before resuming
        auth_check = DecisionPlannerService.evaluate_authorization(
            db=db,
            project_id=workflow.project_id,
            target_resource=workflow.target_resource,
            action_type=workflow.recommended_action or OrchestrationActionType.NO_ACTION_REQUIRED,
            now=now,
        )
        if not auth_check["is_authorized"]:
            raise OrchestrationAuthorizationError(
                f"Cannot resume workflow: Target is not authorized ({auth_check['reason']})."
            )

        workflow.suspension_reason = None
        OrchestrationStateMachine.transition(
            workflow=workflow,
            target_state=OrchestrationState.DECISION_PENDING,
            reason=f"Resumed by {user.email}",
            now=now,
        )
        db.commit()
        db.refresh(workflow)
        return workflow

    @classmethod
    def retry_workflow(
        cls,
        db: Session,
        workflow_id: str,
        user: User,
        now: Optional[datetime] = None,
    ) -> OrchestrationWorkflowRecord:
        """Retries a failed workflow subject to max retry bounds."""
        if now is None:
            now = utc_now()

        workflow = db.query(OrchestrationWorkflowRecord).filter(OrchestrationWorkflowRecord.id == workflow_id).first()
        if not workflow:
            raise ValueError(f"Workflow '{workflow_id}' not found.")

        if workflow.state != OrchestrationState.FAILED:
            raise OrchestrationTransitionError(
                f"Cannot retry workflow in state '{workflow.state.value}'. Only FAILED workflows can be retried."
            )

        if workflow.attempt_count >= workflow.max_retries:
            raise OrchestrationTransitionError(
                f"Workflow '{workflow_id}' has reached maximum retry attempts ({workflow.max_retries})."
            )

        # Re-check scope before queueing retry
        auth_check = DecisionPlannerService.evaluate_authorization(
            db=db,
            project_id=workflow.project_id,
            target_resource=workflow.target_resource,
            action_type=workflow.recommended_action or OrchestrationActionType.NO_ACTION_REQUIRED,
            now=now,
        )
        if not auth_check["is_authorized"]:
            raise OrchestrationAuthorizationError(
                f"Cannot retry workflow: Target is not authorized ({auth_check['reason']})."
            )

        workflow.failure_reason = None
        OrchestrationStateMachine.transition(
            workflow=workflow,
            target_state=OrchestrationState.ACTION_QUEUED,
            reason=f"Retry initiated by {user.email}",
            now=now,
        )
        db.commit()
        db.refresh(workflow)
        return workflow
