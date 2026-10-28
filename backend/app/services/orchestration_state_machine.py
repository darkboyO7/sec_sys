import enum
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional, Set, Tuple
from sqlalchemy.orm import Session

from app.models.orchestration import (
    OrchestrationState,
    OrchestrationWorkflowRecord,
)
from app.models.base import utc_now


class OrchestrationTransitionError(Exception):
    """Raised when an invalid or disallowed state transition is attempted."""
    pass


class ConcurrencyLockError(Exception):
    """Raised when another worker or process holds an active lease on a workflow."""
    pass


class OrchestrationStateMachine:
    """
    Central Orchestration State Machine (Prompt 15 / Section 2).
    Enforces deterministic state transitions, safe concurrency leases,
    crash recovery, and idempotent progression.
    """

    ALLOWED_TRANSITIONS: Dict[OrchestrationState, Set[OrchestrationState]] = {
        OrchestrationState.IDLE: {
            OrchestrationState.EVENT_RECEIVED,
        },
        OrchestrationState.EVENT_RECEIVED: {
            OrchestrationState.CONTEXT_GATHERED,
            OrchestrationState.SUSPENDED,
            OrchestrationState.FAILED,
        },
        OrchestrationState.CONTEXT_GATHERED: {
            OrchestrationState.DECISION_PENDING,
            OrchestrationState.SUSPENDED,
            OrchestrationState.FAILED,
        },
        OrchestrationState.DECISION_PENDING: {
            OrchestrationState.AWAITING_APPROVAL,
            OrchestrationState.ACTION_QUEUED,
            OrchestrationState.COMPLETED,  # e.g. NO_ACTION_REQUIRED
            OrchestrationState.SUSPENDED,
            OrchestrationState.FAILED,
        },
        OrchestrationState.AWAITING_APPROVAL: {
            OrchestrationState.ACTION_QUEUED,
            OrchestrationState.COMPLETED,  # e.g. Rejected by operator
            OrchestrationState.SUSPENDED,
            OrchestrationState.FAILED,
        },
        OrchestrationState.ACTION_QUEUED: {
            OrchestrationState.ACTION_RUNNING,
            OrchestrationState.SUSPENDED,
            OrchestrationState.FAILED,
        },
        OrchestrationState.ACTION_RUNNING: {
            OrchestrationState.VERIFYING_OUTCOME,
            OrchestrationState.COMPLETED,
            OrchestrationState.PARTIALLY_COMPLETED,
            OrchestrationState.SUSPENDED,
            OrchestrationState.FAILED,
        },
        OrchestrationState.VERIFYING_OUTCOME: {
            OrchestrationState.COMPLETED,
            OrchestrationState.PARTIALLY_COMPLETED,
            OrchestrationState.SUSPENDED,
            OrchestrationState.FAILED,
        },
        OrchestrationState.SUSPENDED: {
            OrchestrationState.CONTEXT_GATHERED,
            OrchestrationState.DECISION_PENDING,
            OrchestrationState.ACTION_QUEUED,
            OrchestrationState.FAILED,
        },
        OrchestrationState.FAILED: {
            OrchestrationState.ACTION_QUEUED,  # Allowed when operator or retry engine triggers retry
            OrchestrationState.SUSPENDED,
        },
        OrchestrationState.PARTIALLY_COMPLETED: {
            OrchestrationState.ACTION_QUEUED,  # For follow-up actions
            OrchestrationState.COMPLETED,
        },
        OrchestrationState.COMPLETED: set(),  # Terminal state
    }

    @classmethod
    def can_transition(
        cls,
        current_state: OrchestrationState,
        target_state: OrchestrationState,
    ) -> bool:
        """Checks if a transition between current_state and target_state is permitted."""
        allowed = cls.ALLOWED_TRANSITIONS.get(current_state, set())
        return target_state in allowed

    @classmethod
    def transition(
        cls,
        workflow: OrchestrationWorkflowRecord,
        target_state: OrchestrationState,
        reason: Optional[str] = None,
        failure_category: Optional[str] = None,
        partial_results: Optional[Dict[str, Any]] = None,
        now: Optional[datetime] = None,
    ) -> OrchestrationWorkflowRecord:
        """
        Executes a validated state transition on an orchestration workflow.
        Maintains decision provenance, suspension reasons, and timestamps.
        """
        if now is None:
            now = utc_now()

        current = workflow.state

        # Same state transition is a no-op idempotent return
        if current == target_state:
            return workflow

        if not cls.can_transition(current, target_state):
            raise OrchestrationTransitionError(
                f"Disallowed state transition from '{current.value}' to '{target_state.value}' "
                f"for workflow '{workflow.id}'."
            )

        workflow.state = target_state
        workflow.updated_at = now

        if partial_results:
            current_results = dict(workflow.partial_results or {})
            current_results.update(partial_results)
            workflow.partial_results = current_results

        if target_state == OrchestrationState.ACTION_RUNNING and not workflow.started_at:
            workflow.started_at = now

        if target_state in (OrchestrationState.COMPLETED, OrchestrationState.PARTIALLY_COMPLETED, OrchestrationState.FAILED):
            workflow.completed_at = now
            cls.release_lock(workflow=workflow, worker_id=workflow.locked_by or "system")

        if target_state == OrchestrationState.SUSPENDED:
            workflow.suspension_reason = reason or "Workflow suspended by orchestration policy or operator."
            cls.release_lock(workflow=workflow, worker_id=workflow.locked_by or "system")

        if target_state == OrchestrationState.FAILED:
            workflow.failure_reason = reason or f"Workflow execution failed: {failure_category or 'GENERAL_ERROR'}"
            cls.release_lock(workflow=workflow, worker_id=workflow.locked_by or "system")

        return workflow

    @classmethod
    def acquire_lock(
        cls,
        workflow: OrchestrationWorkflowRecord,
        worker_id: str,
        lease_seconds: int = 60,
        now: Optional[datetime] = None,
    ) -> bool:
        """
        Acquires an exclusive concurrency lease for a worker.
        Returns True if acquired; raises ConcurrencyLockError if actively held by another worker.
        """
        if now is None:
            now = utc_now()

        if workflow.locked_by and workflow.locked_by != worker_id:
            if workflow.lock_expires_at and workflow.lock_expires_at > now:
                raise ConcurrencyLockError(
                    f"Workflow '{workflow.id}' is actively locked by worker '{workflow.locked_by}' "
                    f"until {workflow.lock_expires_at.isoformat()}."
                )

        workflow.locked_by = worker_id
        workflow.locked_at = now
        workflow.lock_expires_at = now + timedelta(seconds=lease_seconds)
        return True

    @classmethod
    def release_lock(
        cls,
        workflow: OrchestrationWorkflowRecord,
        worker_id: str,
    ) -> bool:
        """Releases the concurrency lease if held by the given worker or forced by system."""
        if workflow.locked_by == worker_id or worker_id == "system":
            workflow.locked_by = None
            workflow.locked_at = None
            workflow.lock_expires_at = None
            return True
        return False

    @classmethod
    def recover_expired_leases(
        cls,
        db: Session,
        project_id: Optional[str] = None,
        now: Optional[datetime] = None,
    ) -> int:
        """
        Crash Recovery: Identifies workflows whose lease expired while in active states
        and safely recovers them to SUSPENDED with partial evidence preserved.
        """
        if now is None:
            now = utc_now()

        query = db.query(OrchestrationWorkflowRecord).filter(
            OrchestrationWorkflowRecord.locked_by.isnot(None),
            OrchestrationWorkflowRecord.lock_expires_at <= now,
            OrchestrationWorkflowRecord.state.in_([
                OrchestrationState.ACTION_RUNNING,
                OrchestrationState.CONTEXT_GATHERED,
                OrchestrationState.DECISION_PENDING,
            ])
        )
        if project_id:
            query = query.filter(OrchestrationWorkflowRecord.project_id == project_id)

        expired_workflows = query.all()
        recovered_count = 0

        for wf in expired_workflows:
            holder = wf.locked_by
            wf.locked_by = None
            wf.locked_at = None
            wf.lock_expires_at = None
            cls.transition(
                workflow=wf,
                target_state=OrchestrationState.SUSPENDED,
                reason=f"Interrupted workflow lease held by '{holder}' expired without completion; recovered safely.",
                now=now,
            )
            recovered_count += 1

        if recovered_count > 0:
            db.commit()

        return recovered_count
