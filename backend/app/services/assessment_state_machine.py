from datetime import datetime, timezone
from typing import Dict, Set, Optional
from app.models.assessment import AssessmentStatus, AssessmentJob


class InvalidStateTransitionException(Exception):
    """Raised when an illegal assessment job state transition is attempted."""
    pass


# Strict finite state machine governing assessment lifecycle
LEGAL_TRANSITIONS: Dict[AssessmentStatus, Set[AssessmentStatus]] = {
    AssessmentStatus.QUEUED: {
        AssessmentStatus.RUNNING,
        AssessmentStatus.CANCELLED,
        AssessmentStatus.FAILED,
    },
    AssessmentStatus.RUNNING: {
        AssessmentStatus.COMPLETED,
        AssessmentStatus.PARTIAL,
        AssessmentStatus.FAILED,
        AssessmentStatus.CANCELLED,
        AssessmentStatus.TIMED_OUT,
    },
    AssessmentStatus.COMPLETED: set(),  # Terminal state
    AssessmentStatus.FAILED: set(),     # Terminal state (requires new job or explicit retry)
    AssessmentStatus.CANCELLED: set(),  # Terminal state
    AssessmentStatus.TIMED_OUT: set(),  # Terminal state
    AssessmentStatus.PARTIAL: set(),    # Terminal state
}


class AssessmentStateMachine:
    @staticmethod
    def can_transition(current: AssessmentStatus, target: AssessmentStatus) -> bool:
        """Check if transition between statuses is legal under the state machine rules."""
        return target in LEGAL_TRANSITIONS.get(current, set())

    @classmethod
    def transition(
        cls,
        job: AssessmentJob,
        new_status: AssessmentStatus,
        error_message: Optional[str] = None,
        now: Optional[datetime] = None,
    ) -> AssessmentJob:
        """
        Transition an assessment job to a new state.
        Validates legality and updates associated execution timestamps.
        """
        if now is None:
            now = datetime.now(timezone.utc)

        if not cls.can_transition(job.status, new_status):
            raise InvalidStateTransitionException(
                f"Illegal assessment state transition from '{job.status.value}' to '{new_status.value}'."
            )

        job.status = new_status

        if new_status == AssessmentStatus.RUNNING:
            if not job.started_at:
                job.started_at = now
            if job.progress_pct == 0:
                job.progress_pct = 10

        elif new_status in (
            AssessmentStatus.COMPLETED,
            AssessmentStatus.PARTIAL,
            AssessmentStatus.FAILED,
            AssessmentStatus.CANCELLED,
            AssessmentStatus.TIMED_OUT,
        ):
            job.completed_at = now
            if new_status == AssessmentStatus.COMPLETED:
                job.progress_pct = 100
            elif new_status == AssessmentStatus.PARTIAL:
                job.progress_pct = max(job.progress_pct, 75)

        if error_message is not None:
            job.error_message = error_message

        return job

    @classmethod
    def check_timeout(cls, job: AssessmentJob, now: Optional[datetime] = None) -> bool:
        """Evaluate if an active RUNNING job has exceeded its configured execution deadline."""
        if job.status != AssessmentStatus.RUNNING or not job.started_at:
            return False

        if now is None:
            now = datetime.now(timezone.utc)

        started = job.started_at
        if started.tzinfo is None:
            started = started.replace(tzinfo=timezone.utc)
        if now.tzinfo is None:
            now = now.replace(tzinfo=timezone.utc)

        elapsed = (now - started).total_seconds()
        if elapsed > job.timeout_seconds:
            cls.transition(
                job,
                AssessmentStatus.TIMED_OUT,
                error_message=f"Assessment exceeded maximum allocated execution time of {job.timeout_seconds} seconds.",
                now=now,
            )
            return True
        return False
