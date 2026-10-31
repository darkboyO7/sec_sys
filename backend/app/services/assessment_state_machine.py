from datetime import datetime, timezone
from typing import Dict, Set, Optional
from app.models.assessment import AssessmentStatus, AssessmentJob


class InvalidStateTransitionException(Exception):
    """Raised when an illegal assessment job state transition is attempted."""
    pass


# Strict finite state machine governing assessment lifecycle
LEGAL_TRANSITIONS: Dict[AssessmentStatus, Set[AssessmentStatus]] = {
    AssessmentStatus.QUEUED: {
        AssessmentStatus.PREFLIGHT,
        AssessmentStatus.RUNNING,  # direct execution support
        AssessmentStatus.CANCELLATION_REQUESTED,
        AssessmentStatus.CANCELLED,
        AssessmentStatus.FAILED,
        AssessmentStatus.REJECTED,
        AssessmentStatus.DEAD_LETTER,
    },
    AssessmentStatus.PREFLIGHT: {
        AssessmentStatus.READY,
        AssessmentStatus.RUNNING,
        AssessmentStatus.CANCELLATION_REQUESTED,
        AssessmentStatus.CANCELLED,
        AssessmentStatus.FAILED,
        AssessmentStatus.REJECTED,
        AssessmentStatus.DEAD_LETTER,
    },
    AssessmentStatus.READY: {
        AssessmentStatus.RUNNING,
        AssessmentStatus.CANCELLATION_REQUESTED,
        AssessmentStatus.CANCELLED,
        AssessmentStatus.FAILED,
        AssessmentStatus.DEAD_LETTER,
    },
    AssessmentStatus.RUNNING: {
        AssessmentStatus.COMPLETED,
        AssessmentStatus.PARTIAL,
        AssessmentStatus.FAILED,
        AssessmentStatus.CANCELLATION_REQUESTED,
        AssessmentStatus.CANCELLED,
        AssessmentStatus.TIMED_OUT,
        AssessmentStatus.DEAD_LETTER,
    },
    AssessmentStatus.CANCELLATION_REQUESTED: {
        AssessmentStatus.CANCELLED,
        AssessmentStatus.COMPLETED,
        AssessmentStatus.PARTIAL,
        AssessmentStatus.FAILED,
        AssessmentStatus.DEAD_LETTER,
    },
    AssessmentStatus.COMPLETED: set(),  # Terminal state
    AssessmentStatus.FAILED: {AssessmentStatus.QUEUED, AssessmentStatus.DEAD_LETTER},     # Terminal state (requires new job or explicit retry)
    AssessmentStatus.CANCELLED: set(),  # Terminal state
    AssessmentStatus.REJECTED: set(),   # Terminal state (preflight policy/scope denial)
    AssessmentStatus.TIMED_OUT: {AssessmentStatus.QUEUED, AssessmentStatus.DEAD_LETTER},  # Terminal state
    AssessmentStatus.PARTIAL: set(),    # Terminal state
    AssessmentStatus.DEAD_LETTER: {AssessmentStatus.QUEUED},  # Terminal DLQ state (allows replay)
}

TERMINAL_STATUSES: Set[AssessmentStatus] = {
    AssessmentStatus.COMPLETED,
    AssessmentStatus.FAILED,
    AssessmentStatus.CANCELLED,
    AssessmentStatus.REJECTED,
    AssessmentStatus.TIMED_OUT,
    AssessmentStatus.PARTIAL,
    AssessmentStatus.DEAD_LETTER,
}


class AssessmentStateMachine:
    LEGAL_TRANSITIONS = LEGAL_TRANSITIONS
    TERMINAL_STATUSES = TERMINAL_STATUSES

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
        failure_category: Optional[str] = None,
        now: Optional[datetime] = None,
    ) -> AssessmentJob:
        """
        Transition an assessment job to a new state.
        Validates legality and updates associated execution timestamps and progress.
        """
        if now is None:
            now = datetime.now(timezone.utc)

        if not cls.can_transition(job.status, new_status):
            raise InvalidStateTransitionException(
                f"Illegal assessment state transition from '{job.status.value}' to '{new_status.value}'."
            )

        job.status = new_status

        if new_status == AssessmentStatus.PREFLIGHT:
            job.preflight_at = now
            if job.progress_pct < 10:
                job.progress_pct = 10

        elif new_status == AssessmentStatus.READY:
            if job.progress_pct < 20:
                job.progress_pct = 20

        elif new_status == AssessmentStatus.RUNNING:
            if not job.started_at:
                job.started_at = now
            job.heartbeat_at = now
            if job.progress_pct < 10:
                job.progress_pct = 10

        elif new_status == AssessmentStatus.CANCELLATION_REQUESTED:
            job.cancellation_requested_at = now

        elif new_status in (
            AssessmentStatus.COMPLETED,
            AssessmentStatus.PARTIAL,
            AssessmentStatus.FAILED,
            AssessmentStatus.CANCELLED,
            AssessmentStatus.REJECTED,
            AssessmentStatus.TIMED_OUT,
        ):
            job.completed_at = now
            if new_status == AssessmentStatus.COMPLETED:
                job.progress_pct = 100
            elif new_status == AssessmentStatus.PARTIAL:
                job.progress_pct = max(job.progress_pct, 75)

        if error_message is not None:
            job.error_message = error_message
        if failure_category is not None:
            job.failure_category = failure_category

        return job

    @classmethod
    def update_progress(cls, job: AssessmentJob, progress_pct: int) -> int:
        """
        Update job execution progress with monotonic non-decreasing guarantees.
        Clamps progress between current progress and 100.
        """
        clamped = max(0, min(100, int(progress_pct)))
        if clamped > job.progress_pct:
            job.progress_pct = clamped
        return job.progress_pct

    @classmethod
    def record_heartbeat(cls, job: AssessmentJob, now: Optional[datetime] = None) -> None:
        """Record a live worker heartbeat for an actively running job."""
        if job.status == AssessmentStatus.RUNNING:
            if now is None:
                now = datetime.now(timezone.utc)
            job.heartbeat_at = now

    @classmethod
    def check_heartbeat(
        cls,
        job: AssessmentJob,
        timeout_seconds: int = 60,
        now: Optional[datetime] = None,
    ) -> bool:
        """
        Evaluate if an active RUNNING job has lost its worker heartbeat.
        If timed out, transitions to FAILED with category WORKER_HEARTBEAT_LOST.
        """
        if job.status != AssessmentStatus.RUNNING:
            return False

        if now is None:
            now = datetime.now(timezone.utc)

        last_beat = job.heartbeat_at or job.started_at
        if not last_beat:
            return False

        if last_beat.tzinfo is None:
            last_beat = last_beat.replace(tzinfo=timezone.utc)
        if now.tzinfo is None:
            now = now.replace(tzinfo=timezone.utc)

        elapsed = (now - last_beat).total_seconds()
        if elapsed > timeout_seconds:
            cls.transition(
                job,
                AssessmentStatus.FAILED,
                error_message=f"Assessment worker lost heartbeat (no report for {int(elapsed)}s).",
                failure_category="WORKER_HEARTBEAT_LOST",
                now=now,
            )
            return True
        return False

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
