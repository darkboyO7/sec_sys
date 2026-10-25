import pytest
from datetime import datetime, timedelta, timezone
from app.models.assessment import AssessmentJob, AssessmentStatus
from app.services.assessment_state_machine import (
    AssessmentStateMachine,
    InvalidStateTransitionException,
)


def create_dummy_job(status=AssessmentStatus.QUEUED) -> AssessmentJob:
    return AssessmentJob(
        id="job-uuid-1",
        project_id="proj-uuid-1",
        target_input="192.168.1.50",
        adapter_name="local_fixture_adapter",
        adapter_version="1.0.0",
        status=status,
        progress_pct=0,
        timeout_seconds=60,
        created_by_id="user-1",
    )


def test_legal_state_machine_transitions():
    now = datetime.now(timezone.utc)

    # 1. QUEUED -> RUNNING
    job1 = create_dummy_job(AssessmentStatus.QUEUED)
    AssessmentStateMachine.transition(job1, AssessmentStatus.RUNNING, now=now)
    assert job1.status == AssessmentStatus.RUNNING
    assert job1.started_at == now
    assert job1.progress_pct == 10

    # 2. RUNNING -> COMPLETED
    AssessmentStateMachine.transition(job1, AssessmentStatus.COMPLETED, now=now)
    assert job1.status == AssessmentStatus.COMPLETED
    assert job1.completed_at == now
    assert job1.progress_pct == 100

    # 3. QUEUED -> CANCELLED
    job2 = create_dummy_job(AssessmentStatus.QUEUED)
    AssessmentStateMachine.transition(job2, AssessmentStatus.CANCELLED, error_message="Cancelled by user", now=now)
    assert job2.status == AssessmentStatus.CANCELLED
    assert job2.completed_at == now
    assert job2.error_message == "Cancelled by user"

    # 4. RUNNING -> PARTIAL
    job3 = create_dummy_job(AssessmentStatus.RUNNING)
    AssessmentStateMachine.transition(job3, AssessmentStatus.PARTIAL, error_message="Partial failures", now=now)
    assert job3.status == AssessmentStatus.PARTIAL
    assert job3.progress_pct >= 75

    # 5. RUNNING -> FAILED
    job4 = create_dummy_job(AssessmentStatus.RUNNING)
    AssessmentStateMachine.transition(job4, AssessmentStatus.FAILED, error_message="Driver crash", now=now)
    assert job4.status == AssessmentStatus.FAILED


def test_illegal_state_machine_transitions():
    now = datetime.now(timezone.utc)

    # COMPLETED is terminal
    completed_job = create_dummy_job(AssessmentStatus.COMPLETED)
    with pytest.raises(InvalidStateTransitionException):
        AssessmentStateMachine.transition(completed_job, AssessmentStatus.RUNNING, now=now)

    with pytest.raises(InvalidStateTransitionException):
        AssessmentStateMachine.transition(completed_job, AssessmentStatus.FAILED, now=now)

    # CANCELLED is terminal
    cancelled_job = create_dummy_job(AssessmentStatus.CANCELLED)
    with pytest.raises(InvalidStateTransitionException):
        AssessmentStateMachine.transition(cancelled_job, AssessmentStatus.COMPLETED, now=now)

    # FAILED is terminal
    failed_job = create_dummy_job(AssessmentStatus.FAILED)
    with pytest.raises(InvalidStateTransitionException):
        AssessmentStateMachine.transition(failed_job, AssessmentStatus.RUNNING, now=now)


def test_timeout_transition_detection():
    now = datetime.now(timezone.utc)
    started = now - timedelta(seconds=120)

    # Job with 60 second timeout that started 120 seconds ago must time out
    job = create_dummy_job(AssessmentStatus.RUNNING)
    job.started_at = started
    job.timeout_seconds = 60

    timed_out = AssessmentStateMachine.check_timeout(job, now=now)
    assert timed_out is True
    assert job.status == AssessmentStatus.TIMED_OUT
    assert "exceeded maximum allocated execution time" in job.error_message

    # Job that has only been running for 30s must NOT time out
    job2 = create_dummy_job(AssessmentStatus.RUNNING)
    job2.started_at = now - timedelta(seconds=30)
    job2.timeout_seconds = 60

    timed_out2 = AssessmentStateMachine.check_timeout(job2, now=now)
    assert timed_out2 is False
    assert job2.status == AssessmentStatus.RUNNING
