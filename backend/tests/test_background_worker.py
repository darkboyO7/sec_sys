import os
import pytest
from datetime import datetime, timezone
from app.models.project import Project
from app.models.scope import ScopeTarget, TargetType, AuthorizationStatus
from app.models.assessment import AssessmentJob, AssessmentStatus
from app.models.user import User
from app.services.assessment_engine import AssessmentExecutionEngine
from scripts.run_background_worker import run_worker_loop


def test_background_worker_claims_and_executes_queued_job(
    db,
    test_project: Project,
    lead_user: User,
):
    # 1. Authorize target
    target = ScopeTarget(
        project_id=test_project.id,
        target_type=TargetType.DOMAIN,
        target_value="worker-queue-test.corp",
        authorization_status=AuthorizationStatus.AUTHORIZED,
        authorization_evidence="ROE-WORKER-TEST",
        authorized_by_id=lead_user.id,
        authorized_at=datetime.now(timezone.utc),
        created_by_id=lead_user.id,
    )
    db.add(target)
    db.commit()

    # 2. Enqueue an assessment job without executing it (QUEUED status)
    job = AssessmentJob(
        project_id=test_project.id,
        target_input="worker-queue-test.corp",
        adapter_name="local_fixture_adapter",
        config={"fixture_profile": "WEB_APPLICATION_BASELINE"},
        timeout_seconds=30,
        status=AssessmentStatus.QUEUED,
        created_by_id=lead_user.id,
    )
    db.add(job)
    db.commit()
    db.refresh(job)

    assert job.status == AssessmentStatus.QUEUED
    assert job.claimed_by is None

    # 3. Run worker loop once to claim and execute
    processed_count = run_worker_loop(
        worker_id="test-daemon-worker",
        poll_interval=0.1,
        once=True,
        db_session=db,
    )
    assert processed_count == 1

    # 4. Refresh and assert job completed
    db.refresh(job)
    assert job.status == AssessmentStatus.COMPLETED
    assert job.claimed_by == "test-daemon-worker"
    assert job.progress_pct == 100
    assert len(job.findings) >= 2
    assert job.completed_at is not None
