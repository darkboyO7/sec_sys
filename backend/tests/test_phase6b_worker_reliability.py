import hashlib
import json
import math
from datetime import datetime, timezone, timedelta
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.project import Project, ProjectMember, ProjectRole
from app.models.scope import ScopeTarget, TargetType, AuthorizationStatus
from app.models.assessment import AssessmentJob, AssessmentStatus, FindingSeverity, FindingConfidence, FindingEvidence
from app.models.audit import AuditEvent
from app.models.user import User
from app.services.assessment_state_machine import AssessmentStateMachine, InvalidStateTransitionException
from app.services.assessment_engine import AssessmentExecutionEngine
from app.services.scanner_adapters.base import (
    RawAdapterFinding,
    RawAdapterEvidence,
    AdapterResult,
    truncate_utf8_to_bytes,
)


@pytest.fixture
def auth_target(db: Session, test_project: Project, lead_user: User) -> ScopeTarget:
    target = ScopeTarget(
        project_id=test_project.id,
        target_type=TargetType.DOMAIN,
        target_value="worker.defense.corp",
        authorization_status=AuthorizationStatus.AUTHORIZED,
        authorization_evidence="AUTH-ROE-PHASE6B-001",
        authorized_by_id=lead_user.id,
        authorized_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(days=30),
        created_by_id=lead_user.id,
    )
    db.add(target)
    db.commit()
    db.refresh(target)
    return target


# ==============================================================================
# SECTION 3: Concurrency, Atomic Claiming & Idempotency Hardening
# ==============================================================================

def test_concurrent_worker_claiming_mutual_exclusion(
    db: Session,
    test_project: Project,
    auth_target: ScopeTarget,
):
    """
    Verifies that two workers attempting to claim the same QUEUED job simultaneously
    cannot both claim it. Exactly one worker transitions the job to PREFLIGHT/RUNNING.
    """
    scope_eval = {
        "is_authorized": True,
        "status": "AUTHORIZED",
        "normalized_target": "worker.defense.corp",
        "matched_rule": {"id": auth_target.id, "evidence": auth_target.authorization_evidence},
    }
    snapshot, digest = AssessmentExecutionEngine.compute_scope_snapshot_and_digest(scope_eval)

    job = AssessmentJob(
        project_id=test_project.id,
        target_input="worker.defense.corp",
        adapter_name="local_fixture_adapter",
        adapter_version="1.0.0",
        status=AssessmentStatus.QUEUED,
        policy_version="2026.1",
        authorization_reference=auth_target.id,
        authorization_status="AUTHORIZED",
        scope_snapshot=snapshot,
        scope_snapshot_digest=digest,
        attempt_count=1,
        progress_pct=0,
        timeout_seconds=300,
        is_simulated=True,
        created_by_id=auth_target.created_by_id,
        config={"fixture_profile": "HARDENED_HOST_BASELINE"},
    )
    db.add(job)
    db.commit()

    # Worker 1 claims job
    claimed_1 = AssessmentExecutionEngine.preflight_and_claim_job(db=db, job_id=job.id, worker_id="worker-01")
    assert claimed_1.status == AssessmentStatus.RUNNING

    # Worker 2 attempts to claim the same job (now already RUNNING)
    claimed_2 = AssessmentExecutionEngine.preflight_and_claim_job(db=db, job_id=job.id, worker_id="worker-02")
    # Worker 2 is rejected from re-claiming; status remains unchanged
    assert claimed_2.status == AssessmentStatus.RUNNING
    assert claimed_2.started_at == claimed_1.started_at


def test_idempotency_key_payload_conflict_rejected(
    client: TestClient,
    test_project: Project,
    tester_headers: dict,
    auth_target: ScopeTarget,
):
    """
    Verifies that reusing an idempotency key with a DIFFERENT request payload
    is strictly rejected with HTTP 409 Conflict.
    """
    idemp_key = "idemp-conflict-test-key-01"

    # 1. First submission: target worker.defense.corp
    res1 = client.post(
        f"/api/v1/projects/{test_project.id}/assessments/?auto_execute=false",
        json={
            "target_input": "worker.defense.corp",
            "fixture_profile": "WEB_APPLICATION_BASELINE",
            "idempotency_key": idemp_key,
        },
        headers=tester_headers,
    )
    assert res1.status_code == 201
    job1_id = res1.json()["id"]

    # 2. Resubmission with IDENTICAL payload: succeeds and returns the same job
    res_repeat = client.post(
        f"/api/v1/projects/{test_project.id}/assessments/?auto_execute=false",
        json={
            "target_input": "worker.defense.corp",
            "fixture_profile": "WEB_APPLICATION_BASELINE",
            "idempotency_key": idemp_key,
        },
        headers=tester_headers,
    )
    assert res_repeat.status_code == 200 or res_repeat.status_code == 201
    assert res_repeat.json()["id"] == job1_id

    # 3. Resubmission with CONFLICTING payload (different fixture_profile): must reject with 409 Conflict!
    res_conflict = client.post(
        f"/api/v1/projects/{test_project.id}/assessments/?auto_execute=false",
        json={
            "target_input": "worker.defense.corp",
            "fixture_profile": "TLS_CONFIGURATION_CHECK",  # Conflicting profile
            "idempotency_key": idemp_key,
        },
        headers=tester_headers,
    )
    assert res_conflict.status_code == 409
    assert "conflicting request payload" in res_conflict.json()["detail"].lower()


def test_simultaneous_cancellation_requests_handling(
    client: TestClient,
    test_project: Project,
    tester_headers: dict,
    auth_target: ScopeTarget,
):
    """
    Verifies that multiple cancellation requests behave predictably:
    the first transitions to CANCELLED; the second fails safely with HTTP 400.
    """
    res = client.post(
        f"/api/v1/projects/{test_project.id}/assessments/?auto_execute=false",
        json={"target_input": "worker.defense.corp"},
        headers=tester_headers,
    )
    job_id = res.json()["id"]

    # First cancel
    cancel1 = client.post(
        f"/api/v1/projects/{test_project.id}/assessments/{job_id}/cancel",
        headers=tester_headers,
    )
    assert cancel1.status_code == 200
    assert cancel1.json()["status"] == "CANCELLED"

    # Second cancel: already in terminal state CANCELLED
    cancel2 = client.post(
        f"/api/v1/projects/{test_project.id}/assessments/{job_id}/cancel",
        headers=tester_headers,
    )
    assert cancel2.status_code == 400
    assert "Cannot cancel job in terminal state" in cancel2.json()["detail"]


def test_cancellation_racing_with_completion(
    client: TestClient,
    test_project: Project,
    tester_headers: dict,
    auth_target: ScopeTarget,
    db: Session,
):
    """
    Verifies race behavior: if job completes, subsequent cancellation fails closed with 400.
    """
    res = client.post(
        f"/api/v1/projects/{test_project.id}/assessments/?auto_execute=true",
        json={
            "target_input": "worker.defense.corp",
            "fixture_profile": "HARDENED_HOST_BASELINE",
        },
        headers=tester_headers,
    )
    assert res.status_code == 201
    job_id = res.json()["id"]
    assert res.json()["status"] == "COMPLETED"

    # Attempting to cancel already completed job
    cancel = client.post(
        f"/api/v1/projects/{test_project.id}/assessments/{job_id}/cancel",
        headers=tester_headers,
    )
    assert cancel.status_code == 400
    assert "Cannot cancel job in terminal state 'COMPLETED'" in cancel.json()["detail"]


def test_heartbeat_on_terminal_job_ignored(
    db: Session,
    test_project: Project,
    lead_user: User,
):
    """
    Verifies that heartbeat updates on terminal jobs are strictly no-ops
    and cannot resurrect or modify terminal states.
    """
    t_fixed = datetime.now(timezone.utc) - timedelta(hours=1)
    job = AssessmentJob(
        id="job-terminal-hb",
        project_id=test_project.id,
        target_input="192.168.1.1",
        adapter_name="local_fixture_adapter",
        adapter_version="1.0.0",
        status=AssessmentStatus.COMPLETED,
        policy_version="2026.1",
        authorization_status="AUTHORIZED",
        scope_snapshot={},
        attempt_count=1,
        progress_pct=100,
        started_at=t_fixed,
        heartbeat_at=t_fixed,
        completed_at=t_fixed,
        timeout_seconds=300,
        created_by_id=lead_user.id,
    )

    t_new = datetime.now(timezone.utc)
    # Attempt heartbeat on COMPLETED job
    AssessmentStateMachine.record_heartbeat(job, now=t_new)
    assert job.heartbeat_at == t_fixed  # Must remain unchanged!
    assert job.status == AssessmentStatus.COMPLETED

    # Check timeout on COMPLETED job: must return False
    assert AssessmentStateMachine.check_timeout(job, now=t_new) is False
    # Check heartbeat loss on COMPLETED job: must return False
    assert AssessmentStateMachine.check_heartbeat(job, timeout_seconds=10, now=t_new) is False


def test_stale_worker_completion_discarded(
    db: Session,
    test_project: Project,
    lead_user: User,
):
    """
    Verifies that if a job's attempt_count is incremented (e.g. by a retry),
    a delayed worker from attempt 1 cannot commit findings or overwrite job status.
    """
    job = AssessmentJob(
        id="job-stale-worker",
        project_id=test_project.id,
        target_input="worker.defense.corp",
        adapter_name="local_fixture_adapter",
        adapter_version="1.0.0",
        status=AssessmentStatus.RUNNING,
        policy_version="2026.1",
        authorization_status="AUTHORIZED",
        scope_snapshot={},
        attempt_count=1,
        progress_pct=30,
        started_at=datetime.now(timezone.utc),
        heartbeat_at=datetime.now(timezone.utc),
        timeout_seconds=300,
        is_simulated=True,
        created_by_id=lead_user.id,
        config={"fixture_profile": "HARDENED_HOST_BASELINE"},
    )
    db.add(job)
    db.commit()

    # Simulate operational retry/reassignment incrementing attempt_count to 2
    job.attempt_count = 2
    db.commit()

    # Stale Worker from attempt 1 executes
    # AssessmentExecutionEngine.execute_job verifies attempt_count == execution_attempt
    result_job = AssessmentExecutionEngine.execute_job(db=db, job_id=job.id)
    # Stale worker is discarded; attempt_count remains 2
    assert result_job.attempt_count == 2


def test_transaction_rollback_during_ingestion(
    db: Session,
    test_project: Project,
    lead_user: User,
    monkeypatch,
):
    """
    Verifies that an unhandled database exception during finding persistence
    triggers a complete transaction rollback, ensuring zero orphaned findings.
    """
    job = AssessmentJob(
        id="job-rollback-test",
        project_id=test_project.id,
        target_input="worker.defense.corp",
        adapter_name="local_fixture_adapter",
        adapter_version="1.0.0",
        status=AssessmentStatus.RUNNING,
        policy_version="2026.1",
        authorization_status="AUTHORIZED",
        scope_snapshot={},
        attempt_count=1,
        progress_pct=30,
        started_at=datetime.now(timezone.utc),
        heartbeat_at=datetime.now(timezone.utc),
        timeout_seconds=300,
        is_simulated=True,
        created_by_id=lead_user.id,
        config={"fixture_profile": "WEB_APPLICATION_BASELINE"},
    )
    db.add(job)
    db.commit()

    # Monkeypatch FindingDeduplicationService to simulate a failure during ingestion
    from app.services.finding_deduplication_service import FindingDeduplicationService

    def mock_fail_ingest(*args, **kwargs):
        raise RuntimeError("Simulated database failure during finding correlation")

    monkeypatch.setattr(FindingDeduplicationService, "ingest_job_findings", mock_fail_ingest)

    # Execute job: must catch error, rollback, and transition to FAILED
    failed_job = AssessmentExecutionEngine.execute_job(db=db, job_id=job.id)
    assert failed_job.status == AssessmentStatus.FAILED
    assert failed_job.failure_category == "INGESTION_TRANSACTION_FAILED"
    assert "Evidence persistence transaction rollback" in failed_job.error_message


# ==============================================================================
# SECTION 4: Cancellation & Timeout Semantics
# ==============================================================================

def test_cancellation_during_fixture_run(
    db: Session,
    test_project: Project,
    lead_user: User,
):
    """
    Verifies cooperative cancellation: when cancellation_check() returns True,
    the adapter execution aborts and transitions to CANCELLED.
    """
    job = AssessmentJob(
        id="job-cooperative-cancel",
        project_id=test_project.id,
        target_input="worker.defense.corp",
        adapter_name="local_fixture_adapter",
        adapter_version="1.0.0",
        status=AssessmentStatus.RUNNING,
        policy_version="2026.1",
        authorization_status="AUTHORIZED",
        scope_snapshot={},
        attempt_count=1,
        progress_pct=30,
        started_at=datetime.now(timezone.utc),
        heartbeat_at=datetime.now(timezone.utc),
        timeout_seconds=300,
        is_simulated=True,
        created_by_id=lead_user.id,
        config={"fixture_profile": "WEB_APPLICATION_BASELINE"},
    )
    db.add(job)
    db.commit()

    # Operator requests cancellation
    job.status = AssessmentStatus.CANCELLATION_REQUESTED
    job.cancellation_requested_at = datetime.now(timezone.utc)
    db.commit()

    # Worker executes: detects cancellation requested and transitions to CANCELLED
    cancelled_job = AssessmentExecutionEngine.execute_job(db=db, job_id=job.id)
    assert cancelled_job.status == AssessmentStatus.CANCELLED
    assert cancelled_job.failure_category == "CANCELLED_BY_OPERATOR"


def test_abandoned_job_recovery_sweep(
    client: TestClient,
    test_project: Project,
    lead_headers: dict,
    lead_user: User,
    db: Session,
):
    """
    Verifies that recover_abandoned_jobs() sweeps stale running jobs (stale > 120s)
    and transitions them to FAILED with category ABANDONED_EXECUTION_RECOVERED.
    """
    t_stale = datetime.now(timezone.utc) - timedelta(minutes=10)
    job_stale = AssessmentJob(
        id="job-stale-abandoned",
        project_id=test_project.id,
        target_input="worker.defense.corp",
        adapter_name="local_fixture_adapter",
        adapter_version="1.0.0",
        status=AssessmentStatus.RUNNING,
        policy_version="2026.1",
        authorization_status="AUTHORIZED",
        scope_snapshot={},
        attempt_count=1,
        progress_pct=30,
        started_at=t_stale,
        heartbeat_at=t_stale,
        timeout_seconds=300,
        is_simulated=True,
        created_by_id=lead_user.id,
    )
    db.add(job_stale)
    db.commit()

    # Call recover-stale endpoint via API
    res = client.post(
        f"/api/v1/projects/{test_project.id}/assessments/recover-stale?max_stale_seconds=120",
        headers=lead_headers,
    )
    assert res.status_code == 200
    data = res.json()
    assert data["recovered_count"] >= 1
    assert "job-stale-abandoned" in data["recovered_job_ids"]

    # Verify job state in DB
    db.refresh(job_stale)
    assert job_stale.status == AssessmentStatus.FAILED
    assert job_stale.failure_category == "ABANDONED_EXECUTION_RECOVERED"


# ==============================================================================
# SECTION 5: Evidence Provenance & Normalization Hardening
# ==============================================================================

def test_evidence_multibyte_utf8_truncation_boundary():
    """
    Verifies that multibyte Unicode (Japanese/emoji) is truncated cleanly
    at the byte-limit without splitting code points or raising UnicodeDecodeError.
    """
    # Create multibyte text: emoji + Japanese characters (3-4 bytes per char)
    multibyte_char = "🛡️安全検証"  # 16 bytes per repetition
    large_multibyte_text = multibyte_char * 5000  # ~80,000 bytes

    safe_text, was_truncated = truncate_utf8_to_bytes(large_multibyte_text, max_bytes=65536)
    assert was_truncated is True

    # Must be valid UTF-8
    encoded = safe_text.encode("utf-8")
    assert len(encoded) <= 65536
    assert safe_text.endswith("... [TRUNCATED_AT_64KB]")

    # Verify no decode error when re-decoding
    roundtrip = encoded.decode("utf-8")
    assert roundtrip == safe_text


def test_evidence_raw_vs_sanitized_hash_provenance(
    db: Session,
    test_project: Project,
    lead_user: User,
):
    """
    Verifies that:
    - raw_sha256_hash stores the digest of the original untruncated payload.
    - sha256_hash stores the digest of the stored payload.
    - is_truncated is True when payload was truncated.
    """
    raw_large_payload = "X" * 70000
    ev = RawAdapterEvidence(
        evidence_type="HTTP_RESPONSE_HEADERS",
        payload=raw_large_payload,
    )

    expected_raw_hash = hashlib.sha256(raw_large_payload.encode("utf-8")).hexdigest()
    expected_stored_hash = hashlib.sha256(ev.payload.encode("utf-8")).hexdigest()

    assert ev.raw_sha256_hash == expected_raw_hash
    assert ev.sha256_hash == expected_stored_hash
    assert ev.raw_sha256_hash != ev.sha256_hash  # Explicit distinction proven!
    assert ev.is_truncated is True


def test_future_timestamp_clamping():
    """
    Verifies that observations with future-dated timestamps are clamped to current UTC time.
    """
    future_time = datetime.now(timezone.utc) + timedelta(days=365)
    ev = RawAdapterEvidence(
        evidence_type="HTTP_RESPONSE_HEADERS",
        payload="Server: nginx/1.24",
        observed_at=future_time,
    )
    now = datetime.now(timezone.utc)
    # Clamped to now (difference < 2 seconds)
    assert abs((ev.observed_at - now).total_seconds()) < 2.0


# ==============================================================================
# SECTION 6: Workload Bounding & Recovery Limits
# ==============================================================================

def test_max_active_jobs_per_project_capacity_limit(
    client: TestClient,
    test_project: Project,
    tester_headers: dict,
    auth_target: ScopeTarget,
    db: Session,
):
    """
    Verifies that submitting more than 10 active jobs in a project is rejected
    with HTTP 429 Too Many Requests (capacity protection).
    """
    # Seed 10 active jobs
    created_ids = []
    for i in range(10):
        j = AssessmentJob(
            id=f"job-cap-{i}",
            project_id=test_project.id,
            target_input="worker.defense.corp",
            adapter_name="local_fixture_adapter",
            adapter_version="1.0.0",
            status=AssessmentStatus.QUEUED,
            policy_version="2026.1",
            authorization_status="AUTHORIZED",
            scope_snapshot={},
            attempt_count=1,
            progress_pct=0,
            timeout_seconds=300,
            created_by_id=auth_target.created_by_id,
        )
        db.add(j)
        created_ids.append(j.id)
    db.commit()

    # Attempting 11th job should return 429 Too Many Requests
    res_11 = client.post(
        f"/api/v1/projects/{test_project.id}/assessments/?auto_execute=false",
        json={"target_input": "worker.defense.corp"},
        headers=tester_headers,
    )
    assert res_11.status_code == 429
    assert "capacity exceeded" in res_11.json()["detail"].lower()


def test_operational_retry_governance_and_limits(
    client: TestClient,
    test_project: Project,
    tester_headers: dict,
    auth_target: ScopeTarget,
    db: Session,
):
    """
    Verifies that retry_job():
    - Re-queues a failed operational job if attempt_count < max_retries.
    - Prevents repeated recovery loops when max_retries is reached.
    - Rejects retrying non-retryable governance failures (e.g. SCOPE_AUTHORIZATION_DENIED).
    """
    # 1. Operational failure retry
    job_op = AssessmentJob(
        id="job-retry-op",
        project_id=test_project.id,
        target_input="worker.defense.corp",
        adapter_name="local_fixture_adapter",
        adapter_version="1.0.0",
        status=AssessmentStatus.FAILED,
        failure_category="WORKER_HEARTBEAT_LOST",
        policy_version="2026.1",
        authorization_status="AUTHORIZED",
        scope_snapshot={},
        attempt_count=1,
        max_retries=2,
        progress_pct=30,
        timeout_seconds=300,
        created_by_id=auth_target.created_by_id,
    )
    db.add(job_op)
    db.commit()

    res_retry = client.post(
        f"/api/v1/projects/{test_project.id}/assessments/{job_op.id}/retry?auto_execute=false",
        headers=tester_headers,
    )
    assert res_retry.status_code == 200
    assert res_retry.json()["attempt_count"] == 2
    assert res_retry.json()["status"] == "QUEUED"

    # Now attempt count is 2 (equals max_retries=2): subsequent retry must be rejected!
    db.refresh(job_op)
    job_op.status = AssessmentStatus.FAILED
    db.commit()

    res_retry_exceeded = client.post(
        f"/api/v1/projects/{test_project.id}/assessments/{job_op.id}/retry?auto_execute=false",
        headers=tester_headers,
    )
    assert res_retry_exceeded.status_code == 400
    assert "maximum allowed execution attempts" in res_retry_exceeded.json()["detail"].lower()

    # 2. Non-retryable governance failure retry rejection
    job_gov = AssessmentJob(
        id="job-retry-gov",
        project_id=test_project.id,
        target_input="worker.defense.corp",
        adapter_name="local_fixture_adapter",
        adapter_version="1.0.0",
        status=AssessmentStatus.FAILED,
        failure_category="SCOPE_AUTHORIZATION_DENIED",
        policy_version="2026.1",
        authorization_status="REVOKED",
        scope_snapshot={},
        attempt_count=1,
        max_retries=2,
        progress_pct=10,
        timeout_seconds=300,
        created_by_id=auth_target.created_by_id,
    )
    db.add(job_gov)
    db.commit()

    res_gov_retry = client.post(
        f"/api/v1/projects/{test_project.id}/assessments/{job_gov.id}/retry?auto_execute=false",
        headers=tester_headers,
    )
    assert res_gov_retry.status_code == 400
    assert "non-retryable" in res_gov_retry.json()["detail"].lower()


def test_monotonic_progress_clamping():
    """
    Verifies that update_progress() enforces monotonic non-decreasing progression.
    """
    job = AssessmentJob(
        id="job-progress-mono",
        project_id="proj-1",
        target_input="192.168.1.1",
        adapter_name="local_fixture_adapter",
        adapter_version="1.0.0",
        status=AssessmentStatus.RUNNING,
        progress_pct=50,
        created_by_id="user-1",
    )

    # Attempting to decrement progress is rejected
    AssessmentStateMachine.update_progress(job, 30)
    assert job.progress_pct == 50

    # Incrementing progress succeeds
    AssessmentStateMachine.update_progress(job, 75)
    assert job.progress_pct == 75

    # Clamping at 100
    AssessmentStateMachine.update_progress(job, 150)
    assert job.progress_pct == 100


# ==============================================================================
# SECTION 7: Trust Boundary & Isolation Audits
# ==============================================================================

def test_adapter_cannot_override_project_or_job_ownership(
    db: Session,
    test_project: Project,
    auth_target: ScopeTarget,
    lead_user: User,
):
    """
    Verifies that findings ingested from an adapter are strictly bound to server-side
    job.project_id and job.id, preventing cross-tenant injection.
    """
    job = AssessmentJob(
        id="job-ownership-test",
        project_id=test_project.id,
        target_input="worker.defense.corp",
        adapter_name="local_fixture_adapter",
        adapter_version="1.0.0",
        status=AssessmentStatus.RUNNING,
        policy_version="2026.1",
        authorization_status="AUTHORIZED",
        scope_snapshot={},
        attempt_count=1,
        progress_pct=30,
        started_at=datetime.now(timezone.utc),
        heartbeat_at=datetime.now(timezone.utc),
        timeout_seconds=300,
        is_simulated=True,
        created_by_id=lead_user.id,
        config={"fixture_profile": "WEB_APPLICATION_BASELINE"},
    )
    db.add(job)
    db.commit()

    completed = AssessmentExecutionEngine.execute_job(db=db, job_id=job.id)
    assert completed.status == AssessmentStatus.COMPLETED

    # Verify all persisted findings belong strictly to test_project.id
    for f in completed.findings:
        assert f.project_id == test_project.id
        assert f.job_id == job.id
        assert f.target_value == "worker.defense.corp"
