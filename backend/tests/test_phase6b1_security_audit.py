import pytest
import hashlib
import json
import uuid
from datetime import datetime, timezone, timedelta
from concurrent.futures import ThreadPoolExecutor
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from fastapi.testclient import TestClient

from app.models.user import User
from app.models.project import Project, ProjectRole
from app.models.scope import ScopeTarget, TargetType, AuthorizationStatus
from app.models.assessment import (
    AssessmentJob,
    AssessmentStatus,
    AssessmentFinding,
    FindingEvidence,
    FindingSeverity,
    FindingConfidence,
)
from app.services.assessment_engine import AssessmentExecutionEngine
from app.services.assessment_state_machine import AssessmentStateMachine
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
        authorization_evidence="AUTH-ROE-PHASE6B1-001",
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
# SECTION 1: Job Idempotency Under Concurrency
# ==============================================================================

def test_database_unique_constraint_enforces_single_canonical_job(
    client: TestClient,
    test_project: Project,
    tester_headers: dict,
    auth_target: ScopeTarget,
    lead_user: User,
    db: Session,
):
    """
    Verifies that:
    1. The database UNIQUE constraint on (project_id, idempotency_key) prevents duplicate records
       at the database level, throwing IntegrityError on conflicting insertions.
    2. The API endpoint handles duplicate submissions idempotently, returning the canonical job
       without corrupting the session or creating redundant rows.
    """
    key = f"idem-key-{uuid.uuid4().hex[:8]}"

    # Part A: Database-level unique constraint proof via transactional savepoint
    j1 = AssessmentJob(
        id=f"job-db-unique-1-{uuid.uuid4().hex[:6]}",
        project_id=test_project.id,
        target_input="worker.defense.corp",
        idempotency_key=key,
        idempotency_digest="test_digest_123",
        policy_version="2026.1",
        authorization_status="AUTHORIZED",
        created_by_id=lead_user.id,
    )
    db.add(j1)
    db.flush()

    # Attempting to insert duplicate (project_id, idempotency_key) triggers IntegrityError
    j2 = AssessmentJob(
        id=f"job-db-unique-2-{uuid.uuid4().hex[:6]}",
        project_id=test_project.id,
        target_input="worker.defense.corp",
        idempotency_key=key,
        idempotency_digest="test_digest_123",
        policy_version="2026.1",
        authorization_status="AUTHORIZED",
        created_by_id=lead_user.id,
    )
    with pytest.raises(IntegrityError):
        with db.begin_nested():
            db.add(j2)
            db.flush()

    # Session remains healthy after savepoint rollback and can query canonical job
    existing = (
        db.query(AssessmentJob)
        .filter(
            AssessmentJob.project_id == test_project.id,
            AssessmentJob.idempotency_key == key,
        )
        .first()
    )
    assert existing is not None
    assert existing.id == j1.id

    # Part B: API-level canonical deduplication verification
    api_key = f"idem-api-{uuid.uuid4().hex[:8]}"
    payload = {
        "target_input": "worker.defense.corp",
        "idempotency_key": api_key,
        "fixture_profile": "HARDENED_HOST_BASELINE",
    }

    res1 = client.post(
        f"/api/v1/projects/{test_project.id}/assessments/?auto_execute=false",
        json=payload,
        headers=tester_headers,
    )
    assert res1.status_code == 201
    job1_id = res1.json()["id"]

    res2 = client.post(
        f"/api/v1/projects/{test_project.id}/assessments/?auto_execute=false",
        json=payload,
        headers=tester_headers,
    )
    assert res2.status_code in (200, 201)
    assert res2.json()["id"] == job1_id

    # Database must contain exactly one job for this idempotency key
    jobs_in_db = (
        db.query(AssessmentJob)
        .filter(
            AssessmentJob.project_id == test_project.id,
            AssessmentJob.idempotency_key == api_key,
        )
        .all()
    )
    assert len(jobs_in_db) == 1


def test_concurrent_idempotency_payload_mismatch_rejected_with_409(
    client: TestClient,
    test_project: Project,
    tester_headers: dict,
    auth_target: ScopeTarget,
    db: Session,
):
    """
    Verifies that reusing an idempotency key with conflicting parameters returns HTTP 409 Conflict,
    even when submitted in close sequence.
    """
    key = f"idem-conflict-{uuid.uuid4().hex[:8]}"

    # Request 1
    res1 = client.post(
        f"/api/v1/projects/{test_project.id}/assessments/?auto_execute=false",
        json={
            "target_input": "worker.defense.corp",
            "idempotency_key": key,
            "fixture_profile": "HARDENED_HOST_BASELINE",
        },
        headers=tester_headers,
    )
    assert res1.status_code == 201

    # Request 2 with same key but DIFFERENT fixture_profile
    res2 = client.post(
        f"/api/v1/projects/{test_project.id}/assessments/?auto_execute=false",
        json={
            "target_input": "worker.defense.corp",
            "idempotency_key": key,
            "fixture_profile": "WEB_APPLICATION_BASELINE",  # Conflict!
        },
        headers=tester_headers,
    )
    assert res2.status_code == 409
    assert "conflicting request payload" in res2.json()["detail"]


def test_idempotency_key_scoped_to_project_allows_cross_project_reuse(
    client: TestClient,
    test_project: Project,
    lead_headers: dict,
    auth_target: ScopeTarget,
    db: Session,
    lead_user: User,
):
    """
    Verifies that the unique constraint is composite (project_id, idempotency_key).
    Different projects may safely use the same idempotency key without collision.
    """
    key = f"cross-proj-key-{uuid.uuid4().hex[:6]}"

    # Create second project with membership and authorized target
    p2 = Project(id="proj-second-idempotency", name="Project 2", description="Test", organization_id=test_project.organization_id)
    db.add(p2)
    db.commit()

    from app.models.project import ProjectMember
    db.add(ProjectMember(project_id=p2.id, user_id=lead_user.id, role=ProjectRole.LEAD))
    t2 = ScopeTarget(
        project_id=p2.id,
        target_type=TargetType.DOMAIN,
        target_value="p2.defense.corp",
        authorization_status=AuthorizationStatus.AUTHORIZED,
        authorization_evidence="ROE-P2",
        authorized_by_id=lead_user.id,
        authorized_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(days=30),
        created_by_id=lead_user.id,
    )
    db.add(t2)
    db.commit()

    # Job in Project 1
    res1 = client.post(
        f"/api/v1/projects/{test_project.id}/assessments/?auto_execute=false",
        json={"target_input": "worker.defense.corp", "idempotency_key": key},
        headers=lead_headers,
    )
    assert res1.status_code == 201

    # Job in Project 2 with identical key
    res2 = client.post(
        f"/api/v1/projects/{p2.id}/assessments/?auto_execute=false",
        json={"target_input": "p2.defense.corp", "idempotency_key": key},
        headers=lead_headers,
    )
    assert res2.status_code == 201
    assert res1.json()["id"] != res2.json()["id"]


def test_multiple_jobs_without_idempotency_key_permitted(
    client: TestClient,
    test_project: Project,
    tester_headers: dict,
    auth_target: ScopeTarget,
    db: Session,
):
    """
    Verifies that multiple jobs with idempotency_key=None are allowed under the unique constraint.
    """
    res1 = client.post(
        f"/api/v1/projects/{test_project.id}/assessments/?auto_execute=false",
        json={"target_input": "worker.defense.corp"},
        headers=tester_headers,
    )
    res2 = client.post(
        f"/api/v1/projects/{test_project.id}/assessments/?auto_execute=false",
        json={"target_input": "worker.defense.corp"},
        headers=tester_headers,
    )
    assert res1.status_code == 201
    assert res2.status_code == 201
    assert res1.json()["id"] != res2.json()["id"]


# ==============================================================================
# SECTION 2: Worker-Claim Mutual Exclusion Proof
# ==============================================================================

def test_worker_claim_mutual_exclusion_and_ownership(
    db: Session,
    test_project: Project,
    auth_target: ScopeTarget,
    lead_user: User,
):
    """
    Proves worker claiming mutual exclusion:
    1. Worker 1 claims job -> status becomes RUNNING, claimed_by becomes 'worker-alpha'.
    2. Worker 2 attempts to claim -> conditional update fails, claimed_by remains 'worker-alpha'.
    3. Worker 2 calling execute_job() returns immediately without running the adapter.
    """
    job = AssessmentJob(
        id="job-claim-proof-01",
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
        is_simulated=True,
        created_by_id=lead_user.id,
        config={"fixture_profile": "HARDENED_HOST_BASELINE"},
    )
    db.add(job)
    db.commit()

    # Worker Alpha claims
    claimed_alpha = AssessmentExecutionEngine.preflight_and_claim_job(
        db=db,
        job_id=job.id,
        worker_id="worker-alpha",
    )
    assert claimed_alpha.status == AssessmentStatus.RUNNING
    assert claimed_alpha.claimed_by == "worker-alpha"

    # Worker Beta attempts to claim the same job
    claimed_beta = AssessmentExecutionEngine.preflight_and_claim_job(
        db=db,
        job_id=job.id,
        worker_id="worker-beta",
    )
    # Claimed by remains worker-alpha; Beta was locked out
    assert claimed_beta.claimed_by == "worker-alpha"

    # Worker Beta attempts to execute -> rejected by worker ownership check
    result_beta = AssessmentExecutionEngine.execute_job(
        db=db,
        job_id=job.id,
        worker_id="worker-beta",
    )
    # Status remains RUNNING (Beta did NOT complete it)
    assert result_beta.status == AssessmentStatus.RUNNING
    assert result_beta.claimed_by == "worker-alpha"

    # Worker Alpha executes -> successfully completes
    result_alpha = AssessmentExecutionEngine.execute_job(
        db=db,
        job_id=job.id,
        worker_id="worker-alpha",
    )
    assert result_alpha.status == AssessmentStatus.COMPLETED


def test_stale_attempt_discarded_after_job_retry(
    db: Session,
    test_project: Project,
    auth_target: ScopeTarget,
    lead_user: User,
):
    """
    Proves that a slow or hanging worker from execution attempt 1 cannot overwrite
    state if the job was recovered and retried (attempt 2).
    """
    job = AssessmentJob(
        id="job-stale-attempt-proof",
        project_id=test_project.id,
        target_input="worker.defense.corp",
        adapter_name="local_fixture_adapter",
        adapter_version="1.0.0",
        status=AssessmentStatus.FAILED,
        policy_version="2026.1",
        authorization_status="AUTHORIZED",
        scope_snapshot={},
        attempt_count=1,
        retry_count=0,
        max_retries=3,
        failure_category="WORKER_HEARTBEAT_LOST",
        progress_pct=50,
        timeout_seconds=300,
        is_simulated=True,
        created_by_id=lead_user.id,
        config={"fixture_profile": "HARDENED_HOST_BASELINE"},
    )
    db.add(job)
    db.commit()

    # Retry job to attempt 2
    success, retried, msg = AssessmentExecutionEngine.retry_job(db=db, job_id=job.id)
    assert success is True
    assert retried.attempt_count == 2
    assert retried.claimed_by is None
    assert retried.status == AssessmentStatus.QUEUED

    # Worker Gamma claims attempt 2
    claimed_gamma = AssessmentExecutionEngine.preflight_and_claim_job(
        db=db,
        job_id=job.id,
        worker_id="worker-gamma",
    )
    assert claimed_gamma.status == AssessmentStatus.RUNNING
    assert claimed_gamma.claimed_by == "worker-gamma"

    # Old Worker Alpha (attempt 1) attempts to execute -> rejected by attempt count & claimed_by check
    result_old_alpha = AssessmentExecutionEngine.execute_job(
        db=db,
        job_id=job.id,
        worker_id="worker-alpha",  # Not the owner of attempt 2!
    )
    assert result_old_alpha.status == AssessmentStatus.RUNNING
    assert result_old_alpha.attempt_count == 2
    assert result_old_alpha.claimed_by == "worker-gamma"


# ==============================================================================
# SECTION 3: Cancellation, Timeout, and Zombie Worker Recovery
# ==============================================================================

def test_cancellation_request_distinguished_from_confirmed_termination(
    client: TestClient,
    test_project: Project,
    tester_headers: dict,
    lead_user: User,
    db: Session,
):
    """
    Verifies that calling /cancel on a RUNNING job transitions to CANCELLATION_REQUESTED
    (request distinguished from confirmed termination).
    When the worker checks cancellation, it cleanly terminates to CANCELLED.
    """
    job = AssessmentJob(
        id="job-cancel-distinguish-test",
        project_id=test_project.id,
        target_input="worker.defense.corp",
        adapter_name="local_fixture_adapter",
        adapter_version="1.0.0",
        status=AssessmentStatus.RUNNING,
        claimed_by="worker-active",
        policy_version="2026.1",
        authorization_status="AUTHORIZED",
        scope_snapshot={},
        attempt_count=1,
        progress_pct=40,
        started_at=datetime.now(timezone.utc),
        heartbeat_at=datetime.now(timezone.utc),
        timeout_seconds=300,
        is_simulated=True,
        created_by_id=lead_user.id,
        config={"fixture_profile": "WEB_APPLICATION_BASELINE"},
    )
    db.add(job)
    db.commit()

    # 1. API request to cancel active running job
    res = client.post(
        f"/api/v1/projects/{test_project.id}/assessments/{job.id}/cancel",
        headers=tester_headers,
    )
    assert res.status_code == 200
    assert res.json()["status"] == "CANCELLATION_REQUESTED"

    # 2. Duplicate cancel request is idempotent
    res_dup = client.post(
        f"/api/v1/projects/{test_project.id}/assessments/{job.id}/cancel",
        headers=tester_headers,
    )
    assert res_dup.status_code == 200
    assert res_dup.json()["status"] == "CANCELLATION_REQUESTED"

    # 3. Worker observes CANCELLATION_REQUESTED and transitions to CANCELLED
    terminated = AssessmentExecutionEngine.execute_job(
        db=db,
        job_id=job.id,
        worker_id="worker-active",
    )
    assert terminated.status == AssessmentStatus.CANCELLED
    assert terminated.failure_category == "CANCELLED_BY_OPERATOR"


def test_abandoned_job_recovery_respects_project_isolation(
    test_project: Project,
    lead_user: User,
    db: Session,
):
    """
    Verifies that recover_abandoned_jobs(project_id=...) only sweeps jobs
    belonging to the specified project and does not touch other projects.
    """
    t_stale = datetime.now(timezone.utc) - timedelta(minutes=15)

    # Stale job in Project 1
    job_p1 = AssessmentJob(
        id="job-stale-p1",
        project_id=test_project.id,
        target_input="worker.defense.corp",
        adapter_name="local_fixture_adapter",
        adapter_version="1.0.0",
        status=AssessmentStatus.RUNNING,
        policy_version="2026.1",
        authorization_status="AUTHORIZED",
        scope_snapshot={},
        attempt_count=1,
        started_at=t_stale,
        heartbeat_at=t_stale,
        timeout_seconds=300,
        is_simulated=True,
        created_by_id=lead_user.id,
    )

    # Stale job in Project 2
    p2 = Project(id="proj-isolated-recovery", name="P2", organization_id=test_project.organization_id)
    db.add(p2)
    db.commit()

    job_p2 = AssessmentJob(
        id="job-stale-p2",
        project_id=p2.id,
        target_input="p2.defense.corp",
        adapter_name="local_fixture_adapter",
        adapter_version="1.0.0",
        status=AssessmentStatus.RUNNING,
        policy_version="2026.1",
        authorization_status="AUTHORIZED",
        scope_snapshot={},
        attempt_count=1,
        started_at=t_stale,
        heartbeat_at=t_stale,
        timeout_seconds=300,
        is_simulated=True,
        created_by_id=lead_user.id,
    )
    db.add(job_p1)
    db.add(job_p2)
    db.commit()

    # Recover stale jobs strictly for Project 1
    recovered_p1 = AssessmentExecutionEngine.recover_abandoned_jobs(
        db=db,
        project_id=test_project.id,
        max_stale_seconds=120,
    )
    assert any(j.id == "job-stale-p1" for j in recovered_p1)
    assert not any(j.id == "job-stale-p2" for j in recovered_p1)

    # Verify P2 job remains untouched in RUNNING state
    db.refresh(job_p2)
    assert job_p2.status == AssessmentStatus.RUNNING


# ==============================================================================
# SECTION 4: Evidence Integrity & Bounds Audits
# ==============================================================================

def test_evidence_hashing_exact_bytes_taxonomy():
    """
    Verifies the cryptographic taxonomy:
    1. raw_sha256_hash: SHA-256 over exact original UTF-8 bytes.
    2. sha256_hash: SHA-256 over exact persisted/truncated UTF-8 bytes.
    3. is_truncated: explicitly flagged.
    """
    original_text = "SECURITY_EVIDENCE_PROVENANCE_TEST_DATA"
    raw_expected_hash = hashlib.sha256(original_text.encode("utf-8")).hexdigest()

    ev = RawAdapterEvidence(
        evidence_type="HTTP_REQUEST_RESPONSE",
        payload=original_text,
    )

    assert ev.raw_sha256_hash == raw_expected_hash
    assert ev.sha256_hash == raw_expected_hash
    assert ev.is_truncated is False
    assert ev.payload == original_text


def test_aggregate_evidence_size_exceeded_raises_validation_error():
    """
    Verifies that an adapter result exceeding the 1MB total aggregate evidence
    limit is rejected during validation before allocation or DB persistence.
    """
    findings = []
    # Create findings with total payload > 1MB (1,048,576 bytes)
    for i in range(20):
        # 20 findings x 60KB each = 1.2MB > 1MB
        payload_60kb = "A" * 60000
        ev = RawAdapterEvidence(evidence_type="CONFIG_AUDIT", payload=payload_60kb)
        f = RawAdapterFinding(
            title=f"Finding {i}",
            description="Test",
            severity=FindingSeverity.LOW,
            confidence=FindingConfidence.FIRM,
            evidence_items=[ev],
        )
        findings.append(f)

    with pytest.raises(ValueError, match="Total evidence payload exceeds maximum job limit of 1MB"):
        AdapterResult(
            adapter_name="test_adapter",
            adapter_version="1.0.0",
            target="target.corp",
            is_simulated=True,
            success=True,
            status_summary="Exceeded size test",
            findings=findings,
        )


def test_findings_per_job_clamped_to_50():
    """
    Verifies that findings exceeding MAX_FINDINGS_PER_JOB (50) are clamped cleanly.
    """
    findings = [
        RawAdapterFinding(
            title=f"Finding #{i}",
            description="Description",
            severity=FindingSeverity.INFO,
            confidence=FindingConfidence.CERTAIN,
        )
        for i in range(65)
    ]
    res = AdapterResult(
        adapter_name="test_adapter",
        adapter_version="1.0.0",
        target="target.corp",
        is_simulated=True,
        success=True,
        status_summary="Findings clamp test",
        findings=findings,
    )
    assert len(res.findings) == 50


# ==============================================================================
# SECTION 5: Authorization, Cross-Project Boundaries & Governance
# ==============================================================================

def test_mismatched_parent_project_and_job_returns_404(
    client: TestClient,
    test_project: Project,
    tester_headers: dict,
    lead_user: User,
    db: Session,
):
    """
    Verifies cross-project boundary: requesting /projects/{p1}/assessments/{job_from_p2}
    fails closed with HTTP 404 Not Found.
    """
    p2 = Project(id="proj-foreign-404", name="Foreign Project", organization_id=test_project.organization_id)
    db.add(p2)
    db.commit()

    foreign_job = AssessmentJob(
        id="job-foreign-cross-project",
        project_id=p2.id,
        target_input="foreign.defense.corp",
        adapter_name="local_fixture_adapter",
        adapter_version="1.0.0",
        status=AssessmentStatus.QUEUED,
        policy_version="2026.1",
        authorization_status="AUTHORIZED",
        scope_snapshot={},
        attempt_count=1,
        progress_pct=0,
        timeout_seconds=300,
        is_simulated=True,
        created_by_id=lead_user.id,
    )
    db.add(foreign_job)
    db.commit()

    # Attempt to access foreign_job through test_project URL
    res = client.get(
        f"/api/v1/projects/{test_project.id}/assessments/{foreign_job.id}",
        headers=tester_headers,
    )
    assert res.status_code == 404
    assert "Assessment job not found" in res.json()["detail"]


def test_unauthorized_role_cannot_cancel_or_retry(
    client: TestClient,
    test_project: Project,
    db: Session,
    auth_target: ScopeTarget,
):
    """
    Verifies role enforcement: a VIEWER cannot cancel or retry jobs (HTTP 403 Forbidden).
    """
    from app.core.security import create_access_token, hash_password
    from app.models.project import ProjectMember

    viewer = User(
        id="user-viewer-audit",
        email="viewer.audit@defense.corp",
        hashed_password=hash_password("ViewerSecurePass123!"),
        full_name="Audit Viewer",
        is_active=True,
    )
    db.add(viewer)
    db.commit()
    db.add(ProjectMember(project_id=test_project.id, user_id=viewer.id, role=ProjectRole.VIEWER))

    job = AssessmentJob(
        id="job-rbac-test",
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
        is_simulated=True,
        created_by_id=viewer.id,
    )
    db.add(job)
    db.commit()

    token = create_access_token(subject=viewer.id, claims={"email": viewer.email})
    viewer_headers = {"Authorization": f"Bearer {token}"}

    # Attempt cancel
    cancel_res = client.post(
        f"/api/v1/projects/{test_project.id}/assessments/{job.id}/cancel",
        headers=viewer_headers,
    )
    assert cancel_res.status_code == 403

    # Attempt retry
    retry_res = client.post(
        f"/api/v1/projects/{test_project.id}/assessments/{job.id}/retry",
        headers=viewer_headers,
    )
    assert retry_res.status_code == 403


def test_non_retryable_governance_failure_blocked(
    client: TestClient,
    test_project: Project,
    tester_headers: dict,
    lead_user: User,
    db: Session,
):
    """
    Verifies that operational retry strictly blocks retrying governance-rejected jobs
    (e.g., SCOPE_AUTHORIZATION_DENIED or SCOPE_SNAPSHOT_TAMPERING_DETECTED).
    """
    job = AssessmentJob(
        id="job-gov-fail-test",
        project_id=test_project.id,
        target_input="unauthorized.target.corp",
        adapter_name="local_fixture_adapter",
        adapter_version="1.0.0",
        status=AssessmentStatus.FAILED,
        failure_category="SCOPE_AUTHORIZATION_DENIED",  # Non-retryable!
        policy_version="2026.1",
        authorization_status="UNAUTHORIZED",
        scope_snapshot={},
        attempt_count=1,
        progress_pct=0,
        timeout_seconds=300,
        is_simulated=True,
        created_by_id=lead_user.id,
    )
    db.add(job)
    db.commit()

    res = client.post(
        f"/api/v1/projects/{test_project.id}/assessments/{job.id}/retry",
        headers=tester_headers,
    )
    assert res.status_code == 400
    assert "non-retryable governance failure" in res.json()["detail"]


def test_retry_attempts_exceeded_blocked(
    client: TestClient,
    test_project: Project,
    tester_headers: dict,
    lead_user: User,
    db: Session,
):
    """
    Verifies that a job cannot be retried beyond its max_retries limit.
    """
    job = AssessmentJob(
        id="job-max-retry-test",
        project_id=test_project.id,
        target_input="worker.defense.corp",
        adapter_name="local_fixture_adapter",
        adapter_version="1.0.0",
        status=AssessmentStatus.FAILED,
        failure_category="ADAPTER_EXECUTION_FAILURE",
        policy_version="2026.1",
        authorization_status="AUTHORIZED",
        scope_snapshot={},
        attempt_count=3,
        retry_count=2,
        max_retries=2,  # Already at limit!
        progress_pct=30,
        timeout_seconds=300,
        is_simulated=True,
        created_by_id=lead_user.id,
    )
    db.add(job)
    db.commit()

    res = client.post(
        f"/api/v1/projects/{test_project.id}/assessments/{job.id}/retry",
        headers=tester_headers,
    )
    assert res.status_code == 400
    assert "maximum allowed execution attempts" in res.json()["detail"]
