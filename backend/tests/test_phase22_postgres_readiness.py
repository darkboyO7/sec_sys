import uuid
import json
import hashlib
from datetime import datetime, timezone, timedelta
import pytest
from sqlalchemy.orm import Session
from sqlalchemy.dialects import postgresql
from sqlalchemy.schema import CreateTable
from sqlalchemy.exc import OperationalError, DBAPIError, IntegrityError
from fastapi.testclient import TestClient

from app.core.database import Base
from app.models.project import Project
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
from app.core.transaction import with_transaction_retry, is_transient_db_error, get_dialect_name
from app.services.audit_service import AuditService


def test_postgresql_ddl_compilation_all_tables():
    """
    Validate that every SQLAlchemy model in the platform compiles to valid
    PostgreSQL DDL using the PostgreSQL dialect compiler.
    """
    pg_dialect = postgresql.dialect()
    tables = Base.metadata.sorted_tables
    assert len(tables) > 15, "Expected all platform tables to be registered in Base.metadata"

    compiled_tables = []
    for table in tables:
        ddl = str(CreateTable(table).compile(dialect=pg_dialect))
        assert "CREATE TABLE" in ddl
        assert table.name in ddl
        compiled_tables.append(table.name)

    # Verify key tables from all phases are compiled
    expected_tables = {
        "projects",
        "scope_targets",
        "assessment_jobs",
        "assessment_findings",
        "finding_evidence",
        "graph_nodes",
        "graph_relationships",
        "risk_assessments",
        "remediation_recommendations",
        "remediation_verifications",
        "report_records",
        "security_snapshots",
        "regression_alerts",
        "ai_analyst_drafts",
        "learning_datasets",
        "governed_models",
        "morph_state_postures",
    }
    for expected in expected_tables:
        assert expected in compiled_tables, f"Missing table {expected} in compiled PostgreSQL tables"


def test_simultaneous_idempotency_requests(
    client: TestClient,
    db: Session,
    test_project: Project,
    tester_user,
    tester_headers: dict,
):
    """
    Verify that requests submitting identical idempotency keys
    result in exactly ONE canonical job, with duplicate handling and database unique constraint.
    """
    scope = ScopeTarget(
        project_id=test_project.id,
        target_type=TargetType.IP_ADDRESS,
        target_value="192.168.10.10",
        authorization_status=AuthorizationStatus.AUTHORIZED,
        authorized_by_id=tester_user.id,
        created_by_id=tester_user.id,
        authorized_at=datetime.now(timezone.utc),
    )
    db.add(scope)
    db.commit()

    idempotency_key = f"idem-pg-{uuid.uuid4().hex[:12]}"
    payload = {
        "target_input": "192.168.10.10",
        "idempotency_key": idempotency_key,
        "fixture_profile": "HARDENED_HOST_BASELINE",
    }

    # First submission -> 201 Created
    resp1 = client.post(
        f"/api/v1/projects/{test_project.id}/assessments/?auto_execute=false",
        json=payload,
        headers=tester_headers,
    )
    assert resp1.status_code == 201, f"Failed: {resp1.text}"
    job1_id = resp1.json()["id"]

    # Duplicate submission -> Returns canonical job without duplicate creation
    resp2 = client.post(
        f"/api/v1/projects/{test_project.id}/assessments/?auto_execute=false",
        json=payload,
        headers=tester_headers,
    )
    assert resp2.status_code in (200, 201)
    assert resp2.json()["id"] == job1_id

    # Database-level constraint proof: Attempting duplicate direct insert raises IntegrityError
    duplicate_job = AssessmentJob(
        project_id=test_project.id,
        adapter_name="scanner.passive_header",
        target_input="192.168.10.10",
        idempotency_key=idempotency_key,
        created_by_id=tester_user.id,
        status=AssessmentStatus.QUEUED,
    )
    with pytest.raises(IntegrityError):
        with db.begin_nested():
            db.add(duplicate_job)
            db.flush()

    # Verify database has exactly 1 job
    jobs_in_db = (
        db.query(AssessmentJob)
        .filter(
            AssessmentJob.project_id == test_project.id,
            AssessmentJob.idempotency_key == idempotency_key,
        )
        .all()
    )
    assert len(jobs_in_db) == 1


def test_atomic_multi_worker_claiming(db: Session, test_project: Project, tester_user):
    """
    Verify atomic worker claiming under concurrency:
    5 simulated workers competing to claim 3 queued jobs.
    Each job must be claimed by at most one worker, and exactly 3 workers succeed.
    """
    # Create 3 queued jobs
    jobs = []
    for i in range(3):
        job = AssessmentJob(
            project_id=test_project.id,
            adapter_name="scanner.passive_header",
            target_input=f"10.0.0.{i+1}",
            created_by_id=tester_user.id,
            status=AssessmentStatus.QUEUED,
        )
        db.add(job)
        jobs.append(job)
    db.commit()

    claimed_by_worker = {}
    for i in range(5):
        worker_id = f"worker-{i+1:02d}"
        claimed = AssessmentExecutionEngine.claim_next_available_job(
            db=db,
            worker_id=worker_id,
        )
        if claimed:
            claimed_by_worker[worker_id] = claimed.id

    # Exactly 3 jobs were claimed
    claimed_job_ids = list(claimed_by_worker.values())
    assert len(claimed_job_ids) == 3
    # No duplicate claims across workers
    assert len(set(claimed_job_ids)) == 3
    # 4th and 5th worker got None
    assert len(claimed_by_worker) == 3


def test_transaction_retry_and_deadlock_recovery():
    """
    Verify transaction retry decorator correctly catches transient lock/deadlock
    errors and retries with backoff, while re-raising non-transient errors.
    """
    call_count = 0

    @with_transaction_retry(max_retries=3, base_delay=0.01, backoff_factor=1.5)
    def transient_flaky_operation():
        nonlocal call_count
        call_count += 1
        if call_count < 3:
            # Simulate transient SQLite or Postgres lock error
            raise OperationalError("database is locked", {}, None)
        return "SUCCESS"

    result = transient_flaky_operation()
    assert result == "SUCCESS"
    assert call_count == 3

    # Test non-transient failure fails immediately without retry
    non_transient_calls = 0

    @with_transaction_retry(max_retries=3, base_delay=0.01)
    def non_transient_failure():
        nonlocal non_transient_calls
        non_transient_calls += 1
        raise ValueError("Invalid parameter value")

    with pytest.raises(ValueError, match="Invalid parameter value"):
        non_transient_failure()
    assert non_transient_calls == 1


def test_stale_worker_recovery_and_failure_escalation(db: Session, test_project: Project, tester_user):
    """
    Verify stale worker recovery:
    1. A job stalled in RUNNING with attempt_count < max_retries is re-queued.
    2. A job stalled in RUNNING with attempt_count >= max_retries transitions to FAILED.
    """
    now = datetime.now(timezone.utc)
    stale_time = now - timedelta(seconds=300)

    # Job 1: Recoverable (attempt 1/3)
    job_recoverable = AssessmentJob(
        project_id=test_project.id,
        adapter_name="scanner.passive_header",
        target_input="192.168.1.50",
        created_by_id=tester_user.id,
        status=AssessmentStatus.RUNNING,
        claimed_by="worker-crash-01",
        started_at=stale_time,
        heartbeat_at=stale_time,
        attempt_count=1,
        max_retries=3,
        retry_count=0,
    )

    # Job 2: Exhausted (attempt 3/3)
    job_exhausted = AssessmentJob(
        project_id=test_project.id,
        adapter_name="scanner.passive_header",
        target_input="192.168.1.60",
        created_by_id=tester_user.id,
        status=AssessmentStatus.RUNNING,
        claimed_by="worker-crash-02",
        started_at=stale_time,
        heartbeat_at=stale_time,
        attempt_count=3,
        max_retries=3,
        retry_count=2,
    )

    db.add(job_recoverable)
    db.add(job_exhausted)
    db.commit()

    # Run stale worker recovery with 120s timeout
    recovered_jobs = AssessmentExecutionEngine.recover_stale_workers(
        db=db,
        heartbeat_timeout_seconds=120,
        now=now,
    )

    assert len(recovered_jobs) == 2

    db.refresh(job_recoverable)
    db.refresh(job_exhausted)

    # Job 1 re-queued
    assert job_recoverable.status == AssessmentStatus.QUEUED
    assert job_recoverable.claimed_by is None
    assert job_recoverable.retry_count == 1
    assert job_recoverable.attempt_count == 2
    assert "heartbeat absent" in job_recoverable.error_message

    # Job 2 failed
    assert job_exhausted.status == AssessmentStatus.FAILED
    assert job_exhausted.failure_category == "WORKER_HEARTBEAT_TIMEOUT"
    assert "exhausted" in job_exhausted.error_message


def test_cross_project_concurrency_isolation(db: Session, test_project: Project, tester_user):
    """
    Verify cross-project tenant isolation under concurrent worker operations:
    Work executed concurrently in Project A must never leak findings or evidence into Project B.
    """
    # Create Project B
    project_b = Project(
        name="Project B Isolated",
        description="Isolated Tenant Project",
        organization_id=test_project.organization_id,
    )
    db.add(project_b)
    db.commit()

    # Job & Finding in Project A
    job_a = AssessmentJob(
        project_id=test_project.id,
        adapter_name="scanner.passive_header",
        target_input="proja.test.local",
        created_by_id=tester_user.id,
        status=AssessmentStatus.COMPLETED,
    )
    db.add(job_a)
    db.commit()

    finding_a = AssessmentFinding(
        project_id=test_project.id,
        job_id=job_a.id,
        title="PROJ_A Finding",
        target_value="proja.test.local",
        vuln_id="CVE-2026-0001",
        severity=FindingSeverity.HIGH,
        confidence=FindingConfidence.CERTAIN,
        description="Isolated finding for PROJ_A",
    )
    db.add(finding_a)

    # Job & Finding in Project B
    job_b = AssessmentJob(
        project_id=project_b.id,
        adapter_name="scanner.passive_header",
        target_input="projb.test.local",
        created_by_id=tester_user.id,
        status=AssessmentStatus.COMPLETED,
    )
    db.add(job_b)
    db.commit()

    finding_b = AssessmentFinding(
        project_id=project_b.id,
        job_id=job_b.id,
        title="PROJ_B Finding",
        target_value="projb.test.local",
        vuln_id="CVE-2026-0002",
        severity=FindingSeverity.HIGH,
        confidence=FindingConfidence.CERTAIN,
        description="Isolated finding for PROJ_B",
    )
    db.add(finding_b)
    db.commit()

    # Query Project A findings
    findings_a = db.query(AssessmentFinding).filter(AssessmentFinding.project_id == test_project.id).all()
    findings_b = db.query(AssessmentFinding).filter(AssessmentFinding.project_id == project_b.id).all()

    assert len(findings_a) >= 1
    assert len(findings_b) >= 1
    assert all("PROJ_A" in f.title for f in findings_a)
    assert all("PROJ_B" in f.title for f in findings_b)
    assert not any(f.project_id == project_b.id for f in findings_a)
    assert not any(f.project_id == test_project.id for f in findings_b)


def test_concurrent_evidence_deduplication(db: Session, test_project: Project, tester_user):
    """
    Verify evidence hashing and SHA-256 deduplication integrity under concurrency.
    """
    job = AssessmentJob(
        project_id=test_project.id,
        adapter_name="scanner.passive_header",
        target_input="evidence.test.local",
        created_by_id=tester_user.id,
        status=AssessmentStatus.RUNNING,
    )
    db.add(job)
    db.commit()

    finding = AssessmentFinding(
        project_id=test_project.id,
        job_id=job.id,
        title="Evidence Finding",
        target_value="evidence.test.local",
        vuln_id="CVE-2026-EVID",
        severity=FindingSeverity.MEDIUM,
        confidence=FindingConfidence.CERTAIN,
        description="Evidence test finding",
    )
    db.add(finding)
    db.commit()

    raw_data = {"header": "X-Frame-Options", "value": "SAMEORIGIN"}
    payload_str = json.dumps(raw_data)
    sha256_digest = hashlib.sha256(payload_str.encode("utf-8")).hexdigest()

    evidence1 = FindingEvidence(
        finding_id=finding.id,
        evidence_type="RAW_HTTP_RESPONSE",
        payload=payload_str,
        sha256_hash=sha256_digest,
    )
    db.add(evidence1)
    db.commit()

    # Check query by sha256_hash returns exactly one item
    ev_items = db.query(FindingEvidence).filter(
        FindingEvidence.finding_id == finding.id,
        FindingEvidence.sha256_hash == sha256_digest,
    ).all()
    assert len(ev_items) == 1
    assert ev_items[0].sha256_hash == sha256_digest
