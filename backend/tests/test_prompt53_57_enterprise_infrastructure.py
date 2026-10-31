"""
Comprehensive Test Suite for Prompts 53–57: Enterprise Infrastructure,
Database Scalability & Distributed Execution.

Verifies:
1. PostgreSQL & SQLite dual-dialect DDL and index compilation.
2. Safe transaction retry on transient locks/deadlocks with failure-safety.
3. Concurrent database read/write integrity.
4. Worker execution engine interface (LocalSubprocessWorkerEngine and DistributedWorkerEngine).
5. Idempotent job claiming with atomic fencing (fencing tokens).
6. Authenticated worker node registration (HMAC token verification, fail-closed).
7. Worker heartbeat tracking, timeout detection, and dead worker lease scavenging.
8. Poison-pill dead-letter queue (DLQ) handling and operator replay.
9. Worker process isolation & zero-secret boundary (no DB credentials or API secrets exposed).
10. Capacity management: configurable concurrency limits, queue overload backpressure (HTTP 429).
11. Workload priority admission (CRITICAL vs BACKGROUND).
12. Database diagnostics and connection pool monitoring.
13. Capacity and worker API endpoints.
"""
import os
import sys
import time
import uuid
import threading
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any

import pytest
from sqlalchemy import text
from sqlalchemy.orm import Session
from sqlalchemy.dialects import postgresql, sqlite
from sqlalchemy.schema import CreateTable, CreateIndex
from sqlalchemy.exc import OperationalError, IntegrityError
from fastapi.testclient import TestClient

from app.core.config import settings
from app.core.database import Base, engine, SessionLocal
from app.core.transaction import (
    with_safe_transaction_retry,
    with_transaction_retry,
    is_transient_db_error,
    execute_with_safe_retry,
    get_dialect_name,
)
from app.models.base import utc_now
from app.models.project import Project
from app.models.scope import ScopeTarget, TargetType, AuthorizationStatus
from app.models.assessment import AssessmentJob, AssessmentStatus
from app.models.worker_node import WorkerNode, WorkerStatus, WorkerType
from app.worker.execution_interface import (
    WorkerRegistrationRequest,
    WorkerHeartbeatRequest,
    WorkerNodeSummary,
)
from app.worker.worker_registry import worker_registry, WorkerAuthenticationError
from app.worker.local_engine import LocalSubprocessWorkerEngine
from app.worker.distributed_engine import DistributedWorkerEngine
from app.worker.engine_factory import get_worker_engine
from app.worker.ipc_schemas import WorkerIPCRequest
from app.services.subprocess_worker_runner import build_sanitized_env, SubprocessWorkerRunner
from app.services.capacity_management_service import (
    capacity_management_service,
    CapacityOverloadError,
    WorkloadPriority,
)
from app.services.database_diagnostics_service import DatabaseDiagnosticsService


# --------------------------------------------------------------------------
# Test 1: PostgreSQL & SQLite Dual-Dialect Schema & Index Compilation
# --------------------------------------------------------------------------
def test_01_postgresql_and_sqlite_model_ddl_and_index_compilation():
    """Verify every database model and index compiles cleanly to both PostgreSQL and SQLite."""
    import app.models  # load all registered models

    tables = Base.metadata.tables
    assert len(tables) >= 90, f"Expected >= 90 tables registered, found {len(tables)}"

    pg_errors = []
    sqlite_errors = []

    for name, table in tables.items():
        try:
            CreateTable(table).compile(dialect=postgresql.dialect())
        except Exception as e:
            pg_errors.append((name, str(e)))

        try:
            CreateTable(table).compile(dialect=sqlite.dialect())
        except Exception as e:
            sqlite_errors.append((name, str(e)))

    assert len(pg_errors) == 0, f"PostgreSQL DDL compilation failed for tables: {pg_errors}"
    assert len(sqlite_errors) == 0, f"SQLite DDL compilation failed for tables: {sqlite_errors}"

    # Verify all indexes compile to PostgreSQL
    index_count = 0
    idx_errors = []
    for name, table in tables.items():
        for idx in table.indexes:
            index_count += 1
            try:
                CreateIndex(idx).compile(dialect=postgresql.dialect())
            except Exception as e:
                idx_errors.append((table.name, idx.name, str(e)))

    assert index_count >= 400, f"Expected >= 400 indexes, found {index_count}"
    assert len(idx_errors) == 0, f"PostgreSQL index compilation failed: {idx_errors}"


# --------------------------------------------------------------------------
# Test 2: Safe Transaction Retry on Transient Conflicts
# --------------------------------------------------------------------------
def test_02_safe_transaction_retry_on_transient_error():
    """Verify safe transaction retry mechanism handles transient locks and rejects non-idempotent operations."""
    attempts = 0

    @with_safe_transaction_retry(max_retries=3, base_delay=0.01, is_idempotent=True)
    def flakey_operation():
        nonlocal attempts
        attempts += 1
        if attempts < 3:
            # Simulate SQLite locked error
            raise OperationalError("SELECT 1", {}, Exception("database is locked"))
        return "SUCCESS"

    result = flakey_operation()
    assert result == "SUCCESS"
    assert attempts == 3

    # Non-idempotent operations must NOT be retried to prevent duplicate processing
    non_idempotent_attempts = 0

    @with_safe_transaction_retry(max_retries=3, base_delay=0.01, is_idempotent=False)
    def non_idempotent_op():
        nonlocal non_idempotent_attempts
        non_idempotent_attempts += 1
        raise OperationalError("INSERT INTO logs", {}, Exception("database is locked"))

    with pytest.raises(OperationalError):
        non_idempotent_op()
    assert non_idempotent_attempts == 1  # Exactly 1 attempt, zero retries

    # Non-transient errors (like IntegrityError) must never be retried
    integrity_attempts = 0

    @with_safe_transaction_retry(max_retries=3, base_delay=0.01, is_idempotent=True)
    def integrity_failure():
        nonlocal integrity_attempts
        integrity_attempts += 1
        raise IntegrityError("INSERT", {}, Exception("UNIQUE constraint failed"))

    with pytest.raises(IntegrityError):
        integrity_failure()
    assert integrity_attempts == 1


# --------------------------------------------------------------------------
# Test 3: Concurrent Database Reads and Writes
# --------------------------------------------------------------------------
def test_03_concurrent_database_reads_and_writes(tmp_path):
    """Verify concurrent reads and writes execute safely without corruption under WAL mode."""
    from sqlalchemy import create_engine, event
    from sqlalchemy.orm import sessionmaker
    from app.models.organization import Organization
    from app.models.user import User

    db_file = tmp_path / "concurrent_wal_test.db"
    test_db_url = f"sqlite:///{db_file.as_posix()}"
    test_eng = create_engine(test_db_url, connect_args={"check_same_thread": False, "timeout": 30.0})

    @event.listens_for(test_eng, "connect")
    def set_pragmas(dbapi_conn, record):
        c = dbapi_conn.cursor()
        c.execute("PRAGMA journal_mode=WAL")
        c.execute("PRAGMA busy_timeout=30000")
        c.execute("PRAGMA foreign_keys=ON")
        c.close()

    # Create tables
    Base.metadata.create_all(bind=test_eng)
    SessionMaker = sessionmaker(bind=test_eng)

    # Insert prerequisite organization, project, and user in initial setup transaction
    init_session = SessionMaker()
    org = Organization(name="Concurrent Org", slug=f"concurrent-org-{uuid.uuid4().hex[:6]}")
    init_session.add(org)
    init_session.flush()
    user = User(email=f"concurrent-{uuid.uuid4().hex[:6]}@test.local", full_name="concur_user", hashed_password="pw")
    proj = Project(name="Concurrent Project", organization_id=org.id)
    init_session.add_all([user, proj])
    init_session.commit()
    user_id = user.id
    proj_id = proj.id
    init_session.close()

    errors = []
    created_ids = []

    def writer_task(worker_idx: int):
        s = SessionMaker()
        try:
            for i in range(5):
                t = ScopeTarget(
                    project_id=proj_id,
                    target_type=TargetType.IP_ADDRESS,
                    target_value=f"10.0.{worker_idx}.{i+1}",
                    authorization_status=AuthorizationStatus.AUTHORIZED,
                    description=f"Concurrent target from worker {worker_idx}",
                    created_by_id=user_id,
                )
                s.add(t)
                s.commit()
                created_ids.append(t.id)
                time.sleep(0.005)
        except Exception as e:
            errors.append(str(e))
        finally:
            s.close()

    def reader_task():
        s = SessionMaker()
        try:
            for _ in range(10):
                cnt = s.query(ScopeTarget).filter(ScopeTarget.project_id == proj_id).count()
                assert cnt >= 0
                time.sleep(0.003)
        except Exception as e:
            errors.append(str(e))
        finally:
            s.close()

    threads = [threading.Thread(target=writer_task, args=(w,)) for w in range(3)]
    threads += [threading.Thread(target=reader_task) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(errors) == 0, f"Concurrent database execution encountered errors: {errors}"
    assert len(created_ids) == 15


# --------------------------------------------------------------------------
# Test 4: Local Subprocess Worker Engine Execution
# --------------------------------------------------------------------------
def test_04_local_subprocess_worker_engine_execution(db: Session, test_project: Project):
    """Verify LocalSubprocessWorkerEngine executes jobs within isolated child process."""
    engine_inst = LocalSubprocessWorkerEngine(worker_id="test-local-worker-01")

    # Verify registration in worker registry
    engine_inst.ensure_registered(db)
    node = db.query(WorkerNode).filter(WorkerNode.worker_id == "test-local-worker-01").first()
    assert node is not None
    assert node.status == WorkerStatus.ONLINE
    assert node.worker_type == WorkerType.LOCAL_SUBPROCESS

    # Test job execution
    req = WorkerIPCRequest(
        job_id=str(uuid.uuid4()),
        project_id=test_project.id,
        worker_id="test-local-worker-01",
        attempt_count=1,
        target_input="https://example.com",
        adapter_name="local_fixture_adapter",
        adapter_version="1.0.0",
        policy_version="2026.1",
        config={},
        timeout_seconds=10,
        auth_context={"authorization_reference": "AUTH-TEST-1", "scope_snapshot_digest": "abcdef123456"},
    )
    res = engine_inst.execute_job(req)
    assert res is not None
    assert res.is_simulated is True
    assert res.success is True

    health = engine_inst.get_worker_health()
    assert health["engine_type"] == "LOCAL_SUBPROCESS"
    assert health["status"] == "HEALTHY"


# --------------------------------------------------------------------------
# Test 5: Distributed Worker Engine & Idempotent Atomic Job Claiming
# --------------------------------------------------------------------------
def test_05_distributed_worker_engine_claim_and_atomic_fencing(db: Session, test_project: Project, lead_user: Any):
    """Verify atomic job claiming prevents duplicate processing across concurrent workers."""
    # Create a queued job
    job = AssessmentJob(
        project_id=test_project.id,
        target_input="192.168.1.50",
        adapter_name="local_fixture_adapter",
        adapter_version="1.0.0",
        status=AssessmentStatus.QUEUED,
        created_by_id=lead_user.id,
        scope_snapshot_digest="digest-abc-123",
        timeout_seconds=60,
    )
    db.add(job)
    db.commit()
    db.refresh(job)

    engine1 = DistributedWorkerEngine()
    engine2 = DistributedWorkerEngine()

    # Worker 1 claims the job
    claimed1 = engine1.claim_job(worker_id="worker-dist-alpha", db=db)
    assert claimed1 is not None
    assert claimed1.id == job.id
    assert claimed1.status == AssessmentStatus.PREFLIGHT
    assert claimed1.claimed_by == "worker-dist-alpha"

    # Worker 2 attempts to claim the same job - MUST return None because job is already claimed
    claimed2 = engine2.claim_job(worker_id="worker-dist-beta", db=db)
    assert claimed2 is None

    # Verify idempotency and atomic fencing: job remains with worker 1
    db.refresh(job)
    assert job.status == AssessmentStatus.PREFLIGHT
    assert job.claimed_by == "worker-dist-alpha"


# --------------------------------------------------------------------------
# Test 6: Worker Registration & Fail-Closed Authentication
# --------------------------------------------------------------------------
def test_06_worker_registration_and_authentication(db: Session):
    """Verify worker registration enforces cryptographic token validation and fails closed on invalid credentials."""
    valid_token = settings.WORKER_REGISTRATION_SECRET or settings.SECRET_KEY

    # Valid registration
    valid_req = WorkerRegistrationRequest(
        worker_id="remote-node-001",
        worker_type="DISTRIBUTED_NODE",
        hostname="cluster-node-01.local",
        pid=1234,
        concurrency_slots=8,
        capabilities=["nmap", "zap"],
        auth_token=valid_token,
        metadata={"region": "us-east-1"},
    )
    resp = worker_registry.register_worker(valid_req, db)
    assert resp.success is True
    assert resp.worker_id == "remote-node-001"
    assert len(resp.session_token) >= 32

    # Unauthorized registration attempt (tampered token)
    tampered_req = WorkerRegistrationRequest(
        worker_id="unauthorized-rogue-node",
        worker_type="DISTRIBUTED_NODE",
        hostname="malicious.attacker.com",
        pid=9999,
        concurrency_slots=10,
        capabilities=["exploit_runner"],
        auth_token="tampered_unauthorized_token_xyz",
        metadata={},
    )
    with pytest.raises(WorkerAuthenticationError):
        worker_registry.register_worker(tampered_req, db)

    # Rogue node must not exist in registry
    rogue = db.query(WorkerNode).filter(WorkerNode.worker_id == "unauthorized-rogue-node").first()
    assert rogue is None


# --------------------------------------------------------------------------
# Test 7: Worker Heartbeat & Dead Worker Lease Scavenging
# --------------------------------------------------------------------------
def test_07_worker_heartbeat_and_dead_worker_reclamation(db: Session, test_project: Project, lead_user: Any):
    """Verify heartbeats maintain active worker status and expired leases are reclaimed."""
    worker_id = f"worker-lease-{uuid.uuid4().hex[:6]}"
    valid_token = settings.WORKER_REGISTRATION_SECRET or settings.SECRET_KEY

    reg_resp = worker_registry.register_worker(
        WorkerRegistrationRequest(
            worker_id=worker_id,
            worker_type="DISTRIBUTED_NODE",
            hostname="worker-box-1",
            auth_token=valid_token,
            concurrency_slots=4,
        ),
        db,
    )

    # Create job claimed by this worker
    job = AssessmentJob(
        project_id=test_project.id,
        target_input="10.10.10.5",
        adapter_name="local_fixture_adapter",
        status=AssessmentStatus.RUNNING,
        claimed_by=worker_id,
        created_by_id=lead_user.id,
        heartbeat_at=utc_now(),
        retry_count=0,
        max_retries=2,
    )
    db.add(job)
    db.commit()

    # Heartbeat updates active timestamp
    hb_resp = worker_registry.record_heartbeat(
        WorkerHeartbeatRequest(
            worker_id=worker_id,
            session_token=reg_resp.session_token,
            active_job_ids=[job.id],
        ),
        db,
    )
    assert hb_resp.acknowledged is True
    assert hb_resp.canceled_job_ids == []

    # Simulate worker crash: age the heartbeat past the expiration threshold
    node = db.query(WorkerNode).filter(WorkerNode.worker_id == worker_id).first()
    node.last_heartbeat_at = utc_now() - timedelta(seconds=120)
    job.heartbeat_at = utc_now() - timedelta(seconds=120)
    db.commit()

    # Reclaim stale leases
    reclaim_result = worker_registry.reclaim_stale_leases(db, timeout_seconds=30)
    assert reclaim_result["dead_workers_identified"] >= 1
    assert worker_id in reclaim_result["dead_worker_ids"]
    assert reclaim_result["requeued_count"] >= 1

    db.refresh(job)
    assert job.status == AssessmentStatus.QUEUED
    assert job.claimed_by is None
    assert job.retry_count == 1


# --------------------------------------------------------------------------
# Test 8: Poison-Pill Dead-Letter Queue (DLQ) & Operator Replay
# --------------------------------------------------------------------------
def test_08_dead_letter_queue_handling_on_repeated_failure(db: Session, test_project: Project, lead_user: Any):
    """Verify jobs exceeding retry limit transition to DEAD_LETTER and can be replayed."""
    worker_id = f"worker-crash-{uuid.uuid4().hex[:6]}"
    valid_token = settings.WORKER_REGISTRATION_SECRET or settings.SECRET_KEY

    worker_registry.register_worker(
        WorkerRegistrationRequest(
            worker_id=worker_id,
            worker_type="DISTRIBUTED_NODE",
            hostname="crash-box",
            auth_token=valid_token,
        ),
        db,
    )

    # Job that has already exhausted its retries (retry_count == max_retries)
    job = AssessmentJob(
        project_id=test_project.id,
        target_input="poison-payload-input",
        adapter_name="local_fixture_adapter",
        status=AssessmentStatus.RUNNING,
        claimed_by=worker_id,
        created_by_id=lead_user.id,
        heartbeat_at=utc_now() - timedelta(seconds=180),
        retry_count=2,
        max_retries=2,
    )
    db.add(job)
    node = db.query(WorkerNode).filter(WorkerNode.worker_id == worker_id).first()
    node.last_heartbeat_at = utc_now() - timedelta(seconds=180)
    db.commit()

    reclaim = worker_registry.reclaim_stale_leases(db, timeout_seconds=30)
    assert reclaim["dead_letter_count"] >= 1

    db.refresh(job)
    assert job.status == AssessmentStatus.DEAD_LETTER
    assert job.dead_letter_at is not None
    assert "retry limit" in job.dead_letter_reason.lower()

    # Test listing dead-letter jobs
    dlq_list = worker_registry.list_dead_letter_jobs(db)
    assert any(d.job_id == job.id for d in dlq_list)

    # Operator Replay
    replay_ok = worker_registry.replay_dead_letter_job(job.id, db)
    assert replay_ok is True
    db.refresh(job)
    assert job.status == AssessmentStatus.QUEUED
    assert job.retry_count == 0
    assert job.dead_letter_reason is None


# --------------------------------------------------------------------------
# Test 9: Zero-Secret Boundary & Worker Environment Sanitization
# --------------------------------------------------------------------------
def test_09_worker_isolation_and_zero_secret_boundary(monkeypatch):
    """Verify child and distributed worker environments never receive database URLs, secret keys, or cloud tokens."""
    # Inject sensitive variables into host environment
    monkeypatch.setenv("SECRET_KEY", "ultra_sensitive_jwt_secret_9999")
    monkeypatch.setenv("DATABASE_URL", "postgresql://admin:super_secret_pw@db.prod.internal:5432/vapt")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "AKIAIOSFODNN7EXAMPLE")
    monkeypatch.setenv("API_ACCESS_TOKEN", "bearer_token_secret_1234")

    clean_env = build_sanitized_env()

    # Verify sensitive environment variables were completely stripped
    assert "SECRET_KEY" not in clean_env
    assert "DATABASE_URL" not in clean_env
    assert "AWS_SECRET_ACCESS_KEY" not in clean_env
    assert "API_ACCESS_TOKEN" not in clean_env

    # Verify standard OS environment variables are preserved
    assert "PATH" in clean_env or "SYSTEMROOT" in clean_env


# --------------------------------------------------------------------------
# Test 10: Capacity Management & Backpressure (HTTP 429)
# --------------------------------------------------------------------------
def test_10_capacity_management_concurrency_limits_and_backpressure(db: Session, test_project: Project, lead_user: Any):
    """Verify capacity boundaries reject new jobs with HTTP 429 when concurrency or queue depth is exhausted."""
    # Temporarily set low limits for testing
    orig_limits = capacity_management_service.get_limits()
    capacity_management_service.update_limits(
        max_global_concurrency=4,
        max_project_concurrency=2,
        max_queue_depth=3,
    )

    try:
        # 1. Project concurrency limit test
        # Create 2 running jobs for this project
        job1 = AssessmentJob(
            project_id=test_project.id,
            target_input="target-1",
            status=AssessmentStatus.RUNNING,
            created_by_id=lead_user.id,
        )
        job2 = AssessmentJob(
            project_id=test_project.id,
            target_input="target-2",
            status=AssessmentStatus.RUNNING,
            created_by_id=lead_user.id,
        )
        db.add_all([job1, job2])
        db.commit()

        # Third job for same project should be rejected with 429
        with pytest.raises(CapacityOverloadError) as exc_info:
            capacity_management_service.check_admission(
                db, project_id=test_project.id, priority=WorkloadPriority.NORMAL
            )
        assert exc_info.value.status_code == 429
        assert "concurrent execution limit" in str(exc_info.value)

        # 2. Critical priority can use burst headroom (+1)
        can_burst = capacity_management_service.check_admission(
            db, project_id=test_project.id, priority=WorkloadPriority.CRITICAL
        )
        assert can_burst is True

    finally:
        capacity_management_service.update_limits(**orig_limits)


# --------------------------------------------------------------------------
# Test 11: Workload Prioritization & Queue Overload
# --------------------------------------------------------------------------
def test_11_workload_prioritization(db: Session, test_project: Project, lead_user: Any):
    """Verify queue depth limits reject normal jobs when queue is saturated."""
    orig_limits = capacity_management_service.get_limits()
    capacity_management_service.update_limits(max_queue_depth=2, max_project_concurrency=10)

    try:
        # Create 2 queued jobs
        q1 = AssessmentJob(
            project_id=test_project.id,
            target_input="q1",
            status=AssessmentStatus.QUEUED,
            created_by_id=lead_user.id,
        )
        q2 = AssessmentJob(
            project_id=test_project.id,
            target_input="q2",
            status=AssessmentStatus.QUEUED,
            created_by_id=lead_user.id,
        )
        db.add_all([q1, q2])
        db.commit()

        # Normal priority should be rejected due to queue saturation
        with pytest.raises(CapacityOverloadError) as exc:
            capacity_management_service.check_admission(
                db, project_id="another-project", priority=WorkloadPriority.NORMAL
            )
        assert exc.value.status_code == 429
        assert "queue saturated" in str(exc.value).lower()

    finally:
        capacity_management_service.update_limits(**orig_limits)


# --------------------------------------------------------------------------
# Test 12: Database Diagnostics & Connection Pool Health
# --------------------------------------------------------------------------
def test_12_database_diagnostics_and_connection_pooling(db: Session, client: TestClient, lead_headers: dict):
    """Verify DatabaseDiagnosticsService reports dialect, pool status, and latency without SQLite assumptions."""
    diag = DatabaseDiagnosticsService.run_diagnostics(db)
    assert diag["healthy"] is True
    assert diag["database"]["healthy"] is True
    assert diag["database"]["engine"] in ("sqlite", "postgresql")
    assert "pool" in diag
    assert diag["storage"]["writable"] is True

    # Test /api/v1/system/performance/sqlite-wal handles both dialects
    resp = client.get("/api/v1/system/performance/sqlite-wal", headers=lead_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "wal_concurrency_enabled" in data
    assert data["wal_concurrency_enabled"] is True


# --------------------------------------------------------------------------
# Test 13: Capacity & Worker API Endpoints
# --------------------------------------------------------------------------
def test_13_api_endpoints_capacity_and_workers(client: TestClient, lead_headers: dict, admin_headers: dict):
    """Verify REST APIs for capacity monitoring, limits updating, worker nodes, and dead-letter queue."""
    # GET capacity status
    c_status = client.get("/api/v1/system/capacity/status", headers=lead_headers)
    assert c_status.status_code == 200
    c_data = c_status.json()
    assert "utilization_pct" in c_data
    assert "hardware" in c_data

    # GET capacity limits
    c_limits = client.get("/api/v1/system/capacity/limits", headers=lead_headers)
    assert c_limits.status_code == 200
    assert "max_global_concurrency" in c_limits.json()

    # PUT capacity limits (Admin required)
    put_res = client.put(
        "/api/v1/system/capacity/limits",
        json={"max_global_concurrency": 16, "max_project_concurrency": 6},
        headers=admin_headers,
    )
    assert put_res.status_code == 200
    assert put_res.json()["max_global_concurrency"] == 16
    assert put_res.json()["max_project_concurrency"] == 6

    # GET worker nodes
    nodes_resp = client.get("/api/v1/workers/nodes", headers=lead_headers)
    assert nodes_resp.status_code == 200
    assert isinstance(nodes_resp.json(), list)

    # GET dead letter jobs
    dlq_resp = client.get("/api/v1/workers/dead-letter", headers=lead_headers)
    assert dlq_resp.status_code == 200
    assert isinstance(dlq_resp.json(), list)

    # Worker registration via endpoint
    valid_token = settings.WORKER_REGISTRATION_SECRET or settings.SECRET_KEY
    reg_post = client.post(
        "/api/v1/workers/register",
        json={
            "worker_id": "api-worker-node-99",
            "worker_type": "DISTRIBUTED_NODE",
            "hostname": "api-test-host",
            "concurrency_slots": 4,
            "capabilities": ["local_fixture_adapter"],
            "auth_token": valid_token,
            "metadata": {},
        },
    )
    assert reg_post.status_code == 200
    session_token = reg_post.json()["session_token"]

    # Worker heartbeat via endpoint
    hb_post = client.post(
        "/api/v1/workers/heartbeat",
        json={
            "worker_id": "api-worker-node-99",
            "session_token": session_token,
            "active_job_ids": [],
            "system_metrics": {},
        },
    )
    assert hb_post.status_code == 200
    assert hb_post.json()["acknowledged"] is True
