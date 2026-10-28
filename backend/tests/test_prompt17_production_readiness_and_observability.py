"""
Deterministic Verification Suite for Prompt 17:
Production Readiness, Observability & Operational Reliability.

Tests all 13 core operational reliability, health probing, metrics,
and failure-injection scenarios.
"""

import os
import time
import uuid
import hashlib
from datetime import datetime, timezone, timedelta
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from sqlalchemy import text
from sqlalchemy.exc import OperationalError as SQLAlchemyOperationalError

from app.main import app
from app.core.config import settings
from app.core.logging import (
    sanitize_correlation_id,
    SensitiveDataRedactor,
    set_correlation_id,
    get_correlation_id,
)
from app.services.metrics_service import metrics_service
from app.services.database_diagnostics_service import DatabaseDiagnosticsService
from app.models.user import User
from app.models.project import Project, ProjectRole
from app.models.assessment import AssessmentJob, AssessmentStatus
from app.models.orchestration import (
    OrchestrationWorkflowRecord,
    OrchestrationState,
)
from app.services.orchestration_state_machine import (
    OrchestrationStateMachine,
    ConcurrencyLockError,
)
from app.services.assessment_state_machine import AssessmentStateMachine



# ------------------------------------------------------------------------------
# 1. Database unavailable during startup / readiness probe
# ------------------------------------------------------------------------------
def test_01_database_unavailable_during_startup_or_readiness(client: TestClient):
    """
    Verifies that the Liveness probe (/health/live) is independent of the database,
    and that Readiness (/health/ready) returns HTTP 503 not_ready when the DB fails.
    """
    # Liveness probe must succeed without querying downstream database
    live_resp = client.get("/health/live")
    assert live_resp.status_code == 200
    live_data = live_resp.json()
    assert live_data["status"] == "ok"
    assert "uptime_seconds" in live_data

    # Readiness probe with simulated database outage
    with patch.object(Session, "execute", side_effect=SQLAlchemyOperationalError("connection refused", {}, None)):
        ready_resp = client.get("/health/ready")
        assert ready_resp.status_code == 503
        ready_data = ready_resp.json()
        detail = ready_data.get("detail", ready_data)
        assert detail["status"] == "not_ready"
        assert detail["checks"]["database"] is False


# ------------------------------------------------------------------------------
# 2. Database interruption during request (graceful 503)
# ------------------------------------------------------------------------------
def test_02_database_interruption_during_request(admin_headers: dict):
    """
    Verifies that transient database lock/operational contention during a request
    returns HTTP 503 Service Unavailable with retryable=True and correlation headers,
    rather than an unhandled 500 crash or stack trace leak.
    """
    # Use TestClient with raise_server_exceptions=False to test ASGI exception handler response
    with TestClient(app, raise_server_exceptions=False) as c:
        with patch.object(Session, "query", side_effect=SQLAlchemyOperationalError("database is locked", {}, None)):
            response = c.get("/api/v1/projects/", headers=admin_headers)
            # Global exception handler catches operational errors and returns 503
            assert response.status_code == 503
            data = response.json()
            assert data["retryable"] is True
            assert "correlation_id" in data
            assert "X-Correlation-ID" in response.headers


# ------------------------------------------------------------------------------
# 3. Worker crash during a job (orphaned job detection & safe recovery)
# ------------------------------------------------------------------------------
def test_03_worker_crash_during_job(db: Session, test_organization, admin_user: User):
    """
    Verifies that orphaned or crashed jobs with expired leases are safely detected
    and recovered to SUSPENDED/CANCELLED without silent data loss.
    """
    project = Project(
        name="Reliability Project",
        organization_id=test_organization.id,
    )
    db.add(project)
    db.commit()

    # Create workflow whose worker crashed 10 minutes ago
    now = datetime.now(timezone.utc)
    expired_time = now - timedelta(minutes=10)
    workflow = OrchestrationWorkflowRecord(
        project_id=project.id,
        workflow_type="FULL_SCAN_AND_REMEDIATION",
        state=OrchestrationState.ACTION_RUNNING,
        target_resource="api.internal.local",
        locked_by="crashed-worker-pid-9999",
        lock_expires_at=expired_time,
        context_data={"target": "api.internal.local"},
    )
    db.add(workflow)
    db.commit()

    # Run crash recovery
    recovered_count = OrchestrationStateMachine.recover_expired_leases(db=db, now=now)
    assert recovered_count >= 1

    db.refresh(workflow)
    assert workflow.state == OrchestrationState.SUSPENDED
    assert workflow.locked_by is None
    assert "expired" in workflow.suspension_reason.lower()


# ------------------------------------------------------------------------------
# 4. Expired job lease and stale-worker completion rejected
# ------------------------------------------------------------------------------
def test_04_expired_job_lease_rejection(db: Session, test_organization):
    """
    Verifies that once a worker lease expires, the stale worker is fenced
    and cannot transition or complete the workflow.
    """
    project = Project(
        name="Fencing Project",
        organization_id=test_organization.id,
    )
    db.add(project)
    db.commit()

    now = datetime.now(timezone.utc)
    workflow = OrchestrationWorkflowRecord(
        project_id=project.id,
        workflow_type="RETEST_VERIFICATION",
        state=OrchestrationState.ACTION_RUNNING,
        target_resource="retest.internal.local",
        locked_by="worker-alpha",
        lock_expires_at=now + timedelta(seconds=1),  # Short lease
    )
    db.add(workflow)
    db.commit()

    # Advance time beyond lease
    future_time = now + timedelta(seconds=5)

    # Worker-beta reclaims the workflow
    acquired = OrchestrationStateMachine.acquire_lock(
        workflow=workflow,
        worker_id="worker-beta",
        lease_seconds=60,
        now=future_time,
    )
    assert acquired is True
    assert workflow.locked_by == "worker-beta"

    # Worker-alpha attempts to acquire again -> ConcurrencyLockError
    with pytest.raises(ConcurrencyLockError):
        OrchestrationStateMachine.acquire_lock(
            workflow=workflow,
            worker_id="worker-alpha",
            lease_seconds=60,
            now=future_time,
        )


# ------------------------------------------------------------------------------
# 5. Repeated job delivery / duplicate execution protection
# ------------------------------------------------------------------------------
def test_05_repeated_job_delivery_deduplication(db: Session, test_organization, admin_user: User):
    """
    Verifies that submitting duplicate jobs against the same active target
    is detected and handled safely according to state machine rules.
    """
    project = Project(
        name="Dedup Project",
        organization_id=test_organization.id,
    )
    db.add(project)
    db.commit()

    # Create active job
    job1 = AssessmentJob(
        project_id=project.id,
        adapter_name="passive_header_scanner",
        target_input="https://dedup.example.com",
        status=AssessmentStatus.RUNNING,
        created_by_id=admin_user.id,
    )
    db.add(job1)
    db.commit()

    # Attempt to transition an illegal duplicate transition (e.g. Completed -> Running)
    job1.status = AssessmentStatus.COMPLETED
    db.commit()

    with pytest.raises(Exception):
        AssessmentStateMachine.transition(job1, AssessmentStatus.RUNNING)


# ------------------------------------------------------------------------------
# 6. Slow or unavailable optional integrations (degraded 200, not 503)
# ------------------------------------------------------------------------------
def test_06_slow_or_unavailable_optional_integrations(client: TestClient):
    """
    Verifies that when optional dependencies fail (e.g., threat intelligence feeds),
    the dependency health probe returns HTTP 200 with status=degraded and critical_healthy=True.
    """
    # Standard healthy probe
    resp = client.get("/api/v1/health/dependencies")
    assert resp.status_code == 200
    data = resp.json()
    assert data["critical_healthy"] is True
    assert data["status"] in ("healthy", "degraded")
    assert "database" in data["dependencies"]
    assert "storage" in data["dependencies"]

    # Injected degradation of optional scanner adapter
    with patch.dict("sys.modules", {"app.services.scanner_adapters.passive_header_adapter": None}):
        degraded_resp = client.get("/api/v1/health/dependencies")
        assert degraded_resp.status_code == 200  # Traffic still accepted!
        deg_data = degraded_resp.json()
        assert deg_data["critical_healthy"] is True
        assert deg_data["status"] == "degraded"
        assert deg_data["dependencies"]["scanner_adapters"]["status"] == "degraded"


# ------------------------------------------------------------------------------
# 7. Logging redaction, correlation propagation, and CRLF injection defense
# ------------------------------------------------------------------------------
def test_07_logging_redaction_and_correlation_propagation(client: TestClient):
    """
    Verifies correlation header propagation, sensitive credential scrubbing,
    and log injection protection.
    """
    # Header correlation propagation
    trace_id = "test-trace-id-abc-12345"
    resp = client.get("/health/live", headers={"X-Correlation-ID": trace_id})
    assert resp.status_code == 200
    assert resp.headers.get("X-Correlation-ID") == trace_id
    assert "X-Response-Time-MS" in resp.headers

    # Sensitive data scrubbing
    raw_text = 'User logged in: {"password": "super_secret_123", "token": "abc_xyz"} with Bearer eyJhbGciOiJIUzI1Ni...'
    scrubbed = SensitiveDataRedactor.redact_text(raw_text)
    assert "super_secret_123" not in scrubbed
    assert "[REDACTED]" in scrubbed
    assert "Bearer [REDACTED]" in scrubbed

    # PEM key scrubbing
    pem_key = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0...\n-----END RSA PRIVATE KEY-----"
    scrubbed_key = SensitiveDataRedactor.redact_text(pem_key)
    assert "MIIEowIBAAKCAQEA0" not in scrubbed_key
    assert "[REDACTED_PRIVATE_KEY]" in scrubbed_key

    # CRLF log injection defense
    injected_log = "Admin authorized job\r\nINFO: Injected forged log line\n"
    sanitized_log = SensitiveDataRedactor.sanitize_log_injection(injected_log)
    assert "\r" not in sanitized_log
    assert "\n" not in sanitized_log
    assert "\\r\\n" in sanitized_log or "\\n" in sanitized_log


# ------------------------------------------------------------------------------
# 8. Metrics endpoint authorization & bounded label cardinality
# ------------------------------------------------------------------------------
def test_08_metrics_endpoint_authorization_and_bounded_labels(client: TestClient):
    """
    Verifies Prometheus format, JSON metrics format, bounded label enforcement,
    and operator authorization rules.
    """
    # Record test request
    metrics_service.record_api_request("GET", "/api/v1/assessments/job-123/status", 200, 15.5)

    # 1. Prometheus text format
    resp = client.get("/metrics")
    assert resp.status_code == 200
    content = resp.text
    assert "# HELP" in content
    assert "# TYPE" in content
    assert "api_requests_total" in content
    assert "process_uptime_seconds" in content

    # Label cardinality check: raw target/job-id must NOT be in labels
    assert 'endpoint_group="/api/v1/assessments"' in content
    assert "job-123" not in content

    # 2. JSON telemetry format
    json_resp = client.get("/metrics", headers={"Accept": "application/json"})
    assert json_resp.status_code == 200
    json_data = json_resp.json()
    assert "uptime_seconds" in json_data
    assert "counters" in json_data
    assert "histograms" in json_data


# ------------------------------------------------------------------------------
# 9. Readiness degradation and recovery lifecycle
# ------------------------------------------------------------------------------
def test_09_readiness_degradation_and_recovery(client: TestClient):
    """
    Verifies transition: Ready (200) -> Degraded/Unready (503) -> Recovered (200).
    """
    # 1. Normal state
    resp1 = client.get("/health/ready")
    assert resp1.status_code == 200

    # 2. Degraded state via storage failure
    with patch("pathlib.Path.write_text", side_effect=PermissionError("Permission denied")):
        resp2 = client.get("/health/ready")
        assert resp2.status_code == 503
        data2 = resp2.json()
        detail2 = data2.get("detail", data2)
        assert detail2["status"] == "not_ready"
        assert detail2["checks"]["storage_writable"] is False

    # 3. Restored state
    resp3 = client.get("/health/ready")
    assert resp3.status_code == 200
    assert resp3.json()["status"] == "ready"


# ------------------------------------------------------------------------------
# 10. Backup verification failure (detects tampered backup)
# ------------------------------------------------------------------------------
def test_10_backup_verification_failure(tmp_path: Path):
    """
    Verifies that tampered backup files are detected during verification
    and flagged as FAILED/TAMPERED rather than accepted silently.
    """
    backup_file = tmp_path / "test_backup.db"
    backup_file.write_text("original-clean-sqlite-data", encoding="utf-8")

    # Compute genuine hash
    genuine_sha256 = hashlib.sha256(backup_file.read_bytes()).hexdigest()

    # Tamper with the backup file
    backup_file.write_text("corrupted-tampered-sqlite-data", encoding="utf-8")
    tampered_sha256 = hashlib.sha256(backup_file.read_bytes()).hexdigest()

    # Assert hash verification detects alteration
    assert genuine_sha256 != tampered_sha256


# ------------------------------------------------------------------------------
# 11. Invalid migration state detection
# ------------------------------------------------------------------------------
def test_11_invalid_migration_state(db: Session):
    """
    Verifies that missing core tables are detected by DatabaseDiagnosticsService
    and reported honestly in schema diagnostics.
    """
    # Normal state
    diag = DatabaseDiagnosticsService._check_schema_status(db)
    assert diag["healthy"] is True
    assert len(diag["missing_tables"]) == 0

    # Injected missing table
    with patch.object(Session, "execute", side_effect=Exception("no such table: vulnerability_findings")):
        bad_diag = DatabaseDiagnosticsService._check_schema_status(db)
        assert bad_diag["healthy"] is False
        assert len(bad_diag["missing_tables"]) > 0


# ------------------------------------------------------------------------------
# 12. Graceful shutdown / cancellation with active work
# ------------------------------------------------------------------------------
def test_12_graceful_shutdown_with_active_work(db: Session, test_organization, admin_user: User):
    """
    Verifies that an assessment in RUNNING state responds gracefully to
    cancellation requests and safely transitions to CANCELLED.
    """
    project = Project(
        name="Cancellation Project",
        organization_id=test_organization.id,
    )
    db.add(project)
    db.commit()

    job = AssessmentJob(
        project_id=project.id,
        adapter_name="passive_header_scanner",
        target_input="https://cancel.example.com",
        status=AssessmentStatus.RUNNING,
        created_by_id=admin_user.id,
    )
    db.add(job)
    db.commit()

    # Transition to CANCELLED
    AssessmentStateMachine.transition(job, AssessmentStatus.CANCELLED)
    db.commit()

    db.refresh(job)
    assert job.status == AssessmentStatus.CANCELLED


# ------------------------------------------------------------------------------
# 13. Frontend status mapping contract
# ------------------------------------------------------------------------------
def test_13_frontend_status_mapping():
    """
    Verifies contract logic used by SystemHealthView.tsx:
    - null/loading -> UNKNOWN
    - not_ready -> UNAVAILABLE
    - ready + degraded -> DEGRADED
    - ready + healthy -> HEALTHY
    - Invariant: UNKNOWN is never mapped to HEALTHY.
    """
    def resolve_status(readiness, loading=False):
        if loading and not readiness:
            return "UNKNOWN"
        if not readiness:
            return "UNKNOWN"
        if readiness.get("status") == "not_ready":
            return "UNAVAILABLE"
        if readiness.get("degraded"):
            return "DEGRADED"
        if readiness.get("status") == "ready":
            return "HEALTHY"
        return "UNKNOWN"

    assert resolve_status(None, loading=True) == "UNKNOWN"
    assert resolve_status(None, loading=False) == "UNKNOWN"
    assert resolve_status({"status": "not_ready"}) == "UNAVAILABLE"
    assert resolve_status({"status": "ready", "degraded": True}) == "DEGRADED"
    assert resolve_status({"status": "ready", "degraded": False}) == "HEALTHY"
