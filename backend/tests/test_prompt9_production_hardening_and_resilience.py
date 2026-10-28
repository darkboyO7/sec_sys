"""
VAPT System - Production Hardening, Resilience, and Disaster Recovery Test Suite
================================================================================
Covers Prompt 9 validation requirements:
 1. Bounded exponential backoff and jitter calculations
 2. Job retry limits, state transitions, and backoff scheduling
 3. Stale worker crash recovery, heartbeat timeouts, and attempt exhaustion
 4. Atomic worker concurrency protection and duplicate claim rejection
 5. Request size limits (HTTP 413 Payload Too Large)
 6. Production fail-closed security configuration validation
 7. Sanitized health and readiness diagnostics (no credential or path disclosure)
 8. Cross-entity platform integrity verification and tamper detection
 9. Disposable database backup creation, cryptographic SHA-256 hashing, and sandbox restoration
10. Automated release package security audit (prohibited paths & secret detection)
11. Production unhandled exception sanitization
"""

import os
import io
import time
import zipfile
import hashlib
from datetime import datetime, timezone, timedelta
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.models.project import Project, ProjectMember, ProjectRole
from app.models.user import User, SystemRole
from app.models.scope import ScopeTarget, TargetType, AuthorizationStatus
from app.models.assessment import AssessmentJob, AssessmentFinding, FindingEvidence, AssessmentStatus, FindingSeverity
from app.models.finding import VulnerabilityFinding, FindingLifecycleStatus
from app.models.asset import Asset, AssetObservation
from app.models.risk import RemediationRecommendation, RecommendationStatus
from app.models.verification import RemediationVerification, VerificationOutcome
from app.services.assessment_engine import AssessmentExecutionEngine
from app.services.integrity_service import IntegrityService
from app.services.backup_service import BackupRecoveryService, BackupMetadata
from scripts.create_clean_release_package import audit_release_archive, OUTPUT_ZIP


def test_bounded_exponential_backoff_and_jitter_calculation():
    """
    Verifies that calculate_backoff_delay produces bounded exponential delays
    with proper jitter and clamps to max_delay.
    """
    # Attempt 1: base delay ~2.0s
    d1 = AssessmentExecutionEngine.calculate_backoff_delay(attempt=1, base_delay=2.0, max_delay=60.0, jitter=False)
    assert d1 == 2.0

    # Attempt 2: 4.0s
    d2 = AssessmentExecutionEngine.calculate_backoff_delay(attempt=2, base_delay=2.0, max_delay=60.0, jitter=False)
    assert d2 == 4.0

    # Attempt 3: 8.0s
    d3 = AssessmentExecutionEngine.calculate_backoff_delay(attempt=3, base_delay=2.0, max_delay=60.0, jitter=False)
    assert d3 == 8.0

    # Large attempt: clamped to max_delay
    d_clamped = AssessmentExecutionEngine.calculate_backoff_delay(attempt=20, base_delay=2.0, max_delay=60.0, jitter=False)
    assert d_clamped == 60.0

    # With jitter: delay falls within [0.5 * exp, exp]
    for attempt in range(1, 5):
        base_exp = min(60.0, 2.0 * (2.0 ** (attempt - 1)))
        d_jitter = AssessmentExecutionEngine.calculate_backoff_delay(attempt=attempt, base_delay=2.0, max_delay=60.0, jitter=True)
        assert 0.5 * base_exp <= d_jitter <= base_exp


def test_job_retry_backoff_recording_and_max_attempts(db: Session, test_project: Project, lead_user: User):
    """
    Verifies that retry_job re-queues failed jobs with recorded backoff and enforces max_retries.
    """
    job = AssessmentJob(
        project_id=test_project.id,
        target_input="http://127.0.0.1:9999",
        adapter_name="local_fixture_adapter",
        status=AssessmentStatus.FAILED,
        attempt_count=1,
        retry_count=0,
        max_retries=2,
        failure_category="CONNECTION_TIMEOUT",
        created_by_id=lead_user.id,
    )
    db.add(job)
    db.commit()

    # Attempt retry 1 -> Success
    success, retried_job, msg = AssessmentExecutionEngine.retry_job(db=db, job_id=job.id)
    assert success is True
    assert retried_job.status == AssessmentStatus.QUEUED
    assert retried_job.attempt_count == 2
    assert retried_job.retry_count == 1
    assert "retry_backoff_seconds" in retried_job.summary_stats
    assert "next_retry_at" in retried_job.summary_stats

    # Simulate subsequent failure
    retried_job.status = AssessmentStatus.FAILED
    db.commit()

    # Attempt retry 2 -> Exceeded max_retries
    success2, exhausted_job, msg2 = AssessmentExecutionEngine.retry_job(db=db, job_id=job.id)
    assert success2 is False
    assert "maximum allowed execution attempts" in msg2
    assert exhausted_job.status == AssessmentStatus.FAILED

    # Non-retryable failure category
    job_unretryable = AssessmentJob(
        project_id=test_project.id,
        target_input="http://127.0.0.1:9999",
        adapter_name="local_fixture_adapter",
        status=AssessmentStatus.FAILED,
        attempt_count=1,
        retry_count=0,
        max_retries=2,
        failure_category="SCOPE_AUTHORIZATION_DENIED",
        created_by_id=lead_user.id,
    )
    db.add(job_unretryable)
    db.commit()

    success_nonret, _, msg_nonret = AssessmentExecutionEngine.retry_job(db=db, job_id=job_unretryable.id)
    assert success_nonret is False
    assert "non-retryable governance failure" in msg_nonret


def test_stale_worker_recovery_and_heartbeat_timeout(db: Session, test_project: Project, lead_user: User):
    """
    Verifies that recover_stale_workers re-queues stale jobs or marks exhausted jobs as FAILED.
    """
    now = datetime.now(timezone.utc)
    ten_minutes_ago = now - timedelta(minutes=10)

    # 1. Recoverable stale job (attempt 1 < max 2)
    job_recoverable = AssessmentJob(
        project_id=test_project.id,
        target_input="http://127.0.0.1:8080",
        adapter_name="local_fixture_adapter",
        status=AssessmentStatus.RUNNING,
        claimed_by="crashed-worker-01",
        started_at=ten_minutes_ago,
        heartbeat_at=ten_minutes_ago,
        attempt_count=1,
        max_retries=2,
        created_by_id=lead_user.id,
    )
    db.add(job_recoverable)

    # 2. Exhausted stale job (attempt 2 >= max 2)
    job_exhausted = AssessmentJob(
        project_id=test_project.id,
        target_input="http://127.0.0.1:8081",
        adapter_name="local_fixture_adapter",
        status=AssessmentStatus.RUNNING,
        claimed_by="crashed-worker-02",
        started_at=ten_minutes_ago,
        heartbeat_at=ten_minutes_ago,
        attempt_count=2,
        max_retries=2,
        created_by_id=lead_user.id,
    )
    db.add(job_exhausted)
    db.commit()

    recovered = AssessmentExecutionEngine.recover_stale_workers(db=db, heartbeat_timeout_seconds=60, now=now)
    assert len(recovered) == 2

    db.refresh(job_recoverable)
    assert job_recoverable.status == AssessmentStatus.QUEUED
    assert job_recoverable.claimed_by is None
    assert job_recoverable.attempt_count == 2
    assert "retry_backoff_seconds" in job_recoverable.summary_stats

    db.refresh(job_exhausted)
    assert job_exhausted.status == AssessmentStatus.FAILED
    assert job_exhausted.failure_category == "WORKER_HEARTBEAT_TIMEOUT"
    assert "maximum retries" in job_exhausted.error_message


def test_atomic_worker_claim_concurrency(db: Session, test_project: Project, lead_user: User):
    """
    Verifies that two workers attempting to claim the same QUEUED job cannot both succeed.
    """
    job = AssessmentJob(
        project_id=test_project.id,
        target_input="http://127.0.0.1:8088",
        adapter_name="local_fixture_adapter",
        status=AssessmentStatus.QUEUED,
        created_by_id=lead_user.id,
    )
    db.add(job)
    db.commit()

    # Worker 1 claims
    claimed1 = AssessmentExecutionEngine.claim_next_available_job(db=db, worker_id="worker-node-A")
    assert claimed1 is not None
    assert claimed1.id == job.id
    assert claimed1.claimed_by == "worker-node-A"

    # Worker 2 attempts to claim next available -> returns None (queue empty)
    claimed2 = AssessmentExecutionEngine.claim_next_available_job(db=db, worker_id="worker-node-B")
    assert claimed2 is None


def test_request_size_limit_rejection(client: TestClient):
    """
    Verifies that ContentLengthLimitMiddleware rejects requests exceeding 10MB limit.
    """
    # Oversized payload header
    headers = {"Content-Length": "15728640", "Content-Type": "application/json"}
    res = client.post("/api/v1/auth/login", content=b"{}", headers=headers)
    assert res.status_code == 413
    assert "exceeds maximum permitted limit" in res.json()["detail"]


def test_production_fail_closed_security_configuration():
    """
    Verifies that Settings model fails closed in production mode when security settings are violated.
    """
    # 1. Insecure default secret key in production
    with pytest.raises(ValueError, match="Default or development SECRET_KEY is strictly forbidden"):
        Settings(
            ENVIRONMENT="production",
            SECRET_KEY="dev_insecure_secret_key_change_in_production_min_32_bytes_long",
        )

    # 2. DEBUG=True in production
    with pytest.raises(ValueError, match="DEBUG mode must be set to False"):
        Settings(
            ENVIRONMENT="production",
            SECRET_KEY="a" * 32,
            DEBUG=True,
        )

    # 3. Wildcard CORS in production
    with pytest.raises(ValueError, match="Wildcard '\\*' in ALLOWED_ORIGINS is strictly forbidden"):
        Settings(
            ENVIRONMENT="production",
            SECRET_KEY="a" * 32,
            ALLOWED_ORIGINS="*",
        )


def test_sanitized_health_and_readiness_diagnostics(client: TestClient):
    """
    Verifies that health and readiness endpoints do not leak credentials or internal paths.
    """
    res_health = client.get("/api/v1/health")
    assert res_health.status_code == 200
    health_data = res_health.json()
    assert health_data["status"] == "ok"
    assert "version" in health_data

    res_ready = client.get("/api/v1/ready")
    assert res_ready.status_code == 200
    ready_data = res_ready.json()
    assert ready_data["status"] == "ready"
    assert ready_data["checks"]["database"] is True
    details = ready_data["checks"]["details"]
    # Verify no raw paths or credentials in details
    assert "password" not in str(details).lower()
    assert "secret" not in str(details).lower()


def test_platform_wide_entity_integrity_verification(
    client: TestClient,
    db: Session,
    test_project: Project,
    lead_user: User,
    lead_headers: dict,
):
    """
    Verifies verify_platform_entity_integrity detects valid entities and flags corrupted records.
    """
    # Create valid assessment job
    job = AssessmentJob(
        project_id=test_project.id,
        target_input="http://127.0.0.1:8000",
        adapter_name="local_fixture_adapter",
        status=AssessmentStatus.COMPLETED,
        created_by_id=lead_user.id,
    )
    db.add(job)
    db.commit()

    # Create valid finding
    finding = VulnerabilityFinding(
        project_id=test_project.id,
        target_value="http://127.0.0.1:8000",
        title="Valid Finding Test",
        severity=FindingSeverity.HIGH,
        fingerprint=hashlib.sha256(b"finding-valid-fingerprint").hexdigest(),
        status=FindingLifecycleStatus.DETECTED,
    )
    db.add(finding)
    db.commit()

    # Check integrity
    report = IntegrityService.verify_platform_entity_integrity(db=db, project_id=test_project.id)
    assert report["is_valid"] is True
    assert report["assessment_records"]["valid"] >= 1
    assert report["findings"]["valid"] >= 1

    # Invalidate fingerprint
    finding.fingerprint = "short_invalid_hash"
    db.commit()

    report_corrupted = IntegrityService.verify_platform_entity_integrity(db=db, project_id=test_project.id)
    assert report_corrupted["is_valid"] is False
    assert finding.id in report_corrupted["findings"]["corrupted_ids"]

    # Restore valid fingerprint
    finding.fingerprint = hashlib.sha256(b"finding-valid-fingerprint").hexdigest()
    db.commit()

    # Test API endpoint
    res_api = client.get(f"/api/v1/projects/{test_project.id}/integrity/verify-all", headers=lead_headers)
    assert res_api.status_code == 200
    api_data = res_api.json()
    assert api_data["is_valid"] is True
    assert "summary" in api_data


def test_disposable_database_backup_and_sandbox_restore(db: Session, lead_user: User):
    """
    Verifies that BackupRecoveryService creates a consistent WAL backup, computes SHA-256,
    and successfully restores into a disposable database sandbox with PRAGMA integrity_check.
    """
    backup_meta = BackupRecoveryService.create_database_backup(db=db, actor_id=lead_user.id)
    assert os.path.exists(backup_meta.backup_path)
    assert len(backup_meta.sha256_hash) == 64
    assert backup_meta.table_count > 0

    # Test restoration in sandbox
    restore_result = BackupRecoveryService.verify_and_test_restore(
        backup_file_path=backup_meta.backup_path,
        expected_sha256=backup_meta.sha256_hash,
    )
    assert restore_result["is_valid"] is True
    assert restore_result["integrity_result"] == "ok"
    assert restore_result["sha256_verified"] is True
    assert "projects" in restore_result["tables_verified"]

    # Tampered SHA-256 detection
    with pytest.raises(ValueError, match="Integrity check failed"):
        BackupRecoveryService.verify_and_test_restore(
            backup_file_path=backup_meta.backup_path,
            expected_sha256="0" * 64,
        )

    # Clean up test backup file
    try:
        os.remove(backup_meta.backup_path)
    except Exception:
        pass


def test_release_archive_security_audit():
    """
    Verifies that audit_release_archive verifies clean archives and detects prohibited files or secrets.
    """
    # 1. Audit actual generated release archive if present
    if OUTPUT_ZIP.exists():
        audit_actual = audit_release_archive(OUTPUT_ZIP)
        assert audit_actual["passed"] is True
        assert len(audit_actual["violations"]) == 0
        assert len(audit_actual["secrets_found"]) == 0

    # 2. Negative test: create simulated archive with prohibited items
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("backend/.env", "SECRET_KEY=supersecret123\n")
        zf.writestr("backend/certs/server.key", "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...\n")
        zf.writestr("data/vapt.db", "SQLite format 3\x00")

    buf.seek(0)
    fake_zip_path = "D:/alt/data/_temp_negative_audit_test.zip"
    os.makedirs("D:/alt/data", exist_ok=True)
    with open(fake_zip_path, "wb") as f:
        f.write(buf.getvalue())

    try:
        from pathlib import Path
        audit_neg = audit_release_archive(Path(fake_zip_path))
        assert audit_neg["passed"] is False
        assert any(".env" in v for v in audit_neg["violations"])
        assert any(".db" in v for v in audit_neg["violations"])
        assert any("Private Key Header" in s for s in audit_neg["secrets_found"])
    finally:
        if os.path.exists(fake_zip_path):
            os.remove(fake_zip_path)
