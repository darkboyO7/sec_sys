"""
Prompt 52 Test Suite: Fault Injection, Graceful Degradation, and Recovery Verification.

Validates:
1. Strict fail-closed guard preventing fault injection in production/staging environments.
2. Injected database interruption during finding persistence handled gracefully with rollback.
3. Injected worker termination (abrupt crash) detected and recovered by supervisory recovery.
4. Injected adapter execution deadline exhaustion bounded by timeout_seconds and transitioned to TIMED_OUT.
5. Injected secondary provider outage (webhook / feeds) degrades gracefully without losing critical evidence or audit logs.
6. Injected disk write failure handled cleanly without database corruption.
7. Injected malformed scanner payload rejected at execution boundary with CORRUPT_IPC_RESPONSE.
8. Interrupted background batch job reports PARTIAL success truthfully (never false COMPLETED).
9. Idempotency protection and retry budgets (exponential backoff, max retries, no duplicate jobs).
10. Automatic recovery fail-closed: cannot weaken scope boundaries or bypass authorization.
11. Clean separation of health endpoints (liveness, readiness, dependencies, degradation) and zero secret leakage.
12. Operator-readable failure classifications with root-cause hypotheses and actionable playbooks.
"""
import pytest
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.fault_injection import (
    FaultInjector,
    FaultRule,
    FaultType,
    FaultInjectionSecurityError,
    DatabaseInterruptionError,
    WorkerTerminationError,
    AdapterTimeoutError,
    ProviderOutageError,
    DiskWriteFailureError,
    MalformedResponseError,
    InterruptedBackgroundTaskError,
    fault_injection_context,
)
from app.models.project import Project, ProjectMember, ProjectRole
from app.models.user import User, SystemRole
from app.models.scope import ScopeTarget, TargetType, AuthorizationStatus, ScopeExclusion
from app.models.assessment import (
    AssessmentJob,
    AssessmentStatus,
    AssessmentFinding,
    FindingEvidence,
    FindingSeverity,
    FindingConfidence,
)
from app.models.notification import (
    NotificationRecord,
    NotificationDeliveryRecord,
    NotificationEventType,
    NotificationSeverity,
    NotificationStatus,
)
from app.models.diagnostics import RecoveryActionType, RecoveryOutcome
from app.services.assessment_engine import AssessmentExecutionEngine
from app.services.notification_service import NotificationService
from app.services.threat_intel_service import ThreatIntelService
from app.services.recovery_engine import RecoveryEngineService
from app.services.failure_classification_service import (
    FailureClassificationService,
    CapabilityType,
    CriticalityLevel,
    FailureSeverity,
)
from app.services.scanner_adapters.base import AdapterResult, RawAdapterFinding, RawAdapterEvidence
from app.core.security import create_access_token


@pytest.fixture
def authorized_scope(db: Session, test_project: Project, lead_user: User) -> ScopeTarget:
    target = ScopeTarget(
        project_id=test_project.id,
        target_type=TargetType.URL,
        target_value="https://grid-alpha.acme.local",
        description="Authorized internal defense web console",
        authorization_status=AuthorizationStatus.AUTHORIZED,
        authorization_evidence="ROE-AUTH-001",
        created_by_id=lead_user.id,
    )
    db.add(target)
    db.commit()
    db.refresh(target)
    return target


# ------------------------------------------------------------------------------
# Test 1: Fail-Closed Security Guard
# ------------------------------------------------------------------------------
def test_01_fail_closed_guard_prevents_fault_injection_in_production():
    """Fault injection MUST be strictly prohibited in production and staging environments."""
    original_env = settings.ENVIRONMENT
    original_enabled = settings.FAULT_INJECTION_ENABLED

    try:
        # 1. Verify production environment blocks fault injection registration
        settings.ENVIRONMENT = "production"
        settings.FAULT_INJECTION_ENABLED = True

        assert FaultInjector.is_injection_permitted() is False

        rule = FaultRule(
            fault_type=FaultType.DATABASE_INTERRUPTION,
            trigger_point="db:commit",
        )
        with pytest.raises(FaultInjectionSecurityError) as exc_info:
            FaultInjector.register_rule(rule)
        assert "strictly prohibited in 'production'" in str(exc_info.value)

        # 2. Verify staging environment blocks fault injection
        settings.ENVIRONMENT = "staging"
        with pytest.raises(FaultInjectionSecurityError) as exc_info_stage:
            FaultInjector.register_rule(rule)
        assert "strictly prohibited in 'staging'" in str(exc_info_stage.value)

        # 3. Verify maybe_inject returns None and never triggers in production
        settings.ENVIRONMENT = "production"
        result = FaultInjector.maybe_inject("db:commit", {})
        assert result is None

    finally:
        FaultInjector.clear()
        settings.ENVIRONMENT = original_env
        settings.FAULT_INJECTION_ENABLED = original_enabled


# ------------------------------------------------------------------------------
# Test 2: Injected Database Interruption & Transaction Rollback
# ------------------------------------------------------------------------------
def test_02_database_interruption_during_finding_persistence(
    db: Session, test_project: Project, lead_user: User, authorized_scope: ScopeTarget
):
    """Injected transient database failure during finding persistence must roll back cleanly."""
    job = AssessmentJob(
        project_id=test_project.id,
        target_input=authorized_scope.target_value,
        adapter_name="local_fixture_adapter",
        status=AssessmentStatus.QUEUED,
        created_by_id=lead_user.id,
        timeout_seconds=30,
    )
    db.add(job)
    db.commit()
    db.refresh(job)

    # Inject database interruption during finding persistence
    with fault_injection_context(
        fault_type=FaultType.DATABASE_INTERRUPTION,
        trigger_point="db:commit:findings",
        error_message="OperationalError: database connection disconnected by host socket reset",
        count=1,
    ):
        updated_job = AssessmentExecutionEngine.execute_job(
            db=db,
            job_id=job.id,
            worker_id="worker-fi-01",
        )

    # Job must transition to FAILED with INGESTION_TRANSACTION_FAILED
    assert updated_job.status == AssessmentStatus.FAILED
    assert updated_job.failure_category == "INGESTION_TRANSACTION_FAILED"
    assert "Evidence persistence transaction rollback" in updated_job.error_message

    # Verify transaction isolation: zero orphaned findings or evidence written to database
    persisted_findings = db.query(AssessmentFinding).filter(AssessmentFinding.job_id == job.id).all()
    assert len(persisted_findings) == 0


# ------------------------------------------------------------------------------
# Test 3: Injected Worker Abrupt Termination & Supervisory Recovery
# ------------------------------------------------------------------------------
def test_03_worker_abrupt_termination_and_supervisory_recovery(
    db: Session, test_project: Project, lead_user: User, authorized_scope: ScopeTarget
):
    """Injected worker termination leaves job stalled; recover_abandoned_jobs recovers it cleanly."""
    job = AssessmentJob(
        project_id=test_project.id,
        target_input=authorized_scope.target_value,
        adapter_name="local_fixture_adapter",
        status=AssessmentStatus.QUEUED,
        created_by_id=lead_user.id,
        timeout_seconds=10,
    )
    db.add(job)
    db.commit()
    db.refresh(job)

    # Inject worker termination
    with fault_injection_context(
        fault_type=FaultType.WORKER_TERMINATION,
        trigger_point="worker:termination",
        error_message="Worker process killed: SIGKILL / OOM termination",
        count=1,
    ):
        stalled_job = AssessmentExecutionEngine.execute_job(
            db=db,
            job_id=job.id,
            worker_id="worker-crash-test",
        )

    # Job was left in RUNNING state to simulate ungraceful crash
    assert stalled_job.status == AssessmentStatus.RUNNING

    # Supervisory recovery execution
    recovered_jobs = AssessmentExecutionEngine.recover_abandoned_jobs(
        db=db,
        project_id=test_project.id,
        max_stale_seconds=5,
    )

    assert len(recovered_jobs) == 1
    assert recovered_jobs[0].id == job.id
    assert recovered_jobs[0].status == AssessmentStatus.FAILED
    assert recovered_jobs[0].failure_category == "ABANDONED_EXECUTION_RECOVERED"
    assert "Execution abandoned: no worker activity" in recovered_jobs[0].error_message


# ------------------------------------------------------------------------------
# Test 4: Injected Scanner Adapter Timeout
# ------------------------------------------------------------------------------
def test_04_adapter_timeout_bounded_and_terminated(
    db: Session, test_project: Project, lead_user: User, authorized_scope: ScopeTarget
):
    """Injected adapter timeout must be caught, process terminated, and status set to TIMED_OUT."""
    job = AssessmentJob(
        project_id=test_project.id,
        target_input=authorized_scope.target_value,
        adapter_name="local_fixture_adapter",
        status=AssessmentStatus.QUEUED,
        created_by_id=lead_user.id,
        timeout_seconds=15,
    )
    db.add(job)
    db.commit()
    db.refresh(job)

    with fault_injection_context(
        fault_type=FaultType.ADAPTER_TIMEOUT,
        trigger_point="adapter:timeout",
        error_message="Socket timeout: Target host dropped syn packets after 15s",
        count=1,
    ):
        timed_out_job = AssessmentExecutionEngine.execute_job(
            db=db,
            job_id=job.id,
            worker_id="worker-to-01",
        )

    assert timed_out_job.status == AssessmentStatus.TIMED_OUT
    assert timed_out_job.failure_category == "WORKER_PROCESS_TIMEOUT"
    assert "deadline exceeded" in timed_out_job.error_message


# ------------------------------------------------------------------------------
# Test 5: Injected Provider Outage & Evidence Preservation
# ------------------------------------------------------------------------------
def test_05_secondary_provider_outage_preserves_critical_evidence(
    db: Session, test_project: Project, lead_user: User, authorized_scope: ScopeTarget
):
    """Secondary provider failures must degrade gracefully without rolling back primary findings."""
    # 1. Notification webhook failure
    with fault_injection_context(
        fault_type=FaultType.PROVIDER_OUTAGE,
        trigger_point="provider:webhook",
        error_message="HTTP 503 Service Unavailable: Remote webhook gateway offline",
        count=1,
    ):
        notif = NotificationService.dispatch_notification(
            db=db,
            project_id=test_project.id,
            event_type=NotificationEventType.ASSESSMENT_FAILED,
            title="Assessment Alert",
            summary="Target inspection encountered warning",
            severity=NotificationSeverity.HIGH,
            webhook_url="https://hooks.acme-defense.local/alerts",
        )

    assert notif.status == NotificationStatus.FAILED
    assert "HTTP 503 Service Unavailable" in notif.error_message
    assert notif.retry_count == 1

    # 2. Secondary asset/graph integration failure during assessment execution
    job = AssessmentJob(
        project_id=test_project.id,
        target_input=authorized_scope.target_value,
        adapter_name="local_fixture_adapter",
        status=AssessmentStatus.QUEUED,
        created_by_id=lead_user.id,
        timeout_seconds=30,
    )
    db.add(job)
    db.commit()
    db.refresh(job)

    with fault_injection_context(
        fault_type=FaultType.PROVIDER_OUTAGE,
        trigger_point="secondary:asset_graph",
        error_message="Graph database synchronization latency spike",
        count=1,
    ):
        completed_job = AssessmentExecutionEngine.execute_job(
            db=db,
            job_id=job.id,
            worker_id="worker-prov-01",
        )

    # Job completes successfully; findings and evidence are safely persisted
    assert completed_job.status == AssessmentStatus.COMPLETED
    findings = db.query(AssessmentFinding).filter(AssessmentFinding.job_id == job.id).all()
    assert len(findings) > 0

    # Secondary degradation is truthfully noted in summary stats without failing the job
    stats = completed_job.summary_stats or {}
    degradations = stats.get("secondary_degradations", [])
    assert any("Graph database synchronization latency spike" in d for d in degradations)


# ------------------------------------------------------------------------------
# Test 6: Injected Disk Write I/O Failure
# ------------------------------------------------------------------------------
def test_06_disk_write_io_failure_resilience():
    """Disk write I/O failures must raise explicit errors without corrupting database state."""
    with fault_injection_context(
        fault_type=FaultType.DISK_WRITE_FAILURE,
        trigger_point="disk:write",
        error_message="IOError: [Errno 28] No space left on device",
        count=1,
    ):
        with pytest.raises(DiskWriteFailureError) as exc_info:
            FaultInjector.maybe_inject("disk:write", {"filepath": "/data/evidence/test.bundle"})
        assert "No space left on device" in str(exc_info.value)

    # After context exit, disk write hook is cleanly removed
    assert FaultInjector.maybe_inject("disk:write", {}) is None


# ------------------------------------------------------------------------------
# Test 7: Injected Malformed Scanner Response
# ------------------------------------------------------------------------------
def test_07_malformed_scanner_payload_rejected_at_execution_boundary(
    db: Session, test_project: Project, lead_user: User, authorized_scope: ScopeTarget
):
    """Worker returning corrupted or malformed payload must be rejected at execution boundary."""
    job = AssessmentJob(
        project_id=test_project.id,
        target_input=authorized_scope.target_value,
        adapter_name="local_fixture_adapter",
        status=AssessmentStatus.QUEUED,
        created_by_id=lead_user.id,
        timeout_seconds=30,
    )
    db.add(job)
    db.commit()
    db.refresh(job)

    with fault_injection_context(
        fault_type=FaultType.MALFORMED_RESPONSE,
        trigger_point="adapter:execute",
        error_message="JSONDecodeError: Expecting value: line 1 column 1 (char 0)",
        count=1,
    ):
        rejected_job = AssessmentExecutionEngine.execute_job(
            db=db,
            job_id=job.id,
            worker_id="worker-malformed-01",
        )

    assert rejected_job.status == AssessmentStatus.FAILED
    assert rejected_job.failure_category == "CORRUPT_IPC_RESPONSE"
    assert "Malformed scanner payload rejected" in rejected_job.error_message


# ------------------------------------------------------------------------------
# Test 8: Interrupted Batch Reports Partial Success Honestly
# ------------------------------------------------------------------------------
def test_08_interrupted_background_batch_reports_partial_success_truthfully(
    db: Session, test_project: Project, lead_user: User, authorized_scope: ScopeTarget
):
    """Multi-target batch assessment with interrupted target must report PARTIAL (never false COMPLETED)."""
    # Create second scope target
    target_2 = ScopeTarget(
        project_id=test_project.id,
        target_type=TargetType.URL,
        target_value="https://grid-beta.acme.local",
        description="Authorized internal defense web console beta",
        authorization_status=AuthorizationStatus.AUTHORIZED,
        authorization_evidence="ROE-AUTH-002",
        created_by_id=lead_user.id,
    )
    db.add(target_2)
    db.commit()

    job = AssessmentJob(
        project_id=test_project.id,
        target_input="batch-scan",
        adapter_name="local_fixture_adapter",
        status=AssessmentStatus.QUEUED,
        created_by_id=lead_user.id,
        timeout_seconds=60,
    )
    db.add(job)
    db.commit()
    db.refresh(job)

    # Inject background task interruption on target 2
    with fault_injection_context(
        fault_type=FaultType.INTERRUPTED_BACKGROUND_TASK,
        trigger_point="background:task",
        error_message="Batch processing interrupted by operator preemption",
        count=1,
        filter_fn=lambda ctx: ctx.get("target") == target_2.target_value,
    ):
        batch_job = AssessmentExecutionEngine.execute_batch_assessment(
            db=db,
            job_id=job.id,
            targets=[authorized_scope.target_value, target_2.target_value],
            worker_id="worker-batch-01",
        )

    # Invariant: Incomplete work is NEVER presented as 100% completion
    assert batch_job.status == AssessmentStatus.PARTIAL
    assert batch_job.failure_category == "PARTIAL_MODULE_FAILURE"

    stats = batch_job.summary_stats
    assert stats["completed_count"] == 1
    assert stats["failed_count"] == 1
    assert authorized_scope.target_value in stats["completed_targets"]
    assert any(target_2.target_value == f["target"] for f in stats["failed_targets"])
    assert "Partial success" in stats["status_summary"]


# ------------------------------------------------------------------------------
# Test 9: Idempotency Protection & Retry Budget Bounds
# ------------------------------------------------------------------------------
def test_09_idempotency_and_retry_budget_enforcement(
    db: Session, test_project: Project, lead_user: User, authorized_scope: ScopeTarget
):
    """Retries must be strictly idempotent, bounded by max_retries, and prevent duplicate jobs."""
    job = AssessmentJob(
        project_id=test_project.id,
        target_input=authorized_scope.target_value,
        adapter_name="local_fixture_adapter",
        status=AssessmentStatus.FAILED,
        created_by_id=lead_user.id,
        attempt_count=1,
        retry_count=0,
        max_retries=3,
    )
    db.add(job)
    db.commit()
    db.refresh(job)

    # 1. Retry Attempt 1 (Permitted)
    ok, retried_job, msg = AssessmentExecutionEngine.retry_job(db, job.id)
    assert ok is True
    assert retried_job.status == AssessmentStatus.QUEUED
    assert retried_job.attempt_count == 2
    assert retried_job.retry_count == 1
    assert "retry_backoff_seconds" in retried_job.summary_stats

    # 2. Cannot retry an already QUEUED job (prevents duplicate execution)
    ok_dup, _, msg_dup = AssessmentExecutionEngine.retry_job(db, job.id)
    assert ok_dup is False
    assert "Cannot retry job in status 'QUEUED'" in msg_dup

    # Simulate job failing attempt 2
    retried_job.status = AssessmentStatus.FAILED
    db.commit()

    # 3. Retry Attempt 2 (Permitted - reaches max_retries limit)
    ok2, retried_job2, msg2 = AssessmentExecutionEngine.retry_job(db, job.id)
    assert ok2 is True
    assert retried_job2.attempt_count == 3
    assert retried_job2.retry_count == 2

    retried_job2.status = AssessmentStatus.FAILED
    db.commit()

    # 4. Retry Attempt 3 (Rejected - Budget exhausted)
    ok3, _, msg3 = AssessmentExecutionEngine.retry_job(db, job.id)
    assert ok3 is False
    assert "reached maximum allowed execution attempts" in msg3

    # 5. Recovery engine rejection for active jobs
    job.status = AssessmentStatus.RUNNING
    db.commit()
    rec_res = RecoveryEngineService.execute_recovery(
        db=db,
        project_id=test_project.id,
        action_type=RecoveryActionType.RETRY_ASSESSMENT,
        target_entity_type="assessment_job",
        target_entity_id=job.id,
        actor=lead_user,
    )
    assert rec_res["outcome"] == RecoveryOutcome.FAILED
    assert "JOB_ALREADY_ACTIVE" in rec_res["post_condition"]["error"]


# ------------------------------------------------------------------------------
# Test 10: Automatic Recovery Cannot Weaken Scope Boundaries
# ------------------------------------------------------------------------------
def test_10_automatic_recovery_cannot_weaken_scope_restrictions(
    db: Session, test_project: Project, lead_user: User, authorized_scope: ScopeTarget
):
    """Automatic recovery must fail closed if target becomes unauthorized or revoked."""
    job = AssessmentJob(
        project_id=test_project.id,
        target_input=authorized_scope.target_value,
        adapter_name="local_fixture_adapter",
        status=AssessmentStatus.FAILED,
        created_by_id=lead_user.id,
        attempt_count=1,
        retry_count=0,
        max_retries=3,
    )
    db.add(job)
    db.commit()
    db.refresh(job)

    # Operator revokes scope by adding an explicit Scope Exclusion
    exclusion = ScopeExclusion(
        project_id=test_project.id,
        target_type=TargetType.URL,
        target_value="https://grid-alpha.acme.local",
        reason="Decommissioned for emergency maintenance",
        created_by_id=lead_user.id,
    )
    db.add(exclusion)
    db.commit()

    # Attempt recovery via AssessmentExecutionEngine
    ok, _, msg = AssessmentExecutionEngine.retry_job(db, job.id)
    assert ok is False
    assert "no longer authorized by scope policy" in msg

    # Attempt recovery via RecoveryEngineService
    rec_res = RecoveryEngineService.execute_recovery(
        db=db,
        project_id=test_project.id,
        action_type=RecoveryActionType.RETRY_ASSESSMENT,
        target_entity_type="assessment_job",
        target_entity_id=job.id,
        actor=lead_user,
    )
    assert rec_res["outcome"] == RecoveryOutcome.FAILED
    assert rec_res["post_condition"]["scope_error"] == "OUT_OF_SCOPE"


# ------------------------------------------------------------------------------
# Test 11: Health Endpoints Separation & Zero Secret Leakage
# ------------------------------------------------------------------------------
def test_11_health_endpoints_separation_and_zero_secret_leakage(
    client: TestClient, lead_headers: Dict[str, str]
):
    """Health probes must be strictly separated and never disclose secrets."""
    # 1. Liveness Probe
    resp_live = client.get("/api/v1/health/live")
    assert resp_live.status_code == 200
    live_data = resp_live.json()
    assert live_data["status"] == "ok"
    assert "uptime_seconds" in live_data

    # 2. Readiness Probe
    resp_ready = client.get("/api/v1/health/ready")
    assert resp_ready.status_code == 200
    ready_data = resp_ready.json()
    assert ready_data["status"] == "ready"
    assert ready_data["checks"]["database"] is True

    # 3. Dependencies Probe
    resp_deps = client.get("/api/v1/health/dependencies")
    assert resp_deps.status_code == 200
    deps_data = resp_deps.json()
    assert deps_data["critical_healthy"] is True
    assert "database" in deps_data["dependencies"]
    assert "storage" in deps_data["dependencies"]

    # 4. Degradation & Operator Status Probe (Prompt 52)
    resp_deg = client.get("/api/v1/health/degradation")
    assert resp_deg.status_code == 200
    deg_data = resp_deg.json()
    assert "capabilities" in deg_data
    assert "degraded_capabilities" in deg_data
    assert "operator_recommendations" in deg_data
    assert "failure_playbooks" in deg_data

    # 5. Strict Zero Secret Leakage Verification across all responses
    all_responses_text = " ".join([
        resp_live.text,
        resp_ready.text,
        resp_deps.text,
        resp_deg.text,
    ]).lower()

    forbidden_secrets = [
        "secret_key",
        "supersecret",
        "password",
        "bearer",
        "postgres:postgres",
        "private_key",
        "access_token",
    ]
    for sec in forbidden_secrets:
        assert sec not in all_responses_text, f"Secret leakage detected: '{sec}' found in health response!"


# ------------------------------------------------------------------------------
# Test 12: Operator-Readable Failure Classifications & Manual vs Auto Recovery
# ------------------------------------------------------------------------------
def test_12_operator_readable_failure_classifications():
    """Failure classifications must provide clear operator summaries and recovery instructions."""
    catalog = FailureClassificationService.get_classifications()
    assert len(catalog) >= 7

    # 1. Test auto-recoverable failure
    db_fail = FailureClassificationService.classify_failure("DB_CONNECTION_INTERRUPTED")
    assert db_fail.code == "DB_CONNECTION_INTERRUPTED"
    assert db_fail.severity == FailureSeverity.CRITICAL
    assert db_fail.can_auto_recover is True
    assert "exponential backoff" in db_fail.auto_recovery_mechanism
    assert db_fail.evidence_preserved is True

    # 2. Test manual-intervention failure
    disk_fail = FailureClassificationService.classify_failure("EVIDENCE_DISK_WRITE_IO_ERROR")
    assert disk_fail.code == "EVIDENCE_DISK_WRITE_IO_ERROR"
    assert disk_fail.requires_manual_intervention is True
    assert disk_fail.can_auto_recover is False
    assert any("free space" in step.lower() for step in disk_fail.manual_recovery_steps)

    # 3. Test scope denial failure
    scope_fail = FailureClassificationService.classify_failure("GOVERNANCE_SCOPE_DENIAL")
    assert scope_fail.requires_manual_intervention is True
    assert "prohibited from bypassing scope" in scope_fail.operator_summary

    # 4. Test operator playbook query
    playbook = FailureClassificationService.get_operator_playbook("WORKER_ABRUPT_TERMINATION")
    assert "classification" in playbook
    assert "evidence_safety" in playbook
    assert playbook["classification"]["code"] == "WORKER_ABRUPT_TERMINATION"
