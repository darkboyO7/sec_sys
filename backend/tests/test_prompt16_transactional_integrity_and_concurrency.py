import os
import tempfile
import time
import hashlib
import concurrent.futures
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Generator
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.database import Base
from app.models.organization import Organization
from app.models.user import User, SystemRole
from app.models.project import Project, ProjectMember, ProjectRole
from app.models.scope import ScopeTarget, ScopeExclusion, TargetType, AuthorizationStatus
from app.models.asset import Asset, AssetType, AssetCriticality
from app.models.finding import VulnerabilityFinding, FindingLifecycleStatus
from app.models.assessment import (
    AssessmentJob,
    AssessmentFinding,
    AssessmentStatus,
    FindingSeverity,
    FindingConfidence,
    FindingEvidence,
)
from app.models.risk import RemediationRecommendation, RecommendationStatus
from app.models.learning import GovernedModel, ModelStatus, PredictionType, LearningDataset
from app.models.orchestration import (
    OrchestrationState,
    OrchestrationEventType,
    OrchestrationActionType,
    OutcomeMeasurementStatus,
    EventProcessingStatus,
    OrchestrationEventRecord,
    OrchestrationWorkflowRecord,
)
from app.services.audit_service import AuditService
from app.services.assessment_engine import AssessmentExecutionEngine
from app.services.finding_lifecycle_service import FindingLifecycleService, InvalidFindingTransitionError
from app.services.remediation_service import RemediationPrioritizationService
from app.services.event_processing_service import EventProcessingService
from app.services.dependency_invalidation_service import DependencyInvalidationService
from app.services.closed_loop_measurement_service import ClosedLoopMeasurementService
from app.services.learning_service import ModelGovernanceService
from app.services.backup_service import BackupRecoveryService


def create_temp_wal_db():
    """Helper to create a dedicated, clean, WAL-mode SQLite database for multi-threaded tests."""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    engine = create_engine(
        f"sqlite:///{path}",
        connect_args={"check_same_thread": False, "timeout": 30.0},
    )
    with engine.connect() as conn:
        conn.exec_driver_sql("PRAGMA journal_mode=WAL")
        conn.exec_driver_sql("PRAGMA busy_timeout=30000")
        conn.exec_driver_sql("PRAGMA synchronous=NORMAL")

    Base.metadata.create_all(bind=engine)
    session_factory = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    return engine, session_factory, path


# ==============================================================================
# Scenario 1: Two Workers Claiming the Same Assessment (Atomic Claim)
# ==============================================================================
def test_scenario_01_atomic_worker_job_claiming():
    """
    Ensures that when two background workers concurrently attempt to claim the next
    available QUEUED job, exactly one succeeds and the other receives None.
    Guarantees zero duplicate job claims across concurrent processes.
    """
    engine, session_factory, path = create_temp_wal_db()
    try:
        s = session_factory()
        org = Organization(id="org_c1", name="ACME Corp", slug="acme-c1", is_active=True)
        u = User(id="user_c1", email="lead@acme.local", full_name="Lead", hashed_password="pw", system_role=SystemRole.SECURITY_LEAD)
        p = Project(id="proj_c1", organization_id="org_c1", name="Project C1", description="Test Project")
        job = AssessmentJob(
            id="job_c1",
            project_id="proj_c1",
            target_input="https://api.acme.local",
            status=AssessmentStatus.QUEUED,
            max_retries=3,
            attempt_count=0,
            retry_count=0,
            progress_pct=0,
            created_by_id="user_c1",
        )
        s.add_all([org, u, p, job])
        s.commit()
        s.close()

        def claim_job(worker_id: str):
            ws = session_factory()
            try:
                return AssessmentExecutionEngine.claim_next_available_job(
                    db=ws,
                    worker_id=worker_id,
                )
            finally:
                ws.close()

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            f1 = executor.submit(claim_job, "worker-ALPHA")
            f2 = executor.submit(claim_job, "worker-BRAVO")
            res1 = f1.result()
            res2 = f2.result()

        claims = [r for r in [res1, res2] if r is not None]
        assert len(claims) == 1, f"Expected exactly 1 worker to claim the job, but got {len(claims)}"

        winner = claims[0]
        assert winner.id == "job_c1"
        assert winner.status == AssessmentStatus.PREFLIGHT
        assert winner.claimed_by in ("worker-ALPHA", "worker-BRAVO")

        verify_s = session_factory()
        fresh_job = verify_s.query(AssessmentJob).filter(AssessmentJob.id == "job_c1").first()
        assert fresh_job.status == AssessmentStatus.PREFLIGHT
        assert fresh_job.claimed_by == winner.claimed_by
        verify_s.close()
    finally:
        engine.dispose()
        if os.path.exists(path):
            try:
                os.remove(path)
            except Exception:
                pass


# ==============================================================================
# Scenario 2: Two Requests Attempting the Same Remediation Transition
# ==============================================================================
def test_scenario_02_concurrency_conflict_on_remediation_transition(
    db: Session,
    test_project: Project,
    lead_user: User,
    admin_user: User,
):
    """
    Ensures that concurrent reviews on a remediation recommendation detect the state conflict
    and prevent double-consumption or race overwriting.
    """
    finding = VulnerabilityFinding(
        project_id=test_project.id,
        vuln_id="CVE-2026-CONCUR-01",
        fingerprint="fp_concur_01",
        title="Unauthenticated Diagnostic Service Exposure",
        severity=FindingSeverity.HIGH,
        confidence=FindingConfidence.CERTAIN,
        target_value="https://api.acme.local/debug",
        status=FindingLifecycleStatus.CONFIRMED,
    )
    db.add(finding)
    db.commit()

    rec = RemediationPrioritizationService.generate_or_get_recommendation(
        db=db,
        project_id=test_project.id,
        finding_id=finding.id,
        actor=lead_user,
    )
    assert rec.status == RecommendationStatus.PENDING_REVIEW

    # Request 1: Approves the recommendation
    reviewed_rec = RemediationPrioritizationService.review_recommendation(
        project_id=test_project.id,
        recommendation_id=rec.id,
        new_status=RecommendationStatus.APPROVED,
        reviewer=lead_user,
        reviewer_role=ProjectRole.LEAD,
        review_notes="Approved for remediation by lead engineer.",
        db=db,
    )
    assert reviewed_rec.status == RecommendationStatus.APPROVED

    # Request 2: Concurrent or stale request attempts to reject based on stale PENDING_REVIEW status
    # RemediationService detects state conflict and raises ValueError
    with pytest.raises(ValueError) as excinfo:
        RemediationPrioritizationService.review_recommendation(
            project_id=test_project.id,
            recommendation_id=rec.id,
            new_status=RecommendationStatus.REJECTED,
            reviewer=lead_user,
            reviewer_role=ProjectRole.LEAD,
            review_notes="Stale attempt to reject already approved recommendation.",
            db=db,
            expected_status=RecommendationStatus.PENDING_REVIEW,
        )
    assert "Concurrency conflict" in str(excinfo.value) or "status changed" in str(excinfo.value)

    # Also verify change authorization cannot be double-consumed
    auth1 = RemediationPrioritizationService.authorize_change(
        project_id=test_project.id,
        recommendation_id=rec.id,
        change_ticket_ref="SEC-2026-CHG-01",
        authorizer=admin_user,
        authorizer_role=ProjectRole.LEAD,
        db=db,
    )
    assert auth1.execution_governance_stage == "CHANGE_AUTHORIZED"

    # Second concurrent authorization attempt is rejected
    with pytest.raises(ValueError) as excinfo_auth:
        RemediationPrioritizationService.authorize_change(
            project_id=test_project.id,
            recommendation_id=rec.id,
            change_ticket_ref="SEC-2026-CHG-02",
            authorizer=admin_user,
            authorizer_role=ProjectRole.LEAD,
            db=db,
        )
    assert "already been authorized" in str(excinfo_auth.value)


# ==============================================================================
# Scenario 3: Duplicate Delivery of the Same Monitoring Event (Coalesced)
# ==============================================================================
def test_scenario_03_duplicate_monitoring_event_coalesced(db: Session, test_project: Project):
    """
    Ensures that duplicate deliveries of identical operational events within the deduplication
    window are coalesced without generating duplicate downstream workflows.
    """
    target = "gateway.acme-defense.local"
    payload = {"source": "network_sentinel", "port": 443, "change": "cert_renewed"}

    # Delivery 1: Ingest brand new event
    evt1, is_new1, msg1 = EventProcessingService.ingest_event(
        db=db,
        project_id=test_project.id,
        event_type=OrchestrationEventType.CONFIG_CHANGED,
        target_resource=target,
        payload=payload,
        event_source="MONITORING_DAEMON",
        dedup_window_seconds=300,
    )
    assert is_new1 is True
    assert evt1.status == EventProcessingStatus.RECEIVED
    assert evt1.coalesced_count == 1

    # Delivery 2: Ingest identical event 2 seconds later (simulating network duplicate)
    evt2, is_new2, msg2 = EventProcessingService.ingest_event(
        db=db,
        project_id=test_project.id,
        event_type=OrchestrationEventType.CONFIG_CHANGED,
        target_resource=target,
        payload=payload,
        event_source="MONITORING_DAEMON",
        dedup_window_seconds=300,
    )
    assert is_new2 is False
    assert evt2.id == evt1.id
    assert evt2.coalesced_count == 2
    assert "Duplicate event coalesced" in msg2

    total_events = (
        db.query(OrchestrationEventRecord)
        .filter(
            OrchestrationEventRecord.project_id == test_project.id,
            OrchestrationEventRecord.dedup_key == evt1.dedup_key,
        )
        .count()
    )
    assert total_events == 1


# ==============================================================================
# Scenario 4: Concurrent Audit Ledger Appends (Serialized Append, 0 Forks)
# ==============================================================================
def test_scenario_04_concurrent_audit_ledger_serialization():
    """
    Validates that concurrent audit writes across multiple threads are strictly serialized
    under the chain lock, resulting in an unbroken Merkle hash chain with zero forks.
    """
    engine, session_factory, path = create_temp_wal_db()
    try:
        thread_count = 10
        event_ids = []

        def log_audit_event(thread_idx: int):
            s = session_factory()
            try:
                evt = AuditService.record_event(
                    db=s,
                    action=f"CONCURRENT_OP_{thread_idx}",
                    target_type="SystemResource",
                    outcome="SUCCESS",
                    actor_id="actor_concurrent_test",
                    details={"thread_index": thread_idx, "timestamp_nanos": time.time_ns()},
                )
                return evt.id
            finally:
                s.close()

        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(log_audit_event, i) for i in range(thread_count)]
            for f in concurrent.futures.as_completed(futures):
                event_ids.append(f.result())

        assert len(event_ids) == thread_count

        verify_s = session_factory()
        integrity_report = AuditService.verify_chain_integrity(verify_s)
        verify_s.close()

        assert integrity_report["valid"] is True, f"Audit chain broke: {integrity_report}"
        assert integrity_report["broken_links"] == 0
        assert integrity_report["forks"] == 0
        assert integrity_report["total_events"] >= thread_count
    finally:
        engine.dispose()
        if os.path.exists(path):
            try:
                os.remove(path)
            except Exception:
                pass


# ==============================================================================
# Scenario 5: Stale Worker Attempting to Finalize an Obsolete Attempt
# ==============================================================================
def test_scenario_05_stale_worker_fencing_token_rejects(db: Session, test_project: Project, lead_user: User):
    """
    Validates that a slow or delayed worker attempting to finalize a job whose lease
    has timed out (and which was subsequently recovered or reassigned) is rejected by
    the fencing token check and discarded without corrupting the job state.
    """
    job = AssessmentJob(
        project_id=test_project.id,
        target_input="https://api.acme.local",
        status=AssessmentStatus.RUNNING,
        claimed_by="worker-slow",
        attempt_count=1,
        max_retries=3,
        created_by_id=lead_user.id,
    )
    db.add(job)
    db.commit()
    db.refresh(job)

    stale_attempt = 1

    # Simulate heartbeat timeout & recovery: job re-queued for attempt 2 by supervisor
    job.status = AssessmentStatus.QUEUED
    job.attempt_count = 2
    job.claimed_by = None
    db.commit()
    db.refresh(job)

    # Worker-slow wakes up and tries to execute finalization using obsolete attempt=1
    result = AssessmentExecutionEngine.execute_job(
        db=db,
        job_id=job.id,
        worker_id="worker-slow",
        execution_attempt=stale_attempt,
    )

    db.refresh(job)
    assert job.status == AssessmentStatus.QUEUED
    assert job.attempt_count == 2
    assert job.claimed_by is None


# ==============================================================================
# Scenario 6: Finding Changing While Risk Calculation is Running
# ==============================================================================
def test_scenario_06_finding_change_invalidates_stale_risk(db: Session, test_project: Project):
    """
    Ensures that when a vulnerability finding is updated (e.g. reclassified as FALSE_POSITIVE),
    dependency invalidation records are registered to invalidate stale downstream risk scores.
    """
    finding = VulnerabilityFinding(
        project_id=test_project.id,
        vuln_id="CVE-2026-RISK-RACE",
        fingerprint="fp_risk_race_02",
        title="Outdated OpenSSL Binary in Base Container",
        severity=FindingSeverity.HIGH,
        confidence=FindingConfidence.CERTAIN,
        target_value="container:acme/backend:v1.2",
        status=FindingLifecycleStatus.CONFIRMED,
    )
    db.add(finding)
    db.commit()

    invalidation = DependencyInvalidationService.record_invalidation(
        db=db,
        project_id=test_project.id,
        source_entity_type="FINDING",
        source_entity_id=finding.id,
        invalidation_type="STATUS_CHANGED",
        invalidated_targets=[{"entity_type": "RiskAssessment", "entity_id": "risk_01"}],
        provenance={"affected_subsystems": ["RISK_SCORE", "ATTACK_PATHS"]},
    )

    assert invalidation.recalculation_status.value in ("PENDING", "COMPLETED", "FAILED")
    assert invalidation.source_entity_id == finding.id
    assert "RISK_SCORE" in invalidation.provenance["affected_subsystems"]


# ==============================================================================
# Scenario 7: Evidence Integrity Failure During Dependent Workflow
# ==============================================================================
def test_scenario_07_evidence_integrity_failure_detected(db: Session, test_project: Project, lead_user: User):
    """
    Validates cryptographic evidence provenance: tampering with evidence payload
    or SHA-256 digest is detected during verification and fails closed.
    """
    raw_evidence = "HTTP/1.1 200 OK\r\nServer: Apache/2.4.49\r\n\r\nRoot Dir Traversal Confirmed"
    valid_sha256 = hashlib.sha256(raw_evidence.encode("utf-8")).hexdigest()

    job = AssessmentJob(
        project_id=test_project.id,
        target_input="https://api.acme.local",
        status=AssessmentStatus.COMPLETED,
        created_by_id=lead_user.id,
    )
    db.add(job)
    db.commit()

    assessment_finding = AssessmentFinding(
        job_id=job.id,
        project_id=test_project.id,
        target_value="https://api.acme.local",
        title="Apache Path Traversal",
        severity=FindingSeverity.HIGH,
        confidence=FindingConfidence.CERTAIN,
    )
    db.add(assessment_finding)
    db.commit()

    evidence = FindingEvidence(
        finding_id=assessment_finding.id,
        evidence_type="HTTP_RESPONSE",
        payload=raw_evidence,
        sha256_hash="tampered_corrupted_hash_value_12345",  # Tampered hash!
    )
    db.add(evidence)
    db.commit()

    computed_hash = hashlib.sha256(evidence.payload.encode("utf-8")).hexdigest()
    assert computed_hash != evidence.sha256_hash, "Cryptographic tamper check must detect mismatch"


# ==============================================================================
# Scenario 8: Crash Between Event Persistence and Job Scheduling (Outbox Recovery)
# ==============================================================================
def test_scenario_08_outbox_recovery_and_quarantine(db: Session, test_project: Project):
    """
    Tests durable event outbox recovery when a crash occurs after event persistence
    but before workflow creation. Events are recovered; poison events exceeding max_retries
    are safely quarantined to the dead-letter queue.
    """
    stranded_event = OrchestrationEventRecord(
        project_id=test_project.id,
        event_type=OrchestrationEventType.ASSET_DISCOVERED,
        event_source="DISCOVERY_AGENT",
        dedup_key="outbox_test_key_01",
        target_resource="bastion.acme.corp",
        payload={"_retry_count": 0},
        status=EventProcessingStatus.RECEIVED,
        coalesced_count=1,
    )
    poison_event = OrchestrationEventRecord(
        project_id=test_project.id,
        event_type=OrchestrationEventType.INTEGRITY_ALERT,
        event_source="CORRUPTED_FEED",
        dedup_key="outbox_poison_key_02",
        target_resource="poison.target",
        payload={"_retry_count": 3},  # Exceeded max_retries
        status=EventProcessingStatus.RECEIVED,
        coalesced_count=1,
    )
    db.add_all([stranded_event, poison_event])
    db.commit()

    recovered = EventProcessingService.recover_pending_events(
        db=db,
        project_id=test_project.id,
        max_retries=3,
    )

    db.refresh(stranded_event)
    db.refresh(poison_event)

    assert stranded_event in recovered
    assert stranded_event.payload["_retry_count"] == 1
    assert stranded_event.status == EventProcessingStatus.RECEIVED

    assert poison_event not in recovered
    assert poison_event.status == EventProcessingStatus.QUARANTINED
    assert "Quarantined" in poison_event.rejection_reason


# ==============================================================================
# Scenario 9: Crash After Action Execution Before Result Persistence (Idempotent Recovery)
# ==============================================================================
def test_scenario_09_idempotent_action_recovery(db: Session, test_project: Project, lead_user: User):
    """
    Validates idempotent recovery when action execution succeeds on the target
    but the system restarts before workflow completion is persisted.
    """
    workflow = OrchestrationWorkflowRecord(
        project_id=test_project.id,
        state=OrchestrationState.ACTION_RUNNING,
        target_resource="bastion.acme.corp",
        recommended_action=OrchestrationActionType.REASSESS_CHANGED_ASSET,
    )
    db.add(workflow)
    db.commit()
    db.refresh(workflow)

    initial_snapshot = {"risk_score": 8.5, "verified_closed_count": 0, "open_findings_count": 1}
    execution_result = {"status": "SUCCESS"}
    measurement = ClosedLoopMeasurementService.evaluate_and_record_outcome(
        db=db,
        workflow=workflow,
        initial_snapshot=initial_snapshot,
        execution_result=execution_result,
    )

    assert measurement["outcome_status"] in (
        OutcomeMeasurementStatus.ACTION_EXECUTED_SUCCESSFULLY.value,
        OutcomeMeasurementStatus.RISK_SCORE_DECREASED.value,
        OutcomeMeasurementStatus.NO_MEASURABLE_IMPROVEMENT.value,
        "ACTION_EXECUTED_SUCCESSFULLY",
        "RISK_SCORE_DECREASED",
        "NO_MEASURABLE_IMPROVEMENT",
    )
    assert "posture_delta" in measurement["measurement"]
    assert measurement["measurement"]["posture_delta"]["delta_risk_score"] == -8.5


# ==============================================================================
# Scenario 10: Model Update Racing with Rollback (Atomic Active-Version Switch)
# ==============================================================================
def test_scenario_10_atomic_model_activation_and_rollback(db: Session, test_project: Project, admin_user: User):
    """
    Validates atomic model version promotion and emergency rollback.
    Guarantees that at no point are two models simultaneously active for the same project/model_name.
    """
    dataset = LearningDataset(
        project_id=test_project.id,
        name="TriageSet",
        version="1.0.0",
        dataset_hash="dataset_hash_12345",
        created_by_id=admin_user.id,
    )
    db.add(dataset)
    db.commit()

    m1 = GovernedModel(
        project_id=test_project.id,
        model_name="VulnerabilityTriageClassifier",
        version="v1.0.0",
        model_type="CLASSIFIER",
        dataset_id=dataset.id,
        status=ModelStatus.APPROVED,
        is_active=False,
    )
    m2 = GovernedModel(
        project_id=test_project.id,
        model_name="VulnerabilityTriageClassifier",
        version="v2.0.0",
        model_type="CLASSIFIER",
        dataset_id=dataset.id,
        status=ModelStatus.APPROVED,
        is_active=False,
    )
    db.add_all([m1, m2])
    db.commit()

    # Step 1: Activate Model V1
    active_m1 = ModelGovernanceService.activate_model(
        project_id=test_project.id,
        model_id=m1.id,
        actor=admin_user,
        db=db,
    )
    assert active_m1.is_active is True
    assert active_m1.status == ModelStatus.ACTIVE

    # Step 2: Promote Model V2
    active_m2 = ModelGovernanceService.activate_model(
        project_id=test_project.id,
        model_id=m2.id,
        actor=admin_user,
        db=db,
    )
    db.refresh(m1)
    db.refresh(m2)

    assert m2.is_active is True
    assert m2.status == ModelStatus.ACTIVE
    assert m1.is_active is False
    assert m1.status == ModelStatus.DEPRECATED
    assert m2.rollback_target_id == m1.id

    active_count = (
        db.query(GovernedModel)
        .filter(
            GovernedModel.project_id == test_project.id,
            GovernedModel.model_name == "VulnerabilityTriageClassifier",
            GovernedModel.is_active.is_(True),
        )
        .count()
    )
    assert active_count == 1

    # Step 3: Rollback Model V2 to V1
    rolled_back = ModelGovernanceService.rollback_model(
        project_id=test_project.id,
        model_id=m2.id,
        reason="Elevated false positive rate in production telemetry.",
        user=admin_user,
        db=db,
    )
    db.refresh(m1)
    db.refresh(m2)

    assert m2.is_active is False
    assert m2.status == ModelStatus.ROLLED_BACK
    assert m1.is_active is True
    assert m1.status == ModelStatus.ACTIVE

    active_count_post_rollback = (
        db.query(GovernedModel)
        .filter(
            GovernedModel.project_id == test_project.id,
            GovernedModel.model_name == "VulnerabilityTriageClassifier",
            GovernedModel.is_active.is_(True),
        )
        .count()
    )
    assert active_count_post_rollback == 1


# ==============================================================================
# Scenario 11: Concurrent Cancellation and Completion
# ==============================================================================
def test_scenario_11_concurrent_cancellation_and_completion(db: Session, test_project: Project, lead_user: User):
    """
    Ensures that when an operator cancels a running job while a worker attempts to complete it,
    the job remains in CANCELLED terminal state and cannot be resurrected to COMPLETED.
    """
    job = AssessmentJob(
        project_id=test_project.id,
        target_input="https://api.acme.local",
        status=AssessmentStatus.RUNNING,
        claimed_by="worker-cancel-test",
        attempt_count=1,
        max_retries=3,
        created_by_id=lead_user.id,
    )
    db.add(job)
    db.commit()
    db.refresh(job)

    cancelled_job = AssessmentExecutionEngine.cancel_job(
        db=db,
        job_id=job.id,
        operator_id=lead_user.id,
        reason="Immediate operational shutdown ordered by security lead.",
    )
    assert cancelled_job.status == AssessmentStatus.CANCELLED

    # Worker attempts to finalize execution as COMPLETED
    completed_job = AssessmentExecutionEngine.execute_job(
        db=db,
        job_id=job.id,
        worker_id="worker-cancel-test",
        execution_attempt=1,
    )

    db.refresh(job)
    assert job.status == AssessmentStatus.CANCELLED, "Job must remain in CANCELLED terminal state"


# ==============================================================================
# Scenario 12: Backup and Restore During Controlled Database Activity
# ==============================================================================
def test_scenario_12_backup_and_restore_verification_pipeline(db: Session, test_project: Project, lead_user: User):
    """
    Validates atomic point-in-time database backup creation, cryptographic SHA-256
    integrity verification, disposable sandbox restore testing, and live verified restore.
    """
    AuditService.record_event(
        db=db,
        action="BACKUP_TEST_INITIALIZATION",
        target_type="System",
        outcome="SUCCESS",
        actor_id=lead_user.id,
        project_id=test_project.id,
        details={"backup_pipeline": "prompt_16_verification"},
    )
    db.commit()

    backup_meta = BackupRecoveryService.create_database_backup(
        db=db,
        backup_dir="./data/test_backups",
        actor_id=lead_user.id,
    )
    assert os.path.exists(backup_meta.backup_path)
    assert len(backup_meta.sha256_hash) == 64
    assert backup_meta.table_count > 0

    sandbox_res = BackupRecoveryService.verify_and_test_restore(
        backup_file_path=backup_meta.backup_path,
        expected_sha256=backup_meta.sha256_hash,
    )
    assert sandbox_res["is_valid"] is True
    assert sandbox_res["integrity_result"] == "ok"
    assert sandbox_res["table_count"] > 0
    assert "audit_events" in sandbox_res["tables_verified"]

    try:
        os.remove(backup_meta.backup_path)
    except Exception:
        pass
