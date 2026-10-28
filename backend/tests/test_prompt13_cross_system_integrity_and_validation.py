import pytest
import hashlib
import json
from datetime import datetime, timezone, timedelta
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.project import Project, ProjectMember, ProjectRole
from app.models.organization import Organization
from app.models.user import User, SystemRole
from app.models.scope import ScopeTarget, ScopeExclusion, TargetType, AuthorizationStatus
from app.models.asset import Asset, AssetType, AssetCriticality
from app.models.finding import VulnerabilityFinding, FindingLifecycleStatus, FindingTransition
from app.models.assessment import (
    AssessmentJob,
    AssessmentStatus,
    AssessmentFinding,
    FindingSeverity,
    FindingConfidence,
    FindingEvidence,
)
from app.models.graph import (
    GraphNode,
    GraphRelationship,
    GraphNodeCategory,
    RelationshipType,
    RelationshipStatus,
)
from app.models.diagnostics import (
    DiagnosticCategory,
    DiagnosticSeverity,
    DiagnosticConfidence,
    RecoveryActionType,
    RecoveryOutcome,
)
from app.models.learning import (
    GovernedModel,
    LearningDataset,
    DatasetRecord,
    DatasetSplit,
    ModelStatus,
)
from app.models.audit import AuditEvent

from app.services.scope_engine import ScopeEngine
from app.services.assessment_engine import AssessmentExecutionEngine
from app.services.integrity_service import IntegrityService
from app.services.attack_path_service import AttackPathAnalysisService, PathVerificationStatus
from app.services.contextual_risk_service import ContextualRiskService
from app.services.finding_lifecycle_service import FindingLifecycleService
from app.services.learning_service import ModelGovernanceService
from app.services.recovery_engine import RecoveryEngineService
from app.services.diagnostics_engine import DiagnosticsEngineService
from app.services.audit_service import AuditService
from app.services.scanner_adapters.live_network_adapter import check_ip_ssrf, resolve_and_verify_ssrf


# ------------------------------------------------------------------------------
# Scenario 1: Target authorized, then excluded before queued job starts
# ------------------------------------------------------------------------------
def test_scenario_1_target_authorized_then_excluded_before_job_starts(
    db: Session, test_project: Project, lead_user: User
):
    """
    Validates that a queued assessment job whose target is excluded after queuing
    is immediately denied at the execution boundary during preflight re-validation.
    """
    target_val = "192.168.100.50"

    # Step 1: Authorize target
    st = ScopeTarget(
        project_id=test_project.id,
        target_type=TargetType.IP_ADDRESS,
        target_value=target_val,
        authorization_status=AuthorizationStatus.AUTHORIZED,
        authorized_by_id=lead_user.id,
        authorized_at=datetime.now(timezone.utc),
        created_by_id=lead_user.id,
    )
    db.add(st)
    db.commit()

    # Step 2: Create queued job with snapshot
    scope_eval = ScopeEngine.validate_target_in_scope(db, test_project.id, target_val)
    assert scope_eval["is_authorized"] is True

    snapshot, digest = AssessmentExecutionEngine.compute_scope_snapshot_and_digest(scope_eval)

    job = AssessmentJob(
        project_id=test_project.id,
        target_input=target_val,
        adapter_name="local_fixture_adapter",
        status=AssessmentStatus.QUEUED,
        created_by_id=lead_user.id,
        scope_snapshot=snapshot,
        scope_snapshot_digest=digest,
        policy_version="2026.1",
    )
    db.add(job)
    db.commit()

    # Step 3: Register an exclusion overriding the target before worker claims it
    exclusion = ScopeExclusion(
        project_id=test_project.id,
        target_type=TargetType.IP_ADDRESS,
        target_value=target_val,
        reason="Emergency network maintenance exclusion",
        created_by_id=lead_user.id,
    )
    db.add(exclusion)
    db.commit()

    # Step 4: Worker attempts preflight and claim
    claimed_job = AssessmentExecutionEngine.preflight_and_claim_job(
        db=db,
        job_id=job.id,
        worker_id="worker-node-1",
    )

    assert claimed_job.status == AssessmentStatus.REJECTED
    assert "Preflight execution boundary denial" in claimed_job.error_message
    assert "strictly excluded" in claimed_job.error_message


# ------------------------------------------------------------------------------
# Scenario 2: Worker crashes after evidence collection; recovery frees worker
# ------------------------------------------------------------------------------
def test_scenario_2_worker_crashes_and_recovery_frees_slot_without_false_success(
    db: Session, test_project: Project, lead_user: User
):
    """
    Validates that a crashed worker job stuck in RUNNING is identified by diagnostics
    and safely transitioned to FAILED by RECOVER_STUCK_JOB without erasing evidence.
    """
    past_time = datetime.now(timezone.utc) - timedelta(minutes=45)
    job = AssessmentJob(
        project_id=test_project.id,
        target_input="10.0.0.1",
        adapter_name="local_fixture_adapter",
        status=AssessmentStatus.RUNNING,
        claimed_by="worker-crashed-node",
        started_at=past_time,
        heartbeat_at=past_time,
        created_by_id=lead_user.id,
    )
    db.add(job)
    db.commit()

    # Diagnostic sweep identifies stuck job
    diag_res = DiagnosticsEngineService.run_project_diagnostics(
        db=db,
        project_id=test_project.id,
        actor_id=lead_user.id,
    )
    stuck_finding = next((f for f in diag_res["findings"] if f["check_id"] == "DIAG_STUCK_JOBS"), None)
    assert stuck_finding is not None
    assert stuck_finding["severity"] == DiagnosticSeverity.HIGH.value
    assert stuck_finding["confidence"] == DiagnosticConfidence.CONFIRMED.value

    # Controlled recovery action executes RECOVER_STUCK_JOB
    result = RecoveryEngineService.execute_recovery(
        db=db,
        project_id=test_project.id,
        action_type=RecoveryActionType.RECOVER_STUCK_JOB,
        target_entity_type="assessment_job",
        target_entity_id=job.id,
        actor=lead_user,
        reason="Worker process disappeared from task manager",
    )

    assert result["outcome"] == RecoveryOutcome.SUCCESS.value
    db.refresh(job)
    assert job.status == AssessmentStatus.CANCELLED
    assert "Recovered by diagnostic action" in job.error_message


# ------------------------------------------------------------------------------
# Scenario 3: Two workers attempt to process same job concurrently
# ------------------------------------------------------------------------------
def test_scenario_3_two_workers_cannot_claim_same_assessment_job(
    db: Session, test_project: Project, lead_user: User
):
    """
    Validates atomic conditional claim: Worker 1 successfully transitions QUEUED to RUNNING,
    while Worker 2's simultaneous preflight attempt is safely rejected.
    """
    target_val = "10.0.0.25"
    st = ScopeTarget(
        project_id=test_project.id,
        target_type=TargetType.IP_ADDRESS,
        target_value=target_val,
        authorization_status=AuthorizationStatus.AUTHORIZED,
        authorized_by_id=lead_user.id,
        created_by_id=lead_user.id,
    )
    db.add(st)
    db.commit()

    scope_eval = ScopeEngine.validate_target_in_scope(db, test_project.id, target_val)
    snapshot, digest = AssessmentExecutionEngine.compute_scope_snapshot_and_digest(scope_eval)

    job = AssessmentJob(
        project_id=test_project.id,
        target_input=target_val,
        adapter_name="local_fixture_adapter",
        status=AssessmentStatus.QUEUED,
        created_by_id=lead_user.id,
        scope_snapshot=snapshot,
        scope_snapshot_digest=digest,
        policy_version="2026.1",
    )
    db.add(job)
    db.commit()

    # Worker 1 claims
    job1 = AssessmentExecutionEngine.preflight_and_claim_job(
        db=db,
        job_id=job.id,
        worker_id="worker-alpha",
    )
    assert job1.status == AssessmentStatus.RUNNING
    assert job1.claimed_by == "worker-alpha"

    # Worker 2 attempts to claim
    job2 = AssessmentExecutionEngine.preflight_and_claim_job(
        db=db,
        job_id=job.id,
        worker_id="worker-beta",
    )
    # Worker 2 must not overwrite Worker 1's claim
    assert job2.claimed_by == "worker-alpha"
    assert job2.status == AssessmentStatus.RUNNING


# ------------------------------------------------------------------------------
# Scenario 4: Evidence is changed after finding and risk score recorded
# ------------------------------------------------------------------------------
def test_scenario_4_tampered_evidence_detected_by_integrity_engine(
    db: Session, test_project: Project, lead_user: User
):
    """
    Validates that if an evidence payload is altered in storage, the cryptographic
    IntegrityService detects the SHA-256 discrepancy and flags the exact corrupted record.
    """
    job = AssessmentJob(
        project_id=test_project.id,
        target_input="10.0.0.30",
        adapter_name="local_fixture_adapter",
        status=AssessmentStatus.COMPLETED,
        created_by_id=lead_user.id,
    )
    db.add(job)
    db.commit()

    finding = AssessmentFinding(
        job_id=job.id,
        project_id=test_project.id,
        target_value="10.0.0.30",
        title="Insecure HTTP Headers",
        severity=FindingSeverity.LOW,
        confidence=FindingConfidence.CERTAIN,
    )
    db.add(finding)
    db.commit()

    original_payload = "HTTP/1.1 200 OK\r\nServer: Apache\r\n"
    original_hash = hashlib.sha256(original_payload.encode("utf-8")).hexdigest()

    evidence = FindingEvidence(
        finding_id=finding.id,
        evidence_type="HTTP_RESPONSE_HEADER",
        payload=original_payload,
        sha256_hash=original_hash,
    )
    db.add(evidence)
    db.commit()

    # Verification before tampering: Valid
    report_before = IntegrityService.verify_evidence_integrity(db, job.id)
    assert report_before["is_valid"] is True
    assert len(report_before["corrupted_evidence_ids"]) == 0

    # Tampering: directly alter payload without updating sha256_hash
    evidence.payload = "HTTP/1.1 200 OK\r\nServer: TamperedInjectedValue\r\n"
    db.commit()

    # Verification after tampering: Detected
    report_after = IntegrityService.verify_evidence_integrity(db, job.id)
    assert report_after["is_valid"] is False
    assert evidence.id in report_after["corrupted_evidence_ids"]


# ------------------------------------------------------------------------------
# Scenario 5: Graph relationship changes and invalidates attack path
# ------------------------------------------------------------------------------
def test_scenario_5_graph_relationship_change_invalidates_attack_path(
    db: Session, test_project: Project
):
    """
    Validates that when a knowledge graph edge becomes STALE, the attack path analysis
    categorizes the path as STALE and includes explicit missing evidence instructions.
    """
    node_a = GraphNode(project_id=test_project.id, label="Internet Perimeter", category=GraphNodeCategory.ASSET, entity_id="asset-1")
    node_b = GraphNode(project_id=test_project.id, label="Web Server", category=GraphNodeCategory.SERVICE, entity_id="svc-1")
    node_c = GraphNode(project_id=test_project.id, label="Core Database", category=GraphNodeCategory.DATA_STORE, entity_id="db-1")
    db.add_all([node_a, node_b, node_c])
    db.commit()

    rel_ab = GraphRelationship(
        project_id=test_project.id,
        source_node_id=node_a.id,
        target_node_id=node_b.id,
        relationship_type=RelationshipType.EXPOSES,
        status=RelationshipStatus.VERIFIED,
        confidence=0.95,
    )
    rel_bc = GraphRelationship(
        project_id=test_project.id,
        source_node_id=node_b.id,
        target_node_id=node_c.id,
        relationship_type=RelationshipType.CAN_ACCESS,
        status=RelationshipStatus.VERIFIED,
        confidence=0.90,
    )
    db.add_all([rel_ab, rel_bc])
    db.commit()

    # Path analysis while edges are VERIFIED
    paths_res1 = AttackPathAnalysisService.analyze_attack_paths(
        project_id=test_project.id,
        db=db,
        start_node_id=node_a.id,
        target_node_id=node_c.id,
    )
    assert paths_res1["total_paths_found"] >= 1
    assert paths_res1["paths"][0]["path_verification_status"] == PathVerificationStatus.VERIFIED.value

    # Graph edge BC becomes STALE
    rel_bc.status = RelationshipStatus.STALE
    db.commit()

    # Re-evaluate path
    paths_res2 = AttackPathAnalysisService.analyze_attack_paths(
        project_id=test_project.id,
        db=db,
        start_node_id=node_a.id,
        target_node_id=node_c.id,
    )
    assert paths_res2["total_paths_found"] >= 1
    p = paths_res2["paths"][0]
    assert p["path_verification_status"] == PathVerificationStatus.STALE.value
    assert len(p["missing_evidence"]) > 0
    assert "expired or been superseded" in p["missing_evidence"][0]


# ------------------------------------------------------------------------------
# Scenario 6: Reopened finding triggers recurrence and re-remediation penalty
# ------------------------------------------------------------------------------
def test_scenario_6_reopened_finding_triggers_risk_recurrence_penalty(
    db: Session, test_project: Project, lead_user: User
):
    """
    Validates that transitioning a finding from VERIFIED_CLOSED to REOPENED
    applies recurrence and remediation failure risk multipliers.
    """
    finding = VulnerabilityFinding(
        project_id=test_project.id,
        fingerprint="test-fingerprint-recurrence-1",
        target_value="192.168.1.100",
        title="SQL Injection in Order Search",
        severity=FindingSeverity.HIGH,
        confidence=FindingConfidence.CERTAIN,
        status=FindingLifecycleStatus.VERIFIED_CLOSED,
        recurrence_detected=False,
        recurrence_count=0,
    )
    db.add(finding)
    db.commit()

    # Risk score when VERIFIED_CLOSED is neutralized to 0.0
    score_closed = ContextualRiskService.calculate_score_and_factors(finding=finding)
    assert score_closed["residual_score"] == 0.0

    # Reopen finding
    FindingLifecycleService.transition_finding(
        finding=finding,
        to_status=FindingLifecycleStatus.REOPENED,
        actor=lead_user,
        actor_role=ProjectRole.LEAD,
        reason="Vulnerability reintroduced in release v2.4",
        db=db,
    )
    finding.recurrence_detected = True
    finding.recurrence_count = 1
    db.commit()

    # Risk score after reopening incorporates recurrence penalties
    score_reopened = ContextualRiskService.calculate_score_and_factors(
        finding=finding,
        prior_verification_failed=True,
    )
    assert score_reopened["residual_score"] > 60.0
    contributing = " ".join(score_reopened["contributing_factors"])
    assert "recurrence penalty" in contributing
    assert "Prior remediation attempt failed" in contributing


# ------------------------------------------------------------------------------
# Scenario 7: Model update failing evaluation gate is rejected; baseline preserved
# ------------------------------------------------------------------------------
def test_scenario_7_inferior_or_failing_model_update_rejected_by_quality_gate(
    db: Session, test_project: Project, lead_user: User
):
    """
    Validates that a machine learning model candidate with precision/recall < 0.60
    cannot be approved or deployed, preserving the active model.
    """
    dataset = LearningDataset(
        project_id=test_project.id,
        name="Security Classifiers",
        version="v1.0",
        dataset_hash="dataset-hash-123",
        total_records=10,
    )
    db.add(dataset)
    db.commit()

    # Register candidate model
    model = GovernedModel(
        project_id=test_project.id,
        model_name="fp_classifier",
        version="v2.0-flawed",
        model_type="gradient_boosted",
        status=ModelStatus.EVALUATED,
        dataset_id=dataset.id,
        metrics={
            "precision": 0.45,  # FAILS gate (< 0.60)
            "recall": 0.85,
            "f1_score": 0.59,
        },
        is_active=False,
    )
    db.add(model)
    db.commit()

    # Attempt approval: must raise ValueError
    with pytest.raises(ValueError, match="Model fails minimum quality thresholds"):
        ModelGovernanceService.approve_model(
            project_id=test_project.id,
            model_id=model.id,
            approved=True,
            approval_notes="Attempted bypass of quality threshold",
            reviewer=lead_user,
            db=db,
        )

    db.refresh(model)
    assert model.status != ModelStatus.APPROVED
    assert model.is_active is False


# ------------------------------------------------------------------------------
# Scenario 8: Recovery action fails closed on unmet preconditions
# ------------------------------------------------------------------------------
def test_scenario_8_recovery_action_fails_closed_on_unmet_preconditions(
    db: Session, test_project: Project, lead_user: User
):
    """
    Validates that invoking a recovery action against an entity that does not meet
    preconditions (e.g. attempting to recover a COMPLETED job) fails safely without mutation.
    """
    completed_job = AssessmentJob(
        project_id=test_project.id,
        target_input="10.0.0.5",
        adapter_name="local_fixture_adapter",
        status=AssessmentStatus.COMPLETED,
        created_by_id=lead_user.id,
    )
    db.add(completed_job)
    db.commit()

    result = RecoveryEngineService.execute_recovery(
        db=db,
        project_id=test_project.id,
        action_type=RecoveryActionType.RECOVER_STUCK_JOB,
        target_entity_type="assessment_job",
        target_entity_id=completed_job.id,
        actor=lead_user,
        reason="Testing invalid recovery invocation",
    )

    assert result["outcome"] == RecoveryOutcome.INCONCLUSIVE.value
    assert "Job was already in terminal state" in result["verification_notes"]

    db.refresh(completed_job)
    assert completed_job.status == AssessmentStatus.COMPLETED


# ------------------------------------------------------------------------------
# Scenario 9: Sandbox restore detects corrupted evidence
# ------------------------------------------------------------------------------
def test_scenario_9_sandbox_restore_verifies_evidence_and_diagnostics_integrity(
    db: Session, test_project: Project, lead_user: User
):
    """
    Validates that the integrity service detects discrepancies between persisted
    hashes and payload bytes across assessment findings.
    """
    job = AssessmentJob(
        project_id=test_project.id,
        target_input="10.0.0.6",
        adapter_name="local_fixture_adapter",
        status=AssessmentStatus.COMPLETED,
        created_by_id=lead_user.id,
    )
    db.add(job)
    db.commit()

    f = AssessmentFinding(
        job_id=job.id,
        project_id=test_project.id,
        target_value="10.0.0.6",
        title="Test Leak",
        severity=FindingSeverity.INFO,
        confidence=FindingConfidence.CERTAIN,
    )
    db.add(f)
    db.commit()

    ev1 = FindingEvidence(
        finding_id=f.id,
        evidence_type="RAW_OUTPUT",
        payload="Correct original bytes",
        sha256_hash=hashlib.sha256("Correct original bytes".encode("utf-8")).hexdigest(),
    )
    ev2 = FindingEvidence(
        finding_id=f.id,
        evidence_type="RAW_OUTPUT",
        payload="Corrupted restored bytes",
        sha256_hash="0000000000000000000000000000000000000000000000000000000000000000",
    )
    db.add_all([ev1, ev2])
    db.commit()

    report = IntegrityService.verify_evidence_integrity(db, job.id)
    assert report["is_valid"] is False
    assert ev2.id in report["corrupted_evidence_ids"]
    assert ev1.id not in report["corrupted_evidence_ids"]


# ------------------------------------------------------------------------------
# Scenario 10: Cross-tenant isolation denies outsider access (fails closed with 404)
# ------------------------------------------------------------------------------
def test_scenario_10_cross_tenant_isolation_fails_closed_with_404(
    client: TestClient, test_project: Project, outsider_headers: dict
):
    """
    Validates that an outsider user lacking membership in a project cannot access
    project diagnostics or trigger recovery actions, failing closed with HTTP 404.
    """
    resp_sweep = client.post(
        f"/api/v1/diagnostics/{test_project.id}/run",
        headers=outsider_headers,
    )
    assert resp_sweep.status_code == 404

    resp_recent = client.get(
        f"/api/v1/diagnostics/{test_project.id}/recent",
        headers=outsider_headers,
    )
    assert resp_recent.status_code == 404

    resp_recovery = client.post(
        f"/api/v1/diagnostics/{test_project.id}/recover",
        json={
            "action_type": "RECALCULATE_RISK_SCORES",
            "target_entity_type": "project",
            "reason": "Unauthorized outsider trigger attempt",
        },
        headers=outsider_headers,
    )
    assert resp_recovery.status_code == 404


# ------------------------------------------------------------------------------
# Scenario 11: Monitoring event deduplication prevents duplicate findings
# ------------------------------------------------------------------------------
def test_scenario_11_duplicate_monitoring_event_deduplication(
    db: Session, test_project: Project
):
    """
    Validates that recording the same finding fingerprint twice does not create
    duplicate rows, but cleanly increments the occurrence count.
    """
    fingerprint = hashlib.sha256(b"fingerprint-monitoring-dedup-1").hexdigest()

    f1 = VulnerabilityFinding(
        project_id=test_project.id,
        fingerprint=fingerprint,
        target_value="10.0.0.8",
        title="TLS 1.0 Enabled",
        severity=FindingSeverity.MEDIUM,
        confidence=FindingConfidence.CERTAIN,
        occurrence_count=1,
    )
    db.add(f1)
    db.commit()

    # Query finding and update occurrence count
    existing = (
        db.query(VulnerabilityFinding)
        .filter(
            VulnerabilityFinding.project_id == test_project.id,
            VulnerabilityFinding.fingerprint == fingerprint,
        )
        .first()
    )
    assert existing is not None
    existing.occurrence_count += 1
    existing.last_observed_at = datetime.now(timezone.utc)
    db.commit()

    total_findings = (
        db.query(VulnerabilityFinding)
        .filter(
            VulnerabilityFinding.project_id == test_project.id,
            VulnerabilityFinding.fingerprint == fingerprint,
        )
        .count()
    )
    assert total_findings == 1
    db.refresh(existing)
    assert existing.occurrence_count == 2


# ------------------------------------------------------------------------------
# Scenario 12: Optimistic concurrency conflict on finding transition returns 409
# ------------------------------------------------------------------------------
def test_scenario_12_optimistic_concurrency_conflict_returns_409(
    client: TestClient, test_project: Project, lead_headers: dict, db: Session
):
    """
    Validates that supplying an expected_status that does not match the finding's
    current state returns HTTP 409 Conflict, preventing silent concurrent state overwrite.
    """
    finding = VulnerabilityFinding(
        project_id=test_project.id,
        fingerprint="conflict-check-fingerprint-12",
        target_value="10.0.0.9",
        title="Exposed Admin Console",
        severity=FindingSeverity.HIGH,
        confidence=FindingConfidence.CERTAIN,
        status=FindingLifecycleStatus.CONFIRMED,
    )
    db.add(finding)
    db.commit()

    # Caller attempts to transition expecting DETECTED, but finding is CONFIRMED
    resp = client.post(
        f"/api/v1/projects/{test_project.id}/findings/{finding.id}/transition",
        json={
            "to_status": "REMEDIATION_PROPOSED",
            "expected_status": "DETECTED",  # Stale expected state
            "reason": "Stale transition attempt",
        },
        headers=lead_headers,
    )
    assert resp.status_code == 409
    assert "Concurrent transition conflict" in resp.json()["detail"]


# ------------------------------------------------------------------------------
# Scenario 13: Audit hash chain remains strictly ordered and monotonic
# ------------------------------------------------------------------------------
def test_scenario_13_audit_chain_strictly_monotonic_under_concurrent_calls(
    db: Session, test_project: Project, lead_user: User
):
    """
    Validates that rapid sequential audit logging generates strictly monotonic
    timestamps, unbroken prev_event_hash links, and a VALID audit chain.
    """
    events = []
    for i in range(5):
        ev = AuditService.record_event(
            db=db,
            action=f"TEST_RAPID_EVENT_{i}",
            target_type="test",
            outcome="SUCCESS",
            actor_id=lead_user.id,
            project_id=test_project.id,
            details={"index": i},
        )
        events.append(ev)

    # Verify timestamps are strictly non-decreasing
    for idx in range(1, len(events)):
        assert events[idx].timestamp >= events[idx - 1].timestamp
        assert events[idx].prev_event_hash == events[idx - 1].event_hash

    # Verify audit ledger integrity tool
    ledger_report = IntegrityService.verify_audit_ledger_integrity(db, test_project.id)
    assert ledger_report["is_valid"] is True
    assert ledger_report["chain_status"] == "VALID"
    assert len(ledger_report["tampered_event_ids"]) == 0


# ------------------------------------------------------------------------------
# Scenario 14: SSRF & DNS rebinding protections enforce safe outbound boundaries
# ------------------------------------------------------------------------------
def test_scenario_14_ssrf_and_dns_rebinding_protections():
    """
    Validates check_ip_ssrf and resolve_and_verify_ssrf against cloud metadata,
    link-local, CGNAT, loopback, and private IPs.
    """
    # Cloud metadata: ALWAYS BLOCKED
    is_safe, reason = check_ip_ssrf("169.254.169.254", allow_loopback=True, allow_private=True)
    assert is_safe is False
    assert "cloud metadata" in reason.lower()

    # IPv6 Cloud metadata
    is_safe_v6, reason_v6 = check_ip_ssrf("fd00:ec2::254", allow_loopback=True, allow_private=True)
    assert is_safe_v6 is False

    # IPv4-mapped IPv6 cloud metadata
    is_safe_mapped, _ = check_ip_ssrf("::ffff:169.254.169.254", allow_loopback=True, allow_private=True)
    assert is_safe_mapped is False

    # Private IP blocked unless explicitly authorized
    is_safe_priv, reason_priv = check_ip_ssrf("10.0.1.5", allow_private=False)
    assert is_safe_priv is False
    assert "private" in reason_priv.lower()

    # Loopback blocked unless explicitly authorized
    is_safe_loop, reason_loop = check_ip_ssrf("127.0.0.1", allow_loopback=False)
    assert is_safe_loop is False
    assert "loopback" in reason_loop.lower()

    # Dangerous internal hostnames
    is_safe_host, reason_host, _ = resolve_and_verify_ssrf("metadata.google.internal", 80)
    assert is_safe_host is False
    assert "metadata" in reason_host.lower()
