import pytest
from datetime import datetime, timezone, timedelta
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.project import Project, ProjectMember, ProjectRole
from app.models.organization import Organization
from app.models.user import User, SystemRole
from app.models.scope import ScopeTarget, TargetType, AuthorizationStatus
from app.models.asset import Asset, AssetType, AssetCriticality
from app.models.finding import VulnerabilityFinding, FindingLifecycleStatus
from app.models.assessment import (
    AssessmentJob,
    AssessmentStatus,
    AssessmentFinding,
    FindingSeverity,
    FindingConfidence,
    FindingEvidence,
)
from app.models.notification import (
    NotificationRecord,
    NotificationDeliveryRecord,
    NotificationEventType,
    NotificationSeverity,
    NotificationStatus,
)
from app.models.diagnostics import (
    ComponentHealthStatus,
    DiagnosticSeverity,
    DiagnosticConfidence,
    DiagnosticCategory,
    RecoveryActionType,
    RecoveryOutcome,
    SystemHealthSnapshot,
    DiagnosticRunRecord,
    DiagnosticFindingRecord,
    RecoveryActionRecord,
    FailurePatternRecord,
)
from app.models.decision import (
    DecisionLedgerType,
    SecurityDecisionLedgerRecord,
    AutonomousPolicyRecord,
    AutonomyIntensity,
)
from app.models.base import utc_now

from app.services.health_engine import HealthEngineService
from app.services.diagnostics_engine import DiagnosticsEngineService
from app.services.recovery_engine import RecoveryEngineService
from app.services.continuous_improvement_service import ContinuousImprovementService
from app.services.failure_knowledge_base import FailureKnowledgeBase


# ------------------------------------------------------------------------------
# Test 1: System Health Engine Evaluates All 12 Subsystems
# ------------------------------------------------------------------------------
def test_system_health_engine_evaluates_all_subsystems(db: Session):
    """
    Proves that the Central System Health Engine inspects real functionality
    across all 12 platform subsystems without leaking secrets or passwords.
    """
    health = HealthEngineService.evaluate_system_health(db=db)

    assert "timestamp" in health
    assert health["overall_status"] in [s.value for s in ComponentHealthStatus]
    assert health["healthy_count"] >= 0
    assert "components" in health

    components = health["components"]
    expected_subsystems = [
        "api_auth",
        "database_migrations",
        "background_workers",
        "scanner_adapters",
        "asset_evidence",
        "risk_attack_paths",
        "remediation_verification",
        "monitoring_events",
        "learning_governance",
        "notification_pipeline",
        "backup_recovery",
        "frontend_connectivity",
    ]

    for sub in expected_subsystems:
        assert sub in components, f"Subsystem '{sub}' missing from health report."
        c = components[sub]
        assert "status" in c
        assert c["status"] in [s.value for s in ComponentHealthStatus]
        assert "message" in c
        assert "is_live_check" in c
        assert c["is_live_check"] is True

        # Verify zero credential leakage
        raw_repr = str(c).lower()
        assert "password" not in raw_repr or "password" in c.get("name", "").lower()
        assert "secret_key" not in raw_repr
        assert "bearer " not in raw_repr


# ------------------------------------------------------------------------------
# Test 2: Read-Only Project Diagnostics Execution
# ------------------------------------------------------------------------------
def test_read_only_project_diagnostics_execution(
    db: Session,
    test_project: Project,
    lead_user: User,
):
    """
    Proves that self-diagnostics runs bounded read-only checks and
    persists structured diagnostic runs and findings.
    """
    result = DiagnosticsEngineService.run_project_diagnostics(
        db=db,
        project_id=test_project.id,
        actor_id=lead_user.id,
        trigger_type="MANUAL",
    )

    assert "run_id" in result
    assert result["project_id"] == test_project.id
    assert result["total_checks"] == 10
    assert result["passed_checks"] >= 0
    assert "summary" in result

    # Verify run record in database
    run_rec = db.query(DiagnosticRunRecord).filter(DiagnosticRunRecord.id == result["run_id"]).first()
    assert run_rec is not None
    assert run_rec.project_id == test_project.id


# ------------------------------------------------------------------------------
# Test 3: Stuck Job Diagnostic & Recovery Verification
# ------------------------------------------------------------------------------
def test_stuck_job_diagnostic_and_recovery_verification(
    db: Session,
    test_project: Project,
    lead_user: User,
):
    """
    Proves that diagnostics detects a stuck job running > 15m and
    controlled recovery transitions it safely to CANCELLED, releasing capacity.
    """
    now = utc_now()
    twenty_mins_ago = now - timedelta(minutes=20)

    # 1. Create a simulated stuck job
    stuck_job = AssessmentJob(
        project_id=test_project.id,
        target_input="https://portal.acme.local",
        adapter_name="web_adapter",
        status=AssessmentStatus.RUNNING,
        started_at=twenty_mins_ago,
        created_by_id=lead_user.id,
    )
    db.add(stuck_job)
    db.commit()

    # 2. Run diagnostics: verify DIAG_STUCK_JOBS is detected
    diag_res = DiagnosticsEngineService.run_project_diagnostics(
        db=db,
        project_id=test_project.id,
        actor_id=lead_user.id,
    )
    stuck_finding = next((f for f in diag_res["findings"] if f["check_id"] == "DIAG_STUCK_JOBS"), None)
    assert stuck_finding is not None
    assert stuck_job.id in stuck_finding["affected_entities"]
    assert stuck_finding["recovery_action_available"] == RecoveryActionType.RECOVER_STUCK_JOB.value

    # 3. Execute Controlled Recovery Action
    rec_res = RecoveryEngineService.execute_recovery(
        db=db,
        project_id=test_project.id,
        action_type=RecoveryActionType.RECOVER_STUCK_JOB,
        target_entity_type="ASSESSMENT_JOB",
        target_entity_id=stuck_job.id,
        target_resource=stuck_job.target_input,
        actor=lead_user,
        reason="Operator recovered stuck job from diagnostic finding",
    )

    assert rec_res["outcome"] == RecoveryOutcome.SUCCESS.value
    assert rec_res["pre_condition"]["status"] == AssessmentStatus.RUNNING.value
    assert rec_res["post_condition"]["status"] == AssessmentStatus.CANCELLED.value

    # 4. Verify job updated in DB
    db.refresh(stuck_job)
    assert stuck_job.status == AssessmentStatus.CANCELLED

    # 5. Verify Decision Ledger record
    ledger = (
        db.query(SecurityDecisionLedgerRecord)
        .filter(
            SecurityDecisionLedgerRecord.project_id == test_project.id,
            SecurityDecisionLedgerRecord.initiating_event == "RECOVERY_ACTION:RECOVER_STUCK_JOB",
        )
        .first()
    )
    assert ledger is not None
    assert ledger.decision_outcome == "SUCCESS"


# ------------------------------------------------------------------------------
# Test 4: Retry Failed Assessment Within Authorized Scope & Policy
# ------------------------------------------------------------------------------
def test_retry_failed_assessment_within_scope_and_policy(
    db: Session,
    test_project: Project,
    lead_user: User,
):
    """
    Proves that a transiently failed assessment can be recovered via RETRY_ASSESSMENT
    when the target is authorized in scope.
    """
    now = utc_now()
    target = "https://portal.acme.local"

    # Register target as authorized
    st = ScopeTarget(
        project_id=test_project.id,
        target_value=target,
        target_type=TargetType.URL,
        authorization_status=AuthorizationStatus.AUTHORIZED,
        authorization_evidence="ROE-RETRY-01",
        authorized_by_id=lead_user.id,
        authorized_at=now,
        created_by_id=lead_user.id,
    )
    db.add(st)

    failed_job = AssessmentJob(
        project_id=test_project.id,
        target_input=target,
        adapter_name="web_adapter",
        status=AssessmentStatus.FAILED,
        error_message="Connection timed out after 30s",
        created_by_id=lead_user.id,
    )
    db.add(failed_job)
    db.commit()

    # Execute retry recovery
    rec_res = RecoveryEngineService.execute_recovery(
        db=db,
        project_id=test_project.id,
        action_type=RecoveryActionType.RETRY_ASSESSMENT,
        target_entity_type="ASSESSMENT_JOB",
        target_entity_id=failed_job.id,
        target_resource=target,
        actor=lead_user,
        reason="Retrying transient network timeout",
    )

    assert rec_res["outcome"] == RecoveryOutcome.SUCCESS.value
    new_job_id = rec_res["post_condition"]["new_job_id"]
    assert new_job_id is not None

    new_job = db.query(AssessmentJob).filter(AssessmentJob.id == new_job_id).first()
    assert new_job is not None
    assert new_job.status == AssessmentStatus.QUEUED
    assert new_job.target_input == target


# ------------------------------------------------------------------------------
# Test 5: Recovery Action Rejects Out-Of-Scope Target (Fail-Closed)
# ------------------------------------------------------------------------------
def test_recovery_action_rejects_out_of_scope_target(
    db: Session,
    test_project: Project,
    lead_user: User,
):
    """
    Proves that recovery actions cannot be weaponized to bypass scope boundaries.
    """
    unauth_target = "https://unauthorized.evil.com"
    failed_job = AssessmentJob(
        project_id=test_project.id,
        target_input=unauth_target,
        adapter_name="web_adapter",
        status=AssessmentStatus.FAILED,
        created_by_id=lead_user.id,
    )
    db.add(failed_job)
    db.commit()

    rec_res = RecoveryEngineService.execute_recovery(
        db=db,
        project_id=test_project.id,
        action_type=RecoveryActionType.RETRY_ASSESSMENT,
        target_entity_type="ASSESSMENT_JOB",
        target_entity_id=failed_job.id,
        target_resource=unauth_target,
        actor=lead_user,
        reason="Attempting unauthorized target retry",
    )

    assert rec_res["outcome"] == RecoveryOutcome.FAILED.value
    assert "OUT_OF_SCOPE" in str(rec_res["post_condition"])


# ------------------------------------------------------------------------------
# Test 6: Notification Failure Diagnostic & Requeue Recovery
# ------------------------------------------------------------------------------
def test_notification_failure_diagnostic_and_requeue_recovery(
    db: Session,
    test_project: Project,
    lead_user: User,
):
    """
    Proves that notification delivery failures are detected and safely requeued
    within the 3-attempt ceiling.
    """
    now = utc_now()
    notif = NotificationRecord(
        project_id=test_project.id,
        event_type=NotificationEventType.ASSESSMENT_FAILED,
        severity=NotificationSeverity.HIGH,
        status=NotificationStatus.FAILED,
        retry_count=1,
        title="Assessment Job Failed",
        summary="Target connection reset",
        deduplication_key="dedup-test-01",
        created_at=now,
    )
    db.add(notif)
    db.commit()

    # Diagnostics detect failure
    diag_res = DiagnosticsEngineService.run_project_diagnostics(
        db=db,
        project_id=test_project.id,
        actor_id=lead_user.id,
    )
    notif_finding = next((f for f in diag_res["findings"] if f["check_id"] == "DIAG_NOTIFICATIONS_FAILED"), None)
    assert notif_finding is not None
    assert notif.id in notif_finding["affected_entities"]

    # Requeue recovery
    rec_res = RecoveryEngineService.execute_recovery(
        db=db,
        project_id=test_project.id,
        action_type=RecoveryActionType.REQUEUE_NOTIFICATION,
        target_entity_type="NOTIFICATION",
        target_entity_id=notif.id,
        actor=lead_user,
        reason="Operator requeued failed notification",
    )

    assert rec_res["outcome"] == RecoveryOutcome.SUCCESS.value
    db.refresh(notif)
    assert notif.status == NotificationStatus.PENDING
    assert notif.retry_count == 2

    # Exhaust retry limit (attempt 3) and test ceiling
    notif.retry_count = 3
    notif.status = NotificationStatus.FAILED
    db.commit()

    rec_res_blocked = RecoveryEngineService.execute_recovery(
        db=db,
        project_id=test_project.id,
        action_type=RecoveryActionType.REQUEUE_NOTIFICATION,
        target_entity_type="NOTIFICATION",
        target_entity_id=notif.id,
        actor=lead_user,
        reason="Attempting 4th retry",
    )
    assert rec_res_blocked["outcome"] == RecoveryOutcome.FAILED.value
    assert "Maximum retry limit reached" in rec_res_blocked["verification_notes"]


# ------------------------------------------------------------------------------
# Test 7: Contextual Risk Score Recalculation Recovery
# ------------------------------------------------------------------------------
def test_risk_score_recalculation_recovery(
    db: Session,
    test_project: Project,
    test_organization: Organization,
    lead_user: User,
):
    """
    Proves that RECALCULATE_RISK_SCORES updates risk assessments across findings.
    """
    now = utc_now()
    asset = Asset(
        project_id=test_project.id,
        organization_id=test_organization.id,
        asset_type=AssetType.WEB_APP,
        name="Billing Portal",
        canonical_identifier="https://billing.acme.local",
        criticality=AssetCriticality.HIGH,
        last_seen_at=now,
    )
    db.add(asset)
    db.flush()

    finding = VulnerabilityFinding(
        project_id=test_project.id,
        asset_id=asset.id,
        fingerprint="fp-recalc-01",
        target_value="https://billing.acme.local",
        title="Missing Strict-Transport-Security",
        severity=FindingSeverity.MEDIUM,
        confidence=FindingConfidence.CERTAIN,
        status=FindingLifecycleStatus.CONFIRMED,
        last_observed_at=now,
    )
    db.add(finding)
    db.commit()

    rec_res = RecoveryEngineService.execute_recovery(
        db=db,
        project_id=test_project.id,
        action_type=RecoveryActionType.RECALCULATE_RISK_SCORES,
        target_entity_type="PROJECT",
        actor=lead_user,
        reason="Model update to v2.0.0",
    )

    assert rec_res["outcome"] == RecoveryOutcome.SUCCESS.value
    assert rec_res["post_condition"]["recalculated_findings_count"] >= 1


# ------------------------------------------------------------------------------
# Test 8: Backup Trigger Recovery & Sandbox Restore
# ------------------------------------------------------------------------------
def test_backup_trigger_recovery_and_sandbox_restore(
    db: Session,
    test_project: Project,
    lead_user: User,
):
    """
    Proves that TRIGGER_BACKUP creates a non-blocking database backup
    and verifies restore integrity in an isolated disposable sandbox.
    """
    rec_res = RecoveryEngineService.execute_recovery(
        db=db,
        project_id=test_project.id,
        action_type=RecoveryActionType.TRIGGER_BACKUP,
        target_entity_type="PROJECT",
        actor=lead_user,
        reason="Operator scheduled snapshot",
    )

    assert rec_res["outcome"] == RecoveryOutcome.SUCCESS.value
    assert rec_res["post_condition"]["restore_valid"] is True
    assert rec_res["post_condition"]["sha256"] is not None


# ------------------------------------------------------------------------------
# Test 9: Failure Knowledge Base Catalog & Lookup
# ------------------------------------------------------------------------------
def test_failure_knowledge_base_catalog_and_lookup():
    """
    Proves that the failure catalog provides deterministic causes, hypotheses,
    and safe next steps without fabrication.
    """
    catalog = FailureKnowledgeBase.get_catalog()
    assert len(catalog) >= 5

    stuck_entry = FailureKnowledgeBase.lookup_failure("FAIL_JOB_STUCK_RUNNING")
    assert stuck_entry is not None
    assert stuck_entry["category"] == DiagnosticCategory.JOBS.value
    assert len(stuck_entry["likely_causes"]) >= 2
    for cause in stuck_entry["likely_causes"]:
        assert "[Hypothesis]" in cause, "Hypotheses must be explicitly marked."


# ------------------------------------------------------------------------------
# Test 10: Continuous Improvement Failure Pattern Aggregation
# ------------------------------------------------------------------------------
def test_continuous_improvement_pattern_aggregation(
    db: Session,
    test_project: Project,
    lead_user: User,
):
    """
    Proves that continuous improvement aggregates repeated failure patterns
    and produces advisory recommendations without loosening security policies.
    """
    target = "https://api.acme.local"
    for i in range(3):
        failed_job = AssessmentJob(
            project_id=test_project.id,
            target_input=target,
            adapter_name="network_adapter",
            status=AssessmentStatus.FAILED,
            error_message="TCP connection reset by peer",
            created_by_id=lead_user.id,
        )
        db.add(failed_job)
    db.commit()

    report = ContinuousImprovementService.analyze_and_update_patterns(
        db=db,
        project_id=test_project.id,
    )

    assert report["project_id"] == test_project.id
    assert report["total_patterns"] >= 1
    adapter_pat = next((p for p in report["patterns"] if "network_adapter" in p["pattern_key"]), None)
    assert adapter_pat is not None
    assert adapter_pat["occurrence_count"] >= 3
    assert "Recommendation" in adapter_pat["advisory_recommendation"]


# ------------------------------------------------------------------------------
# Test 11: Cross-Tenant Isolation Denies Outsider Access
# ------------------------------------------------------------------------------
def test_cross_tenant_isolation_denies_outsider_access(
    client: TestClient,
    test_project: Project,
    outsider_headers: dict,
):
    """
    Proves that users belonging to another tenant/project are denied access
    to diagnostic runs, recovery endpoints, and failure patterns (fails closed with 404).
    """
    # 1. Outsider cannot trigger diagnostics
    res_run = client.post(f"/api/v1/diagnostics/{test_project.id}/run", headers=outsider_headers)
    assert res_run.status_code == 404

    # 2. Outsider cannot trigger recovery
    res_recover = client.post(
        f"/api/v1/diagnostics/{test_project.id}/recover",
        json={"action_type": "RECOVER_STUCK_JOB", "target_entity_type": "PROJECT"},
        headers=outsider_headers,
    )
    assert res_recover.status_code == 404

    # 3. Outsider cannot query patterns
    res_patterns = client.get(f"/api/v1/diagnostics/{test_project.id}/patterns", headers=outsider_headers)
    assert res_patterns.status_code == 404


# ------------------------------------------------------------------------------
# Test 12: Recovery Action Requires Project Lead Role
# ------------------------------------------------------------------------------
def test_recovery_action_requires_lead_role(
    client: TestClient,
    test_project: Project,
    tester_headers: dict,
):
    """
    Proves that a regular project member (non-lead, e.g. tester) cannot execute recovery actions (403 Forbidden).
    """
    res = client.post(
        f"/api/v1/diagnostics/{test_project.id}/recover",
        json={"action_type": "RECALCULATE_RISK_SCORES", "target_entity_type": "PROJECT"},
        headers=tester_headers,
    )
    assert res.status_code == 403
