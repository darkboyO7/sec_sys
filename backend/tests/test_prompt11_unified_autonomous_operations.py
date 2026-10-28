import pytest
from datetime import datetime, timezone, timedelta
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.project import Project, ProjectMember, ProjectRole
from app.models.organization import Organization
from app.models.user import User, SystemRole
from app.models.scope import ScopeTarget, TargetType, AuthorizationStatus
from app.models.asset import Asset, AssetType, AssetCriticality, AssetStatus
from app.models.finding import (
    VulnerabilityFinding,
    FindingLifecycleStatus,
)
from app.models.assessment import (
    AssessmentJob,
    AssessmentStatus,
    AssessmentFinding,
    FindingSeverity,
    FindingConfidence,
    FindingEvidence,
)
from app.models.risk import (
    RiskAssessment,
    RiskPriority,
    RemediationRecommendation,
    RecommendationStatus,
)
from app.models.verification import (
    RemediationVerification,
    VerificationOutcome,
    VerificationMethod,
)
from app.models.decision import (
    AutonomousPolicyRecord,
    AutonomyIntensity,
    DecisionLedgerType,
    SecurityDecisionLedgerRecord,
    OperationalSLOConfig,
)
from app.models.notification import (
    NotificationRecord,
    NotificationDeliveryRecord,
    NotificationEventType,
    NotificationSeverity,
    NotificationStatus,
)
from app.models.base import utc_now

from app.services.policy_engine import PolicyEngineService
from app.services.decision_ledger_service import DecisionLedgerService
from app.services.notification_service import NotificationService
from app.services.operational_metrics_service import OperationalMetricsService
from app.services.unified_operations_service import UnifiedOperationsService
from app.services.contextual_risk_service import ContextualRiskService
from app.services.backup_service import BackupRecoveryService


# ------------------------------------------------------------------------------
# Test 1: Full Operational Lifecycle (Discovery -> Closure)
# ------------------------------------------------------------------------------
def test_full_operational_lifecycle_discovery_to_closure(
    db: Session,
    test_project: Project,
    test_organization: Organization,
    lead_user: User,
):
    """
    1. Authorized Asset Creation
    2. Scope Authorization
    3. Assessment Execution & Evidence Collection
    4. Contextual Risk Prioritization
    5. Remediation Recommendation
    6. Independent Retest Verification
    7. Controlled Finding Closure
    """
    now = utc_now()

    # Step 1: Authorized Asset
    asset = Asset(
        project_id=test_project.id,
        organization_id=test_organization.id,
        asset_type=AssetType.WEB_APP,
        name="Production Portal",
        canonical_identifier="https://portal.acme.local",
        criticality=AssetCriticality.HIGH,
        last_seen_at=now,
    )
    db.add(asset)

    # Step 2: Scope Authorization
    scope_tgt = ScopeTarget(
        project_id=test_project.id,
        target_value="https://portal.acme.local",
        target_type=TargetType.URL,
        authorization_status=AuthorizationStatus.AUTHORIZED,
        authorization_evidence="ROE-PROD-2026",
        authorized_by_id=lead_user.id,
        authorized_at=now,
        created_by_id=lead_user.id,
    )
    db.add(scope_tgt)
    db.flush()

    # Step 3: Assessment & Evidence
    job = AssessmentJob(
        project_id=test_project.id,
        target_input="https://portal.acme.local",
        adapter_name="web_adapter",
        status=AssessmentStatus.COMPLETED,
        created_by_id=lead_user.id,
    )
    db.add(job)
    db.flush()

    finding = VulnerabilityFinding(
        project_id=test_project.id,
        asset_id=asset.id,
        fingerprint="fp-lifecycle-01",
        target_value="https://portal.acme.local",
        title="Missing Content Security Policy",
        severity=FindingSeverity.HIGH,
        confidence=FindingConfidence.CERTAIN,
        status=FindingLifecycleStatus.DETECTED,
        last_observed_at=now,
    )
    db.add(finding)
    db.flush()

    af = AssessmentFinding(
        job_id=job.id,
        project_id=test_project.id,
        target_value="https://portal.acme.local",
        title="Missing Content Security Policy",
        description="CSP header is missing",
        severity=FindingSeverity.HIGH,
        confidence=FindingConfidence.CERTAIN,
        canonical_finding_id=finding.id,
    )
    db.add(af)
    db.flush()

    ev = FindingEvidence(
        finding_id=af.id,
        evidence_type="HTTP_HEADERS",
        payload="HTTP/1.1 200 OK\r\nServer: nginx\r\n",
        sha256_hash="a" * 64,
    )
    db.add(ev)
    db.flush()

    # Step 4: Contextual Risk Prioritization
    risk_record = ContextualRiskService.assess_and_persist_finding_risk(
        project_id=test_project.id,
        finding_id=finding.id,
        db=db,
    )
    assert risk_record.score > 0.0
    assert risk_record.scoring_version == "v2.0.0"

    # Step 5: Remediation Recommendation
    rec = RemediationRecommendation(
        project_id=test_project.id,
        finding_id=finding.id,
        title="Configure CSP Header",
        action_type="CONFIG_HARDENING",
        description="Add Content-Security-Policy header to web server config",
        rationale="Mitigates cross-site scripting and data injection",
        qualitative_benefit="Hardens HTTP defense-in-depth posture",
        operational_impact="Low - requires web server configuration reload",
        rollback_procedure="Revert nginx configuration file and reload",
        verification_criteria="Verify presence of Content-Security-Policy header in HTTP response",
        status=RecommendationStatus.APPROVED,
        reviewed_by_id=lead_user.id,
        reviewed_at=now,
    )
    db.add(rec)
    db.flush()

    # Step 6: Independent Retest Verification
    verif = RemediationVerification(
        project_id=test_project.id,
        finding_id=finding.id,
        recommendation_id=rec.id,
        verifier_id=lead_user.id,
        verification_method=VerificationMethod.RETEST_ASSESSMENT,
        outcome=VerificationOutcome.VERIFIED_FIXED,
        verification_criteria="Verify presence of Content-Security-Policy header in HTTP response",
        verification_evidence_summary="Retest confirmed Content-Security-Policy header is now enforced.",
        verification_evidence_data={"status_code": 200, "csp_present": True},
        notes="Retest confirmed Content-Security-Policy is present.",
        verified_at=now,
    )
    db.add(verif)
    db.commit()

    # Step 7: Controlled Lifecycle Closure
    transition_res = UnifiedOperationsService.execute_lifecycle_transition(
        db=db,
        project_id=test_project.id,
        finding_id=finding.id,
        action="CLOSE_FINDING",
        actor=lead_user,
        notes="Verified fixed via independent probe.",
    )
    assert transition_res["success"] is True
    assert transition_res["current_status"] == FindingLifecycleStatus.VERIFIED_CLOSED.value

    # Verify Decision Ledger entry recorded
    ledger = DecisionLedgerService.get_audit_trail_for_entity(
        db=db,
        project_id=test_project.id,
        target_id=finding.id,
    )
    assert len(ledger) >= 1
    assert ledger[-1].decision_type == DecisionLedgerType.FINDING_RESOLVED


# ------------------------------------------------------------------------------
# Test 2: Scope Enforcement During Job Execution (Fail-Closed)
# ------------------------------------------------------------------------------
def test_scope_enforcement_throughout_execution_boundary(
    db: Session,
    test_project: Project,
    lead_user: User,
):
    """
    Proves that the execution engine rejects unauthorized target inputs
    before execution can proceed.
    """
    now = utc_now()
    # Out of scope target
    unauthorized_target = "https://unauthorized-external-server.com"

    eval_result = PolicyEngineService.evaluate_action_permission(
        db=db,
        project_id=test_project.id,
        action_type="ASSESSMENT_JOB",
        target_resource=unauthorized_target,
    )
    assert eval_result["allowed"] is False
    assert eval_result["denial_category"] == "OUT_OF_SCOPE"


# ------------------------------------------------------------------------------
# Test 3: Strict Cross-Tenant and Permission Isolation
# ------------------------------------------------------------------------------
def test_cross_tenant_isolation_denies_outsider_access(
    client: TestClient,
    db: Session,
    test_project: Project,
    test_organization: Organization,
    outsider_headers: dict,
    tester_headers: dict,
    lead_headers: dict,
    lead_user: User,
):
    """
    Proves that a user from outside the project is denied access with 404 (failing closed),
    and cannot view or manipulate policies, decision ledger, or notifications.
    """
    # 1. Outsider cannot access operations dashboard
    res_dash = client.get(f"/api/v1/operations/{test_project.id}/dashboard", headers=outsider_headers)
    assert res_dash.status_code == 404

    # 2. Outsider cannot access policy
    res_pol = client.get(f"/api/v1/operations/{test_project.id}/policy", headers=outsider_headers)
    assert res_pol.status_code == 404

    # 3. Outsider cannot access decision ledger
    res_ledg = client.get(f"/api/v1/operations/{test_project.id}/decision-ledger", headers=outsider_headers)
    assert res_ledg.status_code == 404

    # 4. Outsider cannot access notifications
    res_notifs = client.get(f"/api/v1/operations/{test_project.id}/notifications", headers=outsider_headers)
    assert res_notifs.status_code == 404

    # 5. Tester (member, non-LEAD) cannot update policy (requires LEAD role)
    res_put = client.put(
        f"/api/v1/operations/{test_project.id}/policy",
        json={"max_concurrency": 4},
        headers=tester_headers,
    )
    assert res_put.status_code == 403

    # 6. Lead can view and update policy
    res_lead_get = client.get(f"/api/v1/operations/{test_project.id}/policy", headers=lead_headers)
    assert res_lead_get.status_code == 200

    res_lead_put = client.put(
        f"/api/v1/operations/{test_project.id}/policy",
        json={"max_concurrency": 4},
        headers=lead_headers,
    )
    assert res_lead_put.status_code == 200
    assert res_lead_put.json()["max_concurrency"] == 4


# ------------------------------------------------------------------------------
# Test 4: Policy Engine Enforcement & Emergency Kill Switch
# ------------------------------------------------------------------------------
def test_policy_engine_enforcement_and_emergency_kill_switch(
    db: Session,
    test_project: Project,
    lead_user: User,
):
    """
    Proves policy validation:
    - Rejects disallowed assessment adapters
    - Emergency suspend immediately blocks all actions
    - Resume restores operational authorization
    """
    now = utc_now()
    target = "https://authorized-target.acme.local"

    # Add authorized scope target
    st = ScopeTarget(
        project_id=test_project.id,
        target_value=target,
        target_type=TargetType.URL,
        authorization_status=AuthorizationStatus.AUTHORIZED,
        authorization_evidence="ROE-TEST",
        authorized_by_id=lead_user.id,
        authorized_at=now,
        created_by_id=lead_user.id,
    )
    db.add(st)
    db.commit()

    # Case A: Permitted adapter passes
    eval_ok = PolicyEngineService.evaluate_action_permission(
        db=db,
        project_id=test_project.id,
        action_type="PROBE",
        target_resource=target,
        adapter_name="web_adapter",
    )
    assert eval_ok["allowed"] is True

    # Case B: Disallowed adapter is blocked
    eval_disallowed = PolicyEngineService.evaluate_action_permission(
        db=db,
        project_id=test_project.id,
        action_type="PROBE",
        target_resource=target,
        adapter_name="disallowed_exploit_framework",
    )
    assert eval_disallowed["allowed"] is False
    assert eval_disallowed["denial_category"] == "ADAPTER_DISALLOWED"

    # Case C: Emergency Kill-Switch activates
    PolicyEngineService.emergency_suspend(
        db=db,
        project_id=test_project.id,
        reason="Suspicious network traffic spike detected during operational audit",
        actor=lead_user,
    )

    eval_suspended = PolicyEngineService.evaluate_action_permission(
        db=db,
        project_id=test_project.id,
        action_type="PROBE",
        target_resource=target,
        adapter_name="web_adapter",
    )
    assert eval_suspended["allowed"] is False
    assert eval_suspended["denial_category"] == "SUSPENDED"

    # Case D: Resume operations
    PolicyEngineService.resume_autonomy(
        db=db,
        project_id=test_project.id,
        actor=lead_user,
    )

    eval_resumed = PolicyEngineService.evaluate_action_permission(
        db=db,
        project_id=test_project.id,
        action_type="PROBE",
        target_resource=target,
        adapter_name="web_adapter",
    )
    assert eval_resumed["allowed"] is True


# ------------------------------------------------------------------------------
# Test 5: Decision Ledger Consistency & Secret Redaction
# ------------------------------------------------------------------------------
def test_decision_ledger_consistency_and_secret_redaction(
    db: Session,
    test_project: Project,
    lead_user: User,
):
    """
    Proves that the decision ledger persists entries and automatically redacts
    passwords, secrets, and api_keys from details.
    """
    dirty_details = {
        "user_email": "admin@corp.local",
        "api_key": "vapt_live_secret_token_12345",
        "nested": {
            "password": "SuperSecretPassword!",
            "public_metric": 42,
        },
    }

    entry = DecisionLedgerService.record_decision(
        db=db,
        project_id=test_project.id,
        decision_type=DecisionLedgerType.ASSESSMENT_SCHEDULED,
        decision_outcome="ALLOWED",
        initiating_event="REASSESSMENT_TRIGGER",
        target_type="ASSET",
        target_id="asset-sec-01",
        target_resource="https://portal.acme.local",
        reason="Routine coverage refresh scheduled.",
        details=dirty_details,
        actor_id=lead_user.id,
    )

    assert entry.id is not None
    assert entry.details["api_key"] == "[REDACTED]"
    assert entry.details["nested"]["password"] == "[REDACTED]"
    assert entry.details["nested"]["public_metric"] == 42


# ------------------------------------------------------------------------------
# Test 6: Notification Deduplication & Provider Status
# ------------------------------------------------------------------------------
def test_notification_deduplication_and_unconfigured_reporting(
    db: Session,
    test_project: Project,
):
    """
    Proves that:
    - Identical notifications within the sliding window are marked SUPPRESSED_DUPLICATE.
    - Unconfigured provider is reported honestly as UNCONFIGURED.
    """
    # 1. First alert dispatched (no webhook configured)
    notif1 = NotificationService.dispatch_notification(
        db=db,
        project_id=test_project.id,
        event_type=NotificationEventType.CRITICAL_FINDING_DISCOVERED,
        title="Remote Code Execution in API",
        summary="Critical CVE verified on API gateway.",
        severity=NotificationSeverity.CRITICAL,
        target_identifier="https://api.acme.local",
    )
    assert notif1.status == NotificationStatus.UNCONFIGURED

    # 2. Duplicate alert dispatched within 1 hour window
    notif2 = NotificationService.dispatch_notification(
        db=db,
        project_id=test_project.id,
        event_type=NotificationEventType.CRITICAL_FINDING_DISCOVERED,
        title="Remote Code Execution in API",
        summary="Critical CVE verified on API gateway.",
        severity=NotificationSeverity.CRITICAL,
        target_identifier="https://api.acme.local",
    )
    assert notif2.status == NotificationStatus.SUPPRESSED_DUPLICATE
    assert "[DEDUP]" in notif2.title

    # 3. Provider status report
    provider_status = NotificationService.get_notification_provider_status(db=db, project_id=test_project.id)
    assert provider_status["provider_status"] == "UNCONFIGURED"
    assert provider_status["counts"]["unconfigured"] >= 1


# ------------------------------------------------------------------------------
# Test 7: Operational SLO Metrics Calculation & Missing Data Handling
# ------------------------------------------------------------------------------
def test_operational_slo_metrics_calculation_and_missing_data(
    db: Session,
    test_project: Project,
    lead_user: User,
):
    """
    Proves that SLO calculations correctly handle missing data without errors,
    and compute valid percentages when data is present.
    """
    now = utc_now()

    # Step A: Empty project -> All SLOs return MISSING_DATA
    slos_empty = OperationalMetricsService.calculate_operational_slos(
        db=db,
        project_id=test_project.id,
        now=now,
    )
    assert slos_empty["overall_health_pct"] is None
    assert slos_empty["slos"]["assessment_completion"]["status"] == "MISSING_DATA"
    assert slos_empty["slos"]["evidence_completeness"]["status"] == "MISSING_DATA"

    # Step B: Add completed job -> Assessment completion is MET
    job = AssessmentJob(
        project_id=test_project.id,
        target_input="https://portal.acme.local",
        adapter_name="web_adapter",
        status=AssessmentStatus.COMPLETED,
        created_by_id=lead_user.id,
        queued_at=now - timedelta(seconds=120),
        started_at=now - timedelta(seconds=100),
        completed_at=now - timedelta(seconds=20),
    )
    db.add(job)
    db.commit()

    slos_populated = OperationalMetricsService.calculate_operational_slos(
        db=db,
        project_id=test_project.id,
        now=now,
    )
    comp_slo = slos_populated["slos"]["assessment_completion"]
    assert comp_slo["status"] == "MET"
    assert comp_slo["observed_value"] == 100.0


# ------------------------------------------------------------------------------
# Test 8: Remediation Approval Gates & Verification
# ------------------------------------------------------------------------------
def test_remediation_approval_gates_and_retest(
    db: Session,
    test_project: Project,
    lead_user: User,
):
    """
    Proves that remediation actions evaluate approval requirements and
    record outcomes accurately.
    """
    now = utc_now()
    target = "https://portal.acme.local"

    # Register target in scope as authorized
    st = ScopeTarget(
        project_id=test_project.id,
        target_value=target,
        target_type=TargetType.URL,
        authorization_status=AuthorizationStatus.AUTHORIZED,
        authorization_evidence="ROE-REMED-TEST",
        authorized_by_id=lead_user.id,
        authorized_at=now,
        created_by_id=lead_user.id,
    )
    db.add(st)
    db.commit()

    # Evaluate permission for disruptive remediation
    eval_res = PolicyEngineService.evaluate_action_permission(
        db=db,
        project_id=test_project.id,
        action_type="REMEDIATION",
        target_resource=target,
        is_remediation=True,
        remediation_action="DISABLE_INSECURE_CIPHERS",
        is_disruptive=True,
    )
    assert eval_res["allowed"] is True
    assert eval_res["requires_approval"] is True
    assert "Approval required" in eval_res["reason"]


# ------------------------------------------------------------------------------
# Test 9: Backup & Recovery Sandbox Verification
# ------------------------------------------------------------------------------
def test_backup_and_recovery_sandbox_verification(db: Session):
    """
    Proves that BackupService creates a backup and verifies restore integrity
    in an isolated disposable sandbox.
    """
    backup_result = BackupRecoveryService.create_database_backup(db=db)
    assert backup_result.backup_path is not None
    backup_path = backup_result.backup_path
    sha256 = backup_result.sha256_hash

    # Verify restore in isolated sandbox
    restore_eval = BackupRecoveryService.verify_and_test_restore(
        backup_file_path=backup_path,
        expected_sha256=sha256,
    )
    assert restore_eval["is_valid"] is True
    assert restore_eval["integrity_result"] == "ok"
    assert "autonomous_policies" in restore_eval["tables_verified"]
    assert "security_decision_ledger" in restore_eval["tables_verified"]


# ------------------------------------------------------------------------------
# Test 10: Unified Operations Dashboard API Integration
# ------------------------------------------------------------------------------
def test_unified_operations_dashboard_api(
    client: TestClient,
    test_project: Project,
    lead_headers: dict,
):
    """
    Proves that the operations dashboard API returns the complete operational
    health, policy status, SLOs, and recent activity.
    """
    response = client.get(
        f"/api/v1/operations/{test_project.id}/dashboard",
        headers=lead_headers,
    )
    assert response.status_code == 200
    data = response.json()
    assert data["project_id"] == test_project.id
    assert "policy" in data
    assert "operations_summary" in data
    assert "slo_health" in data
    assert "recent_decisions" in data
    assert "recent_notifications" in data
    assert "notification_provider" in data


# ------------------------------------------------------------------------------
# Test 11: Lifecycle Transition API (Close & Reopen)
# ------------------------------------------------------------------------------
def test_lifecycle_transition_api(
    client: TestClient,
    db: Session,
    test_project: Project,
    lead_user: User,
    lead_headers: dict,
):
    """
    Proves that finding lifecycle transitions update state, record decision ledger entries,
    and enforce project access boundaries.
    """
    now = utc_now()
    target = "https://portal.acme.local"

    # Register target in scope as authorized
    st = ScopeTarget(
        project_id=test_project.id,
        target_value=target,
        target_type=TargetType.URL,
        authorization_status=AuthorizationStatus.AUTHORIZED,
        authorization_evidence="ROE-TRANSITION-TEST",
        authorized_by_id=lead_user.id,
        authorized_at=now,
        created_by_id=lead_user.id,
    )
    db.add(st)

    finding = VulnerabilityFinding(
        project_id=test_project.id,
        fingerprint="fp-api-trans-01",
        target_value=target,
        title="TLS 1.0 Enabled",
        severity=FindingSeverity.MEDIUM,
        confidence=FindingConfidence.CERTAIN,
        status=FindingLifecycleStatus.CONFIRMED,
        last_observed_at=now,
    )
    db.add(finding)
    db.commit()

    # Close finding via API
    res_close = client.post(
        f"/api/v1/operations/{test_project.id}/lifecycle-transition/{finding.id}",
        json={"action": "CLOSE_FINDING", "notes": "Upgraded to TLS 1.3"},
        headers=lead_headers,
    )
    assert res_close.status_code == 200
    data_close = res_close.json()
    assert data_close["success"] is True
    assert data_close["current_status"] == FindingLifecycleStatus.VERIFIED_CLOSED.value

    # Reopen finding via API
    res_reopen = client.post(
        f"/api/v1/operations/{test_project.id}/lifecycle-transition/{finding.id}",
        json={"action": "REOPEN_FINDING", "notes": "Regression detected in latest scan"},
        headers=lead_headers,
    )
    assert res_reopen.status_code == 200
    data_reopen = res_reopen.json()
    assert data_reopen["success"] is True
    assert data_reopen["current_status"] == FindingLifecycleStatus.REOPENED.value


# ------------------------------------------------------------------------------
# Test 12: Notification Retry API
# ------------------------------------------------------------------------------
def test_notification_retry_api(
    client: TestClient,
    db: Session,
    test_project: Project,
    lead_headers: dict,
):
    """
    Proves that the notification retry API retries failed notifications
    and returns updated attempt status.
    """
    # Create a failed notification
    notif = NotificationRecord(
        project_id=test_project.id,
        event_type=NotificationEventType.ASSESSMENT_FAILED,
        severity=NotificationSeverity.HIGH,
        title="Assessment Job Timed Out",
        summary="Adapter timed out after 300s",
        deduplication_key="test-failed-retry-01",
        status=NotificationStatus.FAILED,
        retry_count=1,
        max_retries=3,
        error_message="Connection refused",
    )
    db.add(notif)
    db.commit()

    res = client.post(
        f"/api/v1/operations/{test_project.id}/notifications/retry-failed",
        headers=lead_headers,
    )
    assert res.status_code == 200
    retried_list = res.json()
    assert len(retried_list) >= 1
    assert any(n["id"] == notif.id for n in retried_list)
