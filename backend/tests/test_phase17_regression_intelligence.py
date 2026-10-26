import pytest
from datetime import datetime, timezone, timedelta
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.project import Project
from app.models.user import User
from app.models.finding import (
    FindingLifecycleStatus,
    VulnerabilityFinding,
)
from app.models.asset import Asset, AssetType, AssetCriticality
from app.models.risk import RemediationRecommendation, RecommendationStatus
from app.models.verification import RemediationVerification, VerificationOutcome
from app.models.assessment import FindingSeverity, FindingConfidence
from app.models.regression import (
    RegressionAlertType,
    AlertSeverity,
    AlertStatus,
    RegressionAlert,
)
from app.services.regression_service import RegressionDetectionService
from app.models.base import utc_now


def test_phase17_recurring_finding_alert_generation_and_deduplication(
    db: Session,
    test_project: Project,
    tester_user: User,
):
    """Verify recurring finding generates alert with rationale and deduplication prevents spam."""
    finding = VulnerabilityFinding(
        project_id=test_project.id,
        fingerprint="fp-phase17-recur-01",
        target_value="https://test.local/login",
        title="SQL Injection Recurring in Auth",
        description="SQL injection reopened after patch.",
        severity=FindingSeverity.CRITICAL,
        confidence=FindingConfidence.CERTAIN,
        status=FindingLifecycleStatus.REOPENED,
        recurrence_detected=True,
        recurrence_count=2,
        is_simulated=True,
        last_observed_at=utc_now(),
    )
    db.add(finding)
    db.commit()

    # 1. First evaluation: alert must be generated
    alerts = RegressionDetectionService.evaluate_project_regressions(
        project_id=test_project.id,
        db=db,
        actor=tester_user,
    )
    recur_alerts = [a for a in alerts if a.alert_type == RegressionAlertType.RECURRING_FINDING]
    assert len(recur_alerts) == 1
    alert = recur_alerts[0]
    assert alert.severity == AlertSeverity.CRITICAL
    assert "recurrence count is now 2" in alert.evidence_rationale
    assert alert.status == AlertStatus.ACTIVE

    # 2. Second evaluation: deduplication ensures no duplicate alert is created
    alerts2 = RegressionDetectionService.evaluate_project_regressions(
        project_id=test_project.id,
        db=db,
        actor=tester_user,
    )
    recur_alerts2 = [a for a in alerts2 if a.alert_type == RegressionAlertType.RECURRING_FINDING]
    assert len(recur_alerts2) == 1
    assert recur_alerts2[0].id == alert.id


def test_phase17_remediation_regression_and_stale_evidence(
    db: Session,
    test_project: Project,
    tester_user: User,
):
    """Verify broken remediation and stale evidence generate specific regression alerts."""
    now = utc_now()
    # 1. Broken remediation finding
    f_rem = VulnerabilityFinding(
        project_id=test_project.id,
        fingerprint="fp-phase17-rem-02",
        target_value="https://test.local/api/pay",
        title="SSRF in Payment Webhook",
        severity=FindingSeverity.HIGH,
        confidence=FindingConfidence.CERTAIN,
        status=FindingLifecycleStatus.REOPENED,
        is_simulated=True,
        last_observed_at=now,
    )
    db.add(f_rem)
    db.flush()

    rec = RemediationRecommendation(
        project_id=test_project.id,
        finding_id=f_rem.id,
        title="Enforce Egress IP Allowlist",
        action_type="CONFIG_HARDENING",
        description="Restrict outbound webhooks",
        rationale="Prevents internal network pivoting",
        qualitative_benefit="Blocks cloud metadata access",
        operational_impact="Low",
        rollback_procedure="Revert egress policy",
        verification_criteria="Webhook probe rejects private IPs",
        execution_governance_stage="CHANGE_AUTHORIZED",
        status=RecommendationStatus.APPROVED,
    )
    ver = RemediationVerification(
        project_id=test_project.id,
        finding_id=f_rem.id,
        recommendation_id=rec.id,
        outcome=VerificationOutcome.STILL_VULNERABLE,
        verification_criteria="Webhook probe rejects private IPs",
        verification_evidence_summary="Private IP probe connected to internal metadata service.",
        notes="Failed verification probe",
        verified_at=now,
    )
    # 2. Stale evidence finding (observed 45 days ago)
    f_stale = VulnerabilityFinding(
        project_id=test_project.id,
        fingerprint="fp-phase17-stale-03",
        target_value="https://test.local/legacy",
        title="Outdated TLS Protocol on Legacy Portal",
        severity=FindingSeverity.LOW,
        confidence=FindingConfidence.FIRM,
        status=FindingLifecycleStatus.CONFIRMED,
        is_simulated=True,
        last_observed_at=now - timedelta(days=45),
    )
    db.add_all([rec, ver, f_stale])
    db.commit()

    alerts = RegressionDetectionService.evaluate_project_regressions(
        project_id=test_project.id,
        db=db,
        actor=tester_user,
    )

    types = [a.alert_type for a in alerts]
    assert RegressionAlertType.REMEDIATION_REGRESSION in types
    assert RegressionAlertType.STALE_EVIDENCE in types


def test_phase17_new_unassessed_exposure(
    db: Session,
    test_project: Project,
    tester_user: User,
):
    """Verify high-criticality new asset exposure lacking assessment triggers alert."""
    asset = Asset(
        project_id=test_project.id,
        organization_id=test_project.organization_id,
        name="External Payments Ingress Gateway",
        canonical_identifier="payments-ingress.corp.net",
        asset_type=AssetType.SERVICE,
        criticality=AssetCriticality.CRITICAL,
        created_at=utc_now() - timedelta(days=2),
    )
    db.add(asset)
    db.commit()

    alerts = RegressionDetectionService.evaluate_project_regressions(
        project_id=test_project.id,
        db=db,
        actor=tester_user,
    )

    new_exposure_alerts = [a for a in alerts if a.alert_type == RegressionAlertType.NEW_EXPOSURE]
    assert len(new_exposure_alerts) >= 1
    assert "Unassessed Critical Perimeter Asset" in new_exposure_alerts[0].title
    assert new_exposure_alerts[0].severity == AlertSeverity.CRITICAL


def test_phase17_alert_acknowledgment_and_resolution_lifecycle(
    db: Session,
    test_project: Project,
    tester_user: User,
):
    """Verify full alert disposition lifecycle: ACTIVE -> ACKNOWLEDGED -> RESOLVED."""
    alert = RegressionAlert(
        project_id=test_project.id,
        alert_type=RegressionAlertType.RECURRING_FINDING,
        severity=AlertSeverity.HIGH,
        status=AlertStatus.ACTIVE,
        title="Test Recurring Alert Lifecycle",
        description="Alert for testing disposition lifecycle",
        evidence_rationale="Test rationale",
        target_resource="finding:test-01",
        fingerprint="fp-phase17-lifecycle-test",
    )
    db.add(alert)
    db.commit()

    # 1. Acknowledge alert
    ack_alert = RegressionDetectionService.acknowledge_alert(
        project_id=test_project.id,
        alert_id=alert.id,
        user=tester_user,
        notes="Triaged by on-call security engineer.",
        db=db,
    )
    assert ack_alert.status == AlertStatus.ACKNOWLEDGED
    assert ack_alert.acknowledged_by_id == tester_user.id
    assert ack_alert.acknowledged_at is not None

    # 2. Resolve alert
    res_alert = RegressionDetectionService.resolve_alert(
        project_id=test_project.id,
        alert_id=alert.id,
        resolution_notes="Patch validated in staging environment.",
        user=tester_user,
        db=db,
    )
    assert res_alert.status == AlertStatus.RESOLVED
    assert "Patch validated" in res_alert.resolution_notes


def test_phase17_api_regression_endpoints_and_isolation(
    client: TestClient,
    db: Session,
    test_project: Project,
    tester_headers: dict,
):
    """Verify HTTP API endpoints for evaluation, alert listing, acknowledgment, and baseline."""
    # 1. Get default baseline
    base_res = client.get(
        f"/api/v1/projects/{test_project.id}/regressions/baseline",
        headers=tester_headers,
    )
    assert base_res.status_code == 200
    assert base_res.json()["is_active"] is True

    # 2. Evaluate regressions via API
    eval_res = client.post(
        f"/api/v1/projects/{test_project.id}/regressions/evaluate",
        headers=tester_headers,
    )
    assert eval_res.status_code == 200
    eval_data = eval_res.json()
    assert "alerts_generated" in eval_data

    # 3. Create active alert and acknowledge via API
    alert = RegressionAlert(
        project_id=test_project.id,
        alert_type=RegressionAlertType.RECURRING_FINDING,
        severity=AlertSeverity.CRITICAL,
        status=AlertStatus.ACTIVE,
        title="API Test Recurring Alert",
        description="API alert test",
        evidence_rationale="API test rationale",
        target_resource="finding:api-01",
        fingerprint="fp-phase17-api-test",
    )
    db.add(alert)
    db.commit()

    ack_res = client.post(
        f"/api/v1/projects/{test_project.id}/regressions/alerts/{alert.id}/acknowledge",
        headers=tester_headers,
        json={"notes": "Investigating with engineering team."},
    )
    assert ack_res.status_code == 200
    assert ack_res.json()["status"] == "ACKNOWLEDGED"

    # 4. Resolve alert via API
    resolve_res = client.post(
        f"/api/v1/projects/{test_project.id}/regressions/alerts/{alert.id}/resolve",
        headers=tester_headers,
        json={"resolution_notes": "Defensive rule injected; resolved."},
    )
    assert resolve_res.status_code == 200
    assert resolve_res.json()["status"] == "RESOLVED"
