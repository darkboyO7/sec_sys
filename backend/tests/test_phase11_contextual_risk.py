import pytest
from datetime import datetime, timezone, timedelta
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.project import Project
from app.models.user import User
from app.models.asset import Asset, AssetType, AssetCriticality
from app.models.finding import (
    VulnerabilityFinding,
    FindingLifecycleStatus,
)
from app.models.assessment import FindingSeverity, FindingConfidence
from app.models.risk import RiskAssessment, RiskPriority
from app.services.contextual_risk_service import ContextualRiskService


def test_phase11_inherent_vs_residual_risk_and_uncertainty(
    db: Session,
    test_project: Project,
    test_organization,
):
    """Verify separate calculation of inherent vs residual risk and uncertainty range in formula v1.1.0."""
    now = datetime(2026, 10, 26, 12, 0, 0, tzinfo=timezone.utc)

    asset = Asset(
        project_id=test_project.id,
        organization_id=test_organization.id,
        asset_type=AssetType.WEB_APP,
        name="Billing Portal",
        canonical_identifier="https://billing.corp",
        criticality=AssetCriticality.HIGH,
    )
    db.add(asset)
    db.flush()

    finding = VulnerabilityFinding(
        project_id=test_project.id,
        asset_id=asset.id,
        fingerprint="fp-p11-risk-01",
        target_value="https://billing.corp/pay",
        title="Payment Gateway Parameter Tampering",
        severity=FindingSeverity.HIGH,
        confidence=FindingConfidence.FIRM,
        status=FindingLifecycleStatus.ACCEPTED_RISK,
        compensating_controls="Rate-limited and protected behind Cloudflare WAF rule #2004",
        risk_accepted_expires_at=now + timedelta(days=60),
        evidence_quality_score=0.9,
        last_observed_at=now - timedelta(days=3),
    )
    db.add(finding)
    db.flush()

    calc = ContextualRiskService.calculate_score_and_factors(finding=finding, asset=asset, now=now)

    assert calc["input_snapshot"]["scoring_version"] == "v1.1.0"
    assert "inherent_score" in calc
    assert "residual_score" in calc

    # Inherent risk should be higher than residual risk because finding has ACCEPTED_RISK mitigation
    assert calc["inherent_score"] > calc["residual_score"]

    # Verify uncertainty range
    assert "uncertainty_range" in calc
    ur = calc["uncertainty_range"]
    assert ur["min_score"] <= calc["score"] <= ur["max_score"]
    assert ur["confidence_band"] in ("HIGH", "MODERATE", "LOW")


def test_phase11_recurrence_and_quality_score_factors(
    db: Session,
    test_project: Project,
    test_organization,
):
    """Verify that recurrence penalty and evidence quality dynamically influence contextual score."""
    now = datetime(2026, 10, 26, 12, 0, 0, tzinfo=timezone.utc)

    asset = Asset(
        project_id=test_project.id,
        organization_id=test_organization.id,
        asset_type=AssetType.SERVICE,
        name="Auth Service",
        canonical_identifier="tcp://auth.corp:9000",
        criticality=AssetCriticality.MEDIUM,
    )
    db.add(asset)
    db.flush()

    # Finding with recurrence detected
    finding_recurring = VulnerabilityFinding(
        project_id=test_project.id,
        asset_id=asset.id,
        fingerprint="fp-p11-recur-01",
        target_value="tcp://auth.corp:9000",
        title="JWT Key Confusion",
        severity=FindingSeverity.HIGH,
        confidence=FindingConfidence.CERTAIN,
        status=FindingLifecycleStatus.CONFIRMED,
        recurrence_detected=True,
        recurrence_count=3,
        evidence_quality_score=0.95,
        last_observed_at=now - timedelta(days=1),
    )
    db.add(finding_recurring)
    db.flush()

    calc = ContextualRiskService.calculate_score_and_factors(finding=finding_recurring, asset=asset, now=now)
    factors = calc["factor_breakdown"]
    assert factors["recurrence_multiplier"] > 1.0
    assert any("recurrence" in f.lower() for f in calc["contributing_factors"])


def test_phase11_api_risk_details_endpoint(
    client: TestClient,
    db: Session,
    test_project: Project,
    test_organization,
    tester_user: User,
    tester_headers: dict,
):
    """Verify that the risk API returns inherent_score, residual_score, and uncertainty_range."""
    asset = Asset(
        project_id=test_project.id,
        organization_id=test_organization.id,
        asset_type=AssetType.WEB_APP,
        name="Public Storefront",
        canonical_identifier="https://store.corp",
        criticality=AssetCriticality.CRITICAL,
    )
    db.add(asset)
    db.flush()

    finding = VulnerabilityFinding(
        project_id=test_project.id,
        asset_id=asset.id,
        fingerprint="fp-p11-api-01",
        target_value="https://store.corp/checkout",
        title="Stored XSS in Checkout Reviews",
        severity=FindingSeverity.HIGH,
        confidence=FindingConfidence.CERTAIN,
        status=FindingLifecycleStatus.CONFIRMED,
        last_observed_at=datetime.now(timezone.utc),
    )
    db.add(finding)
    db.commit()

    # Calculate and persist risk assessment
    assessment = ContextualRiskService.assess_and_persist_finding_risk(
        project_id=test_project.id,
        finding_id=finding.id,
        db=db,
        force_recalculate=True,
        actor=tester_user,
    )

    res = client.get(
        f"/api/v1/projects/{test_project.id}/risk/findings/{finding.id}",
        headers=tester_headers,
    )
    assert res.status_code == 200, res.text
    data = res.json()
    assert data["scoring_version"] == "v1.1.0"
    assert data["inherent_score"] is not None
    assert data["residual_score"] is not None
    assert "uncertainty_range" in data
    assert "min_score" in data["uncertainty_range"]
    assert "max_score" in data["uncertainty_range"]
