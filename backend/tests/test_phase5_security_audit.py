import pytest
import math
from datetime import datetime, timezone, timedelta
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.organization import Organization
from app.models.project import Project, ProjectMember, ProjectRole
from app.models.user import User, SystemRole
from app.models.asset import Asset, AssetType, AssetCriticality
from app.models.finding import VulnerabilityFinding, FindingLifecycleStatus
from app.models.assessment import FindingSeverity, FindingConfidence
from app.models.graph import (
    GraphNode,
    GraphNodeCategory,
    GraphRelationship,
    RelationshipType,
    RelationshipStatus,
)
from app.models.risk import (
    RiskAssessment,
    RiskPriority,
    RemediationRecommendation,
    RecommendationStatus,
)
from app.services.contextual_risk_service import ContextualRiskService
from app.services.attack_path_service import AttackPathAnalysisService, PathVerificationStatus
from app.services.remediation_service import RemediationPrioritizationService


def test_lifecycle_false_positive_and_verified_closed_preservation(
    db: Session,
    test_project: Project,
    test_organization: Organization,
    lead_user: User,
):
    """
    Verifies that when a finding is marked FALSE_POSITIVE or VERIFIED_CLOSED:
    - Current operational risk is neutralized to 0.0.
    - Historical assessments remain in database (marked superseded) with intact historical scores.
    - Verification and false-positive audit provenance is preserved in contributing factors.
    """
    now = datetime(2026, 10, 25, 12, 0, 0, tzinfo=timezone.utc)

    asset = Asset(
        project_id=test_project.id,
        organization_id=test_organization.id,
        asset_type=AssetType.WEB_APP,
        name="Production Web App",
        canonical_identifier="https://app.corp.internal",
        criticality=AssetCriticality.HIGH,
    )
    db.add(asset)
    db.flush()

    finding = VulnerabilityFinding(
        project_id=test_project.id,
        asset_id=asset.id,
        fingerprint="fp-lifecycle-audit-01",
        target_value="https://app.corp.internal/v1/users",
        title="SQL Injection in User Search",
        severity=FindingSeverity.CRITICAL,
        confidence=FindingConfidence.CERTAIN,
        status=FindingLifecycleStatus.CONFIRMED,
        cvss_score=9.5,
        last_observed_at=now - timedelta(days=1),
    )
    db.add(finding)
    db.flush()

    # Step 1: Initial assessment while CONFIRMED
    initial_assessment = ContextualRiskService.assess_and_persist_finding_risk(
        project_id=test_project.id,
        finding_id=finding.id,
        db=db,
        actor=lead_user,
    )
    initial_id = initial_assessment.id
    initial_score = initial_assessment.score
    assert initial_score >= 80.0
    assert initial_assessment.priority == RiskPriority.CRITICAL
    assert initial_assessment.is_superseded is False

    # Step 2: Disposition finding as FALSE_POSITIVE
    finding.status = FindingLifecycleStatus.FALSE_POSITIVE
    finding.false_positive_at = now
    finding.false_positive_by_id = lead_user.id
    finding.false_positive_reason = "WAF synthetic canary header flagged as payload reflection."
    db.commit()

    fp_assessment = ContextualRiskService.assess_and_persist_finding_risk(
        project_id=test_project.id,
        finding_id=finding.id,
        db=db,
        force_recalculate=True,
        actor=lead_user,
    )

    # Current score is neutralized to 0.0
    assert fp_assessment.score == 0.0
    assert fp_assessment.priority == RiskPriority.INFORMATIONAL
    assert fp_assessment.is_superseded is False
    assert any("FALSE_POSITIVE" in f for f in fp_assessment.contributing_factors)

    # Past assessment is superseded but its historical score is unmutated
    db.refresh(initial_assessment)
    assert initial_assessment.id == initial_id
    assert initial_assessment.is_superseded is True
    assert initial_assessment.superseded_at is not None
    assert initial_assessment.score == initial_score

    # Step 3: Now simulate another finding transitioning to VERIFIED_CLOSED
    finding_closed = VulnerabilityFinding(
        project_id=test_project.id,
        asset_id=asset.id,
        fingerprint="fp-lifecycle-audit-02",
        target_value="https://app.corp.internal/v1/auth",
        title="Legacy TLS 1.0 Protocol Supported",
        severity=FindingSeverity.MEDIUM,
        confidence=FindingConfidence.CERTAIN,
        status=FindingLifecycleStatus.CONFIRMED,
        cvss_score=5.5,
        last_observed_at=now - timedelta(days=3),
    )
    db.add(finding_closed)
    db.flush()

    calc_open = ContextualRiskService.assess_and_persist_finding_risk(
        project_id=test_project.id,
        finding_id=finding_closed.id,
        db=db,
        actor=lead_user,
    )
    assert calc_open.score > 0.0
    open_score = calc_open.score

    # Close finding with verification provenance
    finding_closed.status = FindingLifecycleStatus.VERIFIED_CLOSED
    finding_closed.verified_at = now
    finding_closed.verified_by_id = lead_user.id
    finding_closed.verification_notes = "Independent re-scan confirmed TLS 1.0 and 1.1 disabled."
    db.commit()

    calc_closed = ContextualRiskService.assess_and_persist_finding_risk(
        project_id=test_project.id,
        finding_id=finding_closed.id,
        db=db,
        force_recalculate=True,
        actor=lead_user,
    )
    assert calc_closed.score == 0.0
    assert calc_closed.priority == RiskPriority.INFORMATIONAL
    assert any("VERIFIED_CLOSED" in f or "verified closed" in f for f in calc_closed.contributing_factors)

    # Historical record still holds the original score
    db.refresh(calc_open)
    assert calc_open.is_superseded is True
    assert calc_open.score == open_score


def test_lifecycle_reopened_and_accepted_risk(
    db: Session,
    test_project: Project,
    test_organization: Organization,
    lead_user: User,
):
    """
    Verifies that:
    - REOPENED findings receive elevated priority multiplier (1.10).
    - ACCEPTED_RISK findings maintain residual risk (0.40) and record approver, expiration, and compensating controls.
    - REMEDIATED_PENDING_VERIFICATION maintains residual uncertainty (0.50).
    """
    now = datetime(2026, 10, 25, 12, 0, 0, tzinfo=timezone.utc)
    expires_at = now + timedelta(days=60)

    finding = VulnerabilityFinding(
        project_id=test_project.id,
        fingerprint="fp-lifecycle-reopened",
        target_value="https://reopen.corp",
        title="Cross-Site Scripting in Comment Field",
        severity=FindingSeverity.HIGH,
        confidence=FindingConfidence.FIRM,
        status=FindingLifecycleStatus.REOPENED,
        cvss_score=7.5,
        last_observed_at=now,
    )
    db.add(finding)
    db.flush()

    calc_reopened = ContextualRiskService.calculate_score_and_factors(finding=finding, now=now)
    assert calc_reopened["factor_breakdown"]["lifecycle_multiplier"] == 1.10
    assert any("recurred on target (REOPENED)" in f for f in calc_reopened["contributing_factors"])

    # Transition to ACCEPTED_RISK with expiration and compensating controls
    finding.status = FindingLifecycleStatus.ACCEPTED_RISK
    finding.risk_accepted_at = now
    finding.risk_accepted_by_id = lead_user.id
    finding.risk_accepted_reason = "Business critical migration scheduled for Q4; temporary WAF virtual patching active."
    finding.risk_accepted_expires_at = expires_at
    finding.compensating_controls = "ModSecurity rule #941100 enabled in blocking mode at reverse proxy."
    db.commit()

    calc_accepted = ContextualRiskService.calculate_score_and_factors(finding=finding, now=now)
    assert calc_accepted["factor_breakdown"]["lifecycle_multiplier"] == 0.40
    # Must not be zeroed out
    assert calc_accepted["score"] > 0.0
    assert calc_accepted["input_snapshot"]["risk_accepted_by_id"] == lead_user.id
    assert calc_accepted["input_snapshot"]["risk_accepted_expires_at"] == expires_at.isoformat()
    assert calc_accepted["input_snapshot"]["compensating_controls"] is not None
    assert any("Active authorized risk acceptance" in f for f in calc_accepted["contributing_factors"])

    # Test REMEDIATED_PENDING_VERIFICATION
    finding.status = FindingLifecycleStatus.REMEDIATED_PENDING_VERIFICATION
    calc_pending = ContextualRiskService.calculate_score_and_factors(finding=finding, now=now)
    assert calc_pending["factor_breakdown"]["lifecycle_multiplier"] == 0.50
    assert any("REMEDIATED_PENDING_VERIFICATION" in f for f in calc_pending["contributing_factors"])


def test_malformed_nan_inf_out_of_bounds_cvss_inputs(
    db: Session,
    test_project: Project,
):
    """
    Verifies that malformed CVSS scores (NaN, infinite, negative, > 10.0) are
    safely handled, default to categorical severity base score, and record explicit missing factor gaps.
    """
    now = datetime(2026, 10, 25, 12, 0, 0, tzinfo=timezone.utc)

    # 1. NaN CVSS score
    finding_nan = VulnerabilityFinding(
        project_id=test_project.id,
        fingerprint="fp-cvss-nan",
        target_value="https://test.corp",
        title="Test NaN CVSS",
        severity=FindingSeverity.HIGH,
        confidence=FindingConfidence.FIRM,
        status=FindingLifecycleStatus.DETECTED,
        cvss_score=float("nan"),
        last_observed_at=now,
    )

    calc_nan = ContextualRiskService.calculate_score_and_factors(finding=finding_nan, now=now)
    assert not math.isnan(calc_nan["score"])
    assert calc_nan["score"] > 0.0
    assert calc_nan["factor_breakdown"]["base_score"] == 70.0  # HIGH default
    assert any("non-finite or outside [0.0, 10.0]" in mf for mf in calc_nan["missing_factors"])

    # 2. Infinite CVSS score
    finding_inf = VulnerabilityFinding(
        project_id=test_project.id,
        fingerprint="fp-cvss-inf",
        target_value="https://test.corp",
        title="Test Inf CVSS",
        severity=FindingSeverity.MEDIUM,
        confidence=FindingConfidence.FIRM,
        status=FindingLifecycleStatus.DETECTED,
        cvss_score=float("inf"),
        last_observed_at=now,
    )
    calc_inf = ContextualRiskService.calculate_score_and_factors(finding=finding_inf, now=now)
    assert not math.isinf(calc_inf["score"])
    assert calc_inf["factor_breakdown"]["base_score"] == 45.0  # MEDIUM default

    # 3. Negative CVSS score
    finding_neg = VulnerabilityFinding(
        project_id=test_project.id,
        fingerprint="fp-cvss-neg",
        target_value="https://test.corp",
        title="Test Neg CVSS",
        severity=FindingSeverity.LOW,
        confidence=FindingConfidence.FIRM,
        status=FindingLifecycleStatus.DETECTED,
        cvss_score=-2.5,
        last_observed_at=now,
    )
    calc_neg = ContextualRiskService.calculate_score_and_factors(finding=finding_neg, now=now)
    assert calc_neg["factor_breakdown"]["base_score"] == 20.0  # LOW default

    # 4. Out-of-bounds > 10.0 CVSS score
    finding_oob = VulnerabilityFinding(
        project_id=test_project.id,
        fingerprint="fp-cvss-oob",
        target_value="https://test.corp",
        title="Test OOB CVSS",
        severity=FindingSeverity.CRITICAL,
        confidence=FindingConfidence.FIRM,
        status=FindingLifecycleStatus.DETECTED,
        cvss_score=99.9,
        last_observed_at=now,
    )
    calc_oob = ContextualRiskService.calculate_score_and_factors(finding=finding_oob, now=now)
    assert calc_oob["factor_breakdown"]["base_score"] == 90.0  # CRITICAL default


def test_conflicting_cvss_vs_severity_precedence(
    db: Session,
    test_project: Project,
):
    """
    Verifies deterministic precedence and conflict detection when CVSS conflicts with categorical severity.
    - Low severity with high CVSS (e.g. 9.8) is bounded to LOW max bound (39.0).
    - Critical severity with low CVSS (e.g. 1.2) is bounded to CRITICAL min bound (80.0).
    - Discrepancy warning is logged in contributing factors.
    """
    now = datetime(2026, 10, 25, 12, 0, 0, tzinfo=timezone.utc)

    # Low severity + high CVSS
    finding_conflict_1 = VulnerabilityFinding(
        project_id=test_project.id,
        fingerprint="fp-conflict-1",
        target_value="https://test.corp",
        title="Low Severity but High CVSS",
        severity=FindingSeverity.LOW,
        confidence=FindingConfidence.CERTAIN,
        status=FindingLifecycleStatus.DETECTED,
        cvss_score=9.8,
        last_observed_at=now,
    )
    calc1 = ContextualRiskService.calculate_score_and_factors(finding=finding_conflict_1, now=now)
    # Scaled CVSS = 98.0, but LOW max bound is 39.0
    assert calc1["factor_breakdown"]["base_score"] == 39.0
    assert any("Severity discrepancy detected" in f for f in calc1["contributing_factors"])

    # Critical severity + low CVSS
    finding_conflict_2 = VulnerabilityFinding(
        project_id=test_project.id,
        fingerprint="fp-conflict-2",
        target_value="https://test.corp",
        title="Critical Severity but Low CVSS",
        severity=FindingSeverity.CRITICAL,
        confidence=FindingConfidence.CERTAIN,
        status=FindingLifecycleStatus.DETECTED,
        cvss_score=1.5,
        last_observed_at=now,
    )
    calc2 = ContextualRiskService.calculate_score_and_factors(finding=finding_conflict_2, now=now)
    # Scaled CVSS = 15.0, but CRITICAL min bound is 80.0
    assert calc2["factor_breakdown"]["base_score"] == 80.0
    assert any("Severity discrepancy detected" in f for f in calc2["contributing_factors"])


def test_future_dated_and_naive_timestamps(
    db: Session,
    test_project: Project,
):
    """
    Verifies that future-dated timestamps are clamped to 0 days (fresh) without negative age,
    and naive datetimes are seamlessly converted to UTC without throwing exceptions.
    """
    now = datetime(2026, 10, 25, 12, 0, 0, tzinfo=timezone.utc)
    future_time = now + timedelta(days=10)

    finding_future = VulnerabilityFinding(
        project_id=test_project.id,
        fingerprint="fp-future-timestamp",
        target_value="https://test.corp",
        title="Future Dated Finding",
        severity=FindingSeverity.MEDIUM,
        confidence=FindingConfidence.FIRM,
        status=FindingLifecycleStatus.DETECTED,
        cvss_score=5.0,
        last_observed_at=future_time,
    )
    calc_future = ContextualRiskService.calculate_score_and_factors(finding=finding_future, now=now)
    assert calc_future["factor_breakdown"]["freshness_multiplier"] == 1.0
    assert any("Observation timestamp is future-dated" in f for f in calc_future["contributing_factors"])

    # Test naive datetime
    naive_time = datetime(2026, 10, 20, 12, 0, 0)  # No tzinfo
    finding_naive = VulnerabilityFinding(
        project_id=test_project.id,
        fingerprint="fp-naive-timestamp",
        target_value="https://test.corp",
        title="Naive Timestamp Finding",
        severity=FindingSeverity.MEDIUM,
        confidence=FindingConfidence.FIRM,
        status=FindingLifecycleStatus.DETECTED,
        cvss_score=5.0,
        last_observed_at=naive_time,
    )
    calc_naive = ContextualRiskService.calculate_score_and_factors(finding=finding_naive, now=now)
    assert calc_naive["factor_breakdown"]["freshness_multiplier"] == 1.0  # 5 days old <= 7


def test_scoring_version_change_forces_recalculation(
    db: Session,
    test_project: Project,
    lead_user: User,
):
    """
    Verifies that when an active assessment in the database has an older scoring_version,
    assess_and_persist_finding_risk recognizes the version mismatch and forces recomputation,
    superseding the old assessment.
    """
    finding = VulnerabilityFinding(
        project_id=test_project.id,
        fingerprint="fp-version-test",
        target_value="https://test.corp",
        title="Version Test Finding",
        severity=FindingSeverity.HIGH,
        confidence=FindingConfidence.CERTAIN,
        status=FindingLifecycleStatus.CONFIRMED,
        cvss_score=8.0,
    )
    db.add(finding)
    db.flush()

    # Create an initial active assessment with an older legacy version
    old_assessment = RiskAssessment(
        project_id=test_project.id,
        finding_id=finding.id,
        score=75.0,
        priority=RiskPriority.HIGH,
        scoring_version="v0.9.0-alpha",  # Outdated version
        factor_breakdown={"base_score": 75.0},
        contributing_factors=["Legacy calculation"],
        missing_factors=[],
        input_snapshot={
            "scoring_version": "v0.9.0-alpha",
            "finding_severity": "HIGH",
            "finding_confidence": "CERTAIN",
            "cvss_score": 8.0,
            "finding_status": "CONFIRMED",
        },
        is_superseded=False,
    )
    db.add(old_assessment)
    db.commit()
    old_id = old_assessment.id

    # Call assess_and_persist_finding_risk with force_recalculate=False
    # Because scoring_version is outdated, it MUST force recalculation
    new_assessment = ContextualRiskService.assess_and_persist_finding_risk(
        project_id=test_project.id,
        finding_id=finding.id,
        db=db,
        force_recalculate=False,
        actor=lead_user,
    )

    assert new_assessment.id != old_id
    assert new_assessment.scoring_version == ContextualRiskService.SCORING_VERSION
    assert new_assessment.is_superseded is False

    # Verify old assessment was superseded
    db.refresh(old_assessment)
    assert old_assessment.is_superseded is True
    assert old_assessment.superseded_at is not None


def test_attack_path_stale_and_low_confidence_classification(
    db: Session,
    test_project: Project,
):
    """
    Verifies that:
    - Any path with a STALE or SUPERSEDED edge is classified as STALE (never VERIFIED).
    - Missing evidence explicitly warns about stale/expired evidence.
    - Path with confidence < 0.7 on a verified edge cannot be classified as VERIFIED.
    - Graph cycle does not cause infinite recursion.
    """
    # Create 3 nodes in a cycle: A -> B -> C -> A
    node_a = GraphNode(project_id=test_project.id, category=GraphNodeCategory.ASSET, label="Perimeter Gateway")
    node_b = GraphNode(project_id=test_project.id, category=GraphNodeCategory.SERVICE, label="Auth Proxy")
    node_c = GraphNode(project_id=test_project.id, category=GraphNodeCategory.ASSET, label="Internal DB")
    db.add_all([node_a, node_b, node_c])
    db.flush()

    # Edge A -> B: VERIFIED (conf 1.0)
    rel_ab = GraphRelationship(
        project_id=test_project.id,
        source_node_id=node_a.id,
        target_node_id=node_b.id,
        relationship_type=RelationshipType.CAN_ACCESS,
        status=RelationshipStatus.VERIFIED,
        confidence=1.0,
    )
    # Edge B -> C: STALE (conf 0.9)
    rel_bc = GraphRelationship(
        project_id=test_project.id,
        source_node_id=node_b.id,
        target_node_id=node_c.id,
        relationship_type=RelationshipType.CAN_ACCESS,
        status=RelationshipStatus.STALE,
        confidence=0.9,
    )
    # Edge C -> A (cycle!): VERIFIED
    rel_ca = GraphRelationship(
        project_id=test_project.id,
        source_node_id=node_c.id,
        target_node_id=node_a.id,
        relationship_type=RelationshipType.CAN_ACCESS,
        status=RelationshipStatus.VERIFIED,
        confidence=1.0,
    )
    db.add_all([rel_ab, rel_bc, rel_ca])
    db.commit()

    # Analyze paths from A to C
    analysis = AttackPathAnalysisService.analyze_attack_paths(
        project_id=test_project.id,
        db=db,
        start_node_id=node_a.id,
        target_node_id=node_c.id,
        max_depth=4,
    )

    assert analysis["total_paths_found"] >= 1
    path = analysis["paths"][0]
    # Because B -> C is STALE, path MUST be STALE
    assert path["path_verification_status"] == PathVerificationStatus.STALE.value
    assert any("expired or been superseded" in me for me in path["missing_evidence"])

    # Update B -> C to VERIFIED but low confidence (0.4)
    rel_bc.status = RelationshipStatus.VERIFIED
    rel_bc.confidence = 0.4
    db.commit()

    analysis_low_conf = AttackPathAnalysisService.analyze_attack_paths(
        project_id=test_project.id,
        db=db,
        start_node_id=node_a.id,
        target_node_id=node_c.id,
        max_depth=4,
    )
    path_low = analysis_low_conf["paths"][0]
    # Cannot be VERIFIED when confidence is < 0.7
    assert path_low["path_verification_status"] != PathVerificationStatus.VERIFIED.value
    assert any("low confidence" in me for me in path_low["missing_evidence"])


def test_remediation_safety_rbac_and_lifecycle_invariance(
    db: Session,
    test_project: Project,
    lead_user: User,
    tester_user: User,
):
    """
    Verifies that:
    - Playbooks operate in an advisory capacity without executing code.
    - Idempotency: repeated generation returns the identical record.
    - Only Project LEAD or System ADMIN can approve recommendations requiring approval.
    - Review notes are mandatory and require >= 3 characters.
    - Generating or reviewing a recommendation NEVER changes finding.status.
    """
    finding = VulnerabilityFinding(
        project_id=test_project.id,
        fingerprint="fp-rem-invariance",
        target_value="https://app.corp/search",
        title="SQL Injection in Search Form",
        severity=FindingSeverity.HIGH,
        confidence=FindingConfidence.FIRM,
        status=FindingLifecycleStatus.CONFIRMED,
        cvss_score=8.5,
    )
    db.add(finding)
    db.commit()

    initial_status = finding.status
    assert initial_status == FindingLifecycleStatus.CONFIRMED

    # 1. Generate recommendation
    rec1 = RemediationPrioritizationService.generate_or_get_recommendation(
        project_id=test_project.id,
        finding_id=finding.id,
        db=db,
        actor=lead_user,
    )
    # Check advisory bounds
    assert rec1.status == RecommendationStatus.PENDING_REVIEW
    assert "Parameterized Queries" in rec1.title
    assert rec1.requires_approval is True

    # Check finding status invariance
    db.refresh(finding)
    assert finding.status == initial_status

    # 2. Idempotency check: generate again
    rec2 = RemediationPrioritizationService.generate_or_get_recommendation(
        project_id=test_project.id,
        finding_id=finding.id,
        db=db,
        actor=lead_user,
    )
    assert rec1.id == rec2.id

    # 3. Mandatory justification check: empty or <3 chars rejected
    with pytest.raises(ValueError, match="Review justification is mandatory"):
        RemediationPrioritizationService.review_recommendation(
            project_id=test_project.id,
            recommendation_id=rec1.id,
            new_status=RecommendationStatus.APPROVED,
            reviewer=lead_user,
            reviewer_role=ProjectRole.LEAD,
            review_notes="ok",  # Less than 3 chars
            db=db,
        )

    # 4. RBAC check: Tester cannot approve
    with pytest.raises(PermissionError, match="Only Project LEAD or System ADMIN"):
        RemediationPrioritizationService.review_recommendation(
            project_id=test_project.id,
            recommendation_id=rec1.id,
            new_status=RecommendationStatus.APPROVED,
            reviewer=tester_user,
            reviewer_role=ProjectRole.TESTER,
            review_notes="Tester attempted sign-off",
            db=db,
        )

    # 5. Lead approval succeeds
    reviewed = RemediationPrioritizationService.review_recommendation(
        project_id=test_project.id,
        recommendation_id=rec1.id,
        new_status=RecommendationStatus.APPROVED,
        reviewer=lead_user,
        reviewer_role=ProjectRole.LEAD,
        review_notes="Approved for implementation in Sprint 43",
        db=db,
    )
    assert reviewed.status == RecommendationStatus.APPROVED

    # 6. Verify finding lifecycle status is STILL unchanged (never auto-closed!)
    db.refresh(finding)
    assert finding.status == initial_status


def test_dual_project_scoping_api_endpoints(
    client: TestClient,
    db: Session,
    test_organization: Organization,
    lead_user: User,
    lead_headers: dict,
):
    """
    Verifies that all Phase 5 API endpoints enforce dual parent-child object scoping:
    - GET /projects/{project_id}/risk/assessments/{assessment_id}
    - POST /projects/{project_id}/risk/recalculate/{finding_id}
    - GET /projects/{project_id}/risk/remediations/{recommendation_id}
    - POST /projects/{project_id}/risk/remediations/{recommendation_id}/review
    - Cross-project access with mismatched parent project_id returns 404.
    - Hard pagination limits (e.g. limit > 100) are rejected with 422.
    """
    # Create Project 1 and Project 2
    proj_1 = Project(name="Scoping Project One", organization_id=test_organization.id)
    proj_2 = Project(name="Scoping Project Two", organization_id=test_organization.id)
    db.add_all([proj_1, proj_2])
    db.commit()

    # User is lead in both projects
    mem_1 = ProjectMember(project_id=proj_1.id, user_id=lead_user.id, role=ProjectRole.LEAD)
    mem_2 = ProjectMember(project_id=proj_2.id, user_id=lead_user.id, role=ProjectRole.LEAD)
    db.add_all([mem_1, mem_2])
    db.commit()

    # Create Finding in Project 1
    finding_1 = VulnerabilityFinding(
        project_id=proj_1.id,
        fingerprint="fp-scope-test-1",
        target_value="https://p1.corp",
        title="Reflected XSS in Profile",
        severity=FindingSeverity.HIGH,
        confidence=FindingConfidence.FIRM,
        status=FindingLifecycleStatus.DETECTED,
        cvss_score=7.2,
    )
    db.add(finding_1)
    db.commit()

    # Generate assessment in Project 1
    assessment_1 = ContextualRiskService.assess_and_persist_finding_risk(
        project_id=proj_1.id,
        finding_id=finding_1.id,
        db=db,
        actor=lead_user,
    )

    # Generate remediation in Project 1
    rem_1 = RemediationPrioritizationService.generate_or_get_recommendation(
        project_id=proj_1.id,
        finding_id=finding_1.id,
        db=db,
        actor=lead_user,
    )

    # 1. Access Assessment 1 via correct project_id -> 200
    res = client.get(
        f"/api/v1/projects/{proj_1.id}/risk/assessments/{assessment_1.id}",
        headers=lead_headers,
    )
    assert res.status_code == 200
    assert res.json()["id"] == assessment_1.id

    # 2. Access Assessment 1 via mismatched project_id (Project 2) -> 404
    res = client.get(
        f"/api/v1/projects/{proj_2.id}/risk/assessments/{assessment_1.id}",
        headers=lead_headers,
    )
    assert res.status_code == 404

    # 3. Recalculate Finding 1 via correct project_id -> 200
    res = client.post(
        f"/api/v1/projects/{proj_1.id}/risk/recalculate/{finding_1.id}",
        headers=lead_headers,
    )
    assert res.status_code == 200

    # 4. Recalculate Finding 1 via mismatched project_id (Project 2) -> 404
    res = client.post(
        f"/api/v1/projects/{proj_2.id}/risk/recalculate/{finding_1.id}",
        headers=lead_headers,
    )
    assert res.status_code == 404

    # 5. Access Remediation 1 via correct project_id -> 200
    res = client.get(
        f"/api/v1/projects/{proj_1.id}/risk/remediations/{rem_1.id}",
        headers=lead_headers,
    )
    assert res.status_code == 200
    assert res.json()["id"] == rem_1.id

    # 6. Access Remediation 1 via mismatched project_id (Project 2) -> 404
    res = client.get(
        f"/api/v1/projects/{proj_2.id}/risk/remediations/{rem_1.id}",
        headers=lead_headers,
    )
    assert res.status_code == 404

    # 7. Review Remediation 1 via mismatched project_id (Project 2) -> 404
    res = client.post(
        f"/api/v1/projects/{proj_2.id}/risk/remediations/{rem_1.id}/review",
        json={"status": "APPROVED", "review_notes": "Attempted cross-project review"},
        headers=lead_headers,
    )
    assert res.status_code == 404

    # 8. Review Remediation 1 with short review notes (<3 chars) -> 422
    res = client.post(
        f"/api/v1/projects/{proj_1.id}/risk/remediations/{rem_1.id}/review",
        json={"status": "APPROVED", "review_notes": "ok"},
        headers=lead_headers,
    )
    assert res.status_code == 422

    # 9. Attack path request with finding_id belonging to another project -> 404
    res = client.post(
        f"/api/v1/projects/{proj_2.id}/risk/attack-paths",
        json={"finding_id": finding_1.id},
        headers=lead_headers,
    )
    assert res.status_code == 404

    # 10. Hard pagination limit enforcement: limit=101 must fail validation with 422
    res = client.get(
        f"/api/v1/projects/{proj_1.id}/risk/assessments?limit=101",
        headers=lead_headers,
    )
    assert res.status_code == 422
