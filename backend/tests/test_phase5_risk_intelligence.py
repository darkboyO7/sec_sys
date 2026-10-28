import pytest
from datetime import datetime, timezone, timedelta
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.organization import Organization
from app.models.project import Project, ProjectMember, ProjectRole
from app.models.user import User, SystemRole
from app.models.asset import Asset, AssetType, AssetCriticality
from app.models.finding import (
    VulnerabilityFinding,
    FindingLifecycleStatus,
)
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


def test_risk_scoring_determinism_and_factors(db: Session, test_project: Project, test_organization: Organization):
    """
    Verifies that the contextual risk scoring engine produces identical, deterministic
    scores for identical inputs and properly decomposes contributing factors.
    """
    now = datetime(2026, 10, 25, 12, 0, 0, tzinfo=timezone.utc)

    asset = Asset(
        project_id=test_project.id,
        organization_id=test_organization.id,
        asset_type=AssetType.WEB_APP,
        name="Customer Portal",
        canonical_identifier="https://portal.corp",
        criticality=AssetCriticality.HIGH,
        attributes={"business_impact": "HIGH", "has_known_exploit": True},
    )
    db.add(asset)
    db.flush()

    finding = VulnerabilityFinding(
        project_id=test_project.id,
        asset_id=asset.id,
        fingerprint="fp-det-test-01",
        target_value="https://portal.corp/api/login",
        title="Blind SQL Injection in Authentication",
        severity=FindingSeverity.CRITICAL,
        confidence=FindingConfidence.CERTAIN,
        status=FindingLifecycleStatus.CONFIRMED,
        cvss_score=9.8,
        last_observed_at=now - timedelta(days=2),
    )
    db.add(finding)
    db.flush()

    # Calculate risk twice with identical inputs
    calc1 = ContextualRiskService.calculate_score_and_factors(finding=finding, asset=asset, now=now)
    calc2 = ContextualRiskService.calculate_score_and_factors(finding=finding, asset=asset, now=now)

    assert calc1["score"] == calc2["score"]
    assert calc1["priority"] == calc2["priority"]
    assert calc1["factor_breakdown"] == calc2["factor_breakdown"]
    assert calc1["input_snapshot"] == calc2["input_snapshot"]

    # Critical severity (98.0) * CERTAIN (1.0) * HIGH crit (1.15) * WEB_APP exp (1.25) * fresh (1.0) * CONFIRMED (1.05)
    # Bounded to 100.0
    assert calc1["score"] == 100.0
    assert calc1["priority"] == RiskPriority.CRITICAL
    assert len(calc1["contributing_factors"]) >= 4
    assert len(calc1["missing_factors"]) == 0


def test_risk_scoring_freshness_decay_and_mitigation(db: Session, test_project: Project, test_organization: Organization):
    """
    Verifies that stale evidence decays risk score, and that active risk acceptance
    with compensating controls significantly reduces contextual risk.
    """
    now = datetime(2026, 10, 25, 12, 0, 0, tzinfo=timezone.utc)

    asset = Asset(
        project_id=test_project.id,
        organization_id=test_organization.id,
        asset_type=AssetType.SERVICE,
        name="Internal RPC Service",
        canonical_identifier="tcp://rpc.internal:9090",
        criticality=AssetCriticality.MEDIUM,
    )
    db.add(asset)
    db.flush()

    # Case A: Fresh observation, DETECTED
    finding_fresh = VulnerabilityFinding(
        project_id=test_project.id,
        asset_id=asset.id,
        fingerprint="fp-fresh-01",
        target_value="tcp://rpc.internal:9090",
        title="Unauthenticated RPC Interface",
        severity=FindingSeverity.HIGH,
        confidence=FindingConfidence.FIRM,
        status=FindingLifecycleStatus.DETECTED,
        last_observed_at=now - timedelta(days=1),
    )
    calc_fresh = ContextualRiskService.calculate_score_and_factors(finding=finding_fresh, asset=asset, now=now)

    # Case B: Stale observation (> 90 days ago)
    finding_stale = VulnerabilityFinding(
        project_id=test_project.id,
        asset_id=asset.id,
        fingerprint="fp-stale-01",
        target_value="tcp://rpc.internal:9090",
        title="Unauthenticated RPC Interface",
        severity=FindingSeverity.HIGH,
        confidence=FindingConfidence.FIRM,
        status=FindingLifecycleStatus.DETECTED,
        last_observed_at=now - timedelta(days=95),
    )
    calc_stale = ContextualRiskService.calculate_score_and_factors(finding=finding_stale, asset=asset, now=now)
    assert calc_stale["score"] < calc_fresh["score"]
    assert calc_stale["factor_breakdown"]["freshness_multiplier"] == 0.70

    # Case C: Active ACCEPTED_RISK with compensating controls
    finding_accepted = VulnerabilityFinding(
        project_id=test_project.id,
        asset_id=asset.id,
        fingerprint="fp-accepted-01",
        target_value="tcp://rpc.internal:9090",
        title="Unauthenticated RPC Interface",
        severity=FindingSeverity.HIGH,
        confidence=FindingConfidence.FIRM,
        status=FindingLifecycleStatus.ACCEPTED_RISK,
        compensating_controls="Strict firewall whitelist applied",
        last_observed_at=now - timedelta(days=1),
    )
    calc_accepted = ContextualRiskService.calculate_score_and_factors(finding=finding_accepted, asset=asset, now=now)
    assert calc_accepted["score"] < calc_fresh["score"]
    assert calc_accepted["factor_breakdown"]["lifecycle_multiplier"] == 0.40

    # Case D: VERIFIED_CLOSED neutralizes score to 0.0
    finding_closed = VulnerabilityFinding(
        project_id=test_project.id,
        asset_id=asset.id,
        fingerprint="fp-closed-01",
        target_value="tcp://rpc.internal:9090",
        title="Unauthenticated RPC Interface",
        severity=FindingSeverity.HIGH,
        confidence=FindingConfidence.FIRM,
        status=FindingLifecycleStatus.VERIFIED_CLOSED,
        last_observed_at=now - timedelta(days=1),
    )
    calc_closed = ContextualRiskService.calculate_score_and_factors(finding=finding_closed, asset=asset, now=now)
    assert calc_closed["score"] == 0.0
    assert calc_closed["priority"] == RiskPriority.INFORMATIONAL


def test_risk_scoring_missing_factors_explicit_tracking(db: Session, test_project: Project):
    """
    Verifies that missing variables (no asset, no CVSS, missing timestamp) are explicitly
    recorded in missing_factors rather than silently inventing values.
    """
    finding_sparse = VulnerabilityFinding(
        project_id=test_project.id,
        asset_id=None,  # No asset linked
        fingerprint="fp-sparse-01",
        target_value="unknown-target",
        title="Generic Header Missing",
        severity=FindingSeverity.LOW,
        confidence=FindingConfidence.TENTATIVE,
        status=FindingLifecycleStatus.DETECTED,
        cvss_score=None,  # No CVSS
        last_observed_at=None,  # No timestamp
    )

    calc = ContextualRiskService.calculate_score_and_factors(finding=finding_sparse)
    assert len(calc["missing_factors"]) >= 3
    assert any("Asset context not linked" in m for m in calc["missing_factors"])
    assert any("CVSS score not provided" in m for m in calc["missing_factors"])
    assert any("timestamp missing" in m for m in calc["missing_factors"])


def test_risk_persistence_and_supersession(db: Session, test_project: Project, lead_user: User):
    """
    Verifies that assess_and_persist_finding_risk is idempotent when inputs are unchanged,
    and creates a superseded historical trail when recalculation occurs.
    """
    finding = VulnerabilityFinding(
        project_id=test_project.id,
        fingerprint="fp-persist-01",
        target_value="https://api.corp",
        title="CORS Wildcard Allowed",
        severity=FindingSeverity.MEDIUM,
        confidence=FindingConfidence.FIRM,
        status=FindingLifecycleStatus.DETECTED,
    )
    db.add(finding)
    db.commit()

    # 1. First calculation
    a1 = ContextualRiskService.assess_and_persist_finding_risk(
        project_id=test_project.id,
        finding_id=finding.id,
        db=db,
        actor=lead_user,
    )
    assert a1.id is not None
    assert not a1.is_superseded

    # 2. Second call with unchanged inputs returns identical record
    a2 = ContextualRiskService.assess_and_persist_finding_risk(
        project_id=test_project.id,
        finding_id=finding.id,
        db=db,
        actor=lead_user,
    )
    assert a2.id == a1.id

    # 3. Force recalculation supersedes previous assessment
    a3 = ContextualRiskService.assess_and_persist_finding_risk(
        project_id=test_project.id,
        finding_id=finding.id,
        db=db,
        force_recalculate=True,
        actor=lead_user,
    )
    assert a3.id != a1.id
    db.refresh(a1)
    assert a1.is_superseded is True
    assert a1.superseded_at is not None
    assert a3.is_superseded is False


def test_attack_path_analysis_verified_and_hypothetical_chains(db: Session, test_project: Project):
    """
    Verifies that attack path analysis accurately classifies paths as VERIFIED,
    MIXED_EVIDENCE, or HYPOTHETICAL based on edge epistemic status.
    """
    # Create 4 nodes: Internet Asset -> Public Gateway -> Auth Service -> Customer DB
    n1 = GraphNode(project_id=test_project.id, category=GraphNodeCategory.ASSET, label="Web Gateway")
    n2 = GraphNode(project_id=test_project.id, category=GraphNodeCategory.SERVICE, label="Auth API")
    n3 = GraphNode(project_id=test_project.id, category=GraphNodeCategory.DEPENDENCY, label="JWT Library")
    n4 = GraphNode(project_id=test_project.id, category=GraphNodeCategory.ASSET, label="User Database")
    db.add_all([n1, n2, n3, n4])
    db.commit()

    # Edge 1: n1 -> n2 (VERIFIED)
    e1 = GraphRelationship(
        project_id=test_project.id,
        source_node_id=n1.id,
        target_node_id=n2.id,
        relationship_type=RelationshipType.EXPOSES,
        status=RelationshipStatus.VERIFIED,
        confidence=1.0,
        provenance="NMAP_SCAN",
    )
    # Edge 2: n2 -> n4 (VERIFIED)
    e2 = GraphRelationship(
        project_id=test_project.id,
        source_node_id=n2.id,
        target_node_id=n4.id,
        relationship_type=RelationshipType.CAN_ACCESS,
        status=RelationshipStatus.VERIFIED,
        confidence=0.9,
        provenance="CONFIG_AUDIT",
    )
    db.add_all([e1, e2])
    db.commit()

    # Path n1 -> n2 -> n4 should be VERIFIED
    res = AttackPathAnalysisService.analyze_attack_paths(
        project_id=test_project.id,
        db=db,
        start_node_id=n1.id,
        target_node_id=n4.id,
    )
    assert res["total_paths_found"] == 1
    p1 = res["paths"][0]
    assert p1["path_verification_status"] == PathVerificationStatus.VERIFIED.value
    assert p1["cumulative_confidence"] == 0.9
    assert len(p1["missing_evidence"]) == 0

    # Add Edge 3: n2 -> n3 (INFERRED) and n3 -> n4 (HYPOTHETICAL)
    e3 = GraphRelationship(
        project_id=test_project.id,
        source_node_id=n2.id,
        target_node_id=n3.id,
        relationship_type=RelationshipType.DEPENDS_ON,
        status=RelationshipStatus.INFERRED,
        confidence=0.8,
        provenance="HEURISTIC_ANALYSIS",
    )
    e4 = GraphRelationship(
        project_id=test_project.id,
        source_node_id=n3.id,
        target_node_id=n4.id,
        relationship_type=RelationshipType.CAN_ACCESS,
        status=RelationshipStatus.HYPOTHETICAL,
        confidence=0.5,
        provenance="ANALYST_HYPOTHESIS",
    )
    db.add_all([e3, e4])
    db.commit()

    # Path n1 -> n2 -> n3 -> n4 should be HYPOTHETICAL
    res_hypo = AttackPathAnalysisService.analyze_attack_paths(
        project_id=test_project.id,
        db=db,
        start_node_id=n1.id,
        target_node_id=n4.id,
        max_paths=5,
    )
    assert res_hypo["total_paths_found"] == 2
    statuses = {p["path_verification_status"] for p in res_hypo["paths"]}
    assert PathVerificationStatus.VERIFIED.value in statuses
    assert PathVerificationStatus.HYPOTHETICAL.value in statuses


def test_attack_path_cycle_avoidance_and_truncation(db: Session, test_project: Project):
    """
    Verifies that DFS cycle avoidance terminates loops (A -> B -> A) without infinite recursion.
    """
    na = GraphNode(project_id=test_project.id, category=GraphNodeCategory.SERVICE, label="Node Alpha")
    nb = GraphNode(project_id=test_project.id, category=GraphNodeCategory.SERVICE, label="Node Beta")
    db.add_all([na, nb])
    db.commit()

    # Circular loop: na -> nb and nb -> na
    e_ab = GraphRelationship(
        project_id=test_project.id,
        source_node_id=na.id,
        target_node_id=nb.id,
        relationship_type=RelationshipType.DEPENDS_ON,
        status=RelationshipStatus.VERIFIED,
        confidence=1.0,
        provenance="CYCLE_TEST",
    )
    e_ba = GraphRelationship(
        project_id=test_project.id,
        source_node_id=nb.id,
        target_node_id=na.id,
        relationship_type=RelationshipType.DEPENDS_ON,
        status=RelationshipStatus.VERIFIED,
        confidence=1.0,
        provenance="CYCLE_TEST",
    )
    db.add_all([e_ab, e_ba])
    db.commit()

    # Searching from na should terminate cleanly without stack overflow
    res = AttackPathAnalysisService.analyze_attack_paths(
        project_id=test_project.id,
        db=db,
        start_node_id=na.id,
        max_depth=4,
    )
    assert isinstance(res["paths"], list)


def test_remediation_generation_and_approval_workflow(
    db: Session,
    test_project: Project,
    lead_user: User,
    tester_user: User,
):
    """
    Verifies that remediation recommendations are evidence-based, advisory-only,
    require authorized roles for approval, and never execute changes or alter finding states.
    """
    finding = VulnerabilityFinding(
        project_id=test_project.id,
        fingerprint="fp-rem-test-01",
        target_value="https://payment.corp/checkout",
        title="SQL Injection in Order ID Parameter",
        severity=FindingSeverity.HIGH,
        confidence=FindingConfidence.CERTAIN,
        status=FindingLifecycleStatus.CONFIRMED,
    )
    db.add(finding)
    db.commit()

    # 1. Generate recommendation
    rec = RemediationPrioritizationService.generate_or_get_recommendation(
        project_id=test_project.id,
        finding_id=finding.id,
        db=db,
        actor=lead_user,
    )
    assert rec.id is not None
    assert rec.action_type == "CODE_REFACTOR"
    assert "Parameterized Queries" in rec.title
    assert rec.status == RecommendationStatus.PENDING_REVIEW
    assert rec.requires_approval is True

    # Confirm finding lifecycle state remains CONFIRMED
    db.refresh(finding)
    assert finding.status == FindingLifecycleStatus.CONFIRMED

    # 2. Tester (non-lead) attempts approval -> should fail with PermissionError
    with pytest.raises(PermissionError, match="Only Project LEAD or System ADMIN"):
        RemediationPrioritizationService.review_recommendation(
            project_id=test_project.id,
            recommendation_id=rec.id,
            new_status=RecommendationStatus.APPROVED,
            reviewer=tester_user,
            reviewer_role=ProjectRole.TESTER,
            review_notes="Attempted by tester",
            db=db,
        )

    # 3. Lead user approves recommendation -> succeeds
    reviewed = RemediationPrioritizationService.review_recommendation(
        project_id=test_project.id,
        recommendation_id=rec.id,
        new_status=RecommendationStatus.APPROVED,
        reviewer=lead_user,
        reviewer_role=ProjectRole.LEAD,
        review_notes="Approved for sprint 42 deployment",
        db=db,
    )
    assert reviewed.status == RecommendationStatus.APPROVED
    assert reviewed.reviewed_by_id == lead_user.id
    assert reviewed.review_notes == "Approved for sprint 42 deployment"

    # Finding status still unchanged (independent verification required for closure)
    db.refresh(finding)
    assert finding.status == FindingLifecycleStatus.CONFIRMED


def test_api_risk_and_remediation_endpoints_and_isolation(
    client: TestClient,
    db: Session,
    test_organization: Organization,
    lead_user: User,
    lead_headers: dict,
):
    """
    Verifies Phase 5 REST API endpoints:
    - Summary metrics
    - Finding risk calculation
    - Remediation recommendations list and review
    - Strict cross-project isolation
    """
    # Project Alpha
    proj_a = Project(name="Project Alpha Risk", organization_id=test_organization.id)
    proj_b = Project(name="Project Beta Risk", organization_id=test_organization.id)
    db.add_all([proj_a, proj_b])
    db.commit()

    member_a = ProjectMember(project_id=proj_a.id, user_id=lead_user.id, role=ProjectRole.LEAD)
    member_b = ProjectMember(project_id=proj_b.id, user_id=lead_user.id, role=ProjectRole.LEAD)
    db.add_all([member_a, member_b])
    db.commit()

    # Create Finding in Project Alpha
    finding_a = VulnerabilityFinding(
        project_id=proj_a.id,
        fingerprint="fp-api-test-a",
        target_value="https://alpha.corp",
        title="Reflected XSS in Search Query",
        severity=FindingSeverity.HIGH,
        confidence=FindingConfidence.FIRM,
        status=FindingLifecycleStatus.DETECTED,
    )
    db.add(finding_a)
    db.commit()

    # 1. Calculate risk via API for Finding A
    res = client.post(
        f"/api/v1/projects/{proj_a.id}/risk/findings/{finding_a.id}/assess",
        headers=lead_headers,
    )
    assert res.status_code == 200
    risk_data = res.json()
    assert risk_data["score"] > 0
    assert risk_data["priority"] in ("HIGH", "CRITICAL", "MEDIUM")
    assert "factor_breakdown" in risk_data

    # 2. Risk Summary Endpoint for Project Alpha
    res = client.get(
        f"/api/v1/projects/{proj_a.id}/risk/summary",
        headers=lead_headers,
    )
    assert res.status_code == 200
    summary = res.json()
    assert summary["total_assessed"] >= 1
    assert summary["highest_score"] > 0

    # 3. Generate Remediation for Finding A
    res = client.get(
        f"/api/v1/projects/{proj_a.id}/remediations/findings/{finding_a.id}",
        headers=lead_headers,
    )
    assert res.status_code == 200
    rem_data = res.json()
    assert "Content-Security-Policy" in rem_data["title"] or "Output Encoding" in rem_data["title"]
    rem_id = rem_data["id"]

    # 4. Review Remediation for Finding A
    res = client.post(
        f"/api/v1/projects/{proj_a.id}/remediations/{rem_id}/review",
        json={"status": "APPROVED", "review_notes": "Verified by Security Lead"},
        headers=lead_headers,
    )
    assert res.status_code == 200
    assert res.json()["status"] == "APPROVED"

    # 5. Cross-Project Isolation: Project B user attempting to access Finding A risk via Project B URL -> 404
    res = client.get(
        f"/api/v1/projects/{proj_b.id}/risk/findings/{finding_a.id}",
        headers=lead_headers,
    )
    assert res.status_code == 404

    # 6. Cross-Project Isolation: Project B user attempting to access Remediation of Finding A via Project B URL -> 404
    res = client.get(
        f"/api/v1/projects/{proj_b.id}/remediations/findings/{finding_a.id}",
        headers=lead_headers,
    )
    assert res.status_code == 404
