import hashlib
import json
import pytest
from datetime import datetime, timezone, timedelta
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.organization import Organization
from app.models.project import Project, ProjectMember, ProjectRole
from app.models.user import User, SystemRole
from app.models.asset import Asset, AssetType, AssetCriticality, AssetObservation
from app.models.graph import (
    GraphNode,
    GraphNodeCategory,
    GraphRelationship,
    RelationshipType,
    RelationshipStatus,
)
from app.models.assessment import AssessmentJob, AssessmentStatus
from app.models.finding import (
    VulnerabilityFinding,
    FindingLifecycleStatus,
    FindingSeverity,
    FindingConfidence,
)
from app.services.asset_reconciliation_service import AssetReconciliationService
from app.services.knowledge_graph_service import KnowledgeGraphService
from app.services.assessment_engine import AssessmentExecutionEngine
from app.services.finding_lifecycle_service import FindingLifecycleService
from app.core.security import create_access_token


def test_cwe1288_ipv4_and_cidr_leading_zero_rejection():
    """
    CWE-1288: Ambiguous IPv4 octets with leading zeros (e.g. 0177.0.0.1 or 192.168.001.050)
    must be strictly rejected to prevent decimal vs. octal socket parsing discrepancies.
    """
    ambiguous_ips = [
        "192.168.001.050",
        "0177.0.0.1",
        "010.0.0.1",
        "10.01.0.1",
        "192.168.1.001",
    ]
    for ip in ambiguous_ips:
        with pytest.raises(ValueError, match="CWE-1288"):
            AssetReconciliationService.classify_and_normalize(ip)

    ambiguous_cidrs = [
        "192.168.001.0/24",
        "010.0.0.0/8",
        "172.016.0.0/16",
    ]
    for cidr in ambiguous_cidrs:
        with pytest.raises(ValueError, match="CWE-1288"):
            AssetReconciliationService.classify_and_normalize(cidr)

    ambiguous_services = [
        "http://0177.0.0.1:8080",
        "https://192.168.01.5:443",
    ]
    for svc in ambiguous_services:
        with pytest.raises(ValueError, match="CWE-1288"):
            AssetReconciliationService.classify_and_normalize(svc)

    # Valid IPv4 addresses without leading zeros must succeed cleanly
    valid_ips = [
        ("192.168.1.50", AssetType.IP_ADDRESS, "192.168.1.50"),
        ("127.0.0.1", AssetType.IP_ADDRESS, "127.0.0.1"),
        ("10.0.0.0/8", AssetType.HOST, "10.0.0.0/8"),
        ("http://192.168.1.50:8080", AssetType.WEB_APP, "http://192.168.1.50:8080"),
        ("192.168.1.50:8080", AssetType.SERVICE, "tcp://192.168.1.50:8080"),
    ]
    for raw, expected_type, expected_canon in valid_ips:
        t, c, _ = AssetReconciliationService.classify_and_normalize(raw)
        assert t == expected_type
        assert c == expected_canon


def test_domain_character_validation_and_sanitization():
    """
    Validates that domain and hostname normalization rejects invalid characters
    such as HTML/script injection tags, null bytes, or shell meta-characters.
    """
    invalid_domains = [
        "<script>alert(1)</script>",
        "<svg/onload=alert(1)>",
        "corp.internal\x00malicious.com",
        "evil`rm -rf`.com",
        "sub$domain.example.com",
        "test;rm.corp",
        "evil<script>.corp",
    ]
    for dom in invalid_domains:
        with pytest.raises(ValueError):
            AssetReconciliationService.classify_and_normalize(dom)

    # Explicit check for prohibited characters error message
    with pytest.raises(ValueError, match="Invalid domain or hostname"):
        AssetReconciliationService.classify_and_normalize("evil<script>.corp")

    # Valid domains and wildcards should normalize
    valid_domains = [
        ("api.corp.local", AssetType.DOMAIN, "api.corp.local"),
        ("*.service.internal", AssetType.DOMAIN, "*.service.internal"),
        ("my-host_01.internal", AssetType.DOMAIN, "my-host_01.internal"),
        ("Sub.Domain.Example.Com.", AssetType.DOMAIN, "sub.domain.example.com"),
    ]
    for raw, expected_type, expected_canon in valid_domains:
        t, c, _ = AssetReconciliationService.classify_and_normalize(raw)
        assert t == expected_type
        assert c == expected_canon


def test_deterministic_evidence_hashing_canonicalization(db: Session, test_project: Project, test_organization: Organization):
    """
    Verifies that record_observation automatically computes a deterministic canonical
    SHA-256 digest over observed_attributes when evidence_hash is omitted, and that
    differing dict key ordering produces identical digests.
    """
    asset = AssetReconciliationService.reconcile_or_create_asset(
        project_id=test_project.id,
        organization_id=test_organization.id,
        asset_type=AssetType.DOMAIN,
        canonical_identifier="canonical-hash-test.corp",
        db=db,
    )

    attrs1 = {"b_key": "val2", "a_key": "val1", "nested": {"z": 10, "a": 5}}
    attrs2 = {"nested": {"a": 5, "z": 10}, "a_key": "val1", "b_key": "val2"}

    obs1 = AssetReconciliationService.record_observation(
        asset=asset,
        project_id=test_project.id,
        observation_source="AUDIT_TEST",
        observed_attributes=attrs1,
        db=db,
    )

    obs2 = AssetReconciliationService.record_observation(
        asset=asset,
        project_id=test_project.id,
        observation_source="AUDIT_TEST",
        observed_attributes=attrs2,
        db=db,
    )

    assert obs1.evidence_hash is not None
    assert len(obs1.evidence_hash) == 64
    assert obs1.evidence_hash == obs2.evidence_hash

    # Compare against manual sort_keys JSON SHA-256
    expected_json = json.dumps(attrs1, sort_keys=True, separators=(",", ":"))
    expected_hash = hashlib.sha256(expected_json.encode("utf-8")).hexdigest()
    assert obs1.evidence_hash == expected_hash


def test_graph_self_referential_edge_prohibition(db: Session, test_project: Project):
    """
    Prohibits creating self-referential graph relationships (source == target).
    """
    node = KnowledgeGraphService.get_or_create_node(
        project_id=test_project.id,
        category=GraphNodeCategory.ASSET,
        label="Isolated Node",
        entity_id="iso-001",
        db=db,
    )

    with pytest.raises(ValueError, match="Self-referential relationships.*are prohibited"):
        KnowledgeGraphService.create_or_update_relationship(
            project_id=test_project.id,
            source_node_id=node.id,
            target_node_id=node.id,
            relationship_type=RelationshipType.DEPENDS_ON,
            db=db,
        )


def test_graph_node_idempotency_without_entity_id(db: Session, test_project: Project):
    """
    Verifies that calling get_or_create_node with entity_id=None (synthetic/logical node)
    returns the existing node rather than creating duplicate orphan nodes.
    """
    node1 = KnowledgeGraphService.get_or_create_node(
        project_id=test_project.id,
        category=GraphNodeCategory.DEPENDENCY,
        label="Log4j Core Library",
        entity_id=None,
        entity_type="Library",
        properties={"version": "2.14.1"},
        db=db,
    )

    node2 = KnowledgeGraphService.get_or_create_node(
        project_id=test_project.id,
        category=GraphNodeCategory.DEPENDENCY,
        label="Log4j Core Library",
        entity_id=None,
        entity_type="Library",
        properties={"version": "2.14.1", "ecosystem": "Maven"},
        db=db,
    )

    assert node1.id == node2.id
    assert node2.properties.get("ecosystem") == "Maven"

    # Query directly to ensure only one node exists
    matching = (
        db.query(GraphNode)
        .filter(
            GraphNode.project_id == test_project.id,
            GraphNode.category == GraphNodeCategory.DEPENDENCY,
            GraphNode.label == "Log4j Core Library",
            GraphNode.entity_id.is_(None),
        )
        .all()
    )
    assert len(matching) == 1


def test_cross_project_isolation_assets_and_graph(
    client: TestClient,
    db: Session,
    test_organization: Organization,
    lead_user: User,
    lead_headers: dict,
):
    """
    Verifies that asset and graph endpoints strictly enforce dual parent-child
    project scoping and deny cross-project enumeration or linkage.
    """
    # Create Project Alpha and Project Beta
    proj_a = Project(name="Project Alpha Isolation", organization_id=test_organization.id)
    proj_b = Project(name="Project Beta Isolation", organization_id=test_organization.id)
    db.add_all([proj_a, proj_b])
    db.commit()

    # User lead_user is member of BOTH projects
    member_a = ProjectMember(project_id=proj_a.id, user_id=lead_user.id, role=ProjectRole.LEAD)
    member_b = ProjectMember(project_id=proj_b.id, user_id=lead_user.id, role=ProjectRole.LEAD)
    db.add_all([member_a, member_b])
    db.commit()

    # Create Asset and Graph Node in Project Alpha
    asset_a = AssetReconciliationService.reconcile_or_create_asset(
        project_id=proj_a.id,
        organization_id=test_organization.id,
        asset_type=AssetType.HOST,
        canonical_identifier="srv-alpha-01.corp",
        name="Server Alpha",
        db=db,
    )
    obs_a = AssetReconciliationService.record_observation(
        asset=asset_a,
        project_id=proj_a.id,
        observation_source="SCANNER_A",
        observed_attributes={"os": "Windows Server"},
        db=db,
    )
    node_a = KnowledgeGraphService.get_or_create_node(
        project_id=proj_a.id,
        category=GraphNodeCategory.ASSET,
        label="Server Alpha",
        entity_id=asset_a.id,
        db=db,
    )
    db.commit()

    # 1. Accessing Asset A via Project B URL must return 404
    res = client.get(
        f"/api/v1/projects/{proj_b.id}/assets/{asset_a.id}",
        headers=lead_headers,
    )
    assert res.status_code == 404
    assert "Asset not found" in res.json()["detail"]

    # 2. Accessing Asset A observations via Project B URL must return 404
    res = client.get(
        f"/api/v1/projects/{proj_b.id}/assets/{asset_a.id}/observations",
        headers=lead_headers,
    )
    assert res.status_code == 404

    # 3. Accessing Graph Neighborhood of Node A via Project B must return 404
    res = client.get(
        f"/api/v1/projects/{proj_b.id}/graph/nodes/{node_a.id}/neighborhood",
        headers=lead_headers,
    )
    assert res.status_code == 404
    assert "Root node" in res.json()["detail"] and "not found" in res.json()["detail"]

    # 4. Attempting to link Node A (Project Alpha) to Node B (Project Beta) via Project B must fail
    node_b = KnowledgeGraphService.get_or_create_node(
        project_id=proj_b.id,
        category=GraphNodeCategory.SERVICE,
        label="Service Beta",
        entity_id="svc-b-01",
        db=db,
    )
    db.commit()

    edge_payload = {
        "source_node_id": node_a.id,  # From Proj A
        "target_node_id": node_b.id,  # From Proj B
        "relationship_type": "CAN_ACCESS",
        "status": "VERIFIED",
        "confidence": 1.0,
        "provenance": "ATTACK_ATTEMPT",
    }
    res = client.post(
        f"/api/v1/projects/{proj_b.id}/graph/relationships",
        json=edge_payload,
        headers=lead_headers,
    )
    assert res.status_code in (400, 404)
    assert "does not exist in project" in res.json()["detail"]


def test_failed_assessment_does_not_record_verified_observation_or_edges(
    db: Session,
    test_project: Project,
    lead_user: User,
):
    """
    Verifies that a failed assessment execution does NOT record a successful asset
    observation and does NOT create false VERIFIED relationship edges.
    """
    now = datetime.now(timezone.utc)
    job = AssessmentJob(
        project_id=test_project.id,
        target_id=None,
        adapter_name="local_fixture_adapter",
        adapter_version="1.0.0",
        target_input="https://failed-target.corp",
        config={},
        status=AssessmentStatus.FAILED,
        error_message="Network unreachable / socket timeout",
        created_by_id=lead_user.id,
        created_at=now,
    )
    db.add(job)
    db.commit()

    # Run integration on failed job
    AssessmentExecutionEngine.integrate_assessment_assets_and_graph(
        job=job,
        canonical_findings=[],
        db=db,
    )
    db.commit()

    # Asset should be registered, but have ZERO observations
    asset = (
        db.query(Asset)
        .filter(
            Asset.project_id == test_project.id,
            Asset.canonical_identifier == "https://failed-target.corp",
        )
        .first()
    )
    assert asset is not None
    observations = (
        db.query(AssetObservation)
        .filter(AssetObservation.asset_id == asset.id)
        .all()
    )
    assert len(observations) == 0, "Failed assessment must NOT create an observation record"

    # Assessment Job Node should be recorded with status: FAILED
    job_node = (
        db.query(GraphNode)
        .filter(
            GraphNode.project_id == test_project.id,
            GraphNode.category == GraphNodeCategory.ASSESSMENT,
            GraphNode.entity_id == job.id,
        )
        .first()
    )
    assert job_node is not None
    assert job_node.properties.get("status") == "FAILED"

    # No OBSERVED_AT edge should link the failed job to the asset
    edges = (
        db.query(GraphRelationship)
        .filter(
            GraphRelationship.project_id == test_project.id,
            GraphRelationship.source_node_id == job_node.id,
        )
        .all()
    )
    assert len(edges) == 0, "Failed assessment must NOT create OBSERVED_AT relationships"


def test_neighborhood_traversal_boundary_clamping(db: Session, test_project: Project):
    """
    Verifies that get_bounded_neighborhood enforces safety bounds:
    clamps depth between 1 and 4, clamps max_nodes to at most 100.
    """
    root = KnowledgeGraphService.get_or_create_node(
        project_id=test_project.id,
        category=GraphNodeCategory.ASSET,
        label="Root Asset",
        entity_id="root-asset-01",
        db=db,
    )
    db.commit()

    # Negative / 0 depth should clamp to 1
    res_zero = KnowledgeGraphService.get_bounded_neighborhood(
        project_id=test_project.id,
        root_node_id=root.id,
        max_depth=0,
        max_nodes=50,
        db=db,
    )
    assert res_zero["max_depth"] == 1

    # Excessive depth should clamp to 4
    res_deep = KnowledgeGraphService.get_bounded_neighborhood(
        project_id=test_project.id,
        root_node_id=root.id,
        max_depth=99,
        max_nodes=50,
        db=db,
    )
    assert res_deep["max_depth"] == 4

    # Response should have both 'edges' and 'relationships' schemas populated
    assert "edges" in res_deep
    assert "relationships" in res_deep
    assert isinstance(res_deep["relationships"], list)


def test_sweep_expired_accepted_risks_concurrent_state_safety(
    db: Session,
    test_project: Project,
    lead_user: User,
):
    """
    Verifies that sweep_expired_accepted_risks only transitions findings that are
    actively in ACCEPTED_RISK state, safely ignoring findings whose state changed.
    """
    now = datetime.now(timezone.utc)
    expired_time = now - timedelta(days=2)

    # Finding 1: in ACCEPTED_RISK and overdue
    f1 = VulnerabilityFinding(
        project_id=test_project.id,
        fingerprint="fp-f1-audit-test",
        target_value="https://app.corp/api",
        title="SQL Injection in Login",
        severity=FindingSeverity.HIGH,
        confidence=FindingConfidence.CERTAIN,
        status=FindingLifecycleStatus.ACCEPTED_RISK,
        risk_accepted_at=expired_time - timedelta(days=30),
        risk_accepted_by_id=lead_user.id,
        risk_accepted_reason="Legacy system exemption",
        risk_accepted_expires_at=expired_time,
        compensating_controls="WAF strict rule applied",
        first_detected_at=now,
        last_observed_at=now,
        created_at=now,
    )

    # Finding 2: already remediated / in REMEDIATED_PENDING_VERIFICATION
    f2 = VulnerabilityFinding(
        project_id=test_project.id,
        fingerprint="fp-f2-audit-test",
        target_value="https://app.corp/api",
        title="XSS in Header",
        severity=FindingSeverity.MEDIUM,
        confidence=FindingConfidence.CERTAIN,
        status=FindingLifecycleStatus.REMEDIATED_PENDING_VERIFICATION,
        risk_accepted_at=expired_time - timedelta(days=30),
        risk_accepted_by_id=lead_user.id,
        risk_accepted_reason="Temporary delay",
        risk_accepted_expires_at=expired_time,  # Overdue timestamp, but status is REMEDIATED_PENDING_VERIFICATION
        compensating_controls="CSP header",
        first_detected_at=now,
        last_observed_at=now,
        created_at=now,
    )

    db.add_all([f1, f2])
    db.commit()

    count = FindingLifecycleService.sweep_expired_accepted_risks(
        project_id=test_project.id,
        db=db,
        actor=lead_user,
    )

    assert count == 1
    db.refresh(f1)
    db.refresh(f2)

    assert f1.status == FindingLifecycleStatus.EXPIRED
    assert f2.status == FindingLifecycleStatus.REMEDIATED_PENDING_VERIFICATION
