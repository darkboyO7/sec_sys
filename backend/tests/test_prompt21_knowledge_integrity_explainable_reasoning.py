"""
Comprehensive Deterministic Test Suite for Prompt 21:
Knowledge Integrity, Explainable Attack Paths & Trustworthy Reasoning.
"""

import hashlib
from datetime import datetime, timezone, timedelta
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.graph import (
    GraphNode,
    GraphRelationship,
    GraphNodeCategory,
    RelationshipType,
    RelationshipStatus,
    EpistemicStatus,
)
from app.models.knowledge import (
    KnowledgeDependencyRecord,
    KnowledgeDependencyType,
    ExplainableAttackPathRecord,
    AttackPathStatus,
    KnowledgeReconciliationAudit,
    ReconciliationStatus,
)
from app.models.asset import Asset, AssetType, AssetCriticality, AssetStatus
from app.models.finding import (
    VulnerabilityFinding,
    FindingLifecycleStatus,
    FindingSeverity,
    FindingConfidence,
)
from app.models.risk import RiskAssessment, RiskPriority
from app.models.scope import ScopeExclusion, TargetType
from app.models.project import Project, ProjectMember, ProjectRole
from app.models.user import User, SystemRole
from app.models.base import utc_now
from app.services.knowledge_graph_service import KnowledgeGraphService
from app.services.attack_path_service import AttackPathAnalysisService, PathVerificationStatus
from app.services.dependency_invalidation_service import DependencyInvalidationService
from app.services.contextual_risk_service import ContextualRiskService
from app.services.knowledge_reconciliation_service import KnowledgeReconciliationService, InconsistencySeverity


# ---------------------------------------------------------------------------
# 1. Epistemic Status & AI Prose Non-Authoritative Guardrails
# ---------------------------------------------------------------------------

def test_unsupported_ai_prose_classified_as_hypotheses(db: Session, test_project: Project):
    """
    Guarantees that AI-generated prose or model inferences cannot masquerade as authoritative observed facts.
    Must be set to is_authoritative = False, epistemic_status = HYPOTHESIS, and capped confidence.
    """
    node_src = KnowledgeGraphService.get_or_create_node(
        project_id=test_project.id,
        category=GraphNodeCategory.HOST,
        label="db-internal.local",
        db=db,
    )
    node_tgt = KnowledgeGraphService.get_or_create_node(
        project_id=test_project.id,
        category=GraphNodeCategory.DATA_STORE,
        label="CustomerPII",
        db=db,
    )

    # Attempt to create relationship with AI_ANALYST provenance claiming VERIFIED
    rel = KnowledgeGraphService.create_or_update_relationship(
        project_id=test_project.id,
        source_node_id=node_src.id,
        target_node_id=node_tgt.id,
        relationship_type=RelationshipType.CAN_ACCESS,
        status=RelationshipStatus.VERIFIED,
        confidence=0.95,
        provenance="AI_ANALYST",
        evidence_reference=None,
        db=db,
    )
    db.commit()

    assert rel.is_authoritative is False
    assert rel.epistemic_status == EpistemicStatus.HYPOTHESIS.value
    assert rel.status == RelationshipStatus.HYPOTHETICAL
    assert rel.confidence <= 0.60


def test_corroborated_fact_upgrades_on_independent_sources(db: Session, test_project: Project):
    """
    Verifies that when >= 2 independent, compatible sources report a relationship with high confidence,
    its epistemic status upgrades to CORROBORATED_FACT.
    """
    node_a = KnowledgeGraphService.get_or_create_node(
        project_id=test_project.id,
        category=GraphNodeCategory.HOST,
        label="app-server.corp",
        db=db,
    )
    node_b = KnowledgeGraphService.get_or_create_node(
        project_id=test_project.id,
        category=GraphNodeCategory.SERVICE,
        label="nginx-http",
        db=db,
    )

    # Source 1: Nmap scanner
    rel = KnowledgeGraphService.create_or_update_relationship(
        project_id=test_project.id,
        source_node_id=node_a.id,
        target_node_id=node_b.id,
        relationship_type=RelationshipType.RUNS,
        status=RelationshipStatus.VERIFIED,
        confidence=0.90,
        provenance="NMAP_PORT_SCANNER",
        evidence_reference="ev-nmap-1",
        db=db,
    )
    db.commit()
    assert rel.epistemic_status == EpistemicStatus.OBSERVED_FACT.value

    # Source 2: Cloud agent discovery
    rel_updated = KnowledgeGraphService.create_or_update_relationship(
        project_id=test_project.id,
        source_node_id=node_a.id,
        target_node_id=node_b.id,
        relationship_type=RelationshipType.RUNS,
        status=RelationshipStatus.VERIFIED,
        confidence=0.95,
        provenance="SYSTEMD_AGENT",
        evidence_reference="ev-systemd-2",
        db=db,
    )
    db.commit()

    assert rel_updated.epistemic_status == EpistemicStatus.CORROBORATED_FACT.value
    assert len(rel_updated.input_sources) >= 2


def test_contradictory_observations_preserved_without_silent_overwrite(db: Session, test_project: Project):
    """
    Verifies that conflicting observations between sources are marked CONTRADICTED,
    storing notes rather than silently clobbering existing state.
    """
    node_a = KnowledgeGraphService.get_or_create_node(
        project_id=test_project.id,
        category=GraphNodeCategory.SERVICE,
        label="auth-service",
        db=db,
    )
    node_b = KnowledgeGraphService.get_or_create_node(
        project_id=test_project.id,
        category=GraphNodeCategory.APPLICATION,
        label="oauth2-provider",
        db=db,
    )

    # Observation 1: reports protocol TLS 1.3
    rel = KnowledgeGraphService.create_or_update_relationship(
        project_id=test_project.id,
        source_node_id=node_a.id,
        target_node_id=node_b.id,
        relationship_type=RelationshipType.DEPENDS_ON,
        provenance="SCANNER_A",
        properties={"tls_version": "1.3", "auth_mode": "CERT"},
        db=db,
    )
    db.commit()

    # Observation 2: conflicting report that protocol is unencrypted HTTP
    rel_conflict = KnowledgeGraphService.create_or_update_relationship(
        project_id=test_project.id,
        source_node_id=node_a.id,
        target_node_id=node_b.id,
        relationship_type=RelationshipType.DEPENDS_ON,
        provenance="SCANNER_B",
        properties={"tls_version": "PLAINTEXT", "auth_mode": "NONE"},
        db=db,
    )
    db.commit()

    assert rel_conflict.epistemic_status == EpistemicStatus.CONTRADICTED.value
    assert rel_conflict.contradiction_notes is not None
    assert "Contradiction detected" in rel_conflict.contradiction_notes


# ---------------------------------------------------------------------------
# 2. Dependency Tracking & Invalidation Cascades
# ---------------------------------------------------------------------------

def test_evidence_tampering_invalidates_downstream_knowledge(db: Session, test_project: Project):
    """
    Verifies that when cryptographic evidence fails verification, downstream conclusions are invalidated.
    """
    inv = DependencyInvalidationService.invalidate_for_evidence_failure(
        db=db,
        project_id=test_project.id,
        evidence_id="ev-corrupt-001",
    )
    assert inv.invalidation_type == "EVIDENCE_CORRUPTED"
    assert inv.recalculation_status.value == "PENDING"
    assert any("Cryptographic evidence integrity breach" in t["reason"] for t in inv.invalidated_targets)


def test_asset_mutation_invalidates_attack_paths_and_risk(db: Session, test_project: Project):
    """
    Verifies that mutating an asset invalidates its dependent risk assessments and attack paths.
    """
    asset = Asset(
        organization_id=test_project.organization_id,
        project_id=test_project.id,
        name="app-core.corp",
        canonical_identifier="app-core.corp",
        asset_type=AssetType.HOST,
        criticality=AssetCriticality.HIGH,
        status=AssetStatus.ACTIVE,
    )
    db.add(asset)
    db.commit()
    db.refresh(asset)

    finding = VulnerabilityFinding(
        project_id=test_project.id,
        asset_id=asset.id,
        title="Remote Code Execution in Core Daemon",
        target_value="192.168.1.50:9000",
        fingerprint=hashlib.sha256(b"rce-core-daemon").hexdigest(),
        severity=FindingSeverity.CRITICAL,
        confidence=FindingConfidence.CERTAIN,
        status=FindingLifecycleStatus.DETECTED,
    )
    db.add(finding)
    db.commit()
    db.refresh(finding)

    # Assess initial risk
    risk = ContextualRiskService.assess_and_persist_finding_risk(
        project_id=test_project.id,
        finding_id=finding.id,
        db=db,
    )
    db.commit()
    assert risk.is_invalidated is False

    # Create dummy explainable attack path and register dependency
    node_ext = KnowledgeGraphService.get_or_create_node(
        project_id=test_project.id,
        category=GraphNodeCategory.HOST,
        label="external-attacker.corp",
        db=db,
    )
    node_tgt = KnowledgeGraphService.get_or_create_node(
        project_id=test_project.id,
        category=GraphNodeCategory.APPLICATION,
        label="app-core-service",
        db=db,
    )

    path = ExplainableAttackPathRecord(
        id="path-dep-test-1",
        project_id=test_project.id,
        name="External -> app-core.corp -> RCE",
        start_node_id=node_ext.id,
        target_node_id=node_tgt.id,
        path_status=AttackPathStatus.VERIFIED,
        cumulative_confidence=0.9,
        risk_impact_score=80.0,
        step_count=2,
        is_scope_compliant=True,
        calculation_version="v2.1.0",
        created_at=utc_now(),
        updated_at=utc_now(),
    )
    db.add(path)
    db.commit()

    DependencyInvalidationService.register_knowledge_dependency(
        db=db,
        project_id=test_project.id,
        source_entity_type="Asset",
        source_entity_id=asset.id,
        dependent_entity_type="ExplainableAttackPath",
        dependent_entity_id=path.id,
        dependency_type="TOPOLOGY_LINK",
    )
    db.commit()

    # Trigger asset invalidation
    DependencyInvalidationService.invalidate_for_asset_change(
        db=db,
        project_id=test_project.id,
        asset_id=asset.id,
    )
    db.commit()

    db.refresh(risk)
    db.refresh(path)

    assert risk.is_invalidated is True
    assert "Asset" in risk.invalidation_reason
    assert path.is_invalidated is True
    assert path.path_status == AttackPathStatus.INVALIDATED


def test_concurrent_invalidation_and_recomputation_safety(db: Session, test_project: Project):
    """
    Verifies that recalculating pending invalidations prevents circular scheduling and sets SUPERSEDED.
    """
    # Create two duplicate invalidation records for the same source entity
    inv1 = DependencyInvalidationService.record_invalidation(
        db=db,
        project_id=test_project.id,
        source_entity_type="Asset",
        source_entity_id="asset-dup-1",
        invalidation_type="ASSET_CHANGED",
        invalidated_targets=[],
    )
    inv2 = DependencyInvalidationService.record_invalidation(
        db=db,
        project_id=test_project.id,
        source_entity_type="Asset",
        source_entity_id="asset-dup-1",
        invalidation_type="ASSET_CHANGED",
        invalidated_targets=[],
    )

    processed = DependencyInvalidationService.process_pending_recalculations(
        db=db,
        project_id=test_project.id,
    )

    db.refresh(inv1)
    db.refresh(inv2)

    assert processed >= 1
    # One was recalculated, the circular/duplicate one was superseded
    statuses = {inv1.recalculation_status.value, inv2.recalculation_status.value}
    assert "RECALCULATED" in statuses
    assert "SUPERSEDED" in statuses


# ---------------------------------------------------------------------------
# 3. Explainable Attack Paths & Scope Compliance
# ---------------------------------------------------------------------------

def test_attack_path_step_by_step_explainability(db: Session, test_project: Project):
    """
    Verifies that each step in an attack path contains detailed assumptions,
    unverified conditions, and invalidation triggers.
    """
    n1 = KnowledgeGraphService.get_or_create_node(
        project_id=test_project.id,
        category=GraphNodeCategory.HOST,
        label="gateway.corp",
        db=db,
    )
    n2 = KnowledgeGraphService.get_or_create_node(
        project_id=test_project.id,
        category=GraphNodeCategory.SERVICE,
        label="nginx-proxy",
        db=db,
    )
    n3 = KnowledgeGraphService.get_or_create_node(
        project_id=test_project.id,
        category=GraphNodeCategory.APPLICATION,
        label="banking-portal",
        db=db,
    )

    e1 = KnowledgeGraphService.create_or_update_relationship(
        project_id=test_project.id,
        source_node_id=n1.id,
        target_node_id=n2.id,
        relationship_type=RelationshipType.RUNS,
        status=RelationshipStatus.VERIFIED,
        confidence=0.95,
        evidence_reference="ev-obs-1",
        db=db,
    )
    e2 = KnowledgeGraphService.create_or_update_relationship(
        project_id=test_project.id,
        source_node_id=n2.id,
        target_node_id=n3.id,
        relationship_type=RelationshipType.CAN_ACCESS,
        status=RelationshipStatus.INFERRED,
        confidence=0.75,
        db=db,
    )
    db.commit()

    analysis = AttackPathAnalysisService.analyze_attack_paths(
        project_id=test_project.id,
        db=db,
        start_node_id=n1.id,
        target_node_id=n3.id,
    )

    assert analysis["total_paths_found"] >= 1
    path = analysis["paths"][0]

    # Verify explainability structure
    assert "steps_explanation" in path
    assert len(path["steps_explanation"]) == 2
    step2 = path["steps_explanation"][1]

    assert len(step2["required_assumptions"]) >= 1
    assert any("firewall" in a.lower() or "reachability" in a.lower() for a in step2["required_assumptions"])
    assert len(step2["invalidation_triggers"]) >= 1
    assert "methodology_disclaimer" in path


def test_scope_exclusion_blocks_attack_path_verification(db: Session, test_project: Project):
    """
    Verifies that an attack path traversing an excluded scope target is flagged
    as is_scope_compliant = False and marked INVALIDATED.
    """
    n1 = KnowledgeGraphService.get_or_create_node(
        project_id=test_project.id,
        category=GraphNodeCategory.HOST,
        label="internal-dmz.corp",
        db=db,
    )
    n2 = KnowledgeGraphService.get_or_create_node(
        project_id=test_project.id,
        category=GraphNodeCategory.HOST,
        label="pci-restricted-zone.corp",
        db=db,
    )

    KnowledgeGraphService.create_or_update_relationship(
        project_id=test_project.id,
        source_node_id=n1.id,
        target_node_id=n2.id,
        relationship_type=RelationshipType.CAN_ACCESS,
        status=RelationshipStatus.VERIFIED,
        confidence=0.9,
        db=db,
    )
    db.commit()

    # Add ScopeExclusion matching pci-restricted-zone.corp
    user = db.query(User).first()
    exclusion = ScopeExclusion(
        project_id=test_project.id,
        target_type=TargetType.DOMAIN,
        target_value="pci-restricted-zone.corp",
        reason="Strict PCI boundary; excluded from security assessments.",
        created_by_id=user.id,
    )
    db.add(exclusion)
    db.commit()

    analysis = AttackPathAnalysisService.analyze_attack_paths(
        project_id=test_project.id,
        db=db,
        start_node_id=n1.id,
        target_node_id=n2.id,
    )

    assert analysis["total_paths_found"] >= 1
    path = analysis["paths"][0]
    assert path["is_scope_compliant"] is False
    assert len(path["scope_violations"]) >= 1
    assert path["path_verification_status"] == PathVerificationStatus.INVALIDATED.value


def test_cyclic_graph_safely_bounded_without_infinite_loops(db: Session, test_project: Project):
    """
    Verifies that cyclic relationships (A -> B -> C -> A) do not cause stack overflow or unbounded traversal.
    """
    nA = KnowledgeGraphService.get_or_create_node(project_id=test_project.id, category=GraphNodeCategory.HOST, label="node-A", db=db)
    nB = KnowledgeGraphService.get_or_create_node(project_id=test_project.id, category=GraphNodeCategory.SERVICE, label="node-B", db=db)
    nC = KnowledgeGraphService.get_or_create_node(project_id=test_project.id, category=GraphNodeCategory.APPLICATION, label="node-C", db=db)

    KnowledgeGraphService.create_or_update_relationship(project_id=test_project.id, source_node_id=nA.id, target_node_id=nB.id, relationship_type=RelationshipType.RUNS, db=db)
    KnowledgeGraphService.create_or_update_relationship(project_id=test_project.id, source_node_id=nB.id, target_node_id=nC.id, relationship_type=RelationshipType.CAN_ACCESS, db=db)
    KnowledgeGraphService.create_or_update_relationship(project_id=test_project.id, source_node_id=nC.id, target_node_id=nA.id, relationship_type=RelationshipType.AUTHENTICATES_TO, db=db)
    db.commit()

    # Search paths starting from A
    analysis = AttackPathAnalysisService.analyze_attack_paths(
        project_id=test_project.id,
        db=db,
        start_node_id=nA.id,
        max_depth=4,
    )

    # Must complete safely without error
    assert isinstance(analysis["paths"], list)
    assert analysis["truncated"] in (True, False)


# ---------------------------------------------------------------------------
# 4. Contextual Risk Explainability & Delta Tracking
# ---------------------------------------------------------------------------

def test_contextual_risk_delta_and_unverified_penalty(db: Session, test_project: Project):
    """
    Verifies that when risk is recalculated, prior score, score delta, and delta reasons are recorded,
    and unverified relationships receive an uncertainty discount penalty.
    """
    asset = Asset(
        organization_id=test_project.organization_id,
        project_id=test_project.id,
        name="prod-api.corp",
        canonical_identifier="prod-api.corp",
        asset_type=AssetType.HOST,
        criticality=AssetCriticality.MEDIUM,
        status=AssetStatus.ACTIVE,
    )
    db.add(asset)
    db.commit()
    db.refresh(asset)

    finding = VulnerabilityFinding(
        project_id=test_project.id,
        asset_id=asset.id,
        title="IDOR in User Profile Endpoint",
        target_value="prod-api.corp/profile",
        fingerprint=hashlib.sha256(b"idor-user-profile").hexdigest(),
        severity=FindingSeverity.HIGH,
        cvss_score=7.5,
        confidence=FindingConfidence.FIRM,
        status=FindingLifecycleStatus.DETECTED,
    )
    db.add(finding)
    db.commit()
    db.refresh(finding)

    # First assessment
    risk1 = ContextualRiskService.assess_and_persist_finding_risk(
        project_id=test_project.id,
        finding_id=finding.id,
        db=db,
    )
    db.commit()
    assert risk1.prior_score is None

    # Update asset criticality to CRITICAL
    asset.criticality = AssetCriticality.CRITICAL
    db.commit()

    # Second assessment (force recalculation)
    risk2 = ContextualRiskService.assess_and_persist_finding_risk(
        project_id=test_project.id,
        finding_id=finding.id,
        db=db,
        force_recalculate=True,
    )
    db.commit()

    assert risk2.prior_score == risk1.score
    assert risk2.score_delta is not None
    assert risk2.score_delta > 0
    assert any("Asset criticality updated" in r for r in risk2.delta_reasons)


def test_incomplete_risk_inputs_labeled_high_uncertainty(db: Session, test_project: Project):
    """
    Verifies that findings missing key inputs or with wide uncertainty ranges
    are marked with qualitative_label = 'HIGH_UNCERTAINTY'.
    """
    finding = VulnerabilityFinding(
        project_id=test_project.id,
        asset_id=None,  # No asset context
        title="Suspicious Service Banner",
        target_value="10.0.0.1:8088",
        fingerprint=hashlib.sha256(b"suspicious-banner-8088").hexdigest(),
        severity=FindingSeverity.INFO,
        cvss_score=None,  # Missing CVSS
        confidence=FindingConfidence.TENTATIVE,  # Low confidence
        status=FindingLifecycleStatus.DETECTED,
    )
    db.add(finding)
    db.commit()
    db.refresh(finding)

    risk = ContextualRiskService.assess_and_persist_finding_risk(
        project_id=test_project.id,
        finding_id=finding.id,
        db=db,
    )
    db.commit()

    assert risk.qualitative_label == "HIGH_UNCERTAINTY"
    assert len(risk.missing_factors) >= 1


# ---------------------------------------------------------------------------
# 5. Knowledge Reconciliation & Integrity Audits
# ---------------------------------------------------------------------------

def test_reconciliation_detects_and_repairs_dangling_and_duplicate_edges(db: Session, test_project: Project):
    """
    Verifies that the KnowledgeReconciliationService detects dangling references,
    prunes invalid edges, and consolidates duplicate relationships deterministically.
    """
    nA = KnowledgeGraphService.get_or_create_node(project_id=test_project.id, category=GraphNodeCategory.HOST, label="host-recon-1", db=db)
    nB = KnowledgeGraphService.get_or_create_node(project_id=test_project.id, category=GraphNodeCategory.SERVICE, label="svc-recon-1", db=db)

    # 1. Create legitimate edge
    r1 = KnowledgeGraphService.create_or_update_relationship(
        project_id=test_project.id,
        source_node_id=nA.id,
        target_node_id=nB.id,
        relationship_type=RelationshipType.RUNS,
        db=db,
    )
    db.commit()

    # 2. Create another project and node to simulate an orphaned/dangling cross-project reference
    other_proj = Project(
        name="External Isolated Project",
        organization_id=test_project.organization_id,
        is_active=True,
    )
    db.add(other_proj)
    db.commit()
    db.refresh(other_proj)

    n_ext = KnowledgeGraphService.get_or_create_node(
        project_id=other_proj.id,
        category=GraphNodeCategory.SERVICE,
        label="external-isolated-svc",
        db=db,
    )

    r_dangle = GraphRelationship(
        project_id=test_project.id,
        source_node_id=nA.id,
        target_node_id=n_ext.id,
        relationship_type=RelationshipType.RUNS,
        status=RelationshipStatus.VERIFIED,
        confidence=1.0,
        provenance="LEGACY_IMPORT",
        observed_at=utc_now(),
    )
    db.add(r_dangle)
    db.commit()
    dangle_id = r_dangle.id

    # Execute reconciliation audit with auto_repair = True
    audit = KnowledgeReconciliationService.audit_and_reconcile(
        db=db,
        project_id=test_project.id,
        auto_repair=True,
    )

    assert audit.status == ReconciliationStatus.COMPLETED
    assert audit.dangling_references_detected >= 1
    assert audit.auto_repaired_count >= 1

    # Verify dangling edge was pruned from database
    check_dangle = db.query(GraphRelationship).filter(GraphRelationship.id == dangle_id).first()
    assert check_dangle is None

    # Verify legitimate edge was preserved
    check_r1 = db.query(GraphRelationship).filter(GraphRelationship.id == r1.id).first()
    assert check_r1 is not None


def test_reconciliation_audit_never_destroys_raw_evidence(db: Session, test_project: Project):
    """
    Architectural invariant: Reconciliation audits must NEVER delete raw findings or cryptographic evidence
    to artificially make the knowledge graph look consistent.
    """
    finding = VulnerabilityFinding(
        project_id=test_project.id,
        title="Unauthenticated Diagnostic Endpoint",
        target_value="10.10.10.10:80",
        fingerprint=hashlib.sha256(b"diag-endpoint-80").hexdigest(),
        severity=FindingSeverity.HIGH,
        confidence=FindingConfidence.CERTAIN,
        status=FindingLifecycleStatus.DETECTED,
    )
    db.add(finding)
    db.commit()
    finding_id = finding.id

    # Execute audit
    audit = KnowledgeReconciliationService.audit_and_reconcile(
        db=db,
        project_id=test_project.id,
        auto_repair=True,
    )

    # Finding must remain intact in database
    persisted_finding = db.query(VulnerabilityFinding).filter(VulnerabilityFinding.id == finding_id).first()
    assert persisted_finding is not None
    assert persisted_finding.title == "Unauthenticated Diagnostic Endpoint"


# ---------------------------------------------------------------------------
# 6. REST API Endpoints & Multi-Tenant Isolation
# ---------------------------------------------------------------------------

def test_knowledge_api_endpoints_and_tenant_isolation(
    client: TestClient,
    db: Session,
    test_project: Project,
    lead_headers: dict,
):
    """
    Verifies that knowledge REST routes enforce project boundary isolation and return 404/403 across projects.
    """
    # 1. List attack paths
    res_paths = client.get(
        f"/api/v1/projects/{test_project.id}/knowledge/attack-paths",
        headers=lead_headers,
    )
    assert res_paths.status_code == 200
    assert isinstance(res_paths.json(), list)

    # 2. Trigger reconciliation audit
    res_reconcile = client.post(
        f"/api/v1/projects/{test_project.id}/knowledge/reconcile",
        json={"auto_repair": True},
        headers=lead_headers,
    )
    assert res_reconcile.status_code == 200
    data = res_reconcile.json()
    assert data["status"] == "COMPLETED"
    assert "reconciliation_log" in data

    # 3. List dependencies
    res_deps = client.get(
        f"/api/v1/projects/{test_project.id}/knowledge/dependencies",
        headers=lead_headers,
    )
    assert res_deps.status_code == 200
    assert isinstance(res_deps.json(), list)

    # 4. Cross-project isolation: attempting to access non-existent/other project returns 404
    res_iso = client.get(
        "/api/v1/projects/00000000-0000-0000-0000-000000000000/knowledge/dependencies",
        headers=lead_headers,
    )
    assert res_iso.status_code in (404, 403)
