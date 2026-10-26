import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.user import User
from app.models.project import Project, ProjectRole
from app.models.graph import (
    GraphNode,
    GraphRelationship,
    GraphNodeCategory,
    RelationshipType,
    RelationshipStatus,
)
from app.services.knowledge_graph_service import KnowledgeGraphService


def test_phase10_extended_node_types_and_listing(
    client: TestClient,
    db: Session,
    test_project: Project,
    lead_headers: dict,
):
    """Verify creation and querying of extended Phase 10 security entities."""
    # 1. Register diverse security entities via API
    entities = [
        {"category": "BUSINESS_SERVICE", "label": "Payment Gateway Service", "epistemic_status": "VERIFIED"},
        {"category": "CLOUD_RESOURCE", "label": "AWS S3 Customer Vault", "epistemic_status": "VERIFIED"},
        {"category": "DATA_STORE", "label": "PostgreSQL Primary Cluster", "epistemic_status": "VERIFIED"},
        {"category": "HOST", "label": "prod-app-server-01.internal", "epistemic_status": "VERIFIED"},
        {"category": "DOMAIN", "label": "api.payments.acme.com", "epistemic_status": "VERIFIED"},
        {"category": "IP_ADDRESS", "label": "198.51.100.25", "epistemic_status": "VERIFIED"},
        {"category": "SOFTWARE_COMPONENT", "label": "openssl-3.0.2", "epistemic_status": "VERIFIED"},
    ]

    for entity in entities:
        res = client.post(
            f"/api/v1/projects/{test_project.id}/graph/nodes",
            headers=lead_headers,
            json=entity,
        )
        assert res.status_code == 201, res.text
        data = res.json()
        assert data["category"] == entity["category"]
        assert data["label"] == entity["label"]
        assert data["epistemic_status"] == entity["epistemic_status"]

    # 2. Filter nodes by category
    res_list = client.get(
        f"/api/v1/projects/{test_project.id}/graph/nodes?category=HOST",
        headers=lead_headers,
    )
    assert res_list.status_code == 200
    hosts = res_list.json()
    assert len(hosts) == 1
    assert hosts[0]["label"] == "prod-app-server-01.internal"


def test_phase10_semantic_edge_constraints(
    db: Session,
    test_project: Project,
):
    """Verify semantic edge validation prevents absurd relationships."""
    host = KnowledgeGraphService.get_or_create_node(
        project_id=test_project.id,
        category=GraphNodeCategory.HOST,
        label="db-host-01",
        db=db,
    )
    service = KnowledgeGraphService.get_or_create_node(
        project_id=test_project.id,
        category=GraphNodeCategory.SERVICE,
        label="PostgreSQL Daemon",
        db=db,
    )
    vuln = KnowledgeGraphService.get_or_create_node(
        project_id=test_project.id,
        category=GraphNodeCategory.VULNERABILITY,
        label="CVE-2026-9999",
        db=db,
    )

    # 1. Valid edge: HOST -(RUNS)-> SERVICE
    rel_valid = KnowledgeGraphService.create_or_update_relationship(
        project_id=test_project.id,
        source_node_id=host.id,
        target_node_id=service.id,
        relationship_type=RelationshipType.RUNS,
        status=RelationshipStatus.VERIFIED,
        evidence_reference="ev-runs-01",
        db=db,
    )
    assert rel_valid.relationship_type == RelationshipType.RUNS
    assert rel_valid.status == RelationshipStatus.VERIFIED

    # 2. Valid edge: SERVICE -(AFFECTED_BY)-> VULNERABILITY
    rel_vuln = KnowledgeGraphService.create_or_update_relationship(
        project_id=test_project.id,
        source_node_id=service.id,
        target_node_id=vuln.id,
        relationship_type=RelationshipType.AFFECTED_BY,
        status=RelationshipStatus.VERIFIED,
        evidence_reference="ev-vuln-01",
        db=db,
    )
    assert rel_vuln.relationship_type == RelationshipType.AFFECTED_BY

    # 3. Invalid edge: VULNERABILITY -(RUNS)-> HOST (prohibited semantics)
    with pytest.raises(ValueError) as exc:
        KnowledgeGraphService.create_or_update_relationship(
            project_id=test_project.id,
            source_node_id=vuln.id,
            target_node_id=host.id,
            relationship_type=RelationshipType.RUNS,
            db=db,
        )
    assert "does not allow source node" in str(exc.value)


def test_phase10_epistemic_verification_and_history(
    db: Session,
    test_project: Project,
):
    """Verify epistemic evidence grounding and verification history tracking."""
    domain = KnowledgeGraphService.get_or_create_node(
        project_id=test_project.id,
        category=GraphNodeCategory.DOMAIN,
        label="auth.internal.corp",
        db=db,
    )
    ip_node = KnowledgeGraphService.get_or_create_node(
        project_id=test_project.id,
        category=GraphNodeCategory.IP_ADDRESS,
        label="10.0.0.50",
        db=db,
    )

    # 1. Claiming VERIFIED without evidence provenance downgrades to INFERRED
    rel_unverified = KnowledgeGraphService.create_or_update_relationship(
        project_id=test_project.id,
        source_node_id=domain.id,
        target_node_id=ip_node.id,
        relationship_type=RelationshipType.RESOLVES_TO,
        status=RelationshipStatus.VERIFIED,
        provenance="MANUAL_ANALYST",
        evidence_reference=None,  # No evidence provided!
        db=db,
    )
    assert rel_unverified.status == RelationshipStatus.INFERRED

    # 2. Update relationship with confirmed DNS query evidence -> upgrades to VERIFIED
    rel_verified = KnowledgeGraphService.create_or_update_relationship(
        project_id=test_project.id,
        source_node_id=domain.id,
        target_node_id=ip_node.id,
        relationship_type=RelationshipType.RESOLVES_TO,
        status=RelationshipStatus.VERIFIED,
        provenance="PASSIVE_DNS_PROBE",
        evidence_reference="sha256-dns-record-evidence-001",
        db=db,
    )
    assert rel_verified.status == RelationshipStatus.VERIFIED

    # Check verification history snapshot
    history = rel_verified.verification_history
    assert len(history) >= 2
    assert history[-1]["from_status"] == "INFERRED"
    assert history[-1]["to_status"] == "VERIFIED"


def test_phase10_cross_project_isolation(
    db: Session,
    test_project: Project,
    test_organization,
):
    """Verify strict project isolation prevents cross-project relationship edges."""
    other_proj = Project(
        name="Foreign Project Isolated",
        organization_id=test_organization.id,
    )
    db.add(other_proj)
    db.commit()

    node_a = KnowledgeGraphService.get_or_create_node(
        project_id=test_project.id,
        category=GraphNodeCategory.ASSET,
        label="asset-project-a",
        db=db,
    )
    node_b = KnowledgeGraphService.get_or_create_node(
        project_id=other_proj.id,
        category=GraphNodeCategory.ASSET,
        label="asset-project-b",
        db=db,
    )

    with pytest.raises(ValueError) as exc:
        KnowledgeGraphService.create_or_update_relationship(
            project_id=test_project.id,
            source_node_id=node_a.id,
            target_node_id=node_b.id,
            relationship_type=RelationshipType.CONTAINS,
            db=db,
        )
    assert "does not exist in project" in str(exc.value)
