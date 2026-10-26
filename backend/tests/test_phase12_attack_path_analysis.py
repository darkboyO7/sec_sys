import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.project import Project
from app.models.user import User
from app.models.graph import (
    GraphNode,
    GraphRelationship,
    GraphNodeCategory,
    RelationshipType,
    RelationshipStatus,
)
from app.services.knowledge_graph_service import KnowledgeGraphService
from app.services.attack_path_service import AttackPathAnalysisService, PathVerificationStatus


def test_phase12_attack_path_ranking_and_stable_id(
    db: Session,
    test_project: Project,
):
    """Verify deterministic stable path identification, risk impact scoring, and ranking."""
    # Build a 3-hop attack path: Public Web App -> Internal API Gateway -> Customer DB
    app_node = KnowledgeGraphService.get_or_create_node(
        project_id=test_project.id,
        category=GraphNodeCategory.APPLICATION,
        label="Public Customer App",
        db=db,
    )
    api_node = KnowledgeGraphService.get_or_create_node(
        project_id=test_project.id,
        category=GraphNodeCategory.SERVICE,
        label="Internal Payments API",
        db=db,
    )
    db_node = KnowledgeGraphService.get_or_create_node(
        project_id=test_project.id,
        category=GraphNodeCategory.DATA_STORE,
        label="Customer Credit Vault",
        db=db,
    )

    # Edge 1: App CAN_ACCESS API (VERIFIED, high confidence)
    KnowledgeGraphService.create_or_update_relationship(
        project_id=test_project.id,
        source_node_id=app_node.id,
        target_node_id=api_node.id,
        relationship_type=RelationshipType.CAN_ACCESS,
        status=RelationshipStatus.VERIFIED,
        confidence=0.95,
        evidence_reference="ev-auth-token-01",
        db=db,
    )

    # Edge 2: API CAN_ACCESS Data Store (VERIFIED, high confidence)
    KnowledgeGraphService.create_or_update_relationship(
        project_id=test_project.id,
        source_node_id=api_node.id,
        target_node_id=db_node.id,
        relationship_type=RelationshipType.CAN_ACCESS,
        status=RelationshipStatus.VERIFIED,
        confidence=0.90,
        evidence_reference="ev-db-conn-pool-01",
        db=db,
    )

    result = AttackPathAnalysisService.analyze_attack_paths(
        project_id=test_project.id,
        db=db,
        start_node_id=app_node.id,
        target_node_id=db_node.id,
    )

    assert result["total_paths_found"] >= 1
    path = result["paths"][0]
    assert path["path_id"] is not None
    assert len(path["path_id"]) == 16
    assert path["path_verification_status"] == PathVerificationStatus.VERIFIED.value
    assert path["cumulative_confidence"] > 0.8
    assert path["risk_impact_score"] > 70.0
    assert "ranking_rationale" in path
    assert path["step_count"] == 2


def test_phase12_chokepoints_and_remediation_leverage(
    db: Session,
    test_project: Project,
):
    """Verify identification of defensive chokepoints where multiple attack paths intersect."""
    # Two entry points converge on one gateway before branching:
    # Path 1: App A -> Common API Gateway -> Core DB
    # Path 2: App B -> Common API Gateway -> Core DB
    app_a = KnowledgeGraphService.get_or_create_node(
        project_id=test_project.id,
        category=GraphNodeCategory.APPLICATION,
        label="Marketing App",
        db=db,
    )
    app_b = KnowledgeGraphService.get_or_create_node(
        project_id=test_project.id,
        category=GraphNodeCategory.APPLICATION,
        label="Partner App",
        db=db,
    )
    gateway = KnowledgeGraphService.get_or_create_node(
        project_id=test_project.id,
        category=GraphNodeCategory.SERVICE,
        label="Central API Gateway",
        db=db,
    )
    db_core = KnowledgeGraphService.get_or_create_node(
        project_id=test_project.id,
        category=GraphNodeCategory.DATA_STORE,
        label="Core Relational DB",
        db=db,
    )

    # App A -> Gateway
    KnowledgeGraphService.create_or_update_relationship(
        project_id=test_project.id,
        source_node_id=app_a.id,
        target_node_id=gateway.id,
        relationship_type=RelationshipType.CAN_ACCESS,
        status=RelationshipStatus.VERIFIED,
        confidence=0.9,
        evidence_reference="ev-gw-a",
        db=db,
    )
    # App B -> Gateway
    KnowledgeGraphService.create_or_update_relationship(
        project_id=test_project.id,
        source_node_id=app_b.id,
        target_node_id=gateway.id,
        relationship_type=RelationshipType.CAN_ACCESS,
        status=RelationshipStatus.VERIFIED,
        confidence=0.9,
        evidence_reference="ev-gw-b",
        db=db,
    )
    # Gateway -> DB
    KnowledgeGraphService.create_or_update_relationship(
        project_id=test_project.id,
        source_node_id=gateway.id,
        target_node_id=db_core.id,
        relationship_type=RelationshipType.CAN_ACCESS,
        status=RelationshipStatus.VERIFIED,
        confidence=0.9,
        evidence_reference="ev-db-access",
        db=db,
    )

    result = AttackPathAnalysisService.analyze_attack_paths(
        project_id=test_project.id,
        db=db,
        target_node_id=db_core.id,
    )

    assert result["total_paths_found"] >= 2
    assert "chokepoints" in result
    chokepoints = result["chokepoints"]
    assert len(chokepoints) >= 1
    # Central API Gateway node should be a detected chokepoint intersecting multiple paths
    node_choke = next((c for c in chokepoints if c["element_type"] == "NODE" and c["id"] == gateway.id), None)
    assert node_choke is not None
    assert node_choke["paths_intersected"] >= 2
    assert node_choke["remediation_leverage"] > 0.0


def test_phase12_api_attack_paths_endpoint(
    client: TestClient,
    db: Session,
    test_project: Project,
    tester_headers: dict,
):
    """Verify REST endpoint for attack path evaluation returns structured response with chokepoints."""
    res = client.post(
        f"/api/v1/projects/{test_project.id}/graph/paths",
        headers=tester_headers,
        json={"max_depth": 3, "max_paths": 5},
    )
    assert res.status_code == 200, res.text
    data = res.json()
    assert "total_paths_found" in data
    assert "paths" in data
    assert "chokepoints" in data
    assert "methodology_disclaimer" in data
