import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.database import Base
from app.models.organization import Organization
from app.models.project import Project
from app.models.graph import (
    GraphNode,
    GraphRelationship,
    GraphNodeCategory,
    RelationshipType,
    RelationshipStatus,
)
from app.services.knowledge_graph_service import KnowledgeGraphService

TEST_DB_URL = "sqlite:///:memory:"


@pytest.fixture
def db_session():
    engine = create_engine(TEST_DB_URL, connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
        Base.metadata.drop_all(bind=engine)


@pytest.fixture
def setup_projects(db_session):
    org = Organization(name="Graph Org", slug="graph-org")
    db_session.add(org)
    db_session.flush()

    project_a = Project(name="Project Alpha", organization_id=org.id)
    project_b = Project(name="Project Beta", organization_id=org.id)
    db_session.add_all([project_a, project_b])
    db_session.commit()

    return {"project_a": project_a, "project_b": project_b}


def test_node_creation_and_idempotency(db_session, setup_projects):
    proj_a = setup_projects["project_a"]

    # 1. Create node
    node1 = KnowledgeGraphService.get_or_create_node(
        project_id=proj_a.id,
        category=GraphNodeCategory.ASSET,
        label="Database Primary",
        entity_id="db-001",
        entity_type="Asset",
        properties={"engine": "PostgreSQL"},
        db=db_session,
    )
    assert node1.id is not None
    assert node1.label == "Database Primary"

    # 2. Re-invoking with identical entity_id returns existing node and merges properties
    node2 = KnowledgeGraphService.get_or_create_node(
        project_id=proj_a.id,
        category=GraphNodeCategory.ASSET,
        label="Database Primary Renamed",
        entity_id="db-001",
        properties={"version": "16.2"},
        db=db_session,
    )
    assert node2.id == node1.id
    assert node2.label == "Database Primary Renamed"
    assert node2.properties["engine"] == "PostgreSQL"
    assert node2.properties["version"] == "16.2"


def test_relationship_creation_and_project_isolation(db_session, setup_projects):
    proj_a = setup_projects["project_a"]
    proj_b = setup_projects["project_b"]

    node_a1 = KnowledgeGraphService.get_or_create_node(
        project_id=proj_a.id,
        category=GraphNodeCategory.ASSET,
        label="Web Frontend",
        entity_id="asset-web",
        db=db_session,
    )
    node_a2 = KnowledgeGraphService.get_or_create_node(
        project_id=proj_a.id,
        category=GraphNodeCategory.SERVICE,
        label="HTTPS Ingress",
        entity_id="svc-https",
        db=db_session,
    )
    node_b1 = KnowledgeGraphService.get_or_create_node(
        project_id=proj_b.id,
        category=GraphNodeCategory.ASSET,
        label="Outsider Asset",
        entity_id="asset-outsider",
        db=db_session,
    )

    # 1. Valid edge within project Alpha
    rel = KnowledgeGraphService.create_or_update_relationship(
        project_id=proj_a.id,
        source_node_id=node_a1.id,
        target_node_id=node_a2.id,
        relationship_type=RelationshipType.EXPOSES,
        status=RelationshipStatus.VERIFIED,
        confidence=1.0,
        db=db_session,
    )
    assert rel.id is not None
    assert rel.relationship_type == RelationshipType.EXPOSES
    assert rel.status == RelationshipStatus.VERIFIED

    # 2. Cross-project edge rejected (cannot link node_a1 to node_b1)
    with pytest.raises(ValueError) as exc:
        KnowledgeGraphService.create_or_update_relationship(
            project_id=proj_a.id,
            source_node_id=node_a1.id,
            target_node_id=node_b1.id,
            relationship_type=RelationshipType.CAN_ACCESS,
            db=db_session,
        )
    assert "Invalid relationship endpoints" in str(exc.value)


def test_cycle_safety_and_bounded_neighborhood(db_session, setup_projects):
    proj_a = setup_projects["project_a"]

    # Create cyclic graph: Node A -> Node B -> Node C -> Node A
    node_a = KnowledgeGraphService.get_or_create_node(project_id=proj_a.id, category=GraphNodeCategory.ASSET, label="Node A", entity_id="n-a", db=db_session)
    node_b = KnowledgeGraphService.get_or_create_node(project_id=proj_a.id, category=GraphNodeCategory.SERVICE, label="Node B", entity_id="n-b", db=db_session)
    node_c = KnowledgeGraphService.get_or_create_node(project_id=proj_a.id, category=GraphNodeCategory.APPLICATION, label="Node C", entity_id="n-c", db=db_session)

    KnowledgeGraphService.create_or_update_relationship(project_id=proj_a.id, source_node_id=node_a.id, target_node_id=node_b.id, relationship_type=RelationshipType.EXPOSES, db=db_session)
    KnowledgeGraphService.create_or_update_relationship(project_id=proj_a.id, source_node_id=node_b.id, target_node_id=node_c.id, relationship_type=RelationshipType.DEPENDS_ON, db=db_session)
    KnowledgeGraphService.create_or_update_relationship(project_id=proj_a.id, source_node_id=node_c.id, target_node_id=node_a.id, relationship_type=RelationshipType.CAN_ACCESS, db=db_session)

    # Neighborhood traversal must not hang or infinite-loop on cycles
    neighborhood = KnowledgeGraphService.get_bounded_neighborhood(
        project_id=proj_a.id,
        root_node_id=node_a.id,
        max_depth=3,
        max_nodes=10,
        max_edges=20,
        db=db_session,
    )

    assert len(neighborhood["nodes"]) == 3
    assert len(neighborhood["edges"]) == 3
    assert neighborhood["truncated"] is False

    # Test strict bounding with max_nodes = 2
    bounded = KnowledgeGraphService.get_bounded_neighborhood(
        project_id=proj_a.id,
        root_node_id=node_a.id,
        max_depth=3,
        max_nodes=2,
        max_edges=20,
        db=db_session,
    )
    assert len(bounded["nodes"]) <= 2
    assert bounded["truncated"] is True
