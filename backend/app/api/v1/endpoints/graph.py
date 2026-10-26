from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status, Request, Query
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.core.database import get_db
from app.models.user import User
from app.models.project import ProjectRole
from app.models.graph import (
    GraphNode,
    GraphRelationship,
    GraphNodeCategory,
    RelationshipType,
    RelationshipStatus,
)
from app.schemas.graph import (
    GraphNodeRead,
    GraphNodeCreate,
    GraphRelationshipRead,
    GraphRelationshipCreate,
    GraphNeighborhoodResponse,
)
from app.services.knowledge_graph_service import KnowledgeGraphService
from app.services.audit_service import AuditService
from app.api.deps import get_current_user, verify_project_access, get_client_ip

router = APIRouter()


@router.get("/projects/{project_id}/graph/stats")
def get_graph_statistics(
    project_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Retrieve aggregated node category and edge counts for the project's Knowledge Graph.
    Strict project boundary isolation enforced.
    """
    verify_project_access(project_id, current_user, db)

    total_nodes = db.query(func.count(GraphNode.id)).filter(GraphNode.project_id == project_id).scalar() or 0
    total_edges = db.query(func.count(GraphRelationship.id)).filter(GraphRelationship.project_id == project_id).scalar() or 0

    node_counts = (
        db.query(GraphNode.category, func.count(GraphNode.id))
        .filter(GraphNode.project_id == project_id)
        .group_by(GraphNode.category)
        .all()
    )
    edge_counts = (
        db.query(GraphRelationship.relationship_type, func.count(GraphRelationship.id))
        .filter(GraphRelationship.project_id == project_id)
        .group_by(GraphRelationship.relationship_type)
        .all()
    )

    return {
        "total_nodes": total_nodes,
        "total_edges": total_edges,
        "nodes_by_category": {cat.value: count for cat, count in node_counts},
        "edges_by_type": {rel.value: count for rel, count in edge_counts},
    }


@router.get("/projects/{project_id}/graph/nodes/{node_id}/neighborhood", response_model=GraphNeighborhoodResponse)
def get_node_neighborhood(
    project_id: str,
    node_id: str,
    depth: int = Query(2, ge=1, le=4, description="Maximum traversal depth from root node"),
    max_nodes: int = Query(50, ge=1, le=200, description="Strict upper bound on returned nodes"),
    max_edges: int = Query(100, ge=1, le=300, description="Strict upper bound on returned edges"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Retrieve a bounded, cycle-safe neighborhood graph starting from the specified root node.
    Enforces strict depth and result limits to prevent unbounded traversal.
    """
    verify_project_access(project_id, current_user, db)

    try:
        neighborhood = KnowledgeGraphService.get_bounded_neighborhood(
            project_id=project_id,
            root_node_id=node_id,
            max_depth=depth,
            max_nodes=max_nodes,
            max_edges=max_edges,
            db=db,
        )
        return GraphNeighborhoodResponse(**neighborhood)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )


@router.get("/projects/{project_id}/graph/nodes", response_model=List[GraphNodeRead])
def list_graph_nodes(
    project_id: str,
    category: Optional[GraphNodeCategory] = Query(None, description="Filter by node category"),
    epistemic_status: Optional[str] = Query(None, description="Filter by epistemic status"),
    limit: int = Query(100, ge=1, le=500),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    List graph nodes within the project context with optional category/epistemic filters.
    """
    verify_project_access(project_id, current_user, db)
    return KnowledgeGraphService.list_nodes(
        project_id=project_id,
        category=category,
        epistemic_status=epistemic_status,
        limit=limit,
        db=db,
    )


@router.post("/projects/{project_id}/graph/nodes", response_model=GraphNodeRead, status_code=status.HTTP_201_CREATED)
def create_graph_node(
    project_id: str,
    node_in: GraphNodeCreate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Register a new entity node into the project's Knowledge Graph.
    Requires Project LEAD or System ADMIN.
    """
    verify_project_access(
        project_id,
        current_user,
        db,
        required_project_roles=[ProjectRole.LEAD],
    )

    node = KnowledgeGraphService.get_or_create_node(
        project_id=project_id,
        category=node_in.category,
        label=node_in.label,
        entity_id=node_in.entity_id,
        entity_type=node_in.entity_type,
        properties=node_in.properties,
        epistemic_status=node_in.epistemic_status,
        db=db,
    )

    client_ip = get_client_ip(request)
    AuditService.log(
        db=db,
        action="GRAPH_NODE_CREATE",
        target_resource=f"graph_node:{node.id}",
        actor_id=current_user.id,
        project_id=project_id,
        client_ip=client_ip,
        details={
            "node_id": node.id,
            "category": node.category.value,
            "label": node.label,
            "epistemic_status": node.epistemic_status,
        },
    )
    db.commit()
    return node


@router.get("/projects/{project_id}/graph/nodes/{node_id}", response_model=GraphNodeRead)
def get_graph_node(
    project_id: str,
    node_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Retrieve single graph node metadata and entity linkage.
    """
    verify_project_access(project_id, current_user, db)

    node = (
        db.query(GraphNode)
        .filter(GraphNode.id == node_id, GraphNode.project_id == project_id)
        .first()
    )
    if not node:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Graph node not found in specified project",
        )
    return node


@router.get("/projects/{project_id}/graph/nodes/{node_id}/relationships")
def get_node_relationships(
    project_id: str,
    node_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Retrieve incoming and outgoing edges for a graph node.
    """
    verify_project_access(project_id, current_user, db)

    try:
        return KnowledgeGraphService.get_node_relationships(
            project_id=project_id,
            node_id=node_id,
            db=db,
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )


@router.post("/projects/{project_id}/graph/relationships", response_model=GraphRelationshipRead, status_code=status.HTTP_201_CREATED)
def create_graph_relationship(
    project_id: str,
    rel_in: GraphRelationshipCreate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Create a typed, validated directed relationship edge between two nodes.
    Requires Project LEAD or System ADMIN. Prevents cross-project edge creation.
    """
    verify_project_access(
        project_id,
        current_user,
        db,
        required_project_roles=[ProjectRole.LEAD],
    )

    try:
        rel = KnowledgeGraphService.create_or_update_relationship(
            project_id=project_id,
            source_node_id=rel_in.source_node_id,
            target_node_id=rel_in.target_node_id,
            relationship_type=rel_in.relationship_type,
            status=rel_in.status,
            confidence=rel_in.confidence,
            provenance=rel_in.provenance,
            evidence_reference=rel_in.evidence_reference,
            properties=rel_in.properties,
            db=db,
        )

        client_ip = get_client_ip(request)
        AuditService.log(
            db=db,
            action="GRAPH_RELATIONSHIP_CREATE",
            target_resource=f"graph_rel:{rel.id}",
            actor_id=current_user.id,
            project_id=project_id,
            client_ip=client_ip,
            details={
                "source_node_id": rel.source_node_id,
                "target_node_id": rel.target_node_id,
                "relationship_type": rel.relationship_type.value,
                "status": rel.status.value,
            },
        )
        db.commit()
        return rel
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
