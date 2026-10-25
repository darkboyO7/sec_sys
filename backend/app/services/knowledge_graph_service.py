from collections import deque
from datetime import datetime
from typing import Optional, Dict, Any, List, Set, Tuple
from sqlalchemy.orm import Session
from sqlalchemy import or_

from app.models.graph import (
    GraphNode,
    GraphRelationship,
    GraphNodeCategory,
    RelationshipType,
    RelationshipStatus,
)
from app.models.base import utc_now


class KnowledgeGraphService:
    """
    Universal Security Knowledge Graph Service.
    Enforces project boundaries, cycle safety, strictly bounded neighborhood traversal,
    and provenance/confidence differentiation (VERIFIED vs INFERRED vs HYPOTHETICAL vs STALE).
    """

    @classmethod
    def get_or_create_node(
        cls,
        project_id: str,
        category: GraphNodeCategory,
        label: str,
        entity_id: Optional[str] = None,
        entity_type: Optional[str] = None,
        properties: Optional[Dict[str, Any]] = None,
        db: Optional[Session] = None,
    ) -> GraphNode:
        """
        Retrieves or creates a graph node within a project context.
        Enforces unique constraint on (project_id, category, entity_id).
        """
        assert db is not None, "Database session required"
        clean_label = (label or "Unknown").strip()[:255]
        props = properties or {}

        if entity_id:
            existing = (
                db.query(GraphNode)
                .filter(
                    GraphNode.project_id == project_id,
                    GraphNode.category == category,
                    GraphNode.entity_id == entity_id,
                )
                .first()
            )
            if existing:
                # Update label or merge properties
                existing.label = clean_label
                if props:
                    merged = dict(existing.properties or {})
                    merged.update(props)
                    existing.properties = merged
                db.flush()
                return existing

        # Create new GraphNode
        new_node = GraphNode(
            project_id=project_id,
            category=category,
            label=clean_label,
            entity_id=entity_id,
            entity_type=entity_type,
            properties=props,
        )

        try:
            with db.begin_nested():
                db.add(new_node)
                db.flush()
        except Exception:
            if entity_id:
                existing = (
                    db.query(GraphNode)
                    .filter(
                        GraphNode.project_id == project_id,
                        GraphNode.category == category,
                        GraphNode.entity_id == entity_id,
                    )
                    .first()
                )
                if existing:
                    return existing
            raise

        return new_node

    @classmethod
    def create_or_update_relationship(
        cls,
        project_id: str,
        source_node_id: str,
        target_node_id: str,
        relationship_type: RelationshipType,
        status: RelationshipStatus = RelationshipStatus.VERIFIED,
        confidence: float = 1.0,
        provenance: str = "AUTOMATED_INGESTION",
        evidence_reference: Optional[str] = None,
        properties: Optional[Dict[str, Any]] = None,
        db: Optional[Session] = None,
    ) -> GraphRelationship:
        """
        Creates or updates a typed directed edge between two graph nodes.
        Enforces strict project isolation: both source and target must belong to project_id.
        Fails closed on cross-project edge creation attempts.
        """
        assert db is not None, "Database session required"

        # Validate existence and project ownership of both endpoints
        source_node = (
            db.query(GraphNode)
            .filter(GraphNode.id == source_node_id, GraphNode.project_id == project_id)
            .first()
        )
        target_node = (
            db.query(GraphNode)
            .filter(GraphNode.id == target_node_id, GraphNode.project_id == project_id)
            .first()
        )

        if not source_node or not target_node:
            raise ValueError(
                f"Invalid relationship endpoints: source '{source_node_id}' or target '{target_node_id}' "
                f"does not exist in project '{project_id}'."
            )

        now = utc_now()
        existing_rel = (
            db.query(GraphRelationship)
            .filter(
                GraphRelationship.project_id == project_id,
                GraphRelationship.source_node_id == source_node_id,
                GraphRelationship.target_node_id == target_node_id,
                GraphRelationship.relationship_type == relationship_type,
            )
            .first()
        )

        if existing_rel:
            existing_rel.status = status
            existing_rel.confidence = max(0.0, min(1.0, confidence))
            existing_rel.provenance = provenance
            existing_rel.evidence_reference = evidence_reference
            existing_rel.observed_at = now
            if properties:
                merged = dict(existing_rel.properties or {})
                merged.update(properties)
                existing_rel.properties = merged
            db.flush()
            return existing_rel

        new_rel = GraphRelationship(
            project_id=project_id,
            source_node_id=source_node_id,
            target_node_id=target_node_id,
            relationship_type=relationship_type,
            status=status,
            confidence=max(0.0, min(1.0, confidence)),
            provenance=provenance,
            evidence_reference=evidence_reference,
            properties=properties or {},
            observed_at=now,
        )

        try:
            with db.begin_nested():
                db.add(new_rel)
                db.flush()
        except Exception:
            existing_rel = (
                db.query(GraphRelationship)
                .filter(
                    GraphRelationship.project_id == project_id,
                    GraphRelationship.source_node_id == source_node_id,
                    GraphRelationship.target_node_id == target_node_id,
                    GraphRelationship.relationship_type == relationship_type,
                )
                .first()
            )
            if existing_rel:
                return existing_rel
            raise

        return new_rel

    @classmethod
    def get_bounded_neighborhood(
        cls,
        project_id: str,
        root_node_id: str,
        max_depth: int = 2,
        max_nodes: int = 50,
        max_edges: int = 100,
        db: Optional[Session] = None,
    ) -> Dict[str, Any]:
        """
        Performs a strictly bounded, cycle-safe Breadth-First Search (BFS) starting
        from root_node_id. Enforces depth, node count, and edge count limits.
        """
        assert db is not None, "Database session required"
        bounded_depth = max(1, min(max_depth, 4))
        node_limit = max(1, min(max_nodes, 200))
        edge_limit = max(1, min(max_edges, 300))

        root_node = (
            db.query(GraphNode)
            .filter(GraphNode.id == root_node_id, GraphNode.project_id == project_id)
            .first()
        )
        if not root_node:
            raise ValueError(f"Root node '{root_node_id}' not found in project '{project_id}'")

        visited_nodes: Dict[str, GraphNode] = {root_node.id: root_node}
        collected_edges: List[GraphRelationship] = []
        edge_ids: Set[str] = set()

        # Queue contains: (node_id, current_depth)
        queue: deque[Tuple[str, int]] = deque([(root_node.id, 0)])
        truncated = False

        while queue and len(visited_nodes) < node_limit and len(collected_edges) < edge_limit:
            current_id, current_depth = queue.popleft()

            if current_depth >= bounded_depth:
                continue

            # Query adjacent edges (both outgoing and incoming)
            adjacent_edges = (
                db.query(GraphRelationship)
                .filter(
                    GraphRelationship.project_id == project_id,
                    or_(
                        GraphRelationship.source_node_id == current_id,
                        GraphRelationship.target_node_id == current_id,
                    ),
                )
                .limit(edge_limit - len(collected_edges))
                .all()
            )

            neighbor_ids_to_fetch: List[str] = []
            for edge in adjacent_edges:
                if edge.id not in edge_ids:
                    edge_ids.add(edge.id)
                    collected_edges.append(edge)
                    if len(collected_edges) >= edge_limit:
                        truncated = True
                        break

                neighbor_id = (
                    edge.target_node_id
                    if edge.source_node_id == current_id
                    else edge.source_node_id
                )
                if neighbor_id not in visited_nodes:
                    neighbor_ids_to_fetch.append(neighbor_id)

            if neighbor_ids_to_fetch:
                # Fetch neighbor nodes in batch
                needed_nodes = (
                    db.query(GraphNode)
                    .filter(
                        GraphNode.project_id == project_id,
                        GraphNode.id.in_(neighbor_ids_to_fetch),
                    )
                    .all()
                )
                for node in needed_nodes:
                    if node.id not in visited_nodes:
                        if len(visited_nodes) >= node_limit:
                            truncated = True
                            break
                        visited_nodes[node.id] = node
                        queue.append((node.id, current_depth + 1))

        return {
            "root_node_id": root_node.id,
            "nodes": [
                {
                    "id": n.id,
                    "category": n.category.value,
                    "label": n.label,
                    "entity_id": n.entity_id,
                    "entity_type": n.entity_type,
                    "properties": n.properties,
                }
                for n in visited_nodes.values()
            ],
            "edges": [
                {
                    "id": e.id,
                    "source": e.source_node_id,
                    "target": e.target_node_id,
                    "type": e.relationship_type.value,
                    "status": e.status.value,
                    "confidence": e.confidence,
                    "provenance": e.provenance,
                    "observed_at": e.observed_at.isoformat() if e.observed_at else None,
                    "properties": e.properties,
                }
                for e in collected_edges
            ],
            "total_nodes": len(visited_nodes),
            "total_edges": len(collected_edges),
            "truncated": truncated,
        }

    @classmethod
    def get_node_relationships(
        cls, project_id: str, node_id: str, db: Optional[Session] = None
    ) -> Dict[str, Any]:
        """
        Retrieves all incoming and outgoing relationships for a specific graph node.
        """
        assert db is not None, "Database session required"

        node = (
            db.query(GraphNode)
            .filter(GraphNode.id == node_id, GraphNode.project_id == project_id)
            .first()
        )
        if not node:
            raise ValueError(f"Node '{node_id}' not found in project '{project_id}'")

        outgoing = (
            db.query(GraphRelationship)
            .filter(
                GraphRelationship.project_id == project_id,
                GraphRelationship.source_node_id == node_id,
            )
            .all()
        )
        incoming = (
            db.query(GraphRelationship)
            .filter(
                GraphRelationship.project_id == project_id,
                GraphRelationship.target_node_id == node_id,
            )
            .all()
        )

        return {
            "node_id": node.id,
            "outgoing": [
                {
                    "id": r.id,
                    "target_node_id": r.target_node_id,
                    "type": r.relationship_type.value,
                    "status": r.status.value,
                    "confidence": r.confidence,
                    "provenance": r.provenance,
                }
                for r in outgoing
            ],
            "incoming": [
                {
                    "id": r.id,
                    "source_node_id": r.source_node_id,
                    "type": r.relationship_type.value,
                    "status": r.status.value,
                    "confidence": r.confidence,
                    "provenance": r.provenance,
                }
                for r in incoming
            ],
        }
