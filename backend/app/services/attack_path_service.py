import enum
from typing import List, Dict, Any, Optional, Set, Tuple
from sqlalchemy.orm import Session

from app.models.graph import GraphNode, GraphRelationship, RelationshipStatus, RelationshipType, GraphNodeCategory
from app.models.finding import VulnerabilityFinding
from app.models.asset import Asset


class PathVerificationStatus(str, enum.Enum):
    VERIFIED = "VERIFIED"
    MIXED_EVIDENCE = "MIXED_EVIDENCE"
    HYPOTHETICAL = "HYPOTHETICAL"


class AttackPathAnalysisService:
    """
    Evidence-Aware Bounded Attack Path Analysis Service.
    Discovers candidate attack paths exclusively through persisted Knowledge Graph relationships.
    Categorizes paths as VERIFIED, MIXED_EVIDENCE, or HYPOTHETICAL based on edge epistemic status.
    Enforces strict depth, cycle, path count, and project boundaries.
    """

    MAX_DEPTH_BOUND = 4
    MAX_PATHS_BOUND = 10

    # Relevant forward transversable relationship types in security attack path context
    EXPOSURE_RELATIONSHIPS: Set[RelationshipType] = {
        RelationshipType.EXPOSES,
        RelationshipType.CAN_ACCESS,
        RelationshipType.RUNS,
        RelationshipType.DEPENDS_ON,
        RelationshipType.AUTHENTICATES_TO,
        RelationshipType.AFFECTED_BY,
        RelationshipType.OBSERVED_AT,
        RelationshipType.ASSOCIATED_WITH,
    }

    @classmethod
    def analyze_attack_paths(
        cls,
        project_id: str,
        db: Session,
        start_node_id: Optional[str] = None,
        target_node_id: Optional[str] = None,
        finding_id: Optional[str] = None,
        max_depth: int = 3,
        max_paths: int = 5,
    ) -> Dict[str, Any]:
        """
        Executes bounded, cycle-safe attack path search within the project's knowledge graph.
        Returns candidate paths, verification ratings, confidence scores, and missing evidence.
        """
        bounded_depth = max(1, min(cls.MAX_DEPTH_BOUND, max_depth))
        bounded_max_paths = max(1, min(cls.MAX_PATHS_BOUND, max_paths))

        # Resolve start node if finding_id is specified
        if finding_id and not start_node_id:
            finding_node = (
                db.query(GraphNode)
                .filter(
                    GraphNode.project_id == project_id,
                    GraphNode.category == GraphNodeCategory.FINDING,
                    GraphNode.entity_id == finding_id,
                )
                .first()
            )
            if finding_node:
                start_node_id = finding_node.id

        # If start_node_id is provided, verify it belongs to project
        if start_node_id:
            start_node = (
                db.query(GraphNode)
                .filter(GraphNode.id == start_node_id, GraphNode.project_id == project_id)
                .first()
            )
            if not start_node:
                raise ValueError(f"Start node '{start_node_id}' not found in project '{project_id}'.")

        # If target_node_id is provided, verify it belongs to project
        if target_node_id:
            target_node = (
                db.query(GraphNode)
                .filter(GraphNode.id == target_node_id, GraphNode.project_id == project_id)
                .first()
            )
            if not target_node:
                raise ValueError(f"Target node '{target_node_id}' not found in project '{project_id}'.")

        # Load all relationships for this project
        project_relationships = (
            db.query(GraphRelationship)
            .filter(
                GraphRelationship.project_id == project_id,
                GraphRelationship.relationship_type.in_(cls.EXPOSURE_RELATIONSHIPS),
            )
            .all()
        )

        # Build adjacency map: node_id -> list of relationships originating from or touching node
        adj: Dict[str, List[GraphRelationship]] = {}
        for r in project_relationships:
            adj.setdefault(r.source_node_id, []).append(r)

        # Collect node entities for fast lookup
        all_node_ids = set()
        for r in project_relationships:
            all_node_ids.add(r.source_node_id)
            all_node_ids.add(r.target_node_id)
        if start_node_id:
            all_node_ids.add(start_node_id)
        if target_node_id:
            all_node_ids.add(target_node_id)

        node_map: Dict[str, GraphNode] = {
            n.id: n
            for n in db.query(GraphNode)
            .filter(GraphNode.project_id == project_id, GraphNode.id.in_(all_node_ids))
            .all()
        }

        # If no start node specified, pick asset or finding nodes with highest outgoing degree or internet-facing category
        start_nodes: List[str] = []
        if start_node_id:
            start_nodes = [start_node_id]
        else:
            # Entry point candidates: ASSET, SERVICE, APPLICATION
            candidate_nodes = [
                n.id
                for n in node_map.values()
                if n.category in (GraphNodeCategory.ASSET, GraphNodeCategory.SERVICE, GraphNodeCategory.APPLICATION)
            ]
            start_nodes = candidate_nodes[:5]

        discovered_paths: List[Dict[str, Any]] = []
        truncated = False

        # DFS search for paths up to bounded_depth
        for s_id in start_nodes:
            if len(discovered_paths) >= bounded_max_paths:
                truncated = True
                break

            cls._dfs_paths(
                current_node_id=s_id,
                target_node_id=target_node_id,
                current_path_nodes=[s_id],
                current_path_edges=[],
                adj=adj,
                node_map=node_map,
                max_depth=bounded_depth,
                max_paths=bounded_max_paths,
                collected_paths=discovered_paths,
            )

        # Format and categorize candidate paths
        formatted_paths: List[Dict[str, Any]] = []
        for p in discovered_paths[:bounded_max_paths]:
            formatted = cls._format_path(p, node_map)
            formatted_paths.append(formatted)

        return {
            "project_id": project_id,
            "total_paths_found": len(formatted_paths),
            "max_depth_evaluated": bounded_depth,
            "truncated": truncated or (len(discovered_paths) > bounded_max_paths),
            "paths": formatted_paths,
            "methodology_disclaimer": (
                "Attack path analysis represents relational topology and potential exposure chains. "
                "Adjacency does not prove exploitability or successful breach without independent empirical verification."
            ),
        }

    @classmethod
    def _dfs_paths(
        cls,
        current_node_id: str,
        target_node_id: Optional[str],
        current_path_nodes: List[str],
        current_path_edges: List[GraphRelationship],
        adj: Dict[str, List[GraphRelationship]],
        node_map: Dict[str, GraphNode],
        max_depth: int,
        max_paths: int,
        collected_paths: List[Tuple[List[str], List[GraphRelationship]]],
    ) -> None:
        if len(collected_paths) >= max_paths:
            return

        # Check if current path reaches target or has meaningful length (>= 2 nodes)
        if target_node_id:
            if current_node_id == target_node_id and len(current_path_nodes) > 1:
                collected_paths.append((list(current_path_nodes), list(current_path_edges)))
                return
        else:
            # When no target is specified, paths ending in high-value nodes (FINDING, DATA_STORE, IDENTITY, VULNERABILITY)
            current_node = node_map.get(current_node_id)
            if len(current_path_nodes) >= 2 and current_node:
                if current_node.category in (
                    GraphNodeCategory.FINDING,
                    GraphNodeCategory.VULNERABILITY,
                    GraphNodeCategory.ASSET,
                    GraphNodeCategory.IDENTITY,
                ):
                    collected_paths.append((list(current_path_nodes), list(current_path_edges)))
                    if len(collected_paths) >= max_paths:
                        return

        if len(current_path_nodes) - 1 >= max_depth:
            return

        # Outgoing edges from current_node_id
        edges = adj.get(current_node_id, [])
        for edge in edges:
            next_node_id = edge.target_node_id
            # Cycle avoidance: do not revisit nodes already in current path
            if next_node_id in current_path_nodes:
                continue

            current_path_nodes.append(next_node_id)
            current_path_edges.append(edge)

            cls._dfs_paths(
                current_node_id=next_node_id,
                target_node_id=target_node_id,
                current_path_nodes=current_path_nodes,
                current_path_edges=current_path_edges,
                adj=adj,
                node_map=node_map,
                max_depth=max_depth,
                max_paths=max_paths,
                collected_paths=collected_paths,
            )

            current_path_edges.pop()
            current_path_nodes.pop()

    @classmethod
    def _format_path(
        cls,
        raw_path: Tuple[List[str], List[GraphRelationship]],
        node_map: Dict[str, GraphNode],
    ) -> Dict[str, Any]:
        node_ids, edges = raw_path

        # 1. Classify Path Verification Status
        statuses = [e.status for e in edges]
        if all(s == RelationshipStatus.VERIFIED for s in statuses):
            path_status = PathVerificationStatus.VERIFIED
        elif all(s in (RelationshipStatus.VERIFIED, RelationshipStatus.INFERRED) for s in statuses):
            path_status = PathVerificationStatus.MIXED_EVIDENCE
        else:
            path_status = PathVerificationStatus.HYPOTHETICAL

        # 2. Cumulative Confidence
        confidence_product = 1.0
        for e in edges:
            confidence_product *= max(0.1, min(1.0, e.confidence))
        cumulative_confidence = round(confidence_product, 2)

        # 3. Missing Evidence Extraction
        missing_evidence: List[str] = []
        for e in edges:
            if e.status != RelationshipStatus.VERIFIED:
                src = node_map.get(e.source_node_id)
                tgt = node_map.get(e.target_node_id)
                src_label = src.label if src else e.source_node_id[:8]
                tgt_label = tgt.label if tgt else e.target_node_id[:8]
                missing_evidence.append(
                    f"Relationship '{src_label}' --[{e.relationship_type.value}]--> '{tgt_label}' is {e.status.value}. "
                    f"Direct scanner observation or credential verification required."
                )

        # 4. Narrative / Rationale
        labels = [node_map[nid].label if nid in node_map else nid[:8] for nid in node_ids]
        narrative = " -> ".join(labels)

        # Formatted Node List
        nodes_detail = [
            {
                "id": n_id,
                "label": node_map[n_id].label if n_id in node_map else "Unknown",
                "category": node_map[n_id].category.value if n_id in node_map else "UNKNOWN",
                "entity_type": node_map[n_id].entity_type if n_id in node_map else None,
                "properties": node_map[n_id].properties if n_id in node_map else {},
            }
            for n_id in node_ids
        ]

        # Formatted Edge List
        edges_detail = [
            {
                "id": e.id,
                "source_node_id": e.source_node_id,
                "target_node_id": e.target_node_id,
                "relationship_type": e.relationship_type.value,
                "status": e.status.value,
                "confidence": e.confidence,
                "provenance": e.provenance,
            }
            for e in edges
        ]

        return {
            "path_verification_status": path_status.value,
            "cumulative_confidence": cumulative_confidence,
            "step_count": len(edges),
            "narrative": narrative,
            "nodes": nodes_detail,
            "relationships": edges_detail,
            "missing_evidence": missing_evidence,
        }
