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
    EpistemicStatus,
)
from app.models.base import utc_now


class KnowledgeGraphService:
    """
    Universal Security Knowledge Graph Service.
    Enforces project boundaries, cycle safety, strictly bounded neighborhood traversal,
    epistemic verification states (VERIFIED vs INFERRED vs HYPOTHETICAL vs STALE),
    and semantic edge type validity constraints.
    """

    VALID_EDGE_CONSTRAINTS: Dict[RelationshipType, Tuple[Optional[Set[GraphNodeCategory]], Optional[Set[GraphNodeCategory]]]] = {
        RelationshipType.RUNS: (
            {GraphNodeCategory.HOST, GraphNodeCategory.ASSET, GraphNodeCategory.CLOUD_RESOURCE, GraphNodeCategory.SERVICE},
            {GraphNodeCategory.SERVICE, GraphNodeCategory.APPLICATION, GraphNodeCategory.WEB_APPLICATION, GraphNodeCategory.SOFTWARE_COMPONENT, GraphNodeCategory.PACKAGE},
        ),
        RelationshipType.RESOLVES_TO: (
            {GraphNodeCategory.DOMAIN, GraphNodeCategory.HOST, GraphNodeCategory.ASSET},
            {GraphNodeCategory.IP_ADDRESS, GraphNodeCategory.HOST, GraphNodeCategory.CLOUD_RESOURCE},
        ),
        RelationshipType.EXPOSES: (
            {GraphNodeCategory.HOST, GraphNodeCategory.ASSET, GraphNodeCategory.SERVICE, GraphNodeCategory.WEB_APPLICATION, GraphNodeCategory.CLOUD_RESOURCE},
            {GraphNodeCategory.API_ENDPOINT, GraphNodeCategory.SERVICE, GraphNodeCategory.VULNERABILITY, GraphNodeCategory.FINDING},
        ),
        RelationshipType.DEPENDS_ON: (
            {GraphNodeCategory.APPLICATION, GraphNodeCategory.WEB_APPLICATION, GraphNodeCategory.SERVICE, GraphNodeCategory.SOFTWARE_COMPONENT, GraphNodeCategory.PACKAGE, GraphNodeCategory.BUSINESS_SERVICE, GraphNodeCategory.ASSET},
            {GraphNodeCategory.APPLICATION, GraphNodeCategory.WEB_APPLICATION, GraphNodeCategory.SERVICE, GraphNodeCategory.SOFTWARE_COMPONENT, GraphNodeCategory.PACKAGE, GraphNodeCategory.DEPENDENCY, GraphNodeCategory.DATA_STORE, GraphNodeCategory.CLOUD_RESOURCE, GraphNodeCategory.ASSET, GraphNodeCategory.HOST},
        ),
        RelationshipType.AUTHENTICATES_TO: (
            {GraphNodeCategory.IDENTITY, GraphNodeCategory.ROLE, GraphNodeCategory.SERVICE, GraphNodeCategory.APPLICATION, GraphNodeCategory.WEB_APPLICATION, GraphNodeCategory.ASSET, GraphNodeCategory.HOST},
            {GraphNodeCategory.SERVICE, GraphNodeCategory.APPLICATION, GraphNodeCategory.WEB_APPLICATION, GraphNodeCategory.DATA_STORE, GraphNodeCategory.HOST, GraphNodeCategory.CLOUD_RESOURCE, GraphNodeCategory.ASSET},
        ),
        RelationshipType.CAN_ACCESS: (
            {GraphNodeCategory.IDENTITY, GraphNodeCategory.ROLE, GraphNodeCategory.PERMISSION, GraphNodeCategory.SERVICE, GraphNodeCategory.APPLICATION, GraphNodeCategory.WEB_APPLICATION, GraphNodeCategory.ASSET, GraphNodeCategory.HOST},
            {GraphNodeCategory.DATA_STORE, GraphNodeCategory.API_ENDPOINT, GraphNodeCategory.HOST, GraphNodeCategory.SERVICE, GraphNodeCategory.APPLICATION, GraphNodeCategory.WEB_APPLICATION, GraphNodeCategory.CLOUD_RESOURCE, GraphNodeCategory.ASSET},
        ),
        RelationshipType.AFFECTED_BY: (
            {GraphNodeCategory.ASSET, GraphNodeCategory.HOST, GraphNodeCategory.SERVICE, GraphNodeCategory.APPLICATION, GraphNodeCategory.WEB_APPLICATION, GraphNodeCategory.SOFTWARE_COMPONENT, GraphNodeCategory.PACKAGE, GraphNodeCategory.CLOUD_RESOURCE},
            {GraphNodeCategory.VULNERABILITY, GraphNodeCategory.FINDING},
        ),
        RelationshipType.PROTECTED_BY: (
            {GraphNodeCategory.ASSET, GraphNodeCategory.HOST, GraphNodeCategory.SERVICE, GraphNodeCategory.APPLICATION, GraphNodeCategory.WEB_APPLICATION, GraphNodeCategory.DATA_STORE, GraphNodeCategory.BUSINESS_SERVICE},
            {GraphNodeCategory.SECURITY_CONTROL},
        ),
        RelationshipType.MITIGATES: (
            {GraphNodeCategory.SECURITY_CONTROL, GraphNodeCategory.REMEDIATION},
            {GraphNodeCategory.VULNERABILITY, GraphNodeCategory.FINDING, GraphNodeCategory.ASSET, GraphNodeCategory.SERVICE},
        ),
        RelationshipType.OBSERVED_ON: (
            {GraphNodeCategory.FINDING, GraphNodeCategory.VULNERABILITY, GraphNodeCategory.EVIDENCE, GraphNodeCategory.ASSESSMENT},
            {GraphNodeCategory.ASSET, GraphNodeCategory.HOST, GraphNodeCategory.SERVICE, GraphNodeCategory.API_ENDPOINT, GraphNodeCategory.WEB_APPLICATION, GraphNodeCategory.IP_ADDRESS, GraphNodeCategory.ASSESSMENT},
        ),
        RelationshipType.OBSERVED_AT: (
            {GraphNodeCategory.FINDING, GraphNodeCategory.VULNERABILITY, GraphNodeCategory.EVIDENCE, GraphNodeCategory.ASSESSMENT},
            {GraphNodeCategory.ASSET, GraphNodeCategory.HOST, GraphNodeCategory.SERVICE, GraphNodeCategory.API_ENDPOINT, GraphNodeCategory.WEB_APPLICATION, GraphNodeCategory.IP_ADDRESS, GraphNodeCategory.ASSESSMENT},
        ),
        RelationshipType.DERIVED_FROM: (
            {GraphNodeCategory.FINDING, GraphNodeCategory.VULNERABILITY, GraphNodeCategory.EVIDENCE},
            {GraphNodeCategory.ASSESSMENT, GraphNodeCategory.EVIDENCE, GraphNodeCategory.FINDING},
        ),
        RelationshipType.REMEDIATED_BY: (
            {GraphNodeCategory.VULNERABILITY, GraphNodeCategory.FINDING},
            {GraphNodeCategory.REMEDIATION, GraphNodeCategory.SECURITY_CONTROL},
        ),
        RelationshipType.CONTAINS: (
            None,
            None,
        ),
        RelationshipType.BELONGS_TO: (
            None,
            None,
        ),
        RelationshipType.ASSOCIATED_WITH: (
            None,
            None,
        ),
        RelationshipType.VERIFIED_BY: (
            {GraphNodeCategory.FINDING, GraphNodeCategory.VULNERABILITY, GraphNodeCategory.REMEDIATION},
            {GraphNodeCategory.ASSESSMENT, GraphNodeCategory.EVIDENCE, GraphNodeCategory.IDENTITY},
        ),
    }

    AI_PROSE_PROVENANCES: Set[str] = {
        "AI_ANALYST",
        "LLM_PROSE",
        "AI_ASSISTANT",
        "LLM_INFERENCE",
        "GENERATED_SUMMARY",
        "AI_AGENT",
    }

    @classmethod
    def get_or_create_node(
        cls,
        project_id: str,
        category: GraphNodeCategory,
        label: str,
        entity_id: Optional[str] = None,
        entity_type: Optional[str] = None,
        properties: Optional[Dict[str, Any]] = None,
        epistemic_status: str = "OBSERVED_FACT",
        provenance: str = "AUTOMATED_INGESTION",
        evidence_reference: Optional[str] = None,
        is_authoritative: bool = True,
        is_simulated: bool = False,
        derivation_rule: Optional[str] = None,
        input_sources: Optional[List[Dict[str, Any]]] = None,
        db: Optional[Session] = None,
    ) -> GraphNode:
        """
        Retrieves or creates a graph node within a project context.
        Enforces unique constraint on (project_id, category, entity_id).
        Guarantees epistemic semantics and provenance tracking (Prompt 21).
        """
        assert db is not None, "Database session required"
        clean_label = (label or "Unknown").strip()[:255]
        props = properties or {}
        now = utc_now()

        # Epistemic & Authority Guardrail: AI-generated prose must never be stored as authoritative fact
        effective_authoritative = is_authoritative
        effective_epistemic = epistemic_status
        if provenance.upper() in cls.AI_PROSE_PROVENANCES:
            effective_authoritative = False
            effective_epistemic = EpistemicStatus.HYPOTHESIS.value

        existing_query = db.query(GraphNode).filter(
            GraphNode.project_id == project_id,
            GraphNode.category == category,
        )
        if entity_id:
            existing_query = existing_query.filter(GraphNode.entity_id == entity_id)
        else:
            existing_query = existing_query.filter(
                GraphNode.label == clean_label, GraphNode.entity_id.is_(None)
            )

        existing = existing_query.first()
        if existing:
            # Update label or merge properties
            existing.label = clean_label
            # Only update epistemic status if not downgraded by non-authoritative source
            if effective_authoritative or existing.epistemic_status == EpistemicStatus.UNKNOWN.value:
                existing.epistemic_status = effective_epistemic
            existing.provenance = provenance
            existing.is_authoritative = effective_authoritative
            existing.is_simulated = is_simulated or existing.is_simulated
            if evidence_reference:
                existing.evidence_reference = evidence_reference
            if derivation_rule:
                existing.derivation_rule = derivation_rule
            if input_sources:
                curr_sources = list(existing.input_sources or [])
                existing.input_sources = curr_sources + input_sources
            if props:
                merged = dict(existing.properties or {})
                merged.update(props)
                existing.properties = merged
            db.flush()
            return existing

        initial_sources = input_sources or []
        if not initial_sources and provenance:
            initial_sources = [{"provenance": provenance, "timestamp": now.isoformat(), "evidence_ref": evidence_reference}]

        # Create new GraphNode
        new_node = GraphNode(
            project_id=project_id,
            category=category,
            label=clean_label,
            entity_id=entity_id,
            entity_type=entity_type,
            properties=props,
            epistemic_status=effective_epistemic,
            is_authoritative=effective_authoritative,
            is_simulated=is_simulated,
            provenance=provenance,
            evidence_reference=evidence_reference,
            derivation_rule=derivation_rule,
            input_sources=initial_sources,
        )

        try:
            with db.begin_nested():
                db.add(new_node)
                db.flush()
        except Exception:
            existing = existing_query.first()
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
        epistemic_status: Optional[str] = None,
        is_authoritative: bool = True,
        is_simulated: bool = False,
        derivation_rule: Optional[str] = None,
        input_sources: Optional[List[Dict[str, Any]]] = None,
        freshness_expires_at: Optional[datetime] = None,
        db: Optional[Session] = None,
    ) -> GraphRelationship:
        """
        Creates or updates a typed directed edge between two graph nodes.
        Enforces strict project isolation, category constraints, corroboration logic,
        and AI-generated prose ungrounded prevention (Prompt 21).
        """
        assert db is not None, "Database session required"

        if source_node_id == target_node_id:
            raise ValueError(
                f"Self-referential relationships (source_node_id == target_node_id == '{source_node_id}') "
                f"are prohibited."
            )

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

        # Validate semantic category constraints
        allowed_sources, allowed_targets = cls.VALID_EDGE_CONSTRAINTS.get(relationship_type, (None, None))
        if allowed_sources is not None and source_node.category not in allowed_sources:
            raise ValueError(
                f"Invalid edge source category: relationship type '{relationship_type.value}' does not allow "
                f"source node '{source_node.label}' with category '{source_node.category.value}'."
            )
        if allowed_targets is not None and target_node.category not in allowed_targets:
            raise ValueError(
                f"Invalid edge target category: relationship type '{relationship_type.value}' does not allow "
                f"target node '{target_node.label}' with category '{target_node.category.value}'."
            )

        # Determine effective status and authority
        effective_status = status
        effective_authoritative = is_authoritative
        effective_confidence = max(0.0, min(1.0, confidence))

        # Determine epistemic status default
        if epistemic_status is not None:
            eff_epistemic = epistemic_status
        elif status == RelationshipStatus.VERIFIED:
            eff_epistemic = EpistemicStatus.OBSERVED_FACT.value
        elif status == RelationshipStatus.INFERRED:
            eff_epistemic = EpistemicStatus.DERIVED_CONCLUSION.value
        elif status == RelationshipStatus.HYPOTHETICAL:
            eff_epistemic = EpistemicStatus.HYPOTHESIS.value
        elif status == RelationshipStatus.STALE:
            eff_epistemic = EpistemicStatus.STALE.value
        else:
            eff_epistemic = EpistemicStatus.OBSERVED_FACT.value

        # AI-prose guardrail: AI summaries must never be treated as authoritative evidence
        if provenance.upper() in cls.AI_PROSE_PROVENANCES:
            effective_authoritative = False
            eff_epistemic = EpistemicStatus.HYPOTHESIS.value
            effective_status = RelationshipStatus.HYPOTHETICAL
            effective_confidence = min(0.6, effective_confidence)

        # Grounding check: prevent ungrounded claims of VERIFIED status without evidence or verified observation
        if status == RelationshipStatus.VERIFIED and not evidence_reference and provenance in ("MANUAL_ANALYST", "INFERRED_ENGINE"):
            effective_status = RelationshipStatus.INFERRED
            eff_epistemic = EpistemicStatus.HYPOTHESIS.value

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

        incoming_source_entry = {
            "provenance": provenance,
            "evidence_reference": evidence_reference,
            "confidence": effective_confidence,
            "timestamp": now.isoformat(),
            "derivation_rule": derivation_rule,
        }

        if existing_rel:
            existing_sources = list(existing_rel.input_sources or [])
            
            # Check for Corroboration: >= 2 independent compatible sources
            unique_provenances = {s.get("provenance") for s in existing_sources if s.get("provenance")}
            unique_provenances.add(provenance)
            if len(unique_provenances) >= 2 and effective_confidence >= 0.7:
                eff_epistemic = EpistemicStatus.CORROBORATED_FACT.value

            # Check for Contradiction: conflicting properties without legitimate lifecycle update
            if properties and existing_rel.properties:
                for k, v in properties.items():
                    if k in existing_rel.properties and existing_rel.properties[k] != v:
                        # Conflicting value detected
                        existing_rel.contradiction_notes = (
                            f"Contradiction detected on property '{k}': existing='{existing_rel.properties[k]}' "
                            f"vs incoming='{v}' from '{provenance}'."
                        )
                        eff_epistemic = EpistemicStatus.CONTRADICTED.value

            hist_entry = {
                "from_status": existing_rel.status.value,
                "to_status": effective_status.value,
                "from_epistemic": existing_rel.epistemic_status,
                "to_epistemic": eff_epistemic,
                "confidence": effective_confidence,
                "provenance": provenance,
                "evidence_reference": evidence_reference,
                "timestamp": now.isoformat(),
            }
            existing_rel.verification_history = list(existing_rel.verification_history or []) + [hist_entry]
            existing_rel.status = effective_status
            existing_rel.epistemic_status = eff_epistemic
            existing_rel.confidence = effective_confidence
            existing_rel.is_authoritative = effective_authoritative
            existing_rel.is_simulated = is_simulated or existing_rel.is_simulated
            existing_rel.provenance = provenance
            existing_rel.evidence_reference = evidence_reference
            existing_rel.derivation_rule = derivation_rule or existing_rel.derivation_rule
            existing_rel.input_sources = existing_sources + [incoming_source_entry]
            if freshness_expires_at:
                existing_rel.freshness_expires_at = freshness_expires_at
            existing_rel.observed_at = now
            if properties:
                merged = dict(existing_rel.properties or {})
                merged.update(properties)
                existing_rel.properties = merged
            db.flush()
            return existing_rel

        initial_history = [{
            "from_status": None,
            "to_status": effective_status.value,
            "from_epistemic": None,
            "to_epistemic": eff_epistemic,
            "confidence": effective_confidence,
            "provenance": provenance,
            "evidence_reference": evidence_reference,
            "timestamp": now.isoformat(),
        }]

        new_rel = GraphRelationship(
            project_id=project_id,
            source_node_id=source_node_id,
            target_node_id=target_node_id,
            relationship_type=relationship_type,
            status=effective_status,
            confidence=effective_confidence,
            provenance=provenance,
            evidence_reference=evidence_reference,
            properties=properties or {},
            verification_history=initial_history,
            observed_at=now,
            epistemic_status=eff_epistemic,
            is_authoritative=effective_authoritative,
            is_simulated=is_simulated,
            derivation_rule=derivation_rule,
            input_sources=input_sources or [incoming_source_entry],
            freshness_expires_at=freshness_expires_at,
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
    def invalidate_relationship(
        cls,
        db: Session,
        relationship_id: str,
        reason: str,
    ) -> Optional[GraphRelationship]:
        """
        Marks a relationship as INVALIDATED, preserving its audit trail (Prompt 21).
        """
        rel = db.query(GraphRelationship).filter(GraphRelationship.id == relationship_id).first()
        if not rel:
            return None
        now = utc_now()
        rel.status = RelationshipStatus.INVALIDATED
        rel.epistemic_status = EpistemicStatus.INVALIDATED.value
        rel.is_authoritative = False
        rel.invalidated_at = now
        rel.invalidation_reason = reason
        db.flush()
        return rel

    @classmethod
    def invalidate_node(
        cls,
        db: Session,
        node_id: str,
        reason: str,
    ) -> Optional[GraphNode]:
        """
        Marks a graph node as INVALIDATED.
        """
        node = db.query(GraphNode).filter(GraphNode.id == node_id).first()
        if not node:
            return None
        now = utc_now()
        node.epistemic_status = EpistemicStatus.INVALIDATED.value
        node.is_authoritative = False
        node.invalidated_at = now
        node.invalidation_reason = reason
        db.flush()
        return node

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
            "max_depth": bounded_depth,
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
            "relationships": [
                {
                    "id": e.id,
                    "project_id": e.project_id,
                    "source_node_id": e.source_node_id,
                    "target_node_id": e.target_node_id,
                    "relationship_type": e.relationship_type.value,
                    "status": e.status.value,
                    "confidence": e.confidence,
                    "provenance": e.provenance,
                    "evidence_reference": e.evidence_reference,
                    "properties": e.properties,
                    "observed_at": e.observed_at.isoformat() if e.observed_at else None,
                    "created_at": e.created_at.isoformat() if e.created_at else None,
                }
                for e in collected_edges
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

    @classmethod
    def list_nodes(
        cls,
        project_id: str,
        category: Optional[GraphNodeCategory] = None,
        epistemic_status: Optional[str] = None,
        limit: int = 100,
        db: Optional[Session] = None,
    ) -> List[GraphNode]:
        """
        Lists graph nodes for a project, optionally filtered by category or epistemic status.
        """
        assert db is not None, "Database session required"
        q = db.query(GraphNode).filter(GraphNode.project_id == project_id)
        if category:
            q = q.filter(GraphNode.category == category)
        if epistemic_status:
            q = q.filter(GraphNode.epistemic_status == epistemic_status)
        return q.order_by(GraphNode.created_at.desc()).limit(min(limit, 500)).all()
