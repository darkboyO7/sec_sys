import enum
import hashlib
from typing import List, Dict, Any, Optional, Set, Tuple
from sqlalchemy.orm import Session

from app.models.graph import (
    GraphNode,
    GraphRelationship,
    RelationshipStatus,
    RelationshipType,
    GraphNodeCategory,
    EpistemicStatus,
)
from app.models.scope import ScopeExclusion
from app.models.knowledge import (
    ExplainableAttackPathRecord,
    AttackPathStatus,
    KnowledgeDependencyRecord,
)
from app.models.base import utc_now
from app.models.finding import VulnerabilityFinding
from app.models.asset import Asset


class PathVerificationStatus(str, enum.Enum):
    VERIFIED = "VERIFIED"
    MIXED_EVIDENCE = "MIXED_EVIDENCE"
    HYPOTHETICAL = "HYPOTHETICAL"
    STALE = "STALE"
    INVALIDATED = "INVALIDATED"
    CONTRADICTED = "CONTRADICTED"


class AttackPathAnalysisService:
    """
    Evidence-Aware Bounded Attack Path Analysis Service (Phase 12).
    Discovers candidate attack paths exclusively through persisted Knowledge Graph relationships.
    Categorizes paths as VERIFIED, MIXED_EVIDENCE, or HYPOTHETICAL based on edge epistemic status.
    Computes stable path fingerprints, risk impact scores, ranking rationales, and remediation chokepoints.
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
        RelationshipType.OBSERVED_ON,
        RelationshipType.RESOLVES_TO,
        RelationshipType.CONTAINS,
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
            else:
                raise ValueError(f"Finding node for '{finding_id}' not found in project '{project_id}'.")

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
        for p in discovered_paths:
            formatted = cls._format_path(p, node_map, project_id=project_id, db=db)
            formatted_paths.append(formatted)

        # Status rank weight for sorting
        status_rank_weight = {
            PathVerificationStatus.VERIFIED.value: 4,
            PathVerificationStatus.MIXED_EVIDENCE.value: 3,
            PathVerificationStatus.HYPOTHETICAL.value: 2,
            PathVerificationStatus.STALE.value: 1,
        }

        # Deterministic ranking: status weight DESC, risk impact DESC, confidence DESC, step_count ASC
        formatted_paths.sort(
            key=lambda p: (
                status_rank_weight.get(p["path_verification_status"], 0),
                p.get("risk_impact_score", 0.0),
                p.get("cumulative_confidence", 0.0),
                -p.get("step_count", 0),
            ),
            reverse=True,
        )

        top_paths = formatted_paths[:bounded_max_paths]

        # Identify defensive chokepoints across discovered paths
        edge_freq: Dict[str, int] = {}
        node_freq: Dict[str, int] = {}
        for path in top_paths:
            for edge in path["relationships"]:
                e_id = edge["id"]
                edge_freq[e_id] = edge_freq.get(e_id, 0) + 1
            for node in path["nodes"][1:-1]:
                n_id = node["id"]
                node_freq[n_id] = node_freq.get(n_id, 0) + 1

        chokepoints: List[Dict[str, Any]] = []
        total_p = max(1, len(top_paths))
        for e_id, count in sorted(edge_freq.items(), key=lambda x: x[1], reverse=True):
            if count > 1 or total_p == 1:
                chokepoints.append({
                    "element_type": "RELATIONSHIP",
                    "id": e_id,
                    "paths_intersected": count,
                    "remediation_leverage": round(count / total_p, 2),
                })
        for n_id, count in sorted(node_freq.items(), key=lambda x: x[1], reverse=True):
            if count > 1:
                chokepoints.append({
                    "element_type": "NODE",
                    "id": n_id,
                    "label": node_map.get(n_id).label if node_map.get(n_id) else n_id[:8],
                    "paths_intersected": count,
                    "remediation_leverage": round(count / total_p, 2),
                })

        return {
            "project_id": project_id,
            "total_paths_found": len(top_paths),
            "max_depth_evaluated": bounded_depth,
            "truncated": truncated or (len(discovered_paths) > bounded_max_paths),
            "paths": top_paths,
            "chokepoints": chokepoints,
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
        project_id: Optional[str] = None,
        db: Optional[Session] = None,
    ) -> Dict[str, Any]:
        node_ids, edges = raw_path

        # 1. Scope Boundary Evaluation (Prompt 21)
        is_scope_compliant = True
        scope_violations: List[Dict[str, Any]] = []

        if db and project_id:
            exclusions = db.query(ScopeExclusion).filter(ScopeExclusion.project_id == project_id).all()
            for nid in node_ids:
                node = node_map.get(nid)
                if not node:
                    continue
                label_lower = (node.label or "").lower()
                for exc in exclusions:
                    exc_val = (exc.target_value or "").lower()
                    if exc_val and (exc_val == label_lower or exc_val in label_lower):
                        is_scope_compliant = False
                        scope_violations.append({
                            "node_id": nid,
                            "node_label": node.label,
                            "exclusion_id": exc.id,
                            "exclusion_value": exc.target_value,
                            "reason": exc.reason or "Target explicitly excluded from project scope.",
                        })

        # 2. Epistemic Edge Status & Explainability
        statuses = [e.status for e in edges]
        epistemic_statuses = [getattr(e, "epistemic_status", e.status.value) for e in edges]
        has_invalidated = any(s == RelationshipStatus.INVALIDATED or es == EpistemicStatus.INVALIDATED.value for s, es in zip(statuses, epistemic_statuses))
        has_contradicted = any(s == RelationshipStatus.CONTRADICTED or es == EpistemicStatus.CONTRADICTED.value for s, es in zip(statuses, epistemic_statuses))
        has_stale_or_superseded = any(s in (RelationshipStatus.STALE, RelationshipStatus.SUPERSEDED) or es == EpistemicStatus.STALE.value for s, es in zip(statuses, epistemic_statuses))
        all_observed_facts = all(
            (s == RelationshipStatus.VERIFIED or es in (EpistemicStatus.OBSERVED_FACT.value, EpistemicStatus.CORROBORATED_FACT.value))
            and getattr(e, "is_authoritative", True)
            for s, es, e in zip(statuses, epistemic_statuses, edges)
        )
        all_high_conf = all(e.confidence >= 0.8 for e in edges)
        has_hypothetical = any(s == RelationshipStatus.HYPOTHETICAL or es == EpistemicStatus.HYPOTHESIS.value or not getattr(e, "is_authoritative", True) for s, es, e in zip(statuses, epistemic_statuses, edges))

        if not is_scope_compliant:
            path_status = PathVerificationStatus.INVALIDATED
        elif has_invalidated:
            path_status = PathVerificationStatus.INVALIDATED
        elif has_contradicted:
            path_status = PathVerificationStatus.CONTRADICTED
        elif has_stale_or_superseded:
            path_status = PathVerificationStatus.STALE
        elif has_hypothetical:
            path_status = PathVerificationStatus.HYPOTHETICAL
        elif all_observed_facts and all_high_conf:
            path_status = PathVerificationStatus.VERIFIED
        elif all(s in (RelationshipStatus.VERIFIED, RelationshipStatus.INFERRED) for s in statuses):
            path_status = PathVerificationStatus.MIXED_EVIDENCE
        else:
            path_status = PathVerificationStatus.HYPOTHETICAL

        # 3. Cumulative Confidence
        confidence_product = 1.0
        for e in edges:
            confidence_product *= max(0.1, min(1.0, e.confidence))
        cumulative_confidence = round(confidence_product, 2)

        # 4. Detailed Step-by-Step Explainability (Prompt 21)
        steps_explanation: List[Dict[str, Any]] = []
        missing_evidence: List[str] = []

        for idx, e in enumerate(edges):
            src = node_map.get(e.source_node_id)
            tgt = node_map.get(e.target_node_id)
            src_label = src.label if src else e.source_node_id[:8]
            tgt_label = tgt.label if tgt else e.target_node_id[:8]
            e_status = e.status.value
            e_epistemic = getattr(e, "epistemic_status", e_status)
            is_auth = getattr(e, "is_authoritative", True)
            is_sim = getattr(e, "is_simulated", False)

            # Assumptions required for this step
            assumptions = [
                f"Assumes reachability over '{e.relationship_type.value}' is unblocked by upstream firewall/WAF.",
                f"Assumes service on '{src_label}' remains active and listening on designated ports.",
            ]
            if not is_auth:
                assumptions.append("Non-authoritative link: requires independent scanner verification before considering proven.")

            # Unverified conditions
            unverified = []
            if e.confidence < 0.8:
                unverified.append(f"Confidence is below threshold ({e.confidence:.2f}); path reachability not confirmed.")
            if e_epistemic in (EpistemicStatus.HYPOTHESIS.value, RelationshipStatus.HYPOTHETICAL.value):
                unverified.append("Edge represents a heuristic hypothesis without empirical scanner observation.")
            if not getattr(e, "evidence_reference", None):
                unverified.append("No cryptographic evidence reference attached to this relationship.")

            # Invalidation triggers
            invalidation_triggers = [
                f"Closing port/service on '{src_label}' will break this traversal step.",
                f"Network segmentation isolating '{src_label}' from '{tgt_label}' will invalidate this step.",
            ]

            step_entry = {
                "step": idx + 1,
                "from_node": {"id": e.source_node_id, "label": src_label, "category": src.category.value if src else "UNKNOWN"},
                "to_node": {"id": e.target_node_id, "label": tgt_label, "category": tgt.category.value if tgt else "UNKNOWN"},
                "edge_id": e.id,
                "relationship_type": e.relationship_type.value,
                "status": e_status,
                "epistemic_status": e_epistemic,
                "confidence": e.confidence,
                "is_authoritative": is_auth,
                "is_simulated": is_sim,
                "supporting_evidence": e.evidence_reference or "None recorded",
                "required_assumptions": assumptions,
                "unverified_conditions": unverified,
                "invalidation_triggers": invalidation_triggers,
            }
            steps_explanation.append(step_entry)

            # Missing evidence text
            if e_status in (RelationshipStatus.STALE.value, RelationshipStatus.SUPERSEDED.value):
                missing_evidence.append(
                    f"Relationship '{src_label}' --[{e.relationship_type.value}]--> '{tgt_label}' is {e_status}. "
                    f"Evidence has expired or been superseded; fresh observation is required."
                )
            elif not is_auth:
                missing_evidence.append(
                    f"Relationship '{src_label}' --[{e.relationship_type.value}]--> '{tgt_label}' derived from non-authoritative AI/prose. "
                    f"Authoritative scanner observation required."
                )
            elif e_status != RelationshipStatus.VERIFIED.value:
                missing_evidence.append(
                    f"Relationship '{src_label}' --[{e.relationship_type.value}]--> '{tgt_label}' is {e_status}. "
                    f"Direct scanner observation or credential verification required."
                )
            elif e.confidence < 0.7:
                missing_evidence.append(
                    f"Relationship '{src_label}' --[{e.relationship_type.value}]--> '{tgt_label}' has low confidence ({e.confidence:.2f}). "
                    f"Additional corroboration required to confirm reachability."
                )

        # 5. Narrative / Rationale
        labels = [node_map[nid].label if nid in node_map else nid[:8] for nid in node_ids]
        narrative = " -> ".join(labels)

        # 6. Deterministic Stable Path ID
        raw_sig = f"{'->'.join(node_ids)}|{':'.join(e.relationship_type.value for e in edges)}"
        path_id = hashlib.sha256(raw_sig.encode('utf-8')).hexdigest()[:16]

        # 7. Risk Impact Score Calculation
        target_node = node_map.get(node_ids[-1])
        target_cat = target_node.category if target_node else None
        target_base = 50.0
        if target_cat in (GraphNodeCategory.DATA_STORE, GraphNodeCategory.BUSINESS_SERVICE):
            target_base = 90.0
        elif target_cat in (GraphNodeCategory.FINDING, GraphNodeCategory.VULNERABILITY):
            target_base = 80.0
        elif target_cat in (GraphNodeCategory.ASSET, GraphNodeCategory.HOST, GraphNodeCategory.SERVICE):
            target_base = 70.0
        risk_impact_score = round(target_base * cumulative_confidence, 1)

        ranking_rationale = (
            f"Path status '{path_status.value}' with confidence {cumulative_confidence:.2f} "
            f"terminating at '{labels[-1]}' ({target_cat.value if target_cat else 'UNKNOWN'}) across {len(edges)} hops. "
            f"{'Scope compliant.' if is_scope_compliant else 'Violates scope exclusions.'}"
        )

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
                "epistemic_status": getattr(e, "epistemic_status", e.status.value),
                "confidence": e.confidence,
                "provenance": e.provenance,
                "is_authoritative": getattr(e, "is_authoritative", True),
                "is_simulated": getattr(e, "is_simulated", False),
            }
            for e in edges
        ]

        # 8. Persist ExplainableAttackPathRecord and Knowledge Dependencies
        if db and project_id:
            from app.services.dependency_invalidation_service import DependencyInvalidationService
            now = utc_now()
            existing_rec = db.query(ExplainableAttackPathRecord).filter(
                ExplainableAttackPathRecord.id == path_id,
                ExplainableAttackPathRecord.project_id == project_id,
            ).first()

            status_map = {
                PathVerificationStatus.VERIFIED: AttackPathStatus.VERIFIED,
                PathVerificationStatus.MIXED_EVIDENCE: AttackPathStatus.PLAUSIBLE,
                PathVerificationStatus.HYPOTHETICAL: AttackPathStatus.HYPOTHETICAL,
                PathVerificationStatus.STALE: AttackPathStatus.STALE,
                PathVerificationStatus.CONTRADICTED: AttackPathStatus.CONTRADICTED,
                PathVerificationStatus.INVALIDATED: AttackPathStatus.INVALIDATED,
            }
            db_path_status = status_map.get(path_status, AttackPathStatus.PLAUSIBLE)

            if existing_rec:
                existing_rec.path_status = db_path_status
                existing_rec.cumulative_confidence = cumulative_confidence
                existing_rec.risk_impact_score = risk_impact_score
                existing_rec.step_count = len(edges)
                existing_rec.is_scope_compliant = is_scope_compliant
                existing_rec.scope_violations = scope_violations
                existing_rec.steps_explanation = steps_explanation
                existing_rec.is_invalidated = (path_status == PathVerificationStatus.INVALIDATED)
                existing_rec.is_stale = (path_status == PathVerificationStatus.STALE)
                db.flush()
            else:
                new_rec = ExplainableAttackPathRecord(
                    id=path_id,
                    project_id=project_id,
                    name=f"Attack Path: {narrative[:200]}",
                    start_node_id=node_ids[0],
                    target_node_id=node_ids[-1],
                    path_status=db_path_status,
                    cumulative_confidence=cumulative_confidence,
                    risk_impact_score=risk_impact_score,
                    step_count=len(edges),
                    is_scope_compliant=is_scope_compliant,
                    scope_violations=scope_violations,
                    steps_explanation=steps_explanation,
                    chokepoints=[],
                    calculation_version="v2.1.0",
                    input_hashes={"signature": raw_sig},
                    is_stale=(path_status == PathVerificationStatus.STALE),
                    is_invalidated=(path_status == PathVerificationStatus.INVALIDATED),
                    created_at=now,
                    updated_at=now,
                )
                try:
                    with db.begin_nested():
                        db.add(new_rec)
                        db.flush()
                except Exception:
                    pass

            # Register dependencies for each edge and node in this path
            for e in edges:
                try:
                    DependencyInvalidationService.register_knowledge_dependency(
                        db=db,
                        project_id=project_id,
                        source_entity_type="GraphRelationship",
                        source_entity_id=e.id,
                        dependent_entity_type="ExplainableAttackPath",
                        dependent_entity_id=path_id,
                        dependency_type="ATTACK_PATH_STEP",
                    )
                except Exception:
                    pass

            for nid in node_ids:
                node = node_map.get(nid)
                if node and node.entity_id and node.category == GraphNodeCategory.ASSET:
                    try:
                        DependencyInvalidationService.register_knowledge_dependency(
                            db=db,
                            project_id=project_id,
                            source_entity_type="Asset",
                            source_entity_id=node.entity_id,
                            dependent_entity_type="ExplainableAttackPath",
                            dependent_entity_id=path_id,
                            dependency_type="TOPOLOGY_LINK",
                        )
                    except Exception:
                        pass
                elif node and node.entity_id and node.category == GraphNodeCategory.FINDING:
                    try:
                        DependencyInvalidationService.register_knowledge_dependency(
                            db=db,
                            project_id=project_id,
                            source_entity_type="Finding",
                            source_entity_id=node.entity_id,
                            dependent_entity_type="ExplainableAttackPath",
                            dependent_entity_id=path_id,
                            dependency_type="EVIDENCE_SUPPORT",
                        )
                    except Exception:
                        pass

        return {
            "path_id": path_id,
            "path_verification_status": path_status.value,
            "cumulative_confidence": cumulative_confidence,
            "risk_impact_score": risk_impact_score,
            "step_count": len(edges),
            "narrative": narrative,
            "is_scope_compliant": is_scope_compliant,
            "scope_violations": scope_violations,
            "steps_explanation": steps_explanation,
            "nodes": nodes_detail,
            "relationships": edges_detail,
            "missing_evidence": missing_evidence,
            "ranking_rationale": ranking_rationale,
            "methodology_disclaimer": (
                "Attack path analysis represents relational topology and potential exposure chains. "
                "Adjacency does not prove exploitability or successful breach without independent empirical verification."
            ),
        }


# Backwards compatibility alias
AttackPathService = AttackPathAnalysisService
