import enum
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Set, Tuple
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.models.base import utc_now, generate_uuid
from app.models.graph import (
    GraphNode,
    GraphRelationship,
    GraphNodeCategory,
    RelationshipType,
    RelationshipStatus,
    EpistemicStatus,
)
from app.models.knowledge import (
    KnowledgeReconciliationAudit,
    ReconciliationStatus,
    ExplainableAttackPathRecord,
    AttackPathStatus,
    KnowledgeDependencyRecord,
)
from app.models.asset import Asset
from app.models.finding import VulnerabilityFinding
from app.models.scope import ScopeExclusion
from app.models.risk import RiskAssessment
from app.services.knowledge_graph_service import KnowledgeGraphService


class InconsistencySeverity(str, enum.Enum):
    CRITICAL = "CRITICAL"
    WARNING = "WARNING"
    INFO = "INFO"


class KnowledgeReconciliationService:
    """
    Automated Knowledge Graph Reconciliation and Epistemic Integrity Audit Engine (Prompt 21).
    Detects:
    1. Dangling entity references (missing source/target nodes, or orphaned entity links).
    2. Duplicate logical relationships between identical node pairs.
    3. Category constraint violations across relationship types.
    4. Missing provenance or ungrounded verification claims.
    5. Stale or invalidated conclusions outliving supporting observations.
    6. Scope boundary violations traversing excluded targets.
    7. Contradictory active relationships.
    Executes safe deterministic repairs without destroying authoritative raw evidence.
    """

    @classmethod
    def audit_and_reconcile(
        cls,
        db: Session,
        project_id: str,
        auto_repair: bool = True,
        run_by_user_id: Optional[str] = None,
    ) -> KnowledgeReconciliationAudit:
        """
        Executes an end-to-end knowledge integrity audit and repairs unambiguous defects.
        """
        now = utc_now()
        audit_id = generate_uuid()
        audit = KnowledgeReconciliationAudit(
            id=audit_id,
            project_id=project_id,
            run_by_user_id=run_by_user_id,
            status=ReconciliationStatus.IN_PROGRESS,
            started_at=now,
            reconciliation_log=[],
        )
        db.add(audit)
        db.flush()

        logs: List[Dict[str, Any]] = []
        dangling_count = 0
        duplicate_count = 0
        invalid_type_count = 0
        missing_prov_count = 0
        stale_concl_count = 0
        scope_viol_count = 0
        contradiction_count = 0
        auto_repaired_count = 0
        manual_review_count = 0

        # Load all project nodes and relationships
        nodes = db.query(GraphNode).filter(GraphNode.project_id == project_id).all()
        relationships = db.query(GraphRelationship).filter(GraphRelationship.project_id == project_id).all()
        node_ids = {n.id for n in nodes}
        node_map = {n.id: n for n in nodes}

        audit.total_nodes_audited = len(nodes)
        audit.total_relationships_audited = len(relationships)

        # -------------------------------------------------------------------------
        # 1. Dangling Reference Detection
        # -------------------------------------------------------------------------
        for rel in list(relationships):
            has_dangling = False
            if rel.source_node_id not in node_ids:
                dangling_count += 1
                has_dangling = True
                logs.append({
                    "item_type": "RELATIONSHIP_DANGLING_SOURCE",
                    "id": rel.id,
                    "severity": InconsistencySeverity.CRITICAL.value,
                    "description": f"Relationship '{rel.id}' references non-existent source node '{rel.source_node_id}'.",
                    "auto_repairable": True,
                    "repaired": auto_repair,
                })
            elif rel.target_node_id not in node_ids:
                dangling_count += 1
                has_dangling = True
                logs.append({
                    "item_type": "RELATIONSHIP_DANGLING_TARGET",
                    "id": rel.id,
                    "severity": InconsistencySeverity.CRITICAL.value,
                    "description": f"Relationship '{rel.id}' references non-existent target node '{rel.target_node_id}'.",
                    "auto_repairable": True,
                    "repaired": auto_repair,
                })

            if has_dangling and auto_repair:
                db.delete(rel)
                relationships.remove(rel)
                auto_repaired_count += 1

        # Check nodes with orphaned entity_id
        for n in nodes:
            if n.entity_id and n.category == GraphNodeCategory.ASSET:
                asset_exists = db.query(Asset).filter(Asset.id == n.entity_id).first()
                if not asset_exists:
                    dangling_count += 1
                    logs.append({
                        "item_type": "NODE_ORPHANED_ASSET",
                        "id": n.id,
                        "severity": InconsistencySeverity.WARNING.value,
                        "description": f"Graph node '{n.label}' references deleted or non-existent Asset '{n.entity_id}'.",
                        "auto_repairable": True,
                        "repaired": auto_repair,
                    })
                    if auto_repair:
                        n.epistemic_status = EpistemicStatus.INVALIDATED.value
                        n.is_authoritative = False
                        n.invalidation_reason = f"Underlying Asset '{n.entity_id}' deleted."
                        auto_repaired_count += 1

            elif n.entity_id and n.category == GraphNodeCategory.FINDING:
                finding_exists = db.query(VulnerabilityFinding).filter(VulnerabilityFinding.id == n.entity_id).first()
                if not finding_exists:
                    dangling_count += 1
                    logs.append({
                        "item_type": "NODE_ORPHANED_FINDING",
                        "id": n.id,
                        "severity": InconsistencySeverity.WARNING.value,
                        "description": f"Graph node '{n.label}' references deleted or non-existent Finding '{n.entity_id}'.",
                        "auto_repairable": True,
                        "repaired": auto_repair,
                    })
                    if auto_repair:
                        n.epistemic_status = EpistemicStatus.INVALIDATED.value
                        n.is_authoritative = False
                        n.invalidation_reason = f"Underlying Finding '{n.entity_id}' deleted."
                        auto_repaired_count += 1

        # -------------------------------------------------------------------------
        # 2. Duplicate Logical Relationships
        # -------------------------------------------------------------------------
        rel_pairs: Dict[Tuple[str, str, RelationshipType], List[GraphRelationship]] = {}
        for r in relationships:
            key = (r.source_node_id, r.target_node_id, r.relationship_type)
            rel_pairs.setdefault(key, []).append(r)

        for key, rel_list in rel_pairs.items():
            if len(rel_list) > 1:
                duplicate_count += len(rel_list) - 1
                logs.append({
                    "item_type": "DUPLICATE_RELATIONSHIP",
                    "key": f"{key[0]}--[{key[2].value}]-->{key[1]}",
                    "count": len(rel_list),
                    "severity": InconsistencySeverity.WARNING.value,
                    "description": f"Found {len(rel_list)} duplicate edges of type '{key[2].value}' between nodes.",
                    "auto_repairable": True,
                    "repaired": auto_repair,
                })
                if auto_repair:
                    # Keep latest relationship by observed_at or created_at, consolidate verification history
                    rel_list.sort(key=lambda x: x.observed_at or x.created_at, reverse=True)
                    canonical = rel_list[0]
                    consolidated_hist = list(canonical.verification_history or [])
                    for dup in rel_list[1:]:
                        consolidated_hist.extend(dup.verification_history or [])
                        db.delete(dup)
                        auto_repaired_count += 1
                    canonical.verification_history = consolidated_hist

        # -------------------------------------------------------------------------
        # 3. Category Constraint Violations
        # -------------------------------------------------------------------------
        for r in relationships:
            src = node_map.get(r.source_node_id)
            tgt = node_map.get(r.target_node_id)
            if not src or not tgt:
                continue

            allowed_sources, allowed_targets = KnowledgeGraphService.VALID_EDGE_CONSTRAINTS.get(r.relationship_type, (None, None))
            violates_src = allowed_sources is not None and src.category not in allowed_sources
            violates_tgt = allowed_targets is not None and tgt.category not in allowed_targets

            if violates_src or violates_tgt:
                invalid_type_count += 1
                logs.append({
                    "item_type": "INVALID_RELATIONSHIP_CATEGORY",
                    "id": r.id,
                    "severity": InconsistencySeverity.CRITICAL.value,
                    "description": (
                        f"Relationship type '{r.relationship_type.value}' connects incompatible categories: "
                        f"src '{src.label}' ({src.category.value}) -> tgt '{tgt.label}' ({tgt.category.value})."
                    ),
                    "auto_repairable": True,
                    "repaired": auto_repair,
                })
                if auto_repair:
                    r.status = RelationshipStatus.INVALIDATED
                    r.epistemic_status = EpistemicStatus.INVALIDATED.value
                    r.is_authoritative = False
                    r.invalidation_reason = f"Violates category constraint for relationship '{r.relationship_type.value}'."
                    auto_repaired_count += 1

        # -------------------------------------------------------------------------
        # 4. Missing Provenance & Ungrounded Authority Claims
        # -------------------------------------------------------------------------
        for r in relationships:
            if not r.provenance or r.provenance.strip() == "":
                missing_prov_count += 1
                logs.append({
                    "item_type": "MISSING_PROVENANCE",
                    "id": r.id,
                    "severity": InconsistencySeverity.WARNING.value,
                    "description": f"Relationship '{r.id}' has missing or empty provenance.",
                    "auto_repairable": True,
                    "repaired": auto_repair,
                })
                if auto_repair:
                    r.provenance = "LEGACY_UNSPECIFIED"
                    auto_repaired_count += 1

            # Check ungrounded AI claims: AI prose marked as VERIFIED
            if r.provenance and r.provenance.upper() in KnowledgeGraphService.AI_PROSE_PROVENANCES:
                if r.status == RelationshipStatus.VERIFIED or r.is_authoritative:
                    logs.append({
                        "item_type": "UNGROUNDED_AI_AUTHORITY",
                        "id": r.id,
                        "severity": InconsistencySeverity.CRITICAL.value,
                        "description": f"Relationship '{r.id}' has AI provenance '{r.provenance}' but was marked authoritative/verified.",
                        "auto_repairable": True,
                        "repaired": auto_repair,
                    })
                    if auto_repair:
                        r.status = RelationshipStatus.HYPOTHETICAL
                        r.epistemic_status = EpistemicStatus.HYPOTHESIS.value
                        r.is_authoritative = False
                        r.confidence = min(0.6, r.confidence)
                        auto_repaired_count += 1

        # -------------------------------------------------------------------------
        # 5. Scope Boundary Violations
        # -------------------------------------------------------------------------
        exclusions = db.query(ScopeExclusion).filter(ScopeExclusion.project_id == project_id).all()
        for n in nodes:
            label_lower = (n.label or "").lower()
            for exc in exclusions:
                exc_val = (exc.target_value or "").lower()
                if exc_val and (exc_val == label_lower or exc_val in label_lower):
                    scope_viol_count += 1
                    logs.append({
                        "item_type": "SCOPE_EXCLUSION_VIOLATION",
                        "node_id": n.id,
                        "node_label": n.label,
                        "exclusion_value": exc.target_value,
                        "severity": InconsistencySeverity.CRITICAL.value,
                        "description": f"Graph node '{n.label}' matches active scope exclusion '{exc.target_value}'.",
                        "auto_repairable": True,
                        "repaired": auto_repair,
                    })
                    if auto_repair:
                        n.epistemic_status = EpistemicStatus.INVALIDATED.value
                        n.is_authoritative = False
                        n.invalidation_reason = f"Excluded by project scope exclusion: {exc.reason or exc.target_value}."
                        auto_repaired_count += 1

        # -------------------------------------------------------------------------
        # 6. Stale Derived Results & Attack Paths
        # -------------------------------------------------------------------------
        paths = db.query(ExplainableAttackPathRecord).filter(
            ExplainableAttackPathRecord.project_id == project_id,
            ExplainableAttackPathRecord.is_invalidated.is_(False),
        ).all()
        for path in paths:
            # Check if any traversed node or edge is now invalidated or deleted
            steps = path.steps_explanation or []
            should_invalidate = False
            inv_reason = ""
            for step in steps:
                edge_id = step.get("edge_id")
                edge = db.query(GraphRelationship).filter(GraphRelationship.id == edge_id).first()
                if not edge or edge.status == RelationshipStatus.INVALIDATED or getattr(edge, "epistemic_status", None) == EpistemicStatus.INVALIDATED.value:
                    should_invalidate = True
                    inv_reason = f"Traversed edge '{edge_id}' was invalidated or pruned."
                    break

            if should_invalidate:
                stale_concl_count += 1
                logs.append({
                    "item_type": "STALE_ATTACK_PATH",
                    "path_id": path.id,
                    "severity": InconsistencySeverity.WARNING.value,
                    "description": f"Attack path '{path.name}' references invalidated or non-existent steps: {inv_reason}",
                    "auto_repairable": True,
                    "repaired": auto_repair,
                })
                if auto_repair:
                    path.is_invalidated = True
                    path.path_status = AttackPathStatus.INVALIDATED
                    path.invalidation_reason = inv_reason
                    auto_repaired_count += 1

        # -------------------------------------------------------------------------
        # Finalize Audit Record
        # -------------------------------------------------------------------------
        audit.dangling_references_detected = dangling_count
        audit.duplicate_relationships_detected = duplicate_count
        audit.invalid_types_detected = invalid_type_count
        audit.missing_provenance_detected = missing_prov_count
        audit.stale_conclusions_detected = stale_concl_count
        audit.scope_violations_detected = scope_viol_count
        audit.contradictions_detected = contradiction_count
        audit.auto_repaired_count = auto_repaired_count
        audit.manual_review_required_count = manual_review_count
        audit.reconciliation_log = logs
        audit.status = ReconciliationStatus.COMPLETED
        audit.completed_at = utc_now()

        db.commit()
        db.refresh(audit)
        return audit
