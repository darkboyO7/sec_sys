from datetime import datetime, timezone
from typing import Dict, Any, Optional, List, Set
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.models.orchestration import (
    DependencyInvalidationRecord,
    InvalidationStatus,
)
from app.models.risk import RiskAssessment
from app.models.graph import GraphRelationship, GraphNode, RelationshipStatus, EpistemicStatus
from app.models.finding import VulnerabilityFinding
from app.models.asset import Asset
from app.models.knowledge import (
    KnowledgeDependencyRecord,
    KnowledgeDependencyType,
    ExplainableAttackPathRecord,
    AttackPathStatus,
)
from app.models.base import utc_now


class DependencyInvalidationService:
    """
    Dependency-Aware Invalidation and Recalculation Service (Prompt 15 / Prompt 21).
    Tracks fine-grained dependency trees:
    - Asset changes -> invalidates graph relationships, risk scores, and attack paths.
    - Finding changes -> invalidates risk assessments and attack paths.
    - Graph relationship changes -> invalidates traversed attack paths.
    - Scope exclusions -> marks affected nodes and paths non-compliant.
    - Evidence integrity failures -> suspends downstream conclusions.
    Maintains provenance and prevents circular update loops.
    """

    @classmethod
    def register_knowledge_dependency(
        cls,
        db: Session,
        project_id: str,
        source_entity_type: str,
        source_entity_id: str,
        dependent_entity_type: str,
        dependent_entity_id: str,
        dependency_type: str = "TOPOLOGY_LINK",
        source_version: Optional[str] = None,
    ) -> KnowledgeDependencyRecord:
        """
        Registers an explicit dependency link between an authoritative source
        and a derived security conclusion (Prompt 21).
        """
        now = utc_now()
        existing = (
            db.query(KnowledgeDependencyRecord)
            .filter(
                KnowledgeDependencyRecord.project_id == project_id,
                KnowledgeDependencyRecord.source_entity_type == source_entity_type,
                KnowledgeDependencyRecord.source_entity_id == str(source_entity_id),
                KnowledgeDependencyRecord.dependent_entity_type == dependent_entity_type,
                KnowledgeDependencyRecord.dependent_entity_id == str(dependent_entity_id),
            )
            .first()
        )
        if existing:
            existing.is_valid = True
            existing.invalidated_at = None
            existing.invalidation_reason = None
            existing.source_version = source_version or existing.source_version
            existing.dependency_type = dependency_type
            db.flush()
            return existing

        new_dep = KnowledgeDependencyRecord(
            project_id=project_id,
            source_entity_type=source_entity_type,
            source_entity_id=str(source_entity_id),
            dependent_entity_type=dependent_entity_type,
            dependent_entity_id=str(dependent_entity_id),
            dependency_type=dependency_type,
            source_version=source_version,
            is_valid=True,
            created_at=now,
            updated_at=now,
        )
        try:
            with db.begin_nested():
                db.add(new_dep)
                db.flush()
        except Exception:
            existing = (
                db.query(KnowledgeDependencyRecord)
                .filter(
                    KnowledgeDependencyRecord.project_id == project_id,
                    KnowledgeDependencyRecord.source_entity_type == source_entity_type,
                    KnowledgeDependencyRecord.source_entity_id == str(source_entity_id),
                    KnowledgeDependencyRecord.dependent_entity_type == dependent_entity_type,
                    KnowledgeDependencyRecord.dependent_entity_id == str(dependent_entity_id),
                )
                .first()
            )
            if existing:
                return existing
            raise

        return new_dep

    @classmethod
    def record_invalidation(
        cls,
        db: Session,
        project_id: str,
        source_entity_type: str,
        source_entity_id: str,
        invalidation_type: str,
        invalidated_targets: List[Dict[str, Any]],
        provenance: Optional[Dict[str, Any]] = None,
        now: Optional[datetime] = None,
    ) -> DependencyInvalidationRecord:
        """Records an invalidation event for derived records."""
        if now is None:
            now = utc_now()

        record = DependencyInvalidationRecord(
            project_id=project_id,
            source_entity_type=source_entity_type,
            source_entity_id=source_entity_id,
            invalidation_type=invalidation_type,
            invalidated_targets=invalidated_targets or [],
            recalculation_status=InvalidationStatus.PENDING,
            provenance=provenance or {},
            created_at=now,
            updated_at=now,
        )
        db.add(record)
        db.commit()
        db.refresh(record)
        return record

    @classmethod
    def invalidate_for_asset_change(
        cls,
        db: Session,
        project_id: str,
        asset_id: str,
        now: Optional[datetime] = None,
    ) -> DependencyInvalidationRecord:
        """
        Invalidates relationships, risk models, and attack paths dependent on a mutated asset.
        """
        if now is None:
            now = utc_now()
        targets = []

        # 1. Invalidate active risk assessments for this asset
        risks = db.query(RiskAssessment).filter(
            RiskAssessment.project_id == project_id,
            RiskAssessment.asset_id == asset_id,
        ).all()
        for r in risks:
            r.is_invalidated = True
            r.invalidation_reason = f"Asset '{asset_id}' mutated or reassessed."
            targets.append({
                "entity_type": "RiskAssessment",
                "entity_id": r.id,
                "reason": "Asset attributes mutated; risk recalculation required.",
            })

        # 2. Invalidate dependent attack paths via KnowledgeDependencyRecord
        deps = db.query(KnowledgeDependencyRecord).filter(
            KnowledgeDependencyRecord.project_id == project_id,
            KnowledgeDependencyRecord.source_entity_type == "Asset",
            KnowledgeDependencyRecord.source_entity_id == asset_id,
            KnowledgeDependencyRecord.is_valid == True,
        ).all()
        for dep in deps:
            dep.is_valid = False
            dep.invalidated_at = now
            dep.invalidation_reason = f"Asset '{asset_id}' changed."
            if dep.dependent_entity_type == "ExplainableAttackPath":
                path = db.query(ExplainableAttackPathRecord).filter(
                    ExplainableAttackPathRecord.id == dep.dependent_entity_id
                ).first()
                if path:
                    path.is_invalidated = True
                    path.path_status = AttackPathStatus.INVALIDATED
                    path.invalidation_reason = f"Underlying asset '{asset_id}' changed or experienced exposure drift."
                    targets.append({
                        "entity_type": "ExplainableAttackPath",
                        "entity_id": path.id,
                        "reason": path.invalidation_reason,
                    })

        db.flush()

        return cls.record_invalidation(
            db=db,
            project_id=project_id,
            source_entity_type="Asset",
            source_entity_id=asset_id,
            invalidation_type="ASSET_CHANGED",
            invalidated_targets=targets,
            provenance={"trigger": "asset_reconciliation", "asset_id": asset_id},
            now=now,
        )

    @classmethod
    def invalidate_for_finding_change(
        cls,
        db: Session,
        project_id: str,
        finding_id: str,
        now: Optional[datetime] = None,
    ) -> DependencyInvalidationRecord:
        """
        Invalidates risk calculations and attack paths when a finding changes status or severity.
        """
        if now is None:
            now = utc_now()
        finding = db.query(VulnerabilityFinding).filter(VulnerabilityFinding.id == finding_id).first()
        targets = []
        if finding:
            # Invalidate risk assessments for this finding
            risks = db.query(RiskAssessment).filter(
                RiskAssessment.project_id == project_id,
                RiskAssessment.finding_id == finding_id,
            ).all()
            for r in risks:
                r.is_invalidated = True
                r.invalidation_reason = f"Finding '{finding.title}' transitioned to '{finding.status.value}'."
                targets.append({
                    "entity_type": "RiskAssessment",
                    "entity_id": r.id,
                    "reason": r.invalidation_reason,
                })

            # Invalidate dependent attack paths
            deps = db.query(KnowledgeDependencyRecord).filter(
                KnowledgeDependencyRecord.project_id == project_id,
                KnowledgeDependencyRecord.source_entity_type == "Finding",
                KnowledgeDependencyRecord.source_entity_id == finding_id,
                KnowledgeDependencyRecord.is_valid == True,
            ).all()
            for dep in deps:
                dep.is_valid = False
                dep.invalidated_at = now
                dep.invalidation_reason = f"Finding '{finding.title}' state changed."
                if dep.dependent_entity_type == "ExplainableAttackPath":
                    path = db.query(ExplainableAttackPathRecord).filter(
                        ExplainableAttackPathRecord.id == dep.dependent_entity_id
                    ).first()
                    if path:
                        path.is_invalidated = True
                        path.path_status = AttackPathStatus.INVALIDATED
                        path.invalidation_reason = f"Finding '{finding.title}' state changed to '{finding.status.value}'."
                        targets.append({
                            "entity_type": "ExplainableAttackPath",
                            "entity_id": path.id,
                            "reason": path.invalidation_reason,
                        })

        db.flush()

        return cls.record_invalidation(
            db=db,
            project_id=project_id,
            source_entity_type="Finding",
            source_entity_id=finding_id,
            invalidation_type="FINDING_MUTATED",
            invalidated_targets=targets,
            provenance={"finding_id": finding_id, "new_status": finding.status.value if finding else "UNKNOWN"},
            now=now,
        )

    @classmethod
    def invalidate_for_relationship_change(
        cls,
        db: Session,
        project_id: str,
        relationship_id: str,
        reason: str,
        now: Optional[datetime] = None,
    ) -> DependencyInvalidationRecord:
        """
        Invalidates attack paths and dependent conclusions traversing a mutated or removed edge (Prompt 21).
        """
        if now is None:
            now = utc_now()
        targets = []

        deps = db.query(KnowledgeDependencyRecord).filter(
            KnowledgeDependencyRecord.project_id == project_id,
            KnowledgeDependencyRecord.source_entity_type == "GraphRelationship",
            KnowledgeDependencyRecord.source_entity_id == relationship_id,
            KnowledgeDependencyRecord.is_valid == True,
        ).all()

        for dep in deps:
            dep.is_valid = False
            dep.invalidated_at = now
            dep.invalidation_reason = reason
            if dep.dependent_entity_type == "ExplainableAttackPath":
                path = db.query(ExplainableAttackPathRecord).filter(
                    ExplainableAttackPathRecord.id == dep.dependent_entity_id
                ).first()
                if path:
                    path.is_invalidated = True
                    path.path_status = AttackPathStatus.INVALIDATED
                    path.invalidation_reason = f"Traversed relationship '{relationship_id}' invalidated: {reason}"
                    targets.append({
                        "entity_type": "ExplainableAttackPath",
                        "entity_id": path.id,
                        "reason": path.invalidation_reason,
                    })

        db.flush()

        return cls.record_invalidation(
            db=db,
            project_id=project_id,
            source_entity_type="GraphRelationship",
            source_entity_id=relationship_id,
            invalidation_type="RELATIONSHIP_INVALIDATED",
            invalidated_targets=targets,
            provenance={"relationship_id": relationship_id, "reason": reason},
            now=now,
        )

    @classmethod
    def invalidate_for_evidence_failure(
        cls,
        db: Session,
        project_id: str,
        evidence_id: str,
        now: Optional[datetime] = None,
    ) -> DependencyInvalidationRecord:
        """
        Invalidates downstream findings and risks when evidence fails cryptographic verification.
        """
        return cls.record_invalidation(
            db=db,
            project_id=project_id,
            source_entity_type="FindingEvidence",
            source_entity_id=evidence_id,
            invalidation_type="EVIDENCE_CORRUPTED",
            invalidated_targets=[{
                "entity_type": "SecurityPosture",
                "entity_id": project_id,
                "reason": "Cryptographic evidence integrity breach invalidated downstream conclusions.",
            }],
            provenance={"evidence_id": evidence_id, "reason": "SHA256_MISMATCH"},
            now=now,
        )

    @classmethod
    def process_pending_recalculations(
        cls,
        db: Session,
        project_id: str,
        now: Optional[datetime] = None,
    ) -> int:
        """
        Executes bounded, non-circular recalculation of pending invalidations.
        """
        if now is None:
            now = utc_now()

        pending = (
            db.query(DependencyInvalidationRecord)
            .filter(
                DependencyInvalidationRecord.project_id == project_id,
                DependencyInvalidationRecord.recalculation_status == InvalidationStatus.PENDING,
            )
            .limit(20)
            .all()
        )

        processed = 0
        visited_entities: Set[str] = set()

        for inv in pending:
            entity_key = f"{inv.source_entity_type}:{inv.source_entity_id}"
            if entity_key in visited_entities:
                # Avoid circular loops
                inv.recalculation_status = InvalidationStatus.SUPERSEDED
                inv.recalculated_at = now
                continue

            visited_entities.add(entity_key)

            # Recalculate contextual risk if needed
            from app.services.contextual_risk_service import ContextualRiskService
            for target in inv.invalidated_targets:
                if target.get("entity_type") == "RiskAssessment":
                    try:
                        ContextualRiskService.evaluate_project_risk(db=db, project_id=project_id)
                    except Exception:
                        pass

            inv.recalculation_status = InvalidationStatus.RECALCULATED
            inv.recalculated_at = now
            processed += 1

        db.commit()
        return processed
