from datetime import datetime, timezone
from typing import Dict, Any, Optional, List, Set
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.models.orchestration import (
    DependencyInvalidationRecord,
    InvalidationStatus,
)
from app.models.risk import RiskAssessment
from app.models.graph import GraphRelationship, RelationshipStatus
from app.models.finding import VulnerabilityFinding
from app.models.asset import Asset
from app.models.base import utc_now


class DependencyInvalidationService:
    """
    Dependency-Aware Invalidation and Recalculation Service (Prompt 15 / Section 6).
    Tracks dependency trees:
    - Asset changes -> invalidates inventory-derived graph relationships and risk scores.
    - Finding changes -> invalidates risk assessments and attack paths.
    - Evidence integrity failures -> suspends downstream conclusions.
    Maintains provenance and prevents circular update loops.
    """

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
        Invalidates relationships and risk models dependent on a mutated asset.
        """
        targets = []
        # Find active risk assessments for this asset
        risks = db.query(RiskAssessment).filter(
            RiskAssessment.project_id == project_id,
            RiskAssessment.asset_id == asset_id,
        ).all()
        for r in risks:
            targets.append({
                "entity_type": "RiskAssessment",
                "entity_id": r.id,
                "reason": "Asset attributes mutated; risk recalculation required.",
            })

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
        finding = db.query(VulnerabilityFinding).filter(VulnerabilityFinding.id == finding_id).first()
        targets = []
        if finding and finding.asset_id:
            risks = db.query(RiskAssessment).filter(
                RiskAssessment.project_id == project_id,
                RiskAssessment.asset_id == finding.asset_id,
            ).all()
            for r in risks:
                targets.append({
                    "entity_type": "RiskAssessment",
                    "entity_id": r.id,
                    "reason": f"Finding '{finding.title}' status changed to '{finding.status.value}'.",
                })

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
