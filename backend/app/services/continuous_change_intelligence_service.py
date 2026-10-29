from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session
from sqlalchemy import func, and_, desc

from app.models.asset import (
    Asset,
    AssetObservation,
    AssetType,
    AssetStatus,
    AssetIdentifierAlias,
    AssetIdentityMergeRecord,
)
from app.models.drift import (
    ExposureDriftRecord,
    ReassessmentProposal,
    DriftType,
    DriftMateriality,
    ReassessmentStatus,
)
from app.models.graph import GraphNode, GraphNodeCategory, RelationshipType, RelationshipStatus
from app.models.base import utc_now
from app.services.asset_identity_service import AssetIdentityService
from app.services.exposure_drift_service import ExposureDriftService
from app.services.reassessment_planner_service import ReassessmentPlannerService
from app.services.knowledge_graph_service import KnowledgeGraphService


class ContinuousChangeIntelligenceService:
    """
    Continuous Change Intelligence & Exposure Orchestrator (Prompt 20 / Section 6 & 7).
    Unifies:
    - Asset observation ingestion & identity resolution
    - Exposure drift detection & classification
    - Security Knowledge Graph synchronization
    - Reassessment proposal generation
    - Freshness, completeness, and collection gap tracking
    """

    @classmethod
    def ingest_observation_and_process_change(
        cls,
        project_id: str,
        organization_id: str,
        target_input: str,
        observation_source: str,
        observed_attributes: Dict[str, Any],
        assessment_job_id: Optional[str] = None,
        monitoring_run_id: Optional[str] = None,
        adapter_version: str = "1.0.0",
        authorization_context: Optional[Dict[str, Any]] = None,
        confidence: float = 1.0,
        completeness: float = 1.0,
        collection_errors: Optional[List[Dict[str, Any]]] = None,
        is_simulated: bool = False,
        is_successful_absence: bool = False,
        observed_at: Optional[datetime] = None,
        db: Optional[Session] = None,
    ) -> Dict[str, Any]:
        """
        End-to-end ingestion pipeline:
        1. Classifies and reconciles logical asset identity.
        2. Records versioned observation with dedup hash.
        3. Records aliases (e.g. resolved IP address, port binding).
        4. Detects exposure drift against baseline.
        5. Synchronizes Knowledge Graph.
        6. Creates reassessment proposals for material drift.
        """
        assert db is not None, "Database session required"
        now = observed_at or utc_now()

        # 1. Normalize target and reconcile asset
        asset_type, canonical_id, display_name = AssetIdentityService.classify_and_normalize(target_input)
        asset = AssetIdentityService.reconcile_or_create_asset(
            project_id=project_id,
            organization_id=organization_id,
            asset_type=asset_type,
            canonical_identifier=canonical_id,
            name=display_name,
            attributes=observed_attributes,
            source=observation_source,
            confidence=confidence,
            observed_at=now,
            db=db,
        )

        # 2. Record IP / Hostname Alias if present in attributes
        ip_addr = observed_attributes.get("ip_address")
        if ip_addr:
            AssetIdentityService.record_alias(
                asset=asset,
                identifier_type="IP_ADDRESS",
                identifier_value=ip_addr,
                confidence=confidence,
                evidence_ref=None,
                observed_at=now,
                db=db,
            )

        # 3. Record Versioned Observation
        obs, is_new = AssetIdentityService.record_observation(
            asset=asset,
            project_id=project_id,
            observation_source=observation_source,
            observed_attributes=observed_attributes,
            assessment_job_id=assessment_job_id,
            monitoring_run_id=monitoring_run_id,
            adapter_version=adapter_version,
            authorization_context=authorization_context,
            confidence=confidence,
            completeness=completeness,
            collection_errors=collection_errors,
            is_simulated=is_simulated,
            is_successful_absence=is_successful_absence,
            observed_at=now,
            db=db,
        )

        # 4. Exposure Drift Evaluation
        drifts = []
        proposals = []
        if is_new:
            drifts = ExposureDriftService.evaluate_drift(
                project_id=project_id,
                asset=asset,
                current_observation=obs,
                db=db,
            )

            # 5. Plan reassessments for material drifts
            for drift in drifts:
                proposal = ReassessmentPlannerService.plan_reassessments_for_drift(
                    project_id=project_id,
                    drift_record=drift,
                    db=db,
                )
                if proposal:
                    proposals.append(proposal)

        # 6. Graph Synchronization
        cls._sync_graph_state(project_id, asset, obs, db)

        db.flush()

        return {
            "asset_id": asset.id,
            "canonical_identifier": asset.canonical_identifier,
            "observation_id": obs.id,
            "is_new_observation": is_new,
            "drift_records_count": len(drifts),
            "reassessment_proposals_count": len(proposals),
            "freshness_status": asset.freshness_status,
        }

    @classmethod
    def _sync_graph_state(
        cls,
        project_id: str,
        asset: Asset,
        observation: AssetObservation,
        db: Session,
    ) -> None:
        """
        Synchronizes the Security Knowledge Graph with logical assets and versioned observations.
        """
        # Node for Asset
        asset_node = KnowledgeGraphService.get_or_create_node(
            project_id=project_id,
            category=GraphNodeCategory.ASSET,
            label=asset.name,
            entity_id=asset.id,
            entity_type="Asset",
            properties={
                "asset_type": asset.asset_type.value,
                "canonical_identifier": asset.canonical_identifier,
                "freshness_status": asset.freshness_status,
                "confirmed_absent": asset.confirmed_absent,
            },
            db=db,
        )

        # Node for Observation
        obs_node = KnowledgeGraphService.get_or_create_node(
            project_id=project_id,
            category=GraphNodeCategory.EVIDENCE,
            label=f"Obs: {observation.observation_source}@{observation.observed_at.strftime('%H:%M:%S')}",
            entity_id=observation.id,
            entity_type="AssetObservation",
            properties={
                "observation_source": observation.observation_source,
                "adapter_version": observation.adapter_version,
                "completeness": observation.completeness,
                "evidence_hash": observation.evidence_hash,
            },
            db=db,
        )

        # Edge: Asset -> OBSERVED_AT -> Observation
        KnowledgeGraphService.get_or_create_relationship(
            project_id=project_id,
            source_node_id=asset_node.id,
            target_node_id=obs_node.id,
            relationship_type=RelationshipType.OBSERVED_AT,
            status=RelationshipStatus.VERIFIED,
            confidence=observation.confidence,
            properties={"observed_at": observation.observed_at.isoformat()},
            db=db,
        )

    @classmethod
    def get_project_drift_overview(cls, project_id: str, db: Session) -> Dict[str, Any]:
        """
        Calculates project-wide drift metrics, freshness status, and data gap warnings.
        """
        now = utc_now()
        assets = db.query(Asset).filter(Asset.project_id == project_id).all()

        # Update freshness statuses
        for a in assets:
            AssetIdentityService.update_asset_freshness_status(a, now)
        db.flush()

        freshness_counts = {"FRESH": 0, "AGING": 0, "STALE": 0, "EXPIRED": 0, "UNOBSERVED": 0}
        for a in assets:
            status = a.freshness_status or "UNOBSERVED"
            freshness_counts[status] = freshness_counts.get(status, 0) + 1

        # Drift counts
        drifts = db.query(ExposureDriftRecord).filter(ExposureDriftRecord.project_id == project_id).all()
        materiality_counts = {"MATERIAL": 0, "IMMATERIAL": 0, "INCONCLUSIVE": 0}
        drift_type_counts = {}
        for d in drifts:
            mat = d.materiality.value if hasattr(d.materiality, "value") else str(d.materiality)
            materiality_counts[mat] = materiality_counts.get(mat, 0) + 1
            dtype = d.drift_type.value if hasattr(d.drift_type, "value") else str(d.drift_type)
            drift_type_counts[dtype] = drift_type_counts.get(dtype, 0) + 1

        # Proposals counts
        proposals = db.query(ReassessmentProposal).filter(ReassessmentProposal.project_id == project_id).all()
        proposal_status_counts = {"PROPOSED": 0, "DEFERRED": 0, "APPROVED": 0, "REJECTED": 0, "QUEUED": 0}
        for p in proposals:
            pstat = p.status.value if hasattr(p.status, "value") else str(p.status)
            proposal_status_counts[pstat] = proposal_status_counts.get(pstat, 0) + 1

        # Collection completeness average
        avg_completeness = (
            db.query(func.avg(AssetObservation.completeness))
            .filter(AssetObservation.project_id == project_id)
            .scalar()
            or 1.0
        )

        # Health / Governance Warnings
        warnings = []
        if freshness_counts["STALE"] + freshness_counts["EXPIRED"] > 0:
            warnings.append(
                f"{freshness_counts['STALE'] + freshness_counts['EXPIRED']} assets have stale or expired observation baselines (> 7 days without observation)."
            )
        if materiality_counts["INCONCLUSIVE"] > 5:
            warnings.append(
                f"{materiality_counts['INCONCLUSIVE']} observations resulted in inconclusive drift due to partial collections or socket errors."
            )
        if proposal_status_counts["PROPOSED"] > 0:
            warnings.append(
                f"{proposal_status_counts['PROPOSED']} pending reassessment proposals require review or automated authorization."
            )
        if any(a.is_ambiguous for a in assets):
            ambig_count = sum(1 for a in assets if a.is_ambiguous)
            warnings.append(
                f"{ambig_count} assets have ambiguous identity associations requiring analyst review."
            )

        return {
            "total_assets": len(assets),
            "freshness_distribution": freshness_counts,
            "drift_materiality_distribution": materiality_counts,
            "drift_type_distribution": drift_type_counts,
            "reassessment_proposals_distribution": proposal_status_counts,
            "average_collection_completeness": round(float(avg_completeness), 3),
            "total_drift_records": len(drifts),
            "total_reassessment_proposals": len(proposals),
            "governance_warnings": warnings,
        }
