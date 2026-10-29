"""
Asset Reconciliation Service (Backward Compatibility Wrapper for AssetIdentityService).
Preserves existing method signatures for Phase 4-19 callers while routing to
AssetIdentityService for Prompt 20 capabilities.
"""
from typing import Tuple, Optional, Dict, Any, List
from sqlalchemy.orm import Session
from datetime import datetime

from app.models.asset import (
    Asset,
    AssetObservation,
    AssetType,
    AssetCriticality,
    AssetStatus,
)
from app.services.asset_identity_service import AssetIdentityService


class AssetReconciliationService:
    """
    Conservative asset reconciliation and inventory management service.
    Normalizes identifiers using type-specific rules, separates authoritative asset state
    from supporting historical observations, and preserves conflicting signals.
    """

    @classmethod
    def classify_and_normalize(cls, raw_target: str) -> Tuple[AssetType, str, str]:
        return AssetIdentityService.classify_and_normalize(raw_target)

    @classmethod
    def reconcile_or_create_asset(
        cls,
        project_id: str,
        organization_id: str,
        asset_type: AssetType,
        canonical_identifier: str,
        name: Optional[str] = None,
        environment: str = "PRODUCTION",
        criticality: AssetCriticality = AssetCriticality.MEDIUM,
        attributes: Optional[Dict[str, Any]] = None,
        source: str = "ASSESSMENT",
        confidence: float = 1.0,
        is_ambiguous: bool = False,
        ambiguity_reason: Optional[str] = None,
        observed_at: Optional[datetime] = None,
        db: Optional[Session] = None,
    ) -> Asset:
        return AssetIdentityService.reconcile_or_create_asset(
            project_id=project_id,
            organization_id=organization_id,
            asset_type=asset_type,
            canonical_identifier=canonical_identifier,
            name=name,
            environment=environment,
            criticality=criticality,
            attributes=attributes,
            source=source,
            confidence=confidence,
            is_ambiguous=is_ambiguous,
            ambiguity_reason=ambiguity_reason,
            observed_at=observed_at,
            db=db,
        )

    @classmethod
    def record_observation(
        cls,
        asset: Asset,
        project_id: str,
        observation_source: str,
        observed_attributes: Dict[str, Any],
        assessment_job_id: Optional[str] = None,
        adapter_version: str = "1.0.0",
        confidence: float = 1.0,
        validation_status: str = "VALIDATED",
        evidence_hash: Optional[str] = None,
        observed_at: Optional[datetime] = None,
        db: Optional[Session] = None,
    ) -> AssetObservation:
        obs, _ = AssetIdentityService.record_observation(
            asset=asset,
            project_id=project_id,
            observation_source=observation_source,
            observed_attributes=observed_attributes,
            assessment_job_id=assessment_job_id,
            adapter_version=adapter_version,
            confidence=confidence,
            validation_status=validation_status,
            evidence_hash=evidence_hash,
            observed_at=observed_at,
            db=db,
        )
        return obs
