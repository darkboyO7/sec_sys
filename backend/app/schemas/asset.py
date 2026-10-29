from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, ConfigDict, Field

from app.models.asset import AssetType, AssetCriticality, AssetStatus


class AssetIdentifierAliasRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    asset_id: str
    project_id: str
    identifier_type: str
    identifier_value: str
    is_primary: bool
    confidence: float
    evidence_ref: Optional[str] = None
    first_observed_at: datetime
    last_observed_at: datetime
    is_active: bool
    disassociation_reason: Optional[str] = None
    created_at: datetime
    updated_at: datetime


class AssetIdentifierAliasCreate(BaseModel):
    identifier_type: str = Field(..., min_length=2, max_length=50)
    identifier_value: str = Field(..., min_length=1, max_length=500)
    is_primary: bool = False
    confidence: float = Field(1.0, ge=0.0, le=1.0)
    evidence_ref: Optional[str] = None


class AssetIdentityMergeRecordRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    project_id: str
    target_asset_id: str
    merged_asset_id: str
    merged_canonical_identifier: str
    merged_asset_type: str
    merge_rationale: str
    confidence: float
    actor_id: Optional[str] = None
    is_reversed: bool
    reversed_at: Optional[datetime] = None
    reversed_by_id: Optional[str] = None
    reversal_notes: Optional[str] = None
    created_at: datetime


class AssetMergeRequest(BaseModel):
    source_asset_id: str = Field(..., min_length=1)
    merge_rationale: str = Field(..., min_length=10, max_length=1000)
    confidence: float = Field(1.0, ge=0.0, le=1.0)


class AssetMergeReversalRequest(BaseModel):
    reversal_notes: str = Field(..., min_length=10, max_length=1000)


class AssetObservationRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    asset_id: str
    project_id: str
    assessment_job_id: Optional[str] = None
    monitoring_run_id: Optional[str] = None
    observation_source: str
    adapter_version: str
    observed_at: datetime
    observed_attributes: Dict[str, Any] = Field(default_factory=dict)
    evidence_hash: Optional[str] = None
    confidence: float
    validation_status: str
    authorization_context: Dict[str, Any] = Field(default_factory=dict)
    is_simulated: bool = False
    completeness: float = 1.0
    collection_errors: List[Dict[str, Any]] = Field(default_factory=list)
    observation_schema_version: str = "1.0"
    is_successful_absence: bool = False
    dedup_hash: Optional[str] = None
    created_at: datetime


class AssetRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    organization_id: str
    project_id: str
    asset_type: AssetType
    name: str
    canonical_identifier: str
    environment: str
    criticality: AssetCriticality
    status: AssetStatus
    attributes: Dict[str, Any] = Field(default_factory=dict)
    source: str
    confidence: float
    first_seen_at: datetime
    last_seen_at: datetime
    last_successful_observation_at: Optional[datetime] = None
    completeness_score: float = 1.0
    freshness_status: str = "FRESH"
    consecutive_absences: int = 0
    confirmed_absent: bool = False
    is_ambiguous: bool
    ambiguity_reason: Optional[str] = None
    created_at: datetime
    updated_at: datetime


class AssetDetail(AssetRead):
    observations: List[AssetObservationRead] = Field(default_factory=list)
    aliases: List[AssetIdentifierAliasRead] = Field(default_factory=list)
    finding_count: int = 0
    graph_node_id: Optional[str] = None
    related_nodes_count: int = 0


class AssetCreateFixtureRequest(BaseModel):
    asset_type: AssetType
    canonical_identifier: str = Field(..., min_length=1, max_length=500)
    name: Optional[str] = Field(None, max_length=255)
    environment: str = Field("PRODUCTION", max_length=100)
    criticality: AssetCriticality = AssetCriticality.MEDIUM
    attributes: Dict[str, Any] = Field(default_factory=dict)
    source: str = Field("FIXTURE", max_length=100)
    confidence: float = Field(1.0, ge=0.0, le=1.0)
    is_ambiguous: bool = False
    ambiguity_reason: Optional[str] = None


class ResolveAmbiguityRequest(BaseModel):
    resolution_notes: str = Field(..., min_length=5, max_length=1000)
