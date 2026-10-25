from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, ConfigDict, Field

from app.models.asset import AssetType, AssetCriticality, AssetStatus


class AssetObservationRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    asset_id: str
    project_id: str
    assessment_job_id: Optional[str] = None
    observation_source: str
    adapter_version: str
    observed_at: datetime
    observed_attributes: Dict[str, Any] = Field(default_factory=dict)
    evidence_hash: Optional[str] = None
    confidence: float
    validation_status: str
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
    is_ambiguous: bool
    ambiguity_reason: Optional[str] = None
    created_at: datetime
    updated_at: datetime


class AssetDetail(AssetRead):
    observations: List[AssetObservationRead] = Field(default_factory=list)
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
