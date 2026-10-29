from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, ConfigDict, Field

from app.models.drift import (
    DriftType,
    DriftMateriality,
    ReassessmentPriority,
    ReassessmentStatus,
)


class ExposureDriftRecordRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    project_id: str
    asset_id: Optional[str] = None
    drift_type: DriftType
    materiality: DriftMateriality
    materiality_reason: str
    target_resource: str
    title: str
    previous_observation_id: Optional[str] = None
    current_observation_id: Optional[str] = None
    previous_state: Dict[str, Any] = Field(default_factory=dict)
    new_state: Dict[str, Any] = Field(default_factory=dict)
    evidence_references: List[str] = Field(default_factory=list)
    confidence: float
    is_resolved: bool
    security_impact_summary: Optional[str] = None
    reassessment_recommended: bool
    dedup_key: Optional[str] = None
    detected_at: datetime
    evaluated_at: datetime
    acted_upon_at: Optional[datetime] = None
    created_at: datetime


class ReassessmentProposalRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    project_id: str
    asset_id: Optional[str] = None
    drift_record_id: Optional[str] = None
    target_input: str
    adapter_name: str
    fixture_profile: str
    priority: ReassessmentPriority
    status: ReassessmentStatus
    rationale: str
    scope_authorized: bool
    scope_validation_details: Dict[str, Any] = Field(default_factory=dict)
    requires_human_approval: bool
    approved_by_id: Optional[str] = None
    approved_at: Optional[datetime] = None
    rejection_reason: Optional[str] = None
    scheduled_job_id: Optional[str] = None
    attempt_count: int
    max_attempts: int
    last_error: Optional[str] = None
    created_at: datetime


class ProposalRejectionRequest(BaseModel):
    rejection_reason: str = Field(..., min_length=5, max_length=1000)


class ProjectDriftOverviewResponse(BaseModel):
    total_assets: int
    freshness_distribution: Dict[str, int]
    drift_materiality_distribution: Dict[str, int]
    drift_type_distribution: Dict[str, int]
    reassessment_proposals_distribution: Dict[str, int]
    average_collection_completeness: float
    total_drift_records: int
    total_reassessment_proposals: int
    governance_warnings: List[str]
