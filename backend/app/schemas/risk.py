from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, ConfigDict, Field

from app.models.risk import RiskPriority, RecommendationStatus


class RiskAssessmentRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    project_id: str
    finding_id: str
    asset_id: Optional[str] = None
    score: float
    inherent_score: Optional[float] = None
    residual_score: Optional[float] = None
    priority: RiskPriority
    scoring_version: str
    factor_breakdown: Dict[str, Any] = Field(default_factory=dict)
    contributing_factors: List[str] = Field(default_factory=list)
    missing_factors: List[str] = Field(default_factory=list)
    uncertainty_range: Dict[str, Any] = Field(default_factory=dict)
    evidence_references: List[str] = Field(default_factory=list)
    input_snapshot: Dict[str, Any] = Field(default_factory=dict)
    calculated_at: datetime
    is_superseded: bool
    superseded_at: Optional[datetime] = None
    created_at: datetime


class RiskSummaryResponse(BaseModel):
    total_assessed: int
    by_priority: Dict[str, int]
    average_score: float
    highest_score: float
    critical_count: int
    high_count: int
    unresolved_risk_count: int


class AttackPathRequest(BaseModel):
    start_node_id: Optional[str] = None
    target_node_id: Optional[str] = None
    finding_id: Optional[str] = None
    max_depth: int = Field(3, ge=1, le=4)
    max_paths: int = Field(5, ge=1, le=10)


class AttackPathNode(BaseModel):
    id: str
    label: str
    category: str
    entity_type: Optional[str] = None
    properties: Dict[str, Any] = Field(default_factory=dict)


class AttackPathRelationship(BaseModel):
    id: str
    source_node_id: str
    target_node_id: str
    relationship_type: str
    status: str
    confidence: float
    provenance: str


class AttackPathRead(BaseModel):
    path_id: Optional[str] = None
    path_verification_status: str
    cumulative_confidence: float
    risk_impact_score: Optional[float] = 0.0
    step_count: int
    narrative: str
    nodes: List[AttackPathNode]
    relationships: List[AttackPathRelationship]
    missing_evidence: List[str] = Field(default_factory=list)
    ranking_rationale: Optional[str] = None


class AttackPathAnalysisResponse(BaseModel):
    project_id: str
    total_paths_found: int
    max_depth_evaluated: int
    truncated: bool
    paths: List[AttackPathRead]
    chokepoints: List[Dict[str, Any]] = Field(default_factory=list)
    methodology_disclaimer: str


class RemediationRecommendationRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    project_id: str
    finding_id: str
    asset_id: Optional[str] = None
    title: str
    action_type: str
    description: str
    rationale: str
    qualitative_benefit: str
    estimated_risk_reduction: Optional[float] = None
    root_cause: Optional[str] = None
    recommended_change: Optional[str] = None
    estimated_effort: Optional[str] = None
    related_controls: List[str] = Field(default_factory=list)
    execution_governance_stage: str = "GENERATED"
    prerequisites: List[str] = Field(default_factory=list)
    operational_impact: str
    rollback_procedure: str
    verification_criteria: str
    verification_test_profile: Optional[str] = None
    requires_approval: bool
    approval_role: str
    status: RecommendationStatus
    reviewed_by_id: Optional[str] = None
    reviewed_at: Optional[datetime] = None
    review_notes: Optional[str] = None
    created_at: datetime
    updated_at: datetime


class RemediationReviewRequest(BaseModel):
    status: RecommendationStatus
    review_notes: str = Field(..., min_length=3, max_length=1000)


class AuthorizeChangeRequest(BaseModel):
    change_ticket_ref: str = Field(..., min_length=3, max_length=255)
