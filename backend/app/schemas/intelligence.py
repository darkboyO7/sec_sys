from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field


class HighestPriorityFinding(BaseModel):
    finding_id: str
    title: str
    target_value: str
    severity: str
    confidence: str
    status: str
    risk_score: float
    inherent_score: Optional[float] = None
    residual_score: Optional[float] = None
    priority: str
    scoring_version: str
    contributing_factors: List[str] = Field(default_factory=list)
    missing_factors: List[str] = Field(default_factory=list)
    uncertainty_range: Dict[str, Any] = Field(default_factory=dict)


class StaleAssetInfo(BaseModel):
    asset_id: str
    name: str
    canonical_identifier: str
    asset_type: str
    criticality: str
    last_seen_at: Optional[str] = None
    days_since_assessment: Optional[float] = None
    staleness_reason: str


class CoverageAuditResponse(BaseModel):
    total_assets: int
    covered_assets_count: int
    stale_assets_count: int
    coverage_percentage: float
    stale_assets: List[StaleAssetInfo] = Field(default_factory=list)
    unassessed_scope_targets: List[Dict[str, Any]] = Field(default_factory=list)
    failing_probes: List[Dict[str, Any]] = Field(default_factory=list)
    stale_days_threshold: int


class PlannedCheck(BaseModel):
    check_id: str
    target: str
    adapter_name: str
    action: str
    priority: str
    reason_category: str
    rationale: str
    source_evidence: Dict[str, Any] = Field(default_factory=dict)


class SkippedCheck(BaseModel):
    target: str
    adapter_name: str
    action: str
    skip_reason: str
    rationale: str
    source_evidence: Dict[str, Any] = Field(default_factory=dict)


class AdaptivePlanResponse(BaseModel):
    id: str
    project_id: str
    plan_name: str
    status: str
    scan_budget: int
    total_recommended: int
    total_skipped: int
    recommended_checks: List[PlannedCheck] = Field(default_factory=list)
    skipped_checks: List[SkippedCheck] = Field(default_factory=list)
    execution_summary: Dict[str, Any] = Field(default_factory=dict)
    created_at: str
    updated_at: str


class AdaptivePlanCreateRequest(BaseModel):
    scan_budget: int = Field(default=10, ge=1, le=50)


class ExecutePlanCheckRequest(BaseModel):
    check_id: str


class ProjectIntelligenceSummaryResponse(BaseModel):
    project_id: str
    project_name: str
    timestamp: str
    risk_summary: Dict[str, Any]
    coverage_audit: CoverageAuditResponse
    attack_paths: Dict[str, Any]
    remediation_intelligence: Dict[str, Any]
    monitoring_and_changes: Dict[str, Any]
    adaptive_plan: Optional[Dict[str, Any]] = None
    learning_pipeline: Dict[str, Any]
    data_provenance: Dict[str, Any]
