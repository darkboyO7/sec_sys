from typing import Optional, Dict, Any, List
from datetime import datetime
from pydantic import BaseModel, Field


class ResolutionRequest(BaseModel):
    candidate_target: str = Field(..., description="Target string, IP, domain, URL, or service identifier")
    attributes: Optional[Dict[str, Any]] = Field(default=None, description="Observed attributes such as cloud ARN, TLS cert serial")


class ResolutionResponse(BaseModel):
    outcome: str
    matched_asset_id: Optional[str] = None
    matched_canonical_identifier: Optional[str] = None
    confidence: float
    match_reasons: List[str] = []
    conflicts_detected: List[str] = []


class DryRunImpactResponse(BaseModel):
    source_asset_id: str
    source_canonical_identifier: str
    target_asset_id: str
    target_canonical_identifier: str
    findings_to_repoint: int
    aliases_to_transfer: int
    observations_to_repoint: int
    conflicts_detected: List[str] = []
    safe_to_merge: bool


class ProposeDeduplicationRequest(BaseModel):
    source_asset_id: str
    target_asset_id: str
    rationale: str = Field(..., min_length=3, description="Justification for deduplication merge")
    confidence: Optional[float] = Field(default=0.90, ge=0.0, le=1.0)


class ReviewDeduplicationRequest(BaseModel):
    comments: Optional[str] = None


class DeduplicationProposalResponse(BaseModel):
    id: str
    project_id: str
    source_asset_id: str
    target_asset_id: str
    status: str
    confidence_score: float
    match_reasons: List[str] = []
    conflicts_detected: List[str] = []
    dry_run_impact: Dict[str, Any] = {}
    proposed_by_id: Optional[str] = None
    reviewed_by_id: Optional[str] = None
    review_comments: Optional[str] = None
    created_at: datetime
    reviewed_at: Optional[datetime] = None
    reverted_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class DataQualityIssueResponse(BaseModel):
    id: str
    project_id: str
    issue_type: str
    severity: str
    affected_resource_type: str
    affected_resource_id: str
    details: Dict[str, Any] = {}
    status: str
    detected_at: datetime
    resolved_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class ResolveIssueRequest(BaseModel):
    status: str = Field(..., pattern="^(RESOLVED|IGNORED)$")
