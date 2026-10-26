from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
from app.models.ai_analyst import AIDraftType, AIDraftStatus


class CitationItem(BaseModel):
    citation_type: str = Field(..., description="Resource category: finding, evidence, asset, control")
    resource_id: str = Field(..., description="Unique identifier of cited resource")
    label: str = Field(..., description="Human-readable citation label or title")
    sha256_digest: Optional[str] = Field(None, description="Cryptographic integrity digest if applicable")


class ExplainFindingRequest(BaseModel):
    include_mitre_mapping: bool = Field(True, description="Map flaw to MITRE ATT&CK techniques")
    include_defensive_controls: bool = Field(True, description="Map to CIS and NIST defensive controls")


class DraftRemediationRequest(BaseModel):
    operational_constraints: Optional[str] = Field(None, max_length=500, description="Any operational constraints or change windows")


class SummarizeAttackPathRequest(BaseModel):
    path_id: Optional[str] = Field(None, description="Attack path identifier")
    target_asset_id: Optional[str] = Field(None, description="Target asset identifier to trace pathways to")


class DraftReviewRequest(BaseModel):
    approved: bool = Field(..., description="True if draft is approved, False if rejected")
    review_notes: str = Field(..., min_length=3, max_length=1000, description="Mandatory analyst review comments")


class AIDraftResponse(BaseModel):
    id: str
    project_id: str
    draft_type: AIDraftType
    status: AIDraftStatus
    prompt_version: str
    model_identifier: str
    target_resource: str
    title: str
    summary: str
    content: Dict[str, Any]
    citations: List[Dict[str, Any]]
    uncertainty_notes: Optional[str] = None
    prompt_injection_flags: Optional[List[str]] = None
    is_reviewed: bool
    reviewed_by_id: Optional[str] = None
    reviewed_at: Optional[datetime] = None
    review_notes: Optional[str] = None
    created_at: datetime

    class Config:
        from_attributes = True
