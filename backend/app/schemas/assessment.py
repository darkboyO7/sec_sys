from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field
from app.models.assessment import AssessmentStatus, FindingSeverity, FindingConfidence


class AssessmentJobCreate(BaseModel):
    target_input: str = Field(min_length=1, max_length=500, description="IP, CIDR, domain, or URL to assess")
    adapter_name: Optional[str] = Field(default="local_fixture_adapter", max_length=100)
    fixture_profile: Optional[str] = Field(default="WEB_APPLICATION_BASELINE", max_length=100)
    timeout_seconds: Optional[int] = Field(default=300, ge=10, le=3600)
    idempotency_key: Optional[str] = Field(default=None, max_length=100)
    config: Optional[Dict[str, Any]] = Field(default_factory=dict)


class AssessmentJobResponse(BaseModel):
    id: str
    project_id: str
    target_id: Optional[str] = None
    target_input: str
    adapter_name: str
    adapter_version: str
    status: AssessmentStatus
    idempotency_key: Optional[str] = None
    progress_pct: int
    queued_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    timeout_seconds: int
    retry_count: int
    max_retries: int
    error_message: Optional[str] = None
    is_simulated: bool
    created_by_id: str
    config: Dict[str, Any]
    summary_stats: Dict[str, Any]
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class FindingEvidenceResponse(BaseModel):
    id: str
    finding_id: str
    evidence_type: str
    payload: str
    sha256_hash: str
    observed_at: datetime

    class Config:
        from_attributes = True


class AssessmentFindingResponse(BaseModel):
    id: str
    job_id: str
    project_id: str
    target_value: str
    title: str
    description: str
    severity: FindingSeverity
    confidence: FindingConfidence
    vuln_id: Optional[str] = None
    cvss_score: Optional[float] = None
    is_simulated: bool
    reproduction_steps: str
    created_at: datetime
    evidence_items: List[FindingEvidenceResponse] = Field(default_factory=list)

    class Config:
        from_attributes = True
