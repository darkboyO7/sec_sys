from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field
from app.models.assessment import AssessmentStatus, FindingSeverity, FindingConfidence


class AssessmentJobCreate(BaseModel):
    target_input: str = Field(min_length=1, max_length=500, description="IP, CIDR, domain, or URL to assess")
    adapter_name: Optional[str] = Field(default="local_fixture_adapter", max_length=100)
    fixture_profile: Optional[str] = Field(default=None, max_length=100)
    timeout_seconds: Optional[int] = Field(default=300, ge=10, le=3600)
    idempotency_key: Optional[str] = Field(default=None, max_length=100)
    policy_version: Optional[str] = Field(default="2026.1", max_length=50)
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
    idempotency_digest: Optional[str] = None
    claimed_by: Optional[str] = None
    worker_pid: Optional[int] = None
    lock_version: int = 1
    progress_pct: int
    policy_version: str = "2026.1"
    authorization_reference: Optional[str] = None
    authorization_status: str = "AUTHORIZED"
    scope_snapshot: Dict[str, Any] = Field(default_factory=dict)
    scope_snapshot_digest: Optional[str] = None
    queued_at: datetime
    preflight_at: Optional[datetime] = None
    started_at: Optional[datetime] = None
    heartbeat_at: Optional[datetime] = None
    cancellation_requested_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    failure_category: Optional[str] = None
    attempt_count: int = 1
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


class AdapterCapabilityResponse(BaseModel):
    name: str
    version: str
    declared_capabilities: List[str]
    supported_profiles: List[str]
    permitted_check_categories: List[str]
    supported_target_types: List[str] = Field(default_factory=list)
    required_permissions: List[str] = Field(default_factory=list)
    default_timeout_seconds: int = 300
    min_timeout_seconds: int = 5
    max_timeout_seconds: int = 3600
    config_schema: Optional[Dict[str, Any]] = None
    status: str = "ACTIVE"
    health: Dict[str, Any]


class FindingEvidenceResponse(BaseModel):
    id: str
    finding_id: str
    evidence_type: str
    payload: Optional[str] = None
    sha256_hash: str
    raw_sha256_hash: Optional[str] = None
    is_truncated: bool = False
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
