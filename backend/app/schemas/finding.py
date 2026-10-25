from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, ConfigDict, Field

from app.models.finding import FindingLifecycleStatus
from app.models.assessment import FindingSeverity, FindingConfidence


class FindingTransitionRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    finding_id: str
    from_status: FindingLifecycleStatus
    to_status: FindingLifecycleStatus
    actor_id: Optional[str] = None
    reason: str
    metadata_snapshot: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime


class VulnerabilityFindingRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    project_id: str
    fingerprint: str
    target_value: str
    title: str
    description: str

    status: FindingLifecycleStatus
    severity: FindingSeverity
    confidence: FindingConfidence
    vuln_id: Optional[str] = None
    cvss_score: Optional[float] = None

    is_simulated: bool
    reproduction_steps: str

    first_detected_at: datetime
    last_observed_at: datetime
    occurrence_count: int

    has_contradictions: bool
    contradiction_notes: List[Dict[str, Any]] = Field(default_factory=list)

    assigned_to_id: Optional[str] = None
    remediation_notes: Optional[str] = None

    risk_accepted_at: Optional[datetime] = None
    risk_accepted_by_id: Optional[str] = None
    risk_accepted_reason: Optional[str] = None
    risk_accepted_expires_at: Optional[datetime] = None
    compensating_controls: Optional[str] = None

    false_positive_at: Optional[datetime] = None
    false_positive_by_id: Optional[str] = None
    false_positive_reason: Optional[str] = None

    verified_at: Optional[datetime] = None
    verified_by_id: Optional[str] = None
    verification_job_id: Optional[str] = None
    verification_notes: Optional[str] = None

    created_at: datetime
    updated_at: datetime


class VulnerabilityFindingDetail(VulnerabilityFindingRead):
    transitions: List[FindingTransitionRead] = Field(default_factory=list)
    observation_job_ids: List[str] = Field(default_factory=list)
    evidence_count: int = 0


class FindingTransitionRequest(BaseModel):
    to_status: FindingLifecycleStatus
    reason: str = Field(..., min_length=5, max_length=2000)
    expires_at: Optional[datetime] = None
    compensating_controls: Optional[str] = Field(None, max_length=2000)
    verification_job_id: Optional[str] = None
    verification_notes: Optional[str] = Field(None, max_length=2000)
    remediation_notes: Optional[str] = Field(None, max_length=2000)
    assigned_to_id: Optional[str] = None


class AcceptRiskRequest(BaseModel):
    reason: str = Field(..., min_length=10, max_length=2000)
    expires_at: datetime
    compensating_controls: str = Field(..., min_length=5, max_length=2000)


class FalsePositiveRequest(BaseModel):
    reason: str = Field(..., min_length=10, max_length=2000)


class ProposeRemediationRequest(BaseModel):
    remediation_notes: str = Field(..., min_length=5, max_length=2000)
    assigned_to_id: Optional[str] = None


class FindingStatsResponse(BaseModel):
    total: int
    by_status: Dict[str, int]
    by_severity: Dict[str, int]
    unresolved_count: int
    reopened_count: int
    accepted_risk_count: int
    contradiction_count: int
