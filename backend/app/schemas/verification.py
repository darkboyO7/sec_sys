from datetime import datetime
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, ConfigDict, Field
from app.models.verification import VerificationOutcome, VerificationMethod


class RemediationVerificationCreate(BaseModel):
    verification_method: VerificationMethod = VerificationMethod.PASSIVE_SCAN
    outcome: VerificationOutcome
    verification_criteria: str = Field(..., min_length=5, max_length=1000)
    verification_evidence_summary: str = Field(..., min_length=5, max_length=2000)
    verification_evidence_data: Dict[str, Any] = Field(default_factory=dict)
    notes: str = Field(..., min_length=3, max_length=2000)
    recommendation_id: Optional[str] = None
    baseline_evidence_hash: Optional[str] = None


class RemediationVerificationRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    project_id: str
    finding_id: str
    recommendation_id: Optional[str] = None
    verifier_id: Optional[str] = None
    verification_method: VerificationMethod
    outcome: VerificationOutcome
    verification_criteria: str
    baseline_evidence_hash: Optional[str] = None
    verification_evidence_summary: str
    verification_evidence_data: Dict[str, Any] = Field(default_factory=dict)
    notes: str
    verified_at: datetime
    created_at: datetime
    updated_at: datetime


class AutomatedVerificationRequest(BaseModel):
    adapter_name: str = "passive_header_adapter"
    config: Dict[str, Any] = Field(default_factory=dict)
    notes: str = Field(..., min_length=3, max_length=1000)
