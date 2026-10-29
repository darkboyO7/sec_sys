"""
Compliance Intelligence, Security Baselines & Configuration Drift Governance Schemas (Prompt 33).
Pydantic schemas for controls, baseline profiles, evaluation runs, drift events, and exceptions.
"""
from typing import List, Optional, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field

from app.models.compliance import (
    ComplianceEvaluationStatus,
    ComplianceExceptionStatus,
    ComplianceDriftType,
)


class ComplianceControlBase(BaseModel):
    control_id: str = Field(..., max_length=50)
    version: str = Field(default="1.0.0", max_length=20)
    category: str = Field(..., max_length=50)
    title: str = Field(..., max_length=255)
    description: str
    requirement_statement: str
    framework: str = Field(default="NIST_CSF_2.0", max_length=100)
    framework_reference: Optional[str] = Field(None, max_length=50)
    applicability_criteria: Dict[str, Any] = Field(default_factory=dict)
    required_evidence_types: List[str] = Field(default_factory=list)
    evaluation_rule: str = Field(..., max_length=100)
    severity: str = Field(default="HIGH", max_length=20)
    remediation_guidance: str
    evaluation_limitations: str
    is_active: bool = True


class ComplianceControlCreate(ComplianceControlBase):
    pass


class ComplianceControlResponse(ComplianceControlBase):
    id: str
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class BaselineProfileBase(BaseModel):
    profile_key: str = Field(..., max_length=100)
    version: str = Field(default="1.0.0", max_length=20)
    name: str = Field(..., max_length=255)
    description: str
    target_applicability: str = Field(default="WEB_APPLICATION", max_length=100)
    is_active: bool = True
    control_ids: List[str] = Field(default_factory=list)
    parameters: Dict[str, Any] = Field(default_factory=dict)


class BaselineProfileCreate(BaselineProfileBase):
    pass


class BaselineProfileUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    is_active: Optional[bool] = None
    control_ids: Optional[List[str]] = None
    parameters: Optional[Dict[str, Any]] = None


class BaselineProfileResponse(BaselineProfileBase):
    id: str
    project_id: str
    created_by_id: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class ComplianceControlResultResponse(BaseModel):
    id: str
    run_id: str
    control_id: str
    control_version: str
    status: ComplianceEvaluationStatus
    asset_id: Optional[str] = None
    evidence_refs: List[Dict[str, Any]] = Field(default_factory=list)
    evidence_digests: List[str] = Field(default_factory=list)
    reasoning: str
    missing_evidence_types: List[str] = Field(default_factory=list)
    confidence_score: float
    limitations: Optional[str] = None
    has_exception: bool = False
    exception_id: Optional[str] = None
    created_at: datetime

    class Config:
        from_attributes = True


class ComplianceEvaluationRunResponse(BaseModel):
    id: str
    project_id: str
    baseline_profile_id: str
    baseline_profile_key: Optional[str] = None
    baseline_profile_version: Optional[str] = None
    assessment_id: Optional[str] = None
    run_status: str
    pass_count: int
    fail_count: int
    partial_count: int
    unknown_count: int
    not_applicable_count: int
    error_count: int
    total_controls_evaluated: int
    provenance_digest: str
    evaluated_at: datetime
    evaluated_by_id: Optional[str] = None
    control_results: List[ComplianceControlResultResponse] = Field(default_factory=list)

    class Config:
        from_attributes = True


class ComplianceEvaluationRequest(BaseModel):
    baseline_profile_id: str
    assessment_id: Optional[str] = None
    asset_ids: Optional[List[str]] = None


class ComplianceDriftEventResponse(BaseModel):
    id: str
    project_id: str
    control_id: str
    asset_id: Optional[str] = None
    drift_type: ComplianceDriftType
    previous_status: ComplianceEvaluationStatus
    new_status: ComplianceEvaluationStatus
    previous_run_id: Optional[str] = None
    current_run_id: str
    reason: str
    detected_at: datetime
    deduplication_hash: str

    class Config:
        from_attributes = True


class ComplianceExceptionCreate(BaseModel):
    control_id: str = Field(..., max_length=50)
    asset_id: Optional[str] = None
    justification: str
    risk_assessment: str
    compensating_controls: str
    expires_at: datetime


class ComplianceExceptionReview(BaseModel):
    approved: bool
    review_notes: Optional[str] = None


class ComplianceExceptionResponse(BaseModel):
    id: str
    project_id: str
    control_id: str
    asset_id: Optional[str] = None
    justification: str
    risk_assessment: str
    compensating_controls: str
    requester_id: str
    approver_id: Optional[str] = None
    status: ComplianceExceptionStatus
    expires_at: datetime
    approved_at: Optional[datetime] = None
    revoked_at: Optional[datetime] = None
    review_notes: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class ComplianceComparisonResponse(BaseModel):
    baseline_profile_id: str
    run_a: ComplianceEvaluationRunResponse
    run_b: ComplianceEvaluationRunResponse
    regressions: List[Dict[str, Any]]
    improvements: List[Dict[str, Any]]
    uncertainties: List[Dict[str, Any]]
    unchanged_count: int
