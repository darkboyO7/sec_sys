"""
Pydantic Schemas for Intelligent Assessment Scheduling & Orchestration (Prompt 34).
"""
from datetime import datetime
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field

from app.models.scheduling import (
    QueueItemStatus,
    PriorityBand,
    EligibilityStatus,
    SchedulerDecisionType,
    TriggerSourceType,
)


class PriorityFactorItem(BaseModel):
    signal_name: str
    raw_value: Any
    weight: float
    contribution: float
    source_reference: Optional[str] = None


class PriorityCalculationDetail(BaseModel):
    computed_priority: float = Field(..., ge=0.0, le=100.0)
    priority_band: PriorityBand
    summary: str
    factors: Dict[str, Any]
    policy_version: str
    calculated_at: datetime
    missing_evidence_signals: List[str] = []


class QueueItemCreate(BaseModel):
    schedule_name: Optional[str] = "Ad-Hoc Assessment"
    target_input: str = Field(..., min_length=1, max_length=500)
    adapter_name: Optional[str] = "local_fixture_adapter"
    deadline_at: Optional[datetime] = None
    execution_budget_seconds: Optional[int] = Field(default=600, ge=30, le=7200)


class QueueItemPreviewRequest(BaseModel):
    target_input: str = Field(..., min_length=1, max_length=500)
    adapter_name: Optional[str] = "local_fixture_adapter"


class QueueItemPreviewResponse(BaseModel):
    target_input: str
    adapter_name: str
    is_eligible: bool
    eligibility_status: EligibilityStatus
    eligibility_reasons: List[str]
    computed_priority: float
    priority_band: PriorityBand
    priority_explanation: str
    priority_factors: Dict[str, Any]
    policy_version: str


class QueueItemResponse(BaseModel):
    id: str
    project_id: str
    target_id: Optional[str] = None
    schedule_name: str
    target_input: str
    adapter_name: str
    adapter_version: str
    status: QueueItemStatus
    priority_score: float
    priority_band: PriorityBand
    priority_explanation: str
    priority_factors: Dict[str, Any]
    policy_version: str
    eligibility_status: EligibilityStatus
    eligibility_reasons: List[str]
    idempotency_key: Optional[str] = None
    concurrency_key: str
    worker_claim_id: Optional[str] = None
    claimed_at: Optional[datetime] = None
    lease_expires_at: Optional[datetime] = None
    attempt_count: int
    retry_count: int
    max_retries: int
    backoff_seconds: int
    next_eligible_at: datetime
    deadline_at: Optional[datetime] = None
    execution_budget_seconds: int
    cancellation_requested_at: Optional[datetime] = None
    cancellation_reason: Optional[str] = None
    cancelled_at: Optional[datetime] = None
    last_error_category: Optional[str] = None
    last_error_message: Optional[str] = None
    job_id: Optional[str] = None
    created_by_id: str
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class TriggerAssessmentRequest(BaseModel):
    trigger_source: TriggerSourceType = TriggerSourceType.MANUAL_DISPATCH
    target_input: str = Field(..., min_length=1, max_length=500)
    adapter_name: Optional[str] = "local_fixture_adapter"
    metadata: Optional[Dict[str, Any]] = None


class DispatchResultResponse(BaseModel):
    dispatched: bool
    message: str
    queue_item: Optional[QueueItemResponse] = None
    job_id: Optional[str] = None


class LeaseRecoveryResponse(BaseModel):
    recovered_count: int
    dead_letter_count: int
    recovered_ids: List[str]
    dead_letter_ids: List[str]


class SchedulerCapacityResponse(BaseModel):
    project_id: str
    max_concurrent_assessments: int
    current_running_assessments: int
    available_capacity: int
    total_queued_items: int
    active_by_target: Dict[str, int]
    active_by_adapter: Dict[str, int]
    queue_utilization_pct: float
    stale_unclaimed_leases: int


class SchedulerDecisionResponse(BaseModel):
    id: str
    project_id: str
    queue_item_id: Optional[str] = None
    trigger_source: str
    target_input: str
    decision_type: SchedulerDecisionType
    priority_score: float
    decision_rationale: str
    capacity_snapshot: Dict[str, Any]
    metadata_payload: Dict[str, Any]
    created_at: datetime

    class Config:
        from_attributes = True


class SchedulerPolicyUpdate(BaseModel):
    max_concurrent_assessments: Optional[int] = Field(None, ge=1, le=50)
    max_per_target_concurrency: Optional[int] = Field(None, ge=1, le=10)
    max_per_adapter_concurrency: Optional[int] = Field(None, ge=1, le=20)
    max_queued_jobs: Optional[int] = Field(None, ge=5, le=1000)
    max_execution_duration_sec: Optional[int] = Field(None, ge=30, le=7200)
    max_retries: Optional[int] = Field(None, ge=0, le=10)
    aging_factor_per_hour: Optional[float] = Field(None, ge=0.0, le=50.0)
    stale_lease_timeout_sec: Optional[int] = Field(None, ge=15, le=1800)
    cooldown_period_sec: Optional[int] = Field(None, ge=0, le=86400)
    is_active: Optional[bool] = None


class SchedulerPolicyResponse(BaseModel):
    id: str
    project_id: str
    policy_version: str
    max_concurrent_assessments: int
    max_per_target_concurrency: int
    max_per_adapter_concurrency: int
    max_queued_jobs: int
    max_execution_duration_sec: int
    max_retries: int
    aging_factor_per_hour: float
    stale_lease_timeout_sec: int
    cooldown_period_sec: int
    is_active: bool
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True
