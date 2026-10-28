from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, ConfigDict
from datetime import datetime


# ------------------------------------------------------------------------------
# Policy Schemas
# ------------------------------------------------------------------------------
class PolicyRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    project_id: str
    policy_version: str
    is_active: bool
    is_suspended: bool
    suspension_reason: Optional[str] = None
    suspended_at: Optional[datetime] = None
    permitted_assessment_types: List[str]
    intensity: str
    max_concurrency: int
    rate_limit_rps: float
    permitted_time_windows: List[Dict[str, int]]
    max_daily_budget: int
    daily_budget_spent: int
    permitted_remediation_actions: List[str]
    require_approval_for_disruptive: bool
    require_approval_for_remediation: bool
    max_retries: int
    failure_threshold: int
    consecutive_failures: int


class PolicyUpdateRequest(BaseModel):
    permitted_assessment_types: Optional[List[str]] = None
    intensity: Optional[str] = None
    max_concurrency: Optional[int] = Field(None, ge=1, le=10)
    rate_limit_rps: Optional[float] = Field(None, ge=0.1, le=100.0)
    permitted_time_windows: Optional[List[Dict[str, int]]] = None
    max_daily_budget: Optional[int] = Field(None, ge=1, le=1000)
    permitted_remediation_actions: Optional[List[str]] = None
    require_approval_for_disruptive: Optional[bool] = None
    require_approval_for_remediation: Optional[bool] = None
    max_retries: Optional[int] = Field(None, ge=0, le=5)
    failure_threshold: Optional[int] = Field(None, ge=1, le=20)


class EmergencySuspendRequest(BaseModel):
    reason: str = Field(..., min_length=3, max_length=500)


# ------------------------------------------------------------------------------
# Decision Ledger Schemas
# ------------------------------------------------------------------------------
class DecisionLedgerRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    project_id: str
    decision_type: str
    decision_outcome: str
    initiating_event: str
    target_type: str
    target_id: Optional[str] = None
    target_resource: Optional[str] = None
    policy_version: str
    reason: str
    evidence_references: List[Dict[str, Any]] = Field(default_factory=list)
    details: Dict[str, Any] = Field(default_factory=dict)
    actor_id: Optional[str] = None
    created_at: datetime


class DecisionLedgerListResponse(BaseModel):
    total: int
    limit: int
    offset: int
    records: List[DecisionLedgerRead]


# ------------------------------------------------------------------------------
# Notification Schemas
# ------------------------------------------------------------------------------
class NotificationRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    project_id: str
    event_type: str
    severity: str
    title: str
    summary: str
    deduplication_key: str
    status: str
    retry_count: int
    max_retries: int
    last_attempt_at: Optional[datetime] = None
    error_message: Optional[str] = None
    delivery_metadata: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime


class NotificationListResponse(BaseModel):
    total: int
    limit: int
    offset: int
    records: List[NotificationRead]


class NotificationProviderStatusRead(BaseModel):
    project_id: str
    webhook_configured: bool
    provider_status: str
    destination_preview: Optional[str] = None
    counts: Dict[str, int]


# ------------------------------------------------------------------------------
# Operational SLO Schemas
# ------------------------------------------------------------------------------
class SLOConfigRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    project_id: str
    min_assessment_completion_rate: float
    max_queue_delay_seconds: float
    min_evidence_completeness_rate: float
    max_inconclusive_rate: float
    min_remediation_completion_rate: float
    min_verification_pass_rate: float
    min_asset_coverage_rate: float
    coverage_stale_days: int


class SLOConfigUpdateRequest(BaseModel):
    min_assessment_completion_rate: Optional[float] = Field(None, ge=10.0, le=100.0)
    max_queue_delay_seconds: Optional[float] = Field(None, ge=10.0, le=3600.0)
    min_evidence_completeness_rate: Optional[float] = Field(None, ge=10.0, le=100.0)
    max_inconclusive_rate: Optional[float] = Field(None, ge=1.0, le=50.0)
    min_remediation_completion_rate: Optional[float] = Field(None, ge=10.0, le=100.0)
    min_verification_pass_rate: Optional[float] = Field(None, ge=10.0, le=100.0)
    min_asset_coverage_rate: Optional[float] = Field(None, ge=10.0, le=100.0)
    coverage_stale_days: Optional[int] = Field(None, ge=1, le=90)


# ------------------------------------------------------------------------------
# Dashboard & Lifecycle Schemas
# ------------------------------------------------------------------------------
class OperationsDashboardRead(BaseModel):
    project_id: str
    timestamp: str
    policy: Dict[str, Any]
    operations_summary: Dict[str, Any]
    slo_health: Dict[str, Any]
    recent_decisions: List[Dict[str, Any]]
    recent_notifications: List[Dict[str, Any]]
    notification_provider: Dict[str, Any]


class LifecycleTransitionRequest(BaseModel):
    action: str = Field(..., pattern="^(AUTHORIZE_RETEST|CLOSE_FINDING|REOPEN_FINDING)$")
    notes: Optional[str] = Field(default="", max_length=1000)


class LifecycleTransitionResponse(BaseModel):
    success: bool
    finding_id: str
    previous_status: Optional[str] = None
    current_status: Optional[str] = None
    error: Optional[str] = None
