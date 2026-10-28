from datetime import datetime
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field

from app.models.orchestration import (
    OrchestrationState,
    OrchestrationEventType,
    OrchestrationActionType,
    OutcomeMeasurementStatus,
    EventProcessingStatus,
    InvalidationStatus,
)


class EventIngestRequest(BaseModel):
    event_type: OrchestrationEventType
    target_resource: str
    payload: Dict[str, Any] = Field(default_factory=dict)
    event_source: str = "OPERATOR"


class EventRead(BaseModel):
    id: str
    project_id: str
    event_type: OrchestrationEventType
    event_source: str
    dedup_key: str
    target_resource: str
    payload: Dict[str, Any]
    status: EventProcessingStatus
    coalesced_count: int
    received_at: datetime
    processed_at: Optional[datetime] = None
    rejection_reason: Optional[str] = None

    class Config:
        from_attributes = True


class WorkflowRead(BaseModel):
    id: str
    project_id: str
    state: OrchestrationState
    trigger_event_id: Optional[str] = None
    workflow_type: str
    target_resource: str
    context_data: Dict[str, Any]
    recommended_action: Optional[OrchestrationActionType] = None
    action_rationale: Optional[str] = None
    confidence: float
    uncertainty: float
    required_approval_role: Optional[str] = None
    approved_by_id: Optional[str] = None
    approved_at: Optional[datetime] = None
    locked_by: Optional[str] = None
    attempt_count: int
    max_retries: int
    suspension_reason: Optional[str] = None
    failure_reason: Optional[str] = None
    partial_results: Dict[str, Any]
    outcome_status: Optional[OutcomeMeasurementStatus] = None
    outcome_measurement: Dict[str, Any]
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class WorkflowActionRequest(BaseModel):
    notes: Optional[str] = ""


class WorkflowActionResponse(BaseModel):
    workflow_id: str
    state: OrchestrationState
    message: str


class OrchestrationDashboardRead(BaseModel):
    project_id: str
    timestamp: str
    summary: Dict[str, Any]
    active_workflows: List[WorkflowRead]
    recent_events: List[EventRead]
    pending_approvals: List[WorkflowRead]


class AdaptiveOptimizationRead(BaseModel):
    id: str
    project_id: str
    optimization_name: str
    objective: str
    evaluation_metric: str
    baseline_value: float
    evaluated_value: float
    threshold_value: float
    dataset_summary: Dict[str, Any]
    is_accepted: bool
    rejection_reason: Optional[str] = None
    evaluated_by_model: str
    evaluated_at: datetime

    class Config:
        from_attributes = True


class DependencyInvalidationRead(BaseModel):
    id: str
    project_id: str
    source_entity_type: str
    source_entity_id: str
    invalidation_type: str
    invalidated_targets: List[Dict[str, Any]]
    recalculation_status: InvalidationStatus
    provenance: Dict[str, Any]
    recalculated_at: Optional[datetime] = None
    created_at: datetime

    class Config:
        from_attributes = True
