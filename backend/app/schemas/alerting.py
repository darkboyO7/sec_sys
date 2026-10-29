"""
VAPT Platform — Reliable Security Alerting & Event Intelligence Schemas (Prompt 31).
Defines versioned canonical security event contracts, alert lifecycle schemas,
and transactional outbox models.
"""
from typing import Optional, List, Dict, Any
from datetime import datetime, timezone
import enum
from pydantic import BaseModel, Field

from app.models.notification import (
    NotificationEventType,
    NotificationSeverity,
    NotificationStatus,
    AlertLifecycleStatus,
)


class SecurityEventContract(BaseModel):
    """
    Canonical versioned event contract for meaningful security and operational events.
    """
    event_id: str
    schema_version: str = "v1.0.0"
    event_type: NotificationEventType
    aggregate_type: str  # FINDING, ASSESSMENT, REMEDIATION, SCOPE, SYSTEM
    aggregate_id: str
    project_id: str
    severity: NotificationSeverity = NotificationSeverity.INFO
    title: str
    summary: str
    correlation_id: Optional[str] = None
    causation_id: Optional[str] = None
    idempotency_key: Optional[str] = None
    evidence_ref: Optional[str] = None
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    payload: Dict[str, Any] = Field(default_factory=dict)


class AlertResponse(BaseModel):
    """
    Operational Alert Entity with full lifecycle, provenance, and delivery state.
    """
    id: str
    project_id: str
    event_type: NotificationEventType
    severity: NotificationSeverity
    title: str
    summary: str
    lifecycle_status: AlertLifecycleStatus
    delivery_status: NotificationStatus
    assigned_to_id: Optional[str] = None
    acknowledged_at: Optional[str] = None
    acknowledged_by_id: Optional[str] = None
    resolved_at: Optional[str] = None
    resolved_by_id: Optional[str] = None
    reopened_at: Optional[str] = None
    escalated_at: Optional[str] = None
    correlation_id: Optional[str] = None
    causation_id: Optional[str] = None
    idempotency_key: Optional[str] = None
    schema_version: str
    suppression_reason: Optional[str] = None
    retry_count: int
    max_retries: int
    last_attempt_at: Optional[str] = None
    error_message: Optional[str] = None
    delivery_attempts_count: int = 0
    created_at: str
    updated_at: str


class AlertListResponse(BaseModel):
    total: int
    limit: int
    offset: int
    active_count: int
    unresolved_count: int
    critical_count: int
    items: List[AlertResponse]


class AlertActionRequest(BaseModel):
    notes: Optional[str] = None


class AlertAssignmentRequest(BaseModel):
    assigned_to_id: str
    notes: Optional[str] = None


class OutboxStatusResponse(BaseModel):
    pending_count: int
    delivered_count: int
    dead_letter_count: int
    suppressed_count: int
    oldest_pending_age_seconds: Optional[int] = None
    healthy: bool
    generated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class MaintenanceWindowCreateRequest(BaseModel):
    title: str
    reason: str
    start_time: str
    end_time: str
    suppress_critical: bool = False


class MaintenanceWindowResponse(BaseModel):
    id: str
    project_id: str
    title: str
    reason: str
    start_time: str
    end_time: str
    suppress_critical: bool
    is_currently_active: bool
    created_at: str
