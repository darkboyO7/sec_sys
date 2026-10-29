"""
VAPT Platform — Unified Security Operations Experience Schemas (Prompt 30).
Defines typed models for the Operator Command Center, 12 Core Operational Answers,
and the Actionable Priority Queue.
"""
from typing import Optional, List, Dict, Any
from datetime import datetime, timezone
import enum
from pydantic import BaseModel, Field


class OperationalStatus(str, enum.Enum):
    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    CRITICAL = "CRITICAL"


class PriorityQueueCategory(str, enum.Enum):
    REMEDIATION_APPROVAL = "REMEDIATION_APPROVAL"
    RETEST_FAILED = "RETEST_FAILED"
    JOB_FAILED = "JOB_FAILED"
    EXPOSURE_DRIFT = "EXPOSURE_DRIFT"
    INTEGRITY_ALERT = "INTEGRITY_ALERT"
    RETENTION_EXPIRATION = "RETENTION_EXPIRATION"
    SCOPE_EXPIRING = "SCOPE_EXPIRING"


class PriorityQueueItem(BaseModel):
    item_id: str
    priority_score: int  # 1-100 (100 most urgent)
    category: PriorityQueueCategory
    title: str
    reason: str
    affected_asset: Optional[str] = None
    affected_finding_id: Optional[str] = None
    evidence_ref: Optional[str] = None
    permitted_action: str
    required_role: str
    target_route: str
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class PriorityQueueResponse(BaseModel):
    total_items: int
    urgent_items_count: int
    items: List[PriorityQueueItem]
    retrieved_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class OperatorCoreQuestion(BaseModel):
    question_id: int  # 1 to 12
    question_text: str
    status: str  # "PASS", "WARN", "FAIL", "INFO"
    summary: str
    details: Dict[str, Any] = Field(default_factory=dict)


class UnifiedOpsDashboardResponse(BaseModel):
    overall_posture: str  # "HEALTHY", "ATTENTION_REQUIRED", "ELEVATED_RISK"
    control_plane_health: str
    active_assessments_count: int
    queued_assessments_count: int
    failed_assessments_count: int
    verified_critical_findings: int
    verified_high_findings: int
    unresolved_uncertainties_count: int
    pending_remediation_approvals: int
    failed_retests_count: int
    exposure_drift_records_count: int
    data_freshness_seconds: int
    core_questions: List[OperatorCoreQuestion]
    recommended_next_action: str
    generated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
