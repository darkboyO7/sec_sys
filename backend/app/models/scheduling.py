"""
Intelligent Assessment Scheduling, Risk-Based Prioritization & Resource-Aware Orchestration (Prompt 34).
Domain models for persistent queued work, deterministic priority rankings, eligibility enforcement,
worker lease management, scheduler decision ledger, and project-level orchestration policies.
"""
import enum
from sqlalchemy import (
    Column,
    String,
    Integer,
    Float,
    Boolean,
    ForeignKey,
    Enum as SqlEnum,
    DateTime,
    Text,
    JSON,
    Index,
)
from sqlalchemy.orm import relationship, backref

from app.core.database import Base
from app.models.base import TimestampMixin, generate_uuid, utc_now


class QueueItemStatus(str, enum.Enum):
    PENDING = "PENDING"
    SCHEDULED = "SCHEDULED"
    DISPATCHED = "DISPATCHED"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    DEFERRED = "DEFERRED"
    PAUSED = "PAUSED"


class PriorityBand(str, enum.Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class EligibilityStatus(str, enum.Enum):
    ELIGIBLE = "ELIGIBLE"
    EXCLUDED = "EXCLUDED"
    UNAUTHORIZED = "UNAUTHORIZED"
    APPROVAL_REQUIRED = "APPROVAL_REQUIRED"
    RATE_LIMITED = "RATE_LIMITED"
    UNKNOWN = "UNKNOWN"


class SchedulerDecisionType(str, enum.Enum):
    ENQUEUE = "ENQUEUE"
    DISPATCH = "DISPATCH"
    DEFER = "DEFER"
    DEDUPLICATE = "DEDUPLICATE"
    REJECT = "REJECT"
    CANCEL = "CANCEL"
    RECOVER = "RECOVER"
    RETRY_BACKOFF = "RETRY_BACKOFF"


class TriggerSourceType(str, enum.Enum):
    MANUAL_DISPATCH = "MANUAL_DISPATCH"
    DRIFT_DETECTED = "DRIFT_DETECTED"
    HIGH_SEVERITY_FINDING = "HIGH_SEVERITY_FINDING"
    FAILED_RETEST = "FAILED_RETEST"
    STALE_EVIDENCE = "STALE_EVIDENCE"
    COMPLIANCE_FAILURE = "COMPLIANCE_FAILURE"
    LEASE_RECOVERY = "LEASE_RECOVERY"
    SCHEDULED_TIMER = "SCHEDULED_TIMER"


class AssessmentQueueItem(Base, TimestampMixin):
    """
    Persistent, durable queue entry for authorized assessment workloads.
    Supports deterministic multi-signal priority scores, explainable factor breakdowns,
    worker leases with timeout-based recovery, bounded backoff retries, and cancellation.
    """
    __tablename__ = "assessment_queue_items"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    project_id = Column(String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    target_id = Column(String(36), ForeignKey("scope_targets.id", ondelete="SET NULL"), nullable=True, index=True)

    schedule_name = Column(String(100), default="Ad-Hoc Assessment", nullable=False)
    target_input = Column(String(500), nullable=False, index=True)
    adapter_name = Column(String(100), default="local_fixture_adapter", nullable=False)
    adapter_version = Column(String(50), default="1.0.0", nullable=False)

    status = Column(SqlEnum(QueueItemStatus), default=QueueItemStatus.SCHEDULED, nullable=False, index=True)
    priority_score = Column(Float, default=50.0, nullable=False, index=True)
    priority_band = Column(SqlEnum(PriorityBand), default=PriorityBand.MEDIUM, nullable=False, index=True)
    priority_explanation = Column(Text, nullable=False)
    priority_factors = Column(JSON, default=dict, nullable=False)
    policy_version = Column(String(50), default="scheduling_v1.0", nullable=False)

    eligibility_status = Column(SqlEnum(EligibilityStatus), default=EligibilityStatus.ELIGIBLE, nullable=False, index=True)
    eligibility_reasons = Column(JSON, default=list, nullable=False)

    idempotency_key = Column(String(100), nullable=True, index=True)
    concurrency_key = Column(String(100), nullable=False, index=True)

    worker_claim_id = Column(String(100), nullable=True, index=True)
    claimed_at = Column(DateTime(timezone=True), nullable=True)
    lease_expires_at = Column(DateTime(timezone=True), nullable=True, index=True)

    attempt_count = Column(Integer, default=0, nullable=False)
    retry_count = Column(Integer, default=0, nullable=False)
    max_retries = Column(Integer, default=3, nullable=False)
    backoff_seconds = Column(Integer, default=30, nullable=False)
    next_eligible_at = Column(DateTime(timezone=True), default=utc_now, nullable=False, index=True)

    deadline_at = Column(DateTime(timezone=True), nullable=True)
    execution_budget_seconds = Column(Integer, default=600, nullable=False)

    cancellation_requested_at = Column(DateTime(timezone=True), nullable=True)
    cancellation_reason = Column(Text, nullable=True)
    cancelled_at = Column(DateTime(timezone=True), nullable=True)

    last_error_category = Column(String(100), nullable=True, index=True)
    last_error_message = Column(Text, nullable=True)

    job_id = Column(String(36), ForeignKey("assessment_jobs.id", ondelete="SET NULL"), nullable=True, index=True)
    created_by_id = Column(String(36), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False)

    project = relationship("Project", backref=backref("scheduled_queue_items", cascade="all, delete-orphan"))
    target = relationship("ScopeTarget")
    created_by = relationship("User")
    job = relationship("AssessmentJob")

    __table_args__ = (
        Index("ix_queue_items_proj_status_prio", "project_id", "status", "priority_score"),
        Index("ix_queue_items_claim_lease", "status", "lease_expires_at"),
        Index("ix_queue_items_concurrency", "project_id", "concurrency_key", "status"),
        Index("ix_queue_items_idempotency", "project_id", "idempotency_key"),
    )


class SchedulerDecisionRecord(Base, TimestampMixin):
    """
    Append-only audit ledger of scheduler decisions, preserving full provenance
    for prioritization, deferrals, capacity throttles, deduplications, and lease recoveries.
    """
    __tablename__ = "scheduler_decision_records"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    project_id = Column(String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    queue_item_id = Column(String(36), ForeignKey("assessment_queue_items.id", ondelete="SET NULL"), nullable=True, index=True)

    trigger_source = Column(String(100), default="MANUAL_DISPATCH", nullable=False, index=True)
    target_input = Column(String(500), nullable=False, index=True)
    decision_type = Column(SqlEnum(SchedulerDecisionType), nullable=False, index=True)
    priority_score = Column(Float, default=0.0, nullable=False)

    decision_rationale = Column(Text, nullable=False)
    capacity_snapshot = Column(JSON, default=dict, nullable=False)
    metadata_payload = Column(JSON, default=dict, nullable=False)

    project = relationship("Project", backref=backref("scheduler_decisions", cascade="all, delete-orphan"))
    queue_item = relationship("AssessmentQueueItem")

    __table_args__ = (
        Index("ix_sched_decisions_proj_type_created", "project_id", "decision_type", "created_at"),
    )


class SchedulerPolicyRecord(Base, TimestampMixin):
    """
    Configurable, versioned scheduling and concurrency policy per project.
    Governs total concurrent assessments, per-target and per-adapter throttles,
    anti-starvation aging rates, and queue depth bounds.
    """
    __tablename__ = "scheduler_policies"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    project_id = Column(String(36), ForeignKey("projects.id", ondelete="CASCADE"), unique=True, nullable=False, index=True)

    policy_version = Column(String(50), default="scheduling_v1.0", nullable=False)
    max_concurrent_assessments = Column(Integer, default=5, nullable=False)
    max_per_target_concurrency = Column(Integer, default=1, nullable=False)
    max_per_adapter_concurrency = Column(Integer, default=2, nullable=False)
    max_queued_jobs = Column(Integer, default=100, nullable=False)
    max_execution_duration_sec = Column(Integer, default=600, nullable=False)
    max_retries = Column(Integer, default=3, nullable=False)
    aging_factor_per_hour = Column(Float, default=2.0, nullable=False)
    stale_lease_timeout_sec = Column(Integer, default=120, nullable=False)
    cooldown_period_sec = Column(Integer, default=3600, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)

    project = relationship("Project", backref=backref("scheduler_policy", uselist=False, cascade="all, delete-orphan"))
