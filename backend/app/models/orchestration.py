import enum
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List
from sqlalchemy import (
    Column,
    String,
    Integer,
    Float,
    Boolean,
    DateTime,
    Enum as SqlEnum,
    ForeignKey,
    JSON,
    Text,
    Index,
)
from sqlalchemy.orm import relationship, backref

from app.core.database import Base
from app.models.base import TimestampMixin, generate_uuid, utc_now


class OrchestrationState(str, enum.Enum):
    IDLE = "IDLE"
    EVENT_RECEIVED = "EVENT_RECEIVED"
    CONTEXT_GATHERED = "CONTEXT_GATHERED"
    DECISION_PENDING = "DECISION_PENDING"
    AWAITING_APPROVAL = "AWAITING_APPROVAL"
    ACTION_QUEUED = "ACTION_QUEUED"
    ACTION_RUNNING = "ACTION_RUNNING"
    VERIFYING_OUTCOME = "VERIFYING_OUTCOME"
    COMPLETED = "COMPLETED"
    PARTIALLY_COMPLETED = "PARTIALLY_COMPLETED"
    FAILED = "FAILED"
    SUSPENDED = "SUSPENDED"


class OrchestrationEventType(str, enum.Enum):
    ASSET_DISCOVERED = "ASSET_DISCOVERED"
    CONFIG_CHANGED = "CONFIG_CHANGED"
    SCAN_COMPLETED = "SCAN_COMPLETED"
    FINDING_DETECTED = "FINDING_DETECTED"
    REMEDIATION_APPLIED = "REMEDIATION_APPLIED"
    INTEGRITY_ALERT = "INTEGRITY_ALERT"
    DIAGNOSTIC_FAILURE = "DIAGNOSTIC_FAILURE"
    SCHEDULED_POLL = "SCHEDULED_POLL"
    MANUAL_TRIGGER = "MANUAL_TRIGGER"


class OrchestrationActionType(str, enum.Enum):
    REASSESS_CHANGED_ASSET = "REASSESS_CHANGED_ASSET"
    REFRESH_STALE_EVIDENCE = "REFRESH_STALE_EVIDENCE"
    RETRY_FAILED_ASSESSMENT = "RETRY_FAILED_ASSESSMENT"
    RECALCULATE_RISK_AND_PATHS = "RECALCULATE_RISK_AND_PATHS"
    RECOMMEND_REMEDIATION = "RECOMMEND_REMEDIATION"
    REQUEST_HUMAN_APPROVAL = "REQUEST_HUMAN_APPROVAL"
    SCHEDULE_INDEPENDENT_RETEST = "SCHEDULE_INDEPENDENT_RETEST"
    RUN_DIAGNOSTICS = "RUN_DIAGNOSTICS"
    SUSPEND_ACTIVITY = "SUSPEND_ACTIVITY"
    NO_ACTION_REQUIRED = "NO_ACTION_REQUIRED"


class OutcomeMeasurementStatus(str, enum.Enum):
    ACTION_EXECUTED_SUCCESSFULLY = "ACTION_EXECUTED_SUCCESSFULLY"
    FINDING_VERIFIED_RESOLVED = "FINDING_VERIFIED_RESOLVED"
    RISK_SCORE_DECREASED = "RISK_SCORE_DECREASED"
    EVIDENCE_COVERAGE_IMPROVED = "EVIDENCE_COVERAGE_IMPROVED"
    NO_MEASURABLE_IMPROVEMENT = "NO_MEASURABLE_IMPROVEMENT"
    OUTCOME_INCONCLUSIVE = "OUTCOME_INCONCLUSIVE"
    FAILED = "FAILED"


class EventProcessingStatus(str, enum.Enum):
    RECEIVED = "RECEIVED"
    PROCESSED = "PROCESSED"
    DEDUPLICATED = "DEDUPLICATED"
    DEFERRED = "DEFERRED"
    REJECTED = "REJECTED"
    FAILED = "FAILED"


class OrchestrationEventRecord(Base, TimestampMixin):
    """
    Persistent incoming event record for security operations orchestration.
    Maintains deterministic deduplication keys and coalescing counters.
    """
    __tablename__ = "orchestration_events"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    project_id = Column(String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)

    event_type = Column(SqlEnum(OrchestrationEventType), nullable=False, index=True)
    event_source = Column(String(100), default="ORCHESTRATOR", nullable=False)
    dedup_key = Column(String(64), nullable=False, index=True)
    target_resource = Column(String(500), nullable=False, index=True)

    payload = Column(JSON, default=dict, nullable=False)
    status = Column(SqlEnum(EventProcessingStatus), default=EventProcessingStatus.RECEIVED, nullable=False, index=True)
    coalesced_count = Column(Integer, default=1, nullable=False)

    received_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    processed_at = Column(DateTime(timezone=True), nullable=True)
    rejection_reason = Column(Text, nullable=True)

    project = relationship("Project", backref=backref("orchestration_events", cascade="all, delete-orphan"))

    __table_args__ = (
        Index("ix_orchestration_events_project_dedup", "project_id", "dedup_key"),
        Index("ix_orchestration_events_status_received", "status", "received_at"),
    )


class OrchestrationWorkflowRecord(Base, TimestampMixin):
    """
    Persistent central orchestration workflow state record.
    Tracks state machine progression, decision provenance, locks, approvals, and outcomes.
    """
    __tablename__ = "orchestration_workflows"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    project_id = Column(String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)

    state = Column(SqlEnum(OrchestrationState), default=OrchestrationState.IDLE, nullable=False, index=True)
    trigger_event_id = Column(String(36), ForeignKey("orchestration_events.id", ondelete="SET NULL"), nullable=True, index=True)
    workflow_type = Column(String(100), default="ASSESSMENT_CYCLE", nullable=False)
    target_resource = Column(String(500), nullable=False, index=True)

    context_data = Column(JSON, default=dict, nullable=False)
    recommended_action = Column(SqlEnum(OrchestrationActionType), nullable=True, index=True)
    action_rationale = Column(Text, nullable=True)
    confidence = Column(Float, default=1.0, nullable=False)
    uncertainty = Column(Float, default=0.0, nullable=False)

    decision_record_id = Column(String(36), ForeignKey("security_decision_records.id", ondelete="SET NULL"), nullable=True)
    action_job_id = Column(String(36), ForeignKey("assessment_jobs.id", ondelete="SET NULL"), nullable=True)
    remediation_id = Column(String(36), ForeignKey("remediation_recommendations.id", ondelete="SET NULL"), nullable=True)
    verification_id = Column(String(36), ForeignKey("remediation_verifications.id", ondelete="SET NULL"), nullable=True)

    required_approval_role = Column(String(50), nullable=True)
    approved_by_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    approved_at = Column(DateTime(timezone=True), nullable=True)

    locked_by = Column(String(100), nullable=True, index=True)
    locked_at = Column(DateTime(timezone=True), nullable=True)
    lock_expires_at = Column(DateTime(timezone=True), nullable=True, index=True)

    attempt_count = Column(Integer, default=0, nullable=False)
    max_retries = Column(Integer, default=3, nullable=False)
    suspension_reason = Column(Text, nullable=True)
    failure_reason = Column(Text, nullable=True)

    partial_results = Column(JSON, default=dict, nullable=False)
    outcome_status = Column(SqlEnum(OutcomeMeasurementStatus), nullable=True, index=True)
    outcome_measurement = Column(JSON, default=dict, nullable=False)

    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)

    project = relationship("Project", backref=backref("orchestration_workflows", cascade="all, delete-orphan"))
    trigger_event = relationship("OrchestrationEventRecord")
    decision_record = relationship("SecurityDecisionRecord")
    action_job = relationship("AssessmentJob")
    approver = relationship("User", foreign_keys=[approved_by_id])

    __table_args__ = (
        Index("ix_orchestration_workflows_project_state", "project_id", "state"),
        Index("ix_orchestration_workflows_locked", "locked_by", "lock_expires_at"),
    )


class InvalidationStatus(str, enum.Enum):
    PENDING = "PENDING"
    RECALCULATED = "RECALCULATED"
    SUPERSEDED = "SUPERSEDED"
    FAILED = "FAILED"


class DependencyInvalidationRecord(Base, TimestampMixin):
    """
    Dependency-aware invalidation tracking for derived security records.
    Ensures that changes in raw assets, findings, evidence, or models invalidate downstream conclusions.
    """
    __tablename__ = "dependency_invalidation_records"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    project_id = Column(String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)

    source_entity_type = Column(String(50), nullable=False, index=True)
    source_entity_id = Column(String(255), nullable=False, index=True)
    invalidation_type = Column(String(50), nullable=False, index=True)

    invalidated_targets = Column(JSON, default=list, nullable=False)
    recalculation_status = Column(SqlEnum(InvalidationStatus), default=InvalidationStatus.PENDING, nullable=False, index=True)
    provenance = Column(JSON, default=dict, nullable=False)
    recalculated_at = Column(DateTime(timezone=True), nullable=True)

    project = relationship("Project", backref=backref("dependency_invalidations", cascade="all, delete-orphan"))

    __table_args__ = (
        Index("ix_dep_invalidations_project_status", "project_id", "recalculation_status"),
    )


class AdaptiveOptimizationRecord(Base, TimestampMixin):
    """
    Controlled adaptive optimization record capturing evaluated closed-loop operational improvements.
    Requires objective, evaluation metric, dataset summary, baseline comparison, and rollback safety.
    """
    __tablename__ = "adaptive_optimization_records"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    project_id = Column(String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)

    optimization_name = Column(String(100), nullable=False, index=True)
    objective = Column(Text, nullable=False)
    evaluation_metric = Column(String(100), nullable=False)

    baseline_value = Column(Float, nullable=False)
    evaluated_value = Column(Float, nullable=False)
    threshold_value = Column(Float, nullable=False)

    dataset_summary = Column(JSON, default=dict, nullable=False)
    is_accepted = Column(Boolean, default=False, nullable=False, index=True)
    rejection_reason = Column(Text, nullable=True)
    rollback_payload = Column(JSON, default=dict, nullable=False)

    evaluated_by_model = Column(String(100), default="governed_rule_engine_v1", nullable=False)
    evaluated_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)

    project = relationship("Project", backref=backref("adaptive_optimizations", cascade="all, delete-orphan"))

    __table_args__ = (
        Index("ix_adaptive_optimizations_project_accepted", "project_id", "is_accepted"),
    )
