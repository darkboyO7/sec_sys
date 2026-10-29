import enum
from sqlalchemy import (
    Column,
    String,
    Integer,
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


class NotificationEventType(str, enum.Enum):
    CRITICAL_FINDING_DISCOVERED = "CRITICAL_FINDING_DISCOVERED"
    NEW_EXPOSURE_DETECTED = "NEW_EXPOSURE_DETECTED"
    ASSESSMENT_FAILED = "ASSESSMENT_FAILED"
    REPEATED_JOB_FAILURES = "REPEATED_JOB_FAILURES"
    REMEDIATION_DEADLINE_APPROACHING = "REMEDIATION_DEADLINE_APPROACHING"
    REMEDIATION_OVERDUE = "REMEDIATION_OVERDUE"
    VERIFICATION_FAILED = "VERIFICATION_FAILED"
    POLICY_VIOLATION = "POLICY_VIOLATION"
    AUTONOMY_SUSPENDED = "AUTONOMY_SUSPENDED"
    BACKUP_FAILED = "BACKUP_FAILED"
    RESTORE_FAILED = "RESTORE_FAILED"
    INTEGRITY_BREACH = "INTEGRITY_BREACH"
    SCOPE_EXPIRED = "SCOPE_EXPIRED"


class NotificationSeverity(str, enum.Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class NotificationStatus(str, enum.Enum):
    PENDING = "PENDING"
    DELIVERED = "DELIVERED"
    FAILED = "FAILED"
    SUPPRESSED_DUPLICATE = "SUPPRESSED_DUPLICATE"
    SUPPRESSED_MAINTENANCE_WINDOW = "SUPPRESSED_MAINTENANCE_WINDOW"
    SUPPRESSED_POLICY = "SUPPRESSED_POLICY"
    UNCONFIGURED = "UNCONFIGURED"


class AlertLifecycleStatus(str, enum.Enum):
    NEW = "NEW"
    ACTIVE = "ACTIVE"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    ASSIGNED = "ASSIGNED"
    RESOLVED = "RESOLVED"
    REOPENED = "REOPENED"


class NotificationRecord(Base, TimestampMixin):
    """
    Persistent Security Notification Record and Alert Entity (Prompt 31).
    Captures operational alerts, deduplication anchors, lifecycle state (New, Ack, Assigned, Resolved),
    bounded retries, and delivery telemetry.
    """
    __tablename__ = "notification_records"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    project_id = Column(String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)

    event_type = Column(SqlEnum(NotificationEventType), nullable=False, index=True)
    severity = Column(SqlEnum(NotificationSeverity), default=NotificationSeverity.INFO, nullable=False, index=True)
    title = Column(String(255), nullable=False)
    summary = Column(Text, nullable=False)

    deduplication_key = Column(String(255), nullable=False, index=True)
    status = Column(SqlEnum(NotificationStatus), default=NotificationStatus.PENDING, nullable=False, index=True)
    lifecycle_status = Column(SqlEnum(AlertLifecycleStatus), default=AlertLifecycleStatus.NEW, nullable=False, index=True)

    assigned_to_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    acknowledged_at = Column(DateTime(timezone=True), nullable=True)
    acknowledged_by_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    resolved_at = Column(DateTime(timezone=True), nullable=True)
    resolved_by_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    reopened_at = Column(DateTime(timezone=True), nullable=True)
    escalated_at = Column(DateTime(timezone=True), nullable=True)

    correlation_id = Column(String(64), nullable=True, index=True)
    causation_id = Column(String(64), nullable=True)
    idempotency_key = Column(String(64), nullable=True, index=True)
    schema_version = Column(String(20), default="v1.0.0", nullable=False)
    suppression_reason = Column(String(255), nullable=True)

    retry_count = Column(Integer, default=0, nullable=False)
    max_retries = Column(Integer, default=3, nullable=False)
    last_attempt_at = Column(DateTime(timezone=True), nullable=True)
    error_message = Column(Text, nullable=True)

    delivery_metadata = Column(JSON, default=dict, nullable=False)

    project = relationship("Project", backref=backref("notification_records", cascade="all, delete-orphan"))

    __table_args__ = (
        Index("ix_notifications_project_status", "project_id", "status"),
        Index("ix_notifications_project_lifecycle", "project_id", "lifecycle_status"),
        Index("ix_notifications_dedup", "project_id", "deduplication_key", "created_at"),
    )


class NotificationDeliveryRecord(Base, TimestampMixin):
    """
    Audit ledger entry for an individual delivery attempt across notification channels.
    """
    __tablename__ = "notification_delivery_records"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    notification_id = Column(String(36), ForeignKey("notification_records.id", ondelete="CASCADE"), nullable=False, index=True)

    channel = Column(String(50), default="WEBHOOK", nullable=False)
    attempt_number = Column(Integer, nullable=False)
    status = Column(String(50), nullable=False)  # SUCCESS, FAILED, TIMEOUT, UNCONFIGURED, SUPPRESSED_DUPLICATE
    response_code = Column(Integer, nullable=True)
    error_message = Column(Text, nullable=True)
    attempted_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)

    notification = relationship("NotificationRecord", backref=backref("delivery_attempts", cascade="all, delete-orphan"))


class SecurityEventOutboxRecord(Base, TimestampMixin):
    """
    Transactional Outbox Ledger for reliable security event publication (Prompt 31).
    Guarantees that database mutations and event publications remain consistent,
    with bounded exponential backoff, dead-letter state, and replay capability.
    """
    __tablename__ = "security_events_outbox"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    project_id = Column(String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)

    event_id = Column(String(64), unique=True, nullable=False, index=True)
    event_type = Column(String(100), nullable=False, index=True)
    aggregate_type = Column(String(50), nullable=False, index=True)
    aggregate_id = Column(String(36), nullable=False, index=True)

    schema_version = Column(String(20), default="v1.0.0", nullable=False)
    payload = Column(JSON, default=dict, nullable=False)
    status = Column(String(50), default="PENDING", nullable=False, index=True)  # PENDING, DELIVERED, DEAD_LETTER, SUPPRESSED

    retry_count = Column(Integer, default=0, nullable=False)
    max_retries = Column(Integer, default=5, nullable=False)
    next_retry_at = Column(DateTime(timezone=True), default=utc_now, nullable=False, index=True)
    delivered_at = Column(DateTime(timezone=True), nullable=True)
    last_error = Column(Text, nullable=True)
    idempotency_key = Column(String(64), nullable=True, index=True)

    project = relationship("Project", backref=backref("security_outbox_events", cascade="all, delete-orphan"))

    __table_args__ = (
        Index("ix_outbox_status_retry", "status", "next_retry_at"),
    )


class MaintenanceWindowRecord(Base, TimestampMixin):
    """
    Maintenance window configuration to explainably suppress non-critical notification delivery.
    """
    __tablename__ = "maintenance_windows"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    project_id = Column(String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    title = Column(String(255), nullable=False)
    reason = Column(Text, nullable=False)
    start_time = Column(DateTime(timezone=True), nullable=False)
    end_time = Column(DateTime(timezone=True), nullable=False)
    suppress_critical = Column(Boolean, default=False, nullable=False)
    created_by_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)

    project = relationship("Project", backref=backref("maintenance_windows", cascade="all, delete-orphan"))
