import enum
from sqlalchemy import (
    Column,
    String,
    Integer,
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
    UNCONFIGURED = "UNCONFIGURED"


class NotificationRecord(Base, TimestampMixin):
    """
    Persistent Security Notification Record.
    Captures operational alerts, deduplication anchors, bounded retries, and delivery telemetry.
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

    retry_count = Column(Integer, default=0, nullable=False)
    max_retries = Column(Integer, default=3, nullable=False)
    last_attempt_at = Column(DateTime(timezone=True), nullable=True)
    error_message = Column(Text, nullable=True)

    delivery_metadata = Column(JSON, default=dict, nullable=False)

    project = relationship("Project", backref=backref("notification_records", cascade="all, delete-orphan"))

    __table_args__ = (
        Index("ix_notifications_project_status", "project_id", "status"),
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
    status = Column(String(50), nullable=False)  # SUCCESS, FAILED, TIMEOUT, UNCONFIGURED
    response_code = Column(Integer, nullable=True)
    error_message = Column(Text, nullable=True)
    attempted_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)

    notification = relationship("NotificationRecord", backref=backref("delivery_attempts", cascade="all, delete-orphan"))
