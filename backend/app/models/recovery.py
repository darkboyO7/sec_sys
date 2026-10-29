import enum
from sqlalchemy import (
    Column,
    String,
    Integer,
    ForeignKey,
    Enum as SqlEnum,
    Text,
    DateTime,
    JSON,
    Boolean,
)
from sqlalchemy.orm import relationship

from app.core.database import Base
from app.models.base import TimestampMixin, generate_uuid, utc_now


class RecoveryBundleStatus(str, enum.Enum):
    UNVERIFIED = "UNVERIFIED"
    VERIFIED = "VERIFIED"
    CORRUPTED = "CORRUPTED"
    RESTORE_VERIFIED = "RESTORE_VERIFIED"


class ScheduleRunStatus(str, enum.Enum):
    PENDING = "PENDING"
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    SKIPPED_DISK_LOW = "SKIPPED_DISK_LOW"


class DisasterRecoveryBundleRecord(Base, TimestampMixin):
    """
    Authoritative ledger of disaster recovery backup bundles,
    cryptographic manifest digests, verification drill outcomes, and last-known-good flags.
    """
    __tablename__ = "disaster_recovery_bundles"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    bundle_id = Column(String(128), unique=True, index=True, nullable=False)
    bundle_path = Column(String(512), nullable=False)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False, index=True)
    created_by_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)

    manifest_sha256 = Column(String(64), nullable=False)
    database_sha256 = Column(String(64), nullable=False)
    size_bytes = Column(Integer, nullable=False, default=0)

    status = Column(SqlEnum(RecoveryBundleStatus), nullable=False, default=RecoveryBundleStatus.UNVERIFIED, index=True)
    last_verified_at = Column(DateTime(timezone=True), nullable=True)
    verification_report = Column(JSON, nullable=True)

    last_restore_drill_at = Column(DateTime(timezone=True), nullable=True)
    restore_drill_report = Column(JSON, nullable=True)

    is_last_known_good = Column(Boolean, nullable=False, default=False, index=True)
    table_counts = Column(JSON, nullable=True)
    schema_revision = Column(String(64), nullable=True)

    # Relationships
    created_by = relationship("User", foreign_keys=[created_by_id])


class BackupScheduleRecord(Base, TimestampMixin):
    """
    Automated backup schedule definition with configurable frequency,
    retention limits, isolated drill options, and failure tracking (Prompt 42).
    """
    __tablename__ = "backup_schedules"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    name = Column(String(128), nullable=False)
    interval_hours = Column(Integer, nullable=False, default=24)
    retention_days = Column(Integer, nullable=False, default=30)
    max_bundles_to_keep = Column(Integer, nullable=False, default=10)
    storage_location = Column(String(512), nullable=False, default="./data/backups")
    include_evidence = Column(Boolean, nullable=False, default=True)
    auto_verify_after_backup = Column(Boolean, nullable=False, default=True)
    auto_drill_after_backup = Column(Boolean, nullable=False, default=False)
    is_active = Column(Boolean, nullable=False, default=True, index=True)

    last_run_at = Column(DateTime(timezone=True), nullable=True)
    last_run_status = Column(SqlEnum(ScheduleRunStatus), nullable=True)
    last_run_error = Column(Text, nullable=True)
    last_bundle_id = Column(String(128), nullable=True)
    consecutive_failures = Column(Integer, nullable=False, default=0)
    next_run_at = Column(DateTime(timezone=True), nullable=True, index=True)

    created_by_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_by = relationship("User", foreign_keys=[created_by_id])
