"""
Connector Models for Secure Integration Framework (Prompt 40).
Defines schema for connector configurations, capability declarations,
health tracking, and sync event audit logs.
"""
import enum
import uuid
from datetime import datetime, timezone
from sqlalchemy import (
    Column,
    String,
    Boolean,
    Integer,
    Float,
    DateTime,
    Text,
    JSON,
    ForeignKey,
    Enum as SQLEnum,
)
from sqlalchemy.orm import relationship

from app.core.database import Base


class ConnectorCapability(str, enum.Enum):
    PULL_ASSETS = "PULL_ASSETS"
    PULL_FINDINGS = "PULL_FINDINGS"
    PULL_THREAT_INTEL = "PULL_THREAT_INTEL"
    PUSH_ALERTS = "PUSH_ALERTS"
    EXPORT_TELEMETRY = "EXPORT_TELEMETRY"
    TEST_CONNECTIVITY = "TEST_CONNECTIVITY"


class ConnectorStatus(str, enum.Enum):
    CONFIGURED = "CONFIGURED"
    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    UNAVAILABLE = "UNAVAILABLE"
    DISABLED = "DISABLED"
    ERROR = "ERROR"


class SyncStatus(str, enum.Enum):
    RUNNING = "RUNNING"
    SUCCESS = "SUCCESS"
    PARTIAL_SUCCESS = "PARTIAL_SUCCESS"
    FAILED = "FAILED"


class ImplementationStatus(str, enum.Enum):
    IMPLEMENTED = "IMPLEMENTED"
    SIMULATED = "SIMULATED"
    DISABLED = "DISABLED"
    UNVERIFIED = "UNVERIFIED"


class ConnectorConfiguration(Base):
    __tablename__ = "connector_configurations"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    project_id = Column(String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    name = Column(String(100), nullable=False)
    provider_type = Column(String(50), nullable=False)
    version = Column(String(20), nullable=False, default="1.0.0")
    enabled = Column(Boolean, nullable=False, default=True)
    capabilities = Column(JSON, nullable=False, default=list)
    config_schema_version = Column(String(20), nullable=False, default="1.0.0")
    settings_masked = Column(JSON, nullable=False, default=dict)
    settings_encrypted = Column(Text, nullable=True)
    rate_limit_per_minute = Column(Integer, nullable=False, default=60)
    timeout_seconds = Column(Float, nullable=False, default=10.0)
    max_retries = Column(Integer, nullable=False, default=3)
    max_response_size_kb = Column(Integer, nullable=False, default=10240)
    last_sync_at = Column(DateTime(timezone=True), nullable=True)
    last_sync_watermark = Column(String(100), nullable=True)
    last_health_status = Column(String(30), nullable=False, default=ConnectorStatus.CONFIGURED.value)
    last_health_message = Column(String(255), nullable=True)
    consecutive_failures = Column(Integer, nullable=False, default=0)
    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    # Relationships
    project = relationship("Project", backref="connector_configurations")
    sync_events = relationship("ConnectorSyncEvent", back_populates="connector", cascade="all, delete-orphan")


class ConnectorSyncEvent(Base):
    __tablename__ = "connector_sync_events"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    connector_id = Column(String(36), ForeignKey("connector_configurations.id", ondelete="CASCADE"), nullable=False, index=True)
    project_id = Column(String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    started_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    finished_at = Column(DateTime(timezone=True), nullable=True)
    status = Column(String(30), nullable=False, default=SyncStatus.RUNNING.value)
    records_pulled = Column(Integer, nullable=False, default=0)
    records_normalized = Column(Integer, nullable=False, default=0)
    records_ingested = Column(Integer, nullable=False, default=0)
    records_tombstoned = Column(Integer, nullable=False, default=0)
    error_message = Column(Text, nullable=True)
    error_type = Column(String(50), nullable=True)
    raw_payload_digest = Column(String(64), nullable=True)
    sync_watermark = Column(String(100), nullable=True)
    execution_metadata = Column(JSON, nullable=True)

    # Relationships
    connector = relationship("ConnectorConfiguration", back_populates="sync_events")
    project = relationship("Project")
