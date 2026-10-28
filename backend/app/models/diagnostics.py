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
from sqlalchemy.orm import relationship, backref

from app.core.database import Base
from app.models.base import TimestampMixin, generate_uuid, utc_now


class ComponentHealthStatus(str, enum.Enum):
    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    UNHEALTHY = "UNHEALTHY"
    UNKNOWN = "UNKNOWN"
    NOT_CONFIGURED = "NOT_CONFIGURED"


class DiagnosticSeverity(str, enum.Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class DiagnosticConfidence(str, enum.Enum):
    CONFIRMED = "CONFIRMED"
    SUSPECTED = "SUSPECTED"
    UNAVAILABLE = "UNAVAILABLE"


class DiagnosticCategory(str, enum.Enum):
    DATABASE = "DATABASE"
    JOBS = "JOBS"
    ADAPTERS = "ADAPTERS"
    CONFIG = "CONFIG"
    EVIDENCE = "EVIDENCE"
    ASSETS = "ASSETS"
    FINDINGS = "FINDINGS"
    NOTIFICATIONS = "NOTIFICATIONS"
    BACKUP = "BACKUP"
    SECURITY = "SECURITY"


class RecoveryActionType(str, enum.Enum):
    RETRY_ASSESSMENT = "RETRY_ASSESSMENT"
    RECOVER_STUCK_JOB = "RECOVER_STUCK_JOB"
    REQUEUE_NOTIFICATION = "REQUEUE_NOTIFICATION"
    RECALCULATE_RISK_SCORES = "RECALCULATE_RISK_SCORES"
    REBUILD_KNOWLEDGE_GRAPH = "REBUILD_KNOWLEDGE_GRAPH"
    RESUME_MONITORING = "RESUME_MONITORING"
    TRIGGER_BACKUP = "TRIGGER_BACKUP"
    RETEST_REMEDIATION = "RETEST_REMEDIATION"


class RecoveryOutcome(str, enum.Enum):
    SUCCESS = "SUCCESS"
    PARTIAL_SUCCESS = "PARTIAL_SUCCESS"
    FAILED = "FAILED"
    INCONCLUSIVE = "INCONCLUSIVE"


class SystemHealthSnapshot(Base, TimestampMixin):
    """Stores on-demand or periodic central system health evaluations across all 12 subsystems."""
    __tablename__ = "system_health_snapshots"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    timestamp = Column(DateTime(timezone=True), default=utc_now, nullable=False, index=True)
    overall_status = Column(SqlEnum(ComponentHealthStatus), nullable=False)
    healthy_count = Column(Integer, nullable=False, default=0)
    degraded_count = Column(Integer, nullable=False, default=0)
    unhealthy_count = Column(Integer, nullable=False, default=0)
    components = Column(JSON, nullable=False, default=dict)
    environment = Column(String(50), nullable=False, default="development")


class DiagnosticRunRecord(Base, TimestampMixin):
    """Records an executed self-diagnostic run for a project."""
    __tablename__ = "diagnostic_runs"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    project_id = Column(String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    run_timestamp = Column(DateTime(timezone=True), default=utc_now, nullable=False, index=True)
    executed_by_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    trigger_type = Column(String(50), nullable=False, default="MANUAL")  # MANUAL, SCHEDULED, POST_INCIDENT

    total_checks = Column(Integer, nullable=False, default=0)
    passed_checks = Column(Integer, nullable=False, default=0)
    warning_checks = Column(Integer, nullable=False, default=0)
    failed_checks = Column(Integer, nullable=False, default=0)
    summary = Column(Text, nullable=False, default="")

    project = relationship("Project", backref=backref("diagnostic_runs", cascade="all, delete-orphan"))
    executed_by = relationship("User", foreign_keys=[executed_by_id])


class DiagnosticFindingRecord(Base, TimestampMixin):
    """Stores specific diagnostic findings identified during a diagnostic run."""
    __tablename__ = "diagnostic_findings"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    run_id = Column(String(36), ForeignKey("diagnostic_runs.id", ondelete="CASCADE"), nullable=False, index=True)
    project_id = Column(String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    check_id = Column(String(100), nullable=False, index=True)
    category = Column(SqlEnum(DiagnosticCategory), nullable=False, index=True)
    severity = Column(SqlEnum(DiagnosticSeverity), nullable=False, index=True)
    confidence = Column(SqlEnum(DiagnosticConfidence), nullable=False)

    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    observed_issue = Column(Text, nullable=False)
    affected_entities = Column(JSON, nullable=False, default=list)
    recommended_action = Column(Text, nullable=False)
    recovery_action_available = Column(String(100), nullable=True)

    run = relationship("DiagnosticRunRecord", backref=backref("findings", cascade="all, delete-orphan"))
    project = relationship("Project", backref=backref("diagnostic_findings", cascade="all, delete-orphan"))


class RecoveryActionRecord(Base, TimestampMixin):
    """
    Records controlled recovery action execution, including pre-conditions,
    post-conditions, and independent verification outcome.
    """
    __tablename__ = "recovery_action_records"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    project_id = Column(String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    action_type = Column(SqlEnum(RecoveryActionType), nullable=False, index=True)
    target_entity_type = Column(String(50), nullable=False)  # ASSESSMENT_JOB, NOTIFICATION, FINDING, PROJECT
    target_entity_id = Column(String(36), nullable=True, index=True)
    target_resource = Column(String(255), nullable=True)

    executed_by_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    execution_timestamp = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    reason = Column(Text, nullable=False)

    # Two-phase verification state comparison
    pre_condition = Column(JSON, nullable=False, default=dict)
    post_condition = Column(JSON, nullable=False, default=dict)
    outcome = Column(SqlEnum(RecoveryOutcome), nullable=False, index=True)
    verification_notes = Column(Text, nullable=False, default="")
    verification_timestamp = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    ledger_record_id = Column(String(36), nullable=True)

    project = relationship("Project", backref=backref("recovery_actions", cascade="all, delete-orphan"))
    executed_by = relationship("User", foreign_keys=[executed_by_id])


class FailurePatternRecord(Base, TimestampMixin):
    """
    Tracks repeated operational and assessment failure patterns over time
    for continuous improvement.
    """
    __tablename__ = "failure_pattern_records"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    project_id = Column(String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    pattern_key = Column(String(100), nullable=False, index=True)  # e.g. ADAPTER_TIMEOUT:web_adapter
    category = Column(String(50), nullable=False, default="GENERAL")
    occurrence_count = Column(Integer, nullable=False, default=1)
    first_observed_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    last_observed_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    affected_targets = Column(JSON, nullable=False, default=list)
    sample_error_message = Column(Text, nullable=False, default="")
    advisory_recommendation = Column(Text, nullable=False, default="")

    project = relationship("Project", backref=backref("failure_patterns", cascade="all, delete-orphan"))
