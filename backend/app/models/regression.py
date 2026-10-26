import enum
from sqlalchemy import Column, String, Float, Integer, Boolean, ForeignKey, Enum as SqlEnum, DateTime, Text, JSON
from sqlalchemy.orm import relationship

from app.core.database import Base
from app.models.base import TimestampMixin, generate_uuid, utc_now


class RegressionAlertType(str, enum.Enum):
    NEW_EXPOSURE = "NEW_EXPOSURE"
    RECURRING_FINDING = "RECURRING_FINDING"
    RISK_SCORE_INCREASE = "RISK_SCORE_INCREASE"
    STALE_EVIDENCE = "STALE_EVIDENCE"
    REMEDIATION_REGRESSION = "REMEDIATION_REGRESSION"
    COVERAGE_DECREASE = "COVERAGE_DECREASE"


class AlertSeverity(str, enum.Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class AlertStatus(str, enum.Enum):
    ACTIVE = "ACTIVE"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    RESOLVED = "RESOLVED"
    DISMISSED = "DISMISSED"


class RegressionBaseline(Base, TimestampMixin):
    """
    Formal reference baseline for security regression analysis.
    Defines the baseline snapshot against which future assessments are evaluated,
    along with detection thresholds for risk deltas and evidence staleness.
    """
    __tablename__ = "regression_baselines"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    project_id = Column(String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    snapshot_id = Column(String(36), ForeignKey("security_snapshots.id", ondelete="SET NULL"), nullable=True, index=True)
    name = Column(String(255), nullable=False)
    is_active = Column(Boolean, default=True, nullable=False, index=True)

    risk_score_threshold_delta = Column(Float, default=5.0, nullable=False)
    evidence_stale_days = Column(Integer, default=30, nullable=False)

    # Relationships
    project = relationship("Project", backref="regression_baselines")
    snapshot = relationship("SecuritySnapshot")


class RegressionAlert(Base, TimestampMixin):
    """
    Security Regression Alert.
    Represents an evidence-backed alert triggered when the environment security posture
    degrades relative to a historical baseline (e.g. recurring findings, risk score spikes,
    stale evidence, or broken remediations).
    """
    __tablename__ = "regression_alerts"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    project_id = Column(String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    alert_type = Column(SqlEnum(RegressionAlertType), nullable=False, index=True)
    severity = Column(SqlEnum(AlertSeverity), nullable=False, index=True)
    status = Column(SqlEnum(AlertStatus), default=AlertStatus.ACTIVE, nullable=False, index=True)

    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    evidence_rationale = Column(Text, nullable=False)

    baseline_reference = Column(String(255), nullable=True)
    current_reference = Column(String(255), nullable=True)
    target_resource = Column(String(255), nullable=False, index=True)

    fingerprint = Column(String(64), nullable=False, index=True)  # Deduplication fingerprint

    acknowledged_by_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    acknowledged_at = Column(DateTime(timezone=True), nullable=True)
    resolution_notes = Column(Text, nullable=True)

    # Relationships
    project = relationship("Project", backref="regression_alerts")
    acknowledged_by = relationship("User", foreign_keys=[acknowledged_by_id])
