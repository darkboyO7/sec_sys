import enum
from datetime import datetime, timezone
from sqlalchemy import Column, String, Integer, Boolean, DateTime, Enum as SqlEnum, ForeignKey, JSON, Text, Index
from sqlalchemy.orm import relationship, backref

from app.core.database import Base
from app.models.base import TimestampMixin, generate_uuid, utc_now


class ScheduleFrequency(str, enum.Enum):
    HOURLY = "HOURLY"
    DAILY = "DAILY"
    WEEKLY = "WEEKLY"
    CUSTOM = "CUSTOM"


class ScheduleStatus(str, enum.Enum):
    ACTIVE = "ACTIVE"
    PAUSED = "PAUSED"
    EXPIRED = "EXPIRED"
    FAILED = "FAILED"


class MonitoringSchedule(Base, TimestampMixin):
    """
    Continuous Monitoring Assessment Schedule.
    Enforces authorized recurring assessments, strict scope re-validation at run boundaries,
    change detection between runs, and persistent scheduling state.
    """
    __tablename__ = "monitoring_schedules"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    project_id = Column(String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)

    name = Column(String(255), nullable=False)
    target_input = Column(String(500), nullable=False)
    adapter_name = Column(String(100), default="live_network_auditor_adapter", nullable=False)
    fixture_profile = Column(String(100), default="LIVE_WEB_SECURITY_AUDIT", nullable=False)

    frequency = Column(SqlEnum(ScheduleFrequency), default=ScheduleFrequency.DAILY, nullable=False)
    interval_seconds = Column(Integer, default=86400, nullable=False)
    status = Column(SqlEnum(ScheduleStatus), default=ScheduleStatus.ACTIVE, nullable=False, index=True)

    last_run_at = Column(DateTime(timezone=True), nullable=True)
    next_run_at = Column(DateTime(timezone=True), nullable=True, index=True)
    last_job_id = Column(String(36), ForeignKey("assessment_jobs.id", ondelete="SET NULL"), nullable=True)
    last_status = Column(String(50), nullable=True)
    last_error = Column(Text, nullable=True)

    run_count = Column(Integer, default=0, nullable=False)
    consecutive_failures = Column(Integer, default=0, nullable=False)
    max_consecutive_failures = Column(Integer, default=3, nullable=False)

    config = Column(JSON, default=dict, nullable=False)
    created_by_id = Column(String(36), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False)

    # Relationships
    project = relationship("Project", backref=backref("monitoring_schedules", cascade="all, delete-orphan"))
    created_by = relationship("User")
    last_job = relationship("AssessmentJob", foreign_keys=[last_job_id])
    runs = relationship("MonitoringRun", back_populates="schedule", cascade="all, delete-orphan", order_by="desc(MonitoringRun.executed_at)")

    __table_args__ = (
        Index("ix_monitoring_schedules_project_status", "project_id", "status"),
        Index("ix_monitoring_schedules_next_run", "status", "next_run_at"),
    )


class MonitoringRun(Base):
    """
    Historical execution record for continuous monitoring schedules.
    Captures change detection metrics (new findings, recurring findings, resolved findings).
    """
    __tablename__ = "monitoring_runs"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    schedule_id = Column(String(36), ForeignKey("monitoring_schedules.id", ondelete="CASCADE"), nullable=False, index=True)
    project_id = Column(String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    job_id = Column(String(36), ForeignKey("assessment_jobs.id", ondelete="SET NULL"), nullable=True)

    scheduled_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    executed_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    status = Column(String(50), nullable=False)  # SUCCESS, FAILED, SKIPPED_DUPLICATE, SCOPE_EXPIRED

    new_findings_count = Column(Integer, default=0, nullable=False)
    recurring_findings_count = Column(Integer, default=0, nullable=False)
    resolved_findings_count = Column(Integer, default=0, nullable=False)

    summary_notes = Column(Text, nullable=True)
    run_metadata = Column(JSON, default=dict, nullable=False)

    schedule = relationship("MonitoringSchedule", back_populates="runs")
    project = relationship("Project")
    job = relationship("AssessmentJob")
