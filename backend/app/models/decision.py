import enum
from sqlalchemy import Column, String, Integer, Float, Boolean, DateTime, Enum as SqlEnum, ForeignKey, JSON, Text, Index
from sqlalchemy.orm import relationship, backref

from app.core.database import Base
from app.models.base import TimestampMixin, generate_uuid, utc_now


class ChangeType(str, enum.Enum):
    NEW_ASSET = "NEW_ASSET"
    CONFIG_CHANGED = "CONFIG_CHANGED"
    NEW_FINDING = "NEW_FINDING"
    RESOLVED_FINDING = "RESOLVED_FINDING"
    RECURRING_FINDING = "RECURRING_FINDING"
    RISK_SCORE_CHANGED = "RISK_SCORE_CHANGED"
    ATTACK_PATH_EXPOSED = "ATTACK_PATH_EXPOSED"
    REMEDIATION_OUTCOME = "REMEDIATION_OUTCOME"


class DecisionActionType(str, enum.Enum):
    REASSESS_CHANGED_ASSET = "REASSESS_CHANGED_ASSET"
    VALIDATE_UNCERTAIN_FINDING = "VALIDATE_UNCERTAIN_FINDING"
    INVESTIGATE_HIGH_IMPACT_EXPOSURE = "INVESTIGATE_HIGH_IMPACT_EXPOSURE"
    REFRESH_STALE_EVIDENCE = "REFRESH_STALE_EVIDENCE"
    PRIORITIZE_REMEDIATION = "PRIORITIZE_REMEDIATION"
    VERIFY_APPLIED_FIX = "VERIFY_APPLIED_FIX"
    RECALCULATE_RISK_AND_PATHS = "RECALCULATE_RISK_AND_PATHS"
    REQUEST_HUMAN_REVIEW = "REQUEST_HUMAN_REVIEW"


class DecisionStatus(str, enum.Enum):
    PROPOSED = "PROPOSED"
    APPROVED = "APPROVED"
    EXECUTED = "EXECUTED"
    REJECTED = "REJECTED"
    INCONCLUSIVE = "INCONCLUSIVE"


class PostureChangeRecord(Base, TimestampMixin):
    """
    Persistent Security Posture Change Record.
    Captures verified deltas across assessments:
    - Distinguishes confirmed changes from missing data, failed probes, or unreachable hosts.
    - Records previous state vs new state with evidence summaries.
    """
    __tablename__ = "posture_change_records"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    project_id = Column(String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)

    change_type = Column(SqlEnum(ChangeType), nullable=False, index=True)
    target_resource = Column(String(255), nullable=False, index=True)
    title = Column(String(255), nullable=False)

    previous_state = Column(JSON, nullable=False, default=dict)
    new_state = Column(JSON, nullable=False, default=dict)
    evidence_summary = Column(Text, nullable=False)

    confidence = Column(Float, default=1.0, nullable=False)
    is_confirmed = Column(Boolean, default=True, nullable=False, index=True)

    project = relationship("Project", backref=backref("posture_changes", cascade="all, delete-orphan"))

    __table_args__ = (
        Index("ix_posture_changes_project_type", "project_id", "change_type"),
    )


class SecurityDecisionRecord(Base, TimestampMixin):
    """
    Persistent Security Decision Record.
    Represents an evidence-backed autonomous recommendation or action:
    - Captures triggering observation and evidence considered.
    - Specifies required authorization/approval before execution.
    - Measures verified posture improvement before vs after execution.
    """
    __tablename__ = "security_decision_records"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    project_id = Column(String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)

    action_type = Column(SqlEnum(DecisionActionType), nullable=False, index=True)
    status = Column(SqlEnum(DecisionStatus), default=DecisionStatus.PROPOSED, nullable=False, index=True)

    title = Column(String(255), nullable=False)
    triggering_observation = Column(Text, nullable=False)
    evidence_considered = Column(JSON, nullable=False, default=dict)
    selected_action = Column(String(255), nullable=False)
    rationale = Column(Text, nullable=False)

    confidence = Column(Float, default=0.8, nullable=False)
    uncertainty = Column(Float, default=0.2, nullable=False)

    target_id = Column(String(255), nullable=True, index=True)  # finding_id, asset_id, target_url
    target_resource = Column(String(255), nullable=True, index=True)
    job_id = Column(String(36), ForeignKey("assessment_jobs.id", ondelete="SET NULL"), nullable=True)

    required_approval_role = Column(String(50), nullable=True)  # "LEAD", "ADMIN", or None if safe autonomous
    approved_by_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    approved_at = Column(DateTime(timezone=True), nullable=True)

    executed_at = Column(DateTime(timezone=True), nullable=True)
    execution_outcome = Column(JSON, nullable=True)
    posture_improvement_measured = Column(JSON, nullable=True)  # Delta risk score, resolved findings

    created_by_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)

    project = relationship("Project", backref=backref("security_decisions", cascade="all, delete-orphan"))
    job = relationship("AssessmentJob")
    approver = relationship("User", foreign_keys=[approved_by_id])
    creator = relationship("User", foreign_keys=[created_by_id])

    __table_args__ = (
        Index("ix_security_decisions_project_status", "project_id", "status"),
    )
