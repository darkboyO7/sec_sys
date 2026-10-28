import enum
from sqlalchemy import Column, String, Integer, Float, Boolean, DateTime, Enum, ForeignKey, JSON, Text
from sqlalchemy.orm import relationship, backref

from app.core.database import Base
from app.models.base import generate_uuid, utc_now


class AdaptiveMorphState(str, enum.Enum):
    NORMAL = "NORMAL"
    ELEVATED_MONITORING = "ELEVATED_MONITORING"
    INVESTIGATION_REQUIRED = "INVESTIGATION_REQUIRED"
    CONTAINMENT_RECOMMENDED = "CONTAINMENT_RECOMMENDED"
    RECOVERY_IN_PROGRESS = "RECOVERY_IN_PROGRESS"
    RECOVERY_VERIFICATION_REQUIRED = "RECOVERY_VERIFICATION_REQUIRED"
    RECOVERY_COMPLETE = "RECOVERY_COMPLETE"
    MANUAL_REVIEW_REQUIRED = "MANUAL_REVIEW_REQUIRED"


class AdaptiveTransitionTrigger(str, enum.Enum):
    INITIAL_PROVISIONING = "INITIAL_PROVISIONING"
    CRITICAL_FINDING_DETECTED = "CRITICAL_FINDING_DETECTED"
    REGRESSION_ALERT_RAISED = "REGRESSION_ALERT_RAISED"
    CHANGE_AUTHORIZED = "CHANGE_AUTHORIZED"
    VERIFICATION_FAILED = "VERIFICATION_FAILED"
    VERIFICATION_PASSED = "VERIFICATION_PASSED"
    POSTURE_CLEARED = "POSTURE_CLEARED"
    KILL_SWITCH_ENGAGED = "KILL_SWITCH_ENGAGED"
    KILL_SWITCH_DISENGAGED = "KILL_SWITCH_DISENGAGED"
    MANUAL_OVERRIDE = "MANUAL_OVERRIDE"


class MorphStatePosture(Base):
    """
    Governed Adaptive Defensive Posture (Phase 20).
    Adjusts monitoring emphasis, validation priority, and recovery workflows
    based on empirical, provenance-backed evidence.
    Includes a global emergency kill switch.
    """
    __tablename__ = "morph_state_postures"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    project_id = Column(String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, unique=True, index=True)
    
    current_state = Column(Enum(AdaptiveMorphState), default=AdaptiveMorphState.NORMAL, nullable=False, index=True)
    previous_state = Column(Enum(AdaptiveMorphState), nullable=True)
    state_version = Column(Integer, default=1, nullable=False)
    
    kill_switch_active = Column(Boolean, default=False, nullable=False, index=True)
    kill_switch_engaged_at = Column(DateTime(timezone=True), nullable=True)
    kill_switch_engaged_by_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    kill_switch_reason = Column(Text, nullable=True)
    
    monitoring_cadence_multiplier = Column(Float, default=1.0, nullable=False)
    active_recommendations = Column(JSON, default=list, nullable=False)
    recovery_prerequisites = Column(JSON, default=list, nullable=False)
    
    last_transition_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    last_evaluated_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)

    project = relationship("Project", backref=backref("morph_posture", cascade="all, delete-orphan", uselist=False))
    kill_switch_operator = relationship("User", foreign_keys=[kill_switch_engaged_by_id])
    history = relationship("MorphStateHistory", back_populates="posture", cascade="all, delete-orphan", order_by="desc(MorphStateHistory.created_at)")


class MorphStateHistory(Base):
    """
    Immutable transition history recording every adaptive posture shift and its empirical rationale.
    """
    __tablename__ = "morph_state_histories"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    posture_id = Column(String(36), ForeignKey("morph_state_postures.id", ondelete="CASCADE"), nullable=False, index=True)
    
    from_state = Column(Enum(AdaptiveMorphState), nullable=False)
    to_state = Column(Enum(AdaptiveMorphState), nullable=False)
    trigger = Column(Enum(AdaptiveTransitionTrigger), nullable=False)
    evidence_rationale = Column(Text, nullable=False)
    
    triggered_by_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False, index=True)

    posture = relationship("MorphStatePosture", back_populates="history")
    operator = relationship("User", foreign_keys=[triggered_by_id])
