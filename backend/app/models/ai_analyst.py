import enum
from sqlalchemy import Column, String, Text, Boolean, DateTime, Enum, ForeignKey, JSON
from sqlalchemy.orm import relationship

from app.core.database import Base
from app.models.base import generate_uuid, utc_now


class AIDraftType(str, enum.Enum):
    FINDING_EXPLANATION = "FINDING_EXPLANATION"
    ASSESSMENT_SUMMARY = "ASSESSMENT_SUMMARY"
    REMEDIATION_DRAFT = "REMEDIATION_DRAFT"
    ATTACK_PATH_SUMMARY = "ATTACK_PATH_SUMMARY"
    VALIDATION_CHECKLIST = "VALIDATION_CHECKLIST"


class AIDraftStatus(str, enum.Enum):
    DRAFT = "DRAFT"
    REVIEWED_APPROVED = "REVIEWED_APPROVED"
    REVIEWED_REJECTED = "REVIEWED_REJECTED"
    MODIFIED = "MODIFIED"


class AIAnalystDraft(Base):
    """
    Controlled AI Security Analyst Draft (Phase 18).
    Captures evidence-grounded, non-authoritative AI decision support artifacts.
    Strictly decoupled from authoritative state machines.
    All drafts require human verification before being operationalized.
    """
    __tablename__ = "ai_analyst_drafts"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    project_id = Column(String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    draft_type = Column(Enum(AIDraftType), nullable=False, index=True)
    status = Column(Enum(AIDraftStatus), default=AIDraftStatus.DRAFT, nullable=False, index=True)
    
    prompt_version = Column(String(32), default="v1.0.0", nullable=False)
    model_identifier = Column(String(64), default="grounded-deterministic-v1", nullable=False)
    target_resource = Column(String(255), nullable=False, index=True)
    
    title = Column(String(255), nullable=False)
    summary = Column(Text, nullable=False)
    content = Column(JSON, nullable=False)
    citations = Column(JSON, nullable=False)
    uncertainty_notes = Column(Text, nullable=True)
    prompt_injection_flags = Column(JSON, nullable=True)
    
    is_reviewed = Column(Boolean, default=False, nullable=False)
    reviewed_by_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    reviewed_at = Column(DateTime(timezone=True), nullable=True)
    review_notes = Column(Text, nullable=True)
    
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False, index=True)

    project = relationship("Project", backref="ai_drafts")
    reviewer = relationship("User", foreign_keys=[reviewed_by_id])
