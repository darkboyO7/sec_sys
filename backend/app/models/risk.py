import enum
from sqlalchemy import (
    Column,
    String,
    Float,
    Boolean,
    ForeignKey,
    Enum,
    DateTime,
    Text,
    JSON,
    UniqueConstraint,
)
from sqlalchemy.orm import relationship

from app.core.database import Base
from app.models.base import TimestampMixin, generate_uuid, utc_now


class RiskPriority(str, enum.Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


class RecommendationStatus(str, enum.Enum):
    PENDING_REVIEW = "PENDING_REVIEW"
    APPROVED = "APPROVED"
    DEFERRED = "DEFERRED"
    REJECTED = "REJECTED"


class RiskAssessment(Base, TimestampMixin):
    """
    Contextual Risk Assessment for a vulnerability finding.
    Combines finding severity, confidence, asset criticality, network reachability,
    evidence freshness, and lifecycle mitigating controls.
    Maintains a frozen input_snapshot for historical reproducibility.
    """
    __tablename__ = "risk_assessments"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    project_id = Column(String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    finding_id = Column(String(36), ForeignKey("vulnerability_findings.id", ondelete="CASCADE"), nullable=False, index=True)
    asset_id = Column(String(36), ForeignKey("assets.id", ondelete="SET NULL"), nullable=True, index=True)

    score = Column(Float, nullable=False, index=True)
    inherent_score = Column(Float, nullable=True)
    residual_score = Column(Float, nullable=True)
    priority = Column(Enum(RiskPriority), nullable=False, index=True)
    scoring_version = Column(String(50), nullable=False, default="v1.1.0")

    factor_breakdown = Column(JSON, nullable=False, default=dict)
    contributing_factors = Column(JSON, nullable=False, default=list)
    missing_factors = Column(JSON, nullable=False, default=list)
    uncertainty_range = Column(JSON, nullable=False, default=dict)
    evidence_references = Column(JSON, nullable=False, default=list)
    input_snapshot = Column(JSON, nullable=False, default=dict)

    calculated_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    is_superseded = Column(Boolean, default=False, nullable=False, index=True)
    superseded_at = Column(DateTime(timezone=True), nullable=True)

    # Relationships
    project = relationship("Project", backref="risk_assessments")
    finding = relationship("VulnerabilityFinding", backref="risk_assessments")
    asset = relationship("Asset", backref="risk_assessments")


class RemediationRecommendation(Base, TimestampMixin):
    """
    Evidence-backed remediation guidance mapped to finding types and asset context.
    Defines defensive corrective action, expected benefit, operational impact,
    and independent verification criteria without executing commands.
    """
    __tablename__ = "remediation_recommendations"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    project_id = Column(String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    finding_id = Column(String(36), ForeignKey("vulnerability_findings.id", ondelete="CASCADE"), nullable=False, index=True)
    asset_id = Column(String(36), ForeignKey("assets.id", ondelete="SET NULL"), nullable=True, index=True)

    title = Column(String(255), nullable=False)
    action_type = Column(String(100), nullable=False, index=True)  # e.g., CODE_REFACTOR, CONFIG_HARDENING, PATCH_UPDATE, WAF_RULE
    description = Column(Text, nullable=False)
    rationale = Column(Text, nullable=False)
    qualitative_benefit = Column(Text, nullable=False)
    estimated_risk_reduction = Column(Float, nullable=True)

    prerequisites = Column(JSON, nullable=False, default=list)
    operational_impact = Column(Text, nullable=False)
    rollback_procedure = Column(Text, nullable=False)
    verification_criteria = Column(Text, nullable=False)
    verification_test_profile = Column(String(100), nullable=True)

    requires_approval = Column(Boolean, default=True, nullable=False)
    approval_role = Column(String(50), default="LEAD", nullable=False)
    status = Column(Enum(RecommendationStatus), default=RecommendationStatus.PENDING_REVIEW, nullable=False, index=True)

    reviewed_by_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    reviewed_at = Column(DateTime(timezone=True), nullable=True)
    review_notes = Column(Text, nullable=True)

    # Relationships
    project = relationship("Project", backref="remediation_recommendations")
    finding = relationship("VulnerabilityFinding", backref="remediation_recommendations")
    asset = relationship("Asset", backref="remediation_recommendations")
    reviewed_by = relationship("User", foreign_keys=[reviewed_by_id])
