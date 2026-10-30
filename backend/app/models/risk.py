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
    Integer,
    UniqueConstraint,
)
from sqlalchemy.orm import relationship, backref

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


class GuidanceType(str, enum.Enum):
    """
    Distinguishes the authoritative provenance and certainty of remediation guidance (Prompt 51).
    - VERIFIED_INSTRUCTION: Approved, tested catalog template with deterministic validation criteria.
    - GENERAL_GUIDANCE: Standard defensive posture/heuristic advice without target-specific verification.
    - UNVERIFIED_SUGGESTION: Model-generated proposal or advisory input requiring manual code/config review.
    """
    VERIFIED_INSTRUCTION = "VERIFIED_INSTRUCTION"
    GENERAL_GUIDANCE = "GENERAL_GUIDANCE"
    UNVERIFIED_SUGGESTION = "UNVERIFIED_SUGGESTION"


class BusinessPriority(str, enum.Enum):
    """
    Business priority dimension separated from technical severity (Prompt 51).
    Factors asset criticality, exposure, business impact, and governance policy.
    """
    P1_CRITICAL = "P1_CRITICAL"
    P2_HIGH = "P2_HIGH"
    P3_MEDIUM = "P3_MEDIUM"
    P4_LOW = "P4_LOW"


class RemediationUrgency(str, enum.Enum):
    """
    Operational urgency for applying remediation (Prompt 51).
    """
    IMMEDIATE = "IMMEDIATE"
    SCHEDULED_SPRINT = "SCHEDULED_SPRINT"
    NEXT_CYCLE = "NEXT_CYCLE"
    BACKLOG = "BACKLOG"


class RecommendationFeedbackType(str, enum.Enum):
    """
    User/analyst review feedback on remediation recommendation usefulness (Prompt 51).
    """
    HELPFUL = "HELPFUL"
    UNHELPFUL = "UNHELPFUL"
    INACCURATE = "INACCURATE"
    INCOMPLETE = "INCOMPLETE"
    OUTDATED = "OUTDATED"
    IRRELEVANT = "IRRELEVANT"


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

    # Prompt 21 Explainability & Historical Delta Tracking
    prior_score = Column(Float, nullable=True)
    score_delta = Column(Float, nullable=True)
    delta_reasons = Column(JSON, nullable=False, default=list)
    is_invalidated = Column(Boolean, default=False, nullable=False, index=True)
    invalidation_reason = Column(Text, nullable=True)
    qualitative_label = Column(String(50), default="CALCULATED", nullable=False)
    unverified_penalty = Column(Float, default=0.0, nullable=False)

    calculated_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    is_superseded = Column(Boolean, default=False, nullable=False, index=True)
    superseded_at = Column(DateTime(timezone=True), nullable=True)

    # Relationships
    project = relationship("Project", backref=backref("risk_assessments", cascade="all, delete-orphan"))
    finding = relationship("VulnerabilityFinding", backref=backref("risk_assessments", cascade="all, delete-orphan"))
    asset = relationship("Asset", backref=backref("risk_assessments", cascade="all, delete-orphan"))


class RemediationRecommendation(Base, TimestampMixin):
    """
    Evidence-backed remediation guidance mapped to finding types and asset context.
    Defines defensive corrective action, expected benefit, operational impact,
    explainability breakdown, and independent verification criteria without executing commands.
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

    # Phase 13: Enhanced Remediation Governance & Control Mapping
    root_cause = Column(Text, nullable=True)
    recommended_change = Column(Text, nullable=True)
    estimated_effort = Column(String(50), nullable=True)  # e.g., "LOW (< 2h)", "MEDIUM (1-2d)", "HIGH (> 1w)"
    related_controls = Column(JSON, nullable=False, default=list)
    execution_governance_stage = Column(String(50), nullable=False, default="GENERATED")

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

    # Prompt 51: Explainable Prioritization & Multi-Dimensional Grading
    guidance_type = Column(Enum(GuidanceType), default=GuidanceType.VERIFIED_INSTRUCTION, nullable=False, index=True)
    technical_severity = Column(String(50), default="MEDIUM", nullable=False)
    business_priority = Column(Enum(BusinessPriority), default=BusinessPriority.P3_MEDIUM, nullable=False, index=True)
    confidence = Column(Float, default=1.0, nullable=False)
    remediation_urgency = Column(Enum(RemediationUrgency), default=RemediationUrgency.SCHEDULED_SPRINT, nullable=False)

    source_evidence_ids = Column(JSON, nullable=False, default=list)
    ranking_factors = Column(JSON, nullable=False, default=dict)
    advisory_disclaimer = Column(Text, nullable=False, default="")

    missing_prerequisites = Column(JSON, nullable=False, default=list)
    compatibility_concerns = Column(JSON, nullable=False, default=list)
    dependencies = Column(JSON, nullable=False, default=list)

    # Prompt 51: Version Lineage & Immutability
    version = Column(Integer, default=1, nullable=False)
    prior_version_id = Column(String(36), ForeignKey("remediation_recommendations.id", ondelete="SET NULL"), nullable=True)
    is_latest = Column(Boolean, default=True, nullable=False, index=True)
    superseded_at = Column(DateTime(timezone=True), nullable=True)

    # Prompt 51: Retesting & Verification Linkage
    verification_id = Column(
        String(36),
        ForeignKey("remediation_verifications.id", ondelete="SET NULL", use_alter=True, name="fk_remediation_rec_verification"),
        nullable=True,
    )
    verified_outcome = Column(String(50), nullable=True)

    # Relationships
    project = relationship("Project", backref=backref("remediation_recommendations", cascade="all, delete-orphan"))
    finding = relationship("VulnerabilityFinding", backref=backref("remediation_recommendations", cascade="all, delete-orphan"))
    asset = relationship("Asset", backref=backref("remediation_recommendations", cascade="all, delete-orphan"))
    reviewed_by = relationship("User", foreign_keys=[reviewed_by_id])
    prior_version = relationship("RemediationRecommendation", remote_side=[id], foreign_keys=[prior_version_id])
    verification = relationship("RemediationVerification", foreign_keys=[verification_id])


class RecommendationFeedback(Base, TimestampMixin):
    """
    User and Analyst Feedback on Remediation Recommendations (Prompt 51).
    Grounds recommendation usefulness metrics strictly in historical review and outcome data.
    """
    __tablename__ = "recommendation_feedback"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    project_id = Column(String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    recommendation_id = Column(String(36), ForeignKey("remediation_recommendations.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)

    feedback_type = Column(Enum(RecommendationFeedbackType), nullable=False, index=True)
    rating = Column(Integer, nullable=True)  # 1 to 5
    comment = Column(Text, nullable=True)
    was_actionable = Column(Boolean, default=True, nullable=False)
    applied_as_instructed = Column(Boolean, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)

    # Relationships
    project = relationship("Project", backref=backref("recommendation_feedbacks", cascade="all, delete-orphan"))
    recommendation = relationship(
        "RemediationRecommendation",
        backref=backref("feedback_entries", cascade="all, delete-orphan", order_by="RecommendationFeedback.created_at.desc()"),
    )
    user = relationship("User", foreign_keys=[user_id])
