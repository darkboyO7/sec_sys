import enum
from sqlalchemy import Column, String, ForeignKey, Enum as SqlEnum, Text, DateTime, JSON
from sqlalchemy.orm import relationship, backref

from app.core.database import Base
from app.models.base import TimestampMixin, generate_uuid, utc_now


class VerificationOutcome(str, enum.Enum):
    VERIFIED_FIXED = "VERIFIED_FIXED"
    STILL_VULNERABLE = "STILL_VULNERABLE"
    PARTIALLY_REMEDIATED = "PARTIALLY_REMEDIATED"
    INCONCLUSIVE = "INCONCLUSIVE"


class VerificationMethod(str, enum.Enum):
    PASSIVE_SCAN = "PASSIVE_SCAN"
    RETEST_ASSESSMENT = "RETEST_ASSESSMENT"
    MANUAL_AUDIT = "MANUAL_AUDIT"
    INSPECTION = "INSPECTION"


class RemediationVerification(Base, TimestampMixin):
    """
    Independent Remediation Verification Record.
    Captures objective evidence from targeted re-testing or manual audit to prove or disprove
    whether an identified vulnerability was resolved on target.
    Prevents closing findings merely because a remediation recommendation or change ticket was authorized.
    """
    __tablename__ = "remediation_verifications"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    project_id = Column(String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    finding_id = Column(String(36), ForeignKey("vulnerability_findings.id", ondelete="CASCADE"), nullable=False, index=True)
    recommendation_id = Column(String(36), ForeignKey("remediation_recommendations.id", ondelete="SET NULL"), nullable=True, index=True)
    verifier_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)

    verification_method = Column(SqlEnum(VerificationMethod), default=VerificationMethod.PASSIVE_SCAN, nullable=False)
    outcome = Column(SqlEnum(VerificationOutcome), nullable=False, index=True)

    verification_criteria = Column(Text, nullable=False)
    baseline_evidence_hash = Column(String(64), nullable=True)
    verification_evidence_summary = Column(Text, nullable=False)
    verification_evidence_data = Column(JSON, nullable=False, default=dict)
    notes = Column(Text, nullable=False)
    verified_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)

    # Relationships
    project = relationship(
        "Project",
        backref=backref("remediation_verifications", cascade="all, delete-orphan", passive_deletes=True),
    )
    finding = relationship(
        "VulnerabilityFinding",
        backref=backref("remediation_verifications", cascade="all, delete-orphan", passive_deletes=True),
    )
    recommendation = relationship("RemediationRecommendation", backref="verifications", foreign_keys=[recommendation_id])
    verifier = relationship("User", foreign_keys=[verifier_id])
