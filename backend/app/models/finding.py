import enum
from sqlalchemy import Column, String, Integer, Float, Boolean, ForeignKey, Enum, DateTime, Text, JSON, UniqueConstraint
from sqlalchemy.orm import relationship
from app.core.database import Base
from app.models.base import TimestampMixin, generate_uuid, utc_now
from app.models.assessment import FindingSeverity, FindingConfidence


class FindingLifecycleStatus(str, enum.Enum):
    DETECTED = "DETECTED"
    NEEDS_VALIDATION = "NEEDS_VALIDATION"
    CONFIRMED = "CONFIRMED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    INCONCLUSIVE = "INCONCLUSIVE"
    REMEDIATION_PROPOSED = "REMEDIATION_PROPOSED"
    REMEDIATION_APPROVED = "REMEDIATION_APPROVED"
    REMEDIATION_ATTEMPTED = "REMEDIATION_ATTEMPTED"
    REMEDIATED_PENDING_VERIFICATION = "REMEDIATED_PENDING_VERIFICATION"
    VERIFIED_CLOSED = "VERIFIED_CLOSED"
    REOPENED = "REOPENED"
    ACCEPTED_RISK = "ACCEPTED_RISK"
    EXPIRED = "EXPIRED"


class ValidationOutcome(str, enum.Enum):
    CONFIRMED = "CONFIRMED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    INCONCLUSIVE = "INCONCLUSIVE"
    NEEDS_MANUAL_REVIEW = "NEEDS_MANUAL_REVIEW"
    STALE_EVIDENCE = "STALE_EVIDENCE"


class VulnerabilityFinding(Base, TimestampMixin):
    """
    Canonical, deduplicated project vulnerability tracked through the 13-state lifecycle.
    Correlates multiple scanner/job observations without discarding contradictory evidence.
    """
    __tablename__ = "vulnerability_findings"
    __table_args__ = (
        UniqueConstraint("project_id", "fingerprint", name="uq_vulnerability_finding_project_fingerprint"),
    )

    id = Column(String(36), primary_key=True, default=generate_uuid)
    project_id = Column(String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    asset_id = Column(String(36), ForeignKey("assets.id", ondelete="SET NULL"), nullable=True, index=True)
    fingerprint = Column(String(64), nullable=False, index=True)  # SHA-256 hash for deterministic deduplication

    target_value = Column(String(500), nullable=False, index=True)
    title = Column(String(255), nullable=False)
    description = Column(Text, default="", nullable=False)

    status = Column(Enum(FindingLifecycleStatus), default=FindingLifecycleStatus.DETECTED, nullable=False, index=True)
    severity = Column(Enum(FindingSeverity), default=FindingSeverity.INFO, nullable=False, index=True)
    confidence = Column(Enum(FindingConfidence), default=FindingConfidence.FIRM, nullable=False)

    vuln_id = Column(String(100), nullable=True, index=True)  # e.g. CVE-2026-1049, CWE-89
    cvss_score = Column(Float, nullable=True)

    is_simulated = Column(Boolean, default=True, nullable=False)
    reproduction_steps = Column(Text, default="", nullable=False)

    # Observation metadata
    first_detected_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    last_observed_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    occurrence_count = Column(Integer, default=1, nullable=False)

    # Uncertainty and contradictory evidence tracking
    has_contradictions = Column(Boolean, default=False, nullable=False)
    contradiction_notes = Column(JSON, default=list, nullable=False)

    # Assignment & Remediation
    assigned_to_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    remediation_notes = Column(Text, nullable=True)

    # Risk Acceptance Provenance
    risk_accepted_at = Column(DateTime(timezone=True), nullable=True)
    risk_accepted_by_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    risk_accepted_reason = Column(Text, nullable=True)
    risk_accepted_expires_at = Column(DateTime(timezone=True), nullable=True)
    compensating_controls = Column(Text, nullable=True)

    # False Positive Provenance
    false_positive_at = Column(DateTime(timezone=True), nullable=True)
    false_positive_by_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    false_positive_reason = Column(Text, nullable=True)

    # Independent Verification Provenance
    verified_at = Column(DateTime(timezone=True), nullable=True)
    verified_by_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    verification_job_id = Column(String(36), ForeignKey("assessment_jobs.id", ondelete="SET NULL"), nullable=True)
    verification_notes = Column(Text, nullable=True)

    # Phase 9: Advanced Finding Validation & Recurrence
    validation_outcome = Column(String(50), nullable=True)
    evidence_quality_score = Column(Float, default=1.0, nullable=True)
    analyst_review_notes = Column(Text, nullable=True)
    reviewed_by_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    reviewed_at = Column(DateTime(timezone=True), nullable=True)
    recurrence_detected = Column(Boolean, default=False, nullable=False)
    recurrence_count = Column(Integer, default=0, nullable=False)

    # Relationships
    project = relationship("Project")
    asset = relationship("Asset", back_populates="findings")
    assigned_to = relationship("User", foreign_keys=[assigned_to_id])
    risk_accepted_by = relationship("User", foreign_keys=[risk_accepted_by_id])
    false_positive_by = relationship("User", foreign_keys=[false_positive_by_id])
    verified_by = relationship("User", foreign_keys=[verified_by_id])
    verification_job = relationship("AssessmentJob", foreign_keys=[verification_job_id])
    reviewed_by = relationship("User", foreign_keys=[reviewed_by_id])

    observations = relationship("AssessmentFinding", back_populates="canonical_finding", order_by="AssessmentFinding.created_at.desc()")
    transitions = relationship("FindingTransition", back_populates="finding", cascade="all, delete-orphan", order_by="FindingTransition.created_at.desc()")


class FindingTransition(Base):
    """
    Immutable audit history record of each state transition in a finding's lifecycle.
    Captures the actor, old state, new state, explicit rationale, and timestamp.
    """
    __tablename__ = "finding_transitions"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    finding_id = Column(String(36), ForeignKey("vulnerability_findings.id", ondelete="CASCADE"), nullable=False, index=True)

    from_status = Column(Enum(FindingLifecycleStatus), nullable=False)
    to_status = Column(Enum(FindingLifecycleStatus), nullable=False)

    actor_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    reason = Column(Text, nullable=False)
    metadata_snapshot = Column(JSON, default=dict, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)

    # Relationships
    finding = relationship("VulnerabilityFinding", back_populates="transitions")
    actor = relationship("User")
