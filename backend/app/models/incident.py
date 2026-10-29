import enum
from sqlalchemy import (
    Column,
    String,
    Integer,
    Float,
    Boolean,
    DateTime,
    Enum,
    ForeignKey,
    JSON,
    Text,
    Index,
)
from sqlalchemy.orm import relationship
from app.core.database import Base
from app.models.base import TimestampMixin, generate_uuid, utc_now


class CaseSeverity(str, enum.Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


class CaseStatus(str, enum.Enum):
    OPEN = "OPEN"
    TRIAGED = "TRIAGED"
    INVESTIGATING = "INVESTIGATING"
    CONTAINED = "CONTAINED"
    CLOSED = "CLOSED"
    REOPENED = "REOPENED"


class RelationshipType(str, enum.Enum):
    PRIMARY_TARGET = "PRIMARY_TARGET"
    PIVOT_VECTOR = "PIVOT_VECTOR"
    IMPACTED_DEPENDENCY = "IMPACTED_DEPENDENCY"
    OBSERVED_CORRELATION = "OBSERVED_CORRELATION"


class CorrelationType(str, enum.Enum):
    CONFIRMED_CAUSATION = "CONFIRMED_CAUSATION"
    PROBABLE_CORRELATION = "PROBABLE_CORRELATION"
    TEMPORAL_COINCIDENCE = "TEMPORAL_COINCIDENCE"
    CONTRADICTORY_EVIDENCE = "CONTRADICTORY_EVIDENCE"


class IncidentCase(Base, TimestampMixin):
    """
    Evidence-Preserving Security Incident Investigation Case (Prompt 39).
    Connects related observations, findings, and evidence into reviewable cases
    while strictly separating empirical correlation from confirmed causation.
    """
    __tablename__ = "incident_cases"
    __table_args__ = (
        Index("ix_case_proj_status", "project_id", "status"),
        Index("ix_case_proj_severity", "project_id", "severity"),
    )

    id = Column(String(36), primary_key=True, default=generate_uuid)
    project_id = Column(String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    case_number = Column(String(64), nullable=False, index=True)

    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)

    severity = Column(Enum(CaseSeverity), default=CaseSeverity.MEDIUM, nullable=False, index=True)
    status = Column(Enum(CaseStatus), default=CaseStatus.OPEN, nullable=False, index=True)

    lead_investigator_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    assigned_team = Column(String(128), nullable=True)

    opened_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    closed_at = Column(DateTime(timezone=True), nullable=True)
    reopened_at = Column(DateTime(timezone=True), nullable=True)

    root_cause_hypothesis = Column(Text, nullable=True)
    alternative_explanations = Column(JSON, default=list, nullable=False)

    is_containment_verified = Column(Boolean, default=False, nullable=False)
    closure_summary = Column(Text, nullable=True)
    closure_approved_by_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    reopening_rationale = Column(Text, nullable=True)

    # Relationships
    project = relationship("Project")
    lead_investigator = relationship("User", foreign_keys=[lead_investigator_id])
    closure_approved_by = relationship("User", foreign_keys=[closure_approved_by_id])

    linked_assets = relationship("IncidentCaseAsset", back_populates="case", cascade="all, delete-orphan")
    linked_findings = relationship("IncidentCaseFinding", back_populates="case", cascade="all, delete-orphan")
    linked_evidence = relationship("IncidentCaseEvidence", back_populates="case", cascade="all, delete-orphan")
    transitions = relationship("IncidentCaseTransition", back_populates="case", cascade="all, delete-orphan", order_by="IncidentCaseTransition.created_at.asc()")
    notes = relationship("IncidentCaseNote", back_populates="case", cascade="all, delete-orphan", order_by="IncidentCaseNote.created_at.asc()")


class IncidentCaseAsset(Base):
    """Linked asset record with explicit relationship classification and confidence scoring."""
    __tablename__ = "incident_case_assets"
    __table_args__ = (
        Index("ix_case_asset_uniq", "case_id", "asset_id", unique=True),
    )

    id = Column(String(36), primary_key=True, default=generate_uuid)
    case_id = Column(String(36), ForeignKey("incident_cases.id", ondelete="CASCADE"), nullable=False, index=True)
    asset_id = Column(String(36), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True)

    relationship_type = Column(Enum(RelationshipType), default=RelationshipType.OBSERVED_CORRELATION, nullable=False)
    confidence = Column(Float, default=0.5, nullable=False)
    is_contradictory = Column(Boolean, default=False, nullable=False)
    notes = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)

    case = relationship("IncidentCase", back_populates="linked_assets")
    asset = relationship("Asset")


class IncidentCaseFinding(Base):
    """Linked vulnerability finding with causation vs temporal correlation labeling."""
    __tablename__ = "incident_case_findings"
    __table_args__ = (
        Index("ix_case_finding_uniq", "case_id", "finding_id", unique=True),
    )

    id = Column(String(36), primary_key=True, default=generate_uuid)
    case_id = Column(String(36), ForeignKey("incident_cases.id", ondelete="CASCADE"), nullable=False, index=True)
    finding_id = Column(String(36), ForeignKey("vulnerability_findings.id", ondelete="CASCADE"), nullable=False, index=True)

    correlation_type = Column(Enum(CorrelationType), default=CorrelationType.PROBABLE_CORRELATION, nullable=False)
    confidence = Column(Float, default=0.5, nullable=False)
    rationale = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)

    case = relationship("IncidentCase", back_populates="linked_findings")
    finding = relationship("VulnerabilityFinding")


class IncidentCaseEvidence(Base):
    """Immutable evidence snapshot attached to case, supporting contradictory evidence."""
    __tablename__ = "incident_case_evidence"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    case_id = Column(String(36), ForeignKey("incident_cases.id", ondelete="CASCADE"), nullable=False, index=True)
    finding_evidence_id = Column(String(36), ForeignKey("finding_evidence.id", ondelete="SET NULL"), nullable=True)

    evidence_digest = Column(String(64), nullable=False)  # SHA-256
    evidence_summary = Column(Text, nullable=False)
    is_contradictory = Column(Boolean, default=False, nullable=False)
    provenance_details = Column(JSON, default=dict, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)

    case = relationship("IncidentCase", back_populates="linked_evidence")
    finding_evidence = relationship("FindingEvidence")


class IncidentCaseTransition(Base):
    """Immutable state transition audit record preserving timeline provenance."""
    __tablename__ = "incident_case_transitions"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    case_id = Column(String(36), ForeignKey("incident_cases.id", ondelete="CASCADE"), nullable=False, index=True)
    from_status = Column(Enum(CaseStatus), nullable=False)
    to_status = Column(Enum(CaseStatus), nullable=False)
    transitioned_by_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    reason = Column(Text, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)

    case = relationship("IncidentCase", back_populates="transitions")
    transitioned_by = relationship("User")


class IncidentCaseNote(Base):
    """Analyst case notes, hypothesis logs, and task tracking."""
    __tablename__ = "incident_case_notes"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    case_id = Column(String(36), ForeignKey("incident_cases.id", ondelete="CASCADE"), nullable=False, index=True)
    author_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    note_type = Column(String(64), default="ANALYST_OBSERVATION", nullable=False)
    content = Column(Text, nullable=False)
    is_alternative_hypothesis = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)

    case = relationship("IncidentCase", back_populates="notes")
    author = relationship("User")
