"""
VAPT Platform — Forensic Evidence Preservation & Chain of Custody Models (Prompt 48).
Strengthens trustworthiness, reproducibility, and traceability of collected security evidence.
Enforces strict separation between original untouched raw records and derived normalized interpretations.
"""
import enum
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List

from sqlalchemy import (
    Column,
    String,
    Text,
    DateTime,
    Boolean,
    ForeignKey,
    JSON,
    Enum as SAEnum,
)
from sqlalchemy.orm import relationship

from app.models.base import Base, generate_uuid, utc_now


class EvidenceLifecycleState(str, enum.Enum):
    COLLECTED = "COLLECTED"
    INGESTED = "INGESTED"
    NORMALIZED = "NORMALIZED"
    ANALYZED = "ANALYZED"
    REPORTED = "REPORTED"
    ARCHIVED = "ARCHIVED"
    AUTHORIZED_DELETED = "AUTHORIZED_DELETED"


class VerificationOutcome(str, enum.Enum):
    VERIFIED = "VERIFIED"
    FAILED = "FAILED"
    UNAVAILABLE = "UNAVAILABLE"
    NOT_CHECKED = "NOT_CHECKED"


class ContradictionStatus(str, enum.Enum):
    SUPPORTING = "SUPPORTING"
    CONTRADICTORY = "CONTRADICTORY"
    CORRECTION = "CORRECTION"
    SUPERSEDED = "SUPERSEDED"


class CustodyEventType(str, enum.Enum):
    COLLECTION = "COLLECTION"
    INGESTION = "INGESTION"
    NORMALIZATION = "NORMALIZATION"
    ANALYSIS_LINK = "ANALYSIS_LINK"
    VERIFICATION = "VERIFICATION"
    CONTRADICTION_ATTACHED = "CONTRADICTION_ATTACHED"
    EXPORT = "EXPORT"
    IMPORT = "IMPORT"
    ARCHIVAL = "ARCHIVAL"
    HOLD_APPLIED = "HOLD_APPLIED"
    HOLD_RELEASED = "HOLD_RELEASED"
    DELETION_AUTHORIZED = "DELETION_AUTHORIZED"


class ForensicEvidenceRecord(Base):
    """
    Forensic evidence record maintaining absolute separation between untouched raw evidence
    and derived interpretations, with provenance, digital signatures, and lifecycle states.
    """
    __tablename__ = "forensic_evidence_records"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    finding_id = Column(String(36), ForeignKey("assessment_findings.id", ondelete="SET NULL"), nullable=True, index=True)
    job_id = Column(String(36), ForeignKey("assessment_jobs.id", ondelete="SET NULL"), nullable=True, index=True)
    project_id = Column(String(36), nullable=False, index=True)

    evidence_type = Column(String(100), nullable=False)  # RAW_HTTP, NETWORK_CAPTURE, BANNER, CONFIG, CONSOLE
    raw_payload = Column(Text, nullable=False)  # Exact original untouched payload
    raw_digest_sha256 = Column(String(64), nullable=False, index=True)  # SHA-256 digest of untouched raw_payload

    # Derived normalized interpretation (never overwrites raw_payload)
    normalized_payload = Column(JSON, nullable=True)
    normalized_digest_sha256 = Column(String(64), nullable=True)

    # Provenance metadata
    source_identity = Column(String(255), nullable=False)  # Sensor/Adapter/Analyst identity
    adapter_version = Column(String(100), nullable=False)
    collection_time = Column(DateTime(timezone=True), nullable=False)
    ingestion_time = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    assessment_context = Column(JSON, nullable=False, default=dict)
    transformation_history = Column(JSON, nullable=False, default=list)

    # Cryptographic proof of origin (distinct from checksum)
    origin_signature = Column(String(512), nullable=False)
    signing_key_id = Column(String(128), nullable=False)
    signature_algorithm = Column(String(64), nullable=False)  # ED25519 or HMAC-SHA256-ORIGIN

    # Lifecycle & Verification
    lifecycle_state = Column(
        SAEnum(EvidenceLifecycleState, native_enum=False),
        default=EvidenceLifecycleState.INGESTED,
        nullable=False,
    )
    last_verification_status = Column(
        SAEnum(VerificationOutcome, native_enum=False),
        default=VerificationOutcome.NOT_CHECKED,
        nullable=False,
    )
    last_verified_at = Column(DateTime(timezone=True), nullable=True)
    last_verified_by = Column(String(255), nullable=True)
    verification_details = Column(JSON, nullable=True, default=dict)

    # Contradiction & History Preservation
    contradiction_status = Column(
        SAEnum(ContradictionStatus, native_enum=False),
        default=ContradictionStatus.SUPPORTING,
        nullable=False,
    )
    superseded_by_id = Column(String(36), nullable=True)
    prior_evidence_id = Column(String(36), nullable=True)
    is_contradictory = Column(Boolean, default=False, nullable=False)
    contradiction_notes = Column(Text, nullable=True)

    # Governance & Retention
    classification = Column(String(50), default="RESTRICTED", nullable=False)
    is_redacted = Column(Boolean, default=False, nullable=False)
    is_archived = Column(Boolean, default=False, nullable=False)
    is_deleted = Column(Boolean, default=False, nullable=False)
    deleted_at = Column(DateTime(timezone=True), nullable=True)
    deleted_by = Column(String(255), nullable=True)

    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False)

    # Relationships
    custody_events = relationship(
        "EvidenceCustodyEvent",
        back_populates="evidence",
        cascade="all, delete-orphan",
        order_by="EvidenceCustodyEvent.timestamp",
    )


class EvidenceCustodyEvent(Base):
    """
    Monotonically hash-chained custody event attesting to an action taken on evidence.
    """
    __tablename__ = "evidence_custody_events"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    evidence_id = Column(
        String(36),
        ForeignKey("forensic_evidence_records.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    event_type = Column(String(100), nullable=False)
    actor_id = Column(String(255), nullable=False)
    actor_role = Column(String(100), nullable=False)
    timestamp = Column(DateTime(timezone=True), default=utc_now, nullable=False, index=True)
    action_details = Column(JSON, nullable=False, default=dict)

    # Cryptographic Merkle Hash Chaining
    prev_custody_hash = Column(String(64), nullable=False)
    custody_hash = Column(String(64), nullable=False)

    # Relationship
    evidence = relationship("ForensicEvidenceRecord", back_populates="custody_events")
