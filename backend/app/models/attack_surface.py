"""
Authorized Attack-Surface Inventory and Exposure Governance Models (Prompt 46).
Defines schemas for externally observable attack surface tracking,
service exposures, TLS certificate tracking, observation provenance,
freshness lifecycle, and discovery inclusion proposals.
"""
import enum
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List
from sqlalchemy import (
    Column,
    String,
    Integer,
    Float,
    Boolean,
    DateTime,
    Enum as SQLEnum,
    ForeignKey,
    JSON,
    Text,
    Index,
    UniqueConstraint,
)
from sqlalchemy.orm import relationship

from app.core.database import Base
from app.models.base import TimestampMixin, generate_uuid, utc_now
from app.models.scope import TargetType


class ExposureClassification(str, enum.Enum):
    INTERNET_FACING = "INTERNET_FACING"
    INTERNAL_RESTRICTED = "INTERNAL_RESTRICTED"
    CLOUD_EDGE = "CLOUD_EDGE"
    MANAGED_SERVICE = "MANAGED_SERVICE"
    UNKNOWN = "UNKNOWN"


class ObservationProvenanceType(str, enum.Enum):
    VERIFIED_OBSERVATION = "VERIFIED_OBSERVATION"
    IMPORTED_OBSERVATION = "IMPORTED_OBSERVATION"
    SIMULATED_RESULT = "SIMULATED_RESULT"
    INFERRED_RELATIONSHIP = "INFERRED_RELATIONSHIP"


class ExposureFreshness(str, enum.Enum):
    FRESH = "FRESH"
    AGING = "AGING"
    STALE = "STALE"
    UNVERIFIED_ABSENT = "UNVERIFIED_ABSENT"
    CONFIRMED_DECOMMISSIONED = "CONFIRMED_DECOMMISSIONED"


class ProposalStatus(str, enum.Enum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"


class AttackSurfaceExposure(Base, TimestampMixin):
    """
    Authoritative externally observable exposure point belonging to an authorized asset.
    Maintains service metadata, TLS certificates, exposure classification,
    provenance, and deduplicated observation telemetry.
    """
    __tablename__ = "attack_surface_exposures"
    __table_args__ = (
        Index("ix_exposure_proj_asset", "project_id", "asset_id"),
        Index("ix_exposure_dedup", "dedup_hash", unique=True),
        Index("ix_exposure_class_freshness", "project_id", "exposure_classification", "freshness"),
    )

    id = Column(String(36), primary_key=True, default=generate_uuid)
    project_id = Column(String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    asset_id = Column(String(36), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True)

    # Asset canonical identifier snapshot
    canonical_identifier = Column(String(500), nullable=False, index=True)

    # Observable Service & Network Details
    service_name = Column(String(100), nullable=False, default="unknown")
    port = Column(Integer, nullable=False, default=0)
    protocol = Column(String(20), nullable=False, default="tcp")
    transport_security = Column(String(50), nullable=False, default="PLAINTEXT")

    # Cryptographic & Domain Provenance
    certificate_details = Column(JSON, default=dict, nullable=False)
    relevant_hostnames = Column(JSON, default=list, nullable=False)

    # Classification & Governance
    exposure_classification = Column(SQLEnum(ExposureClassification), default=ExposureClassification.INTERNET_FACING, nullable=False)
    provenance_type = Column(SQLEnum(ObservationProvenanceType), default=ObservationProvenanceType.VERIFIED_OBSERVATION, nullable=False)
    freshness = Column(SQLEnum(ExposureFreshness), default=ExposureFreshness.FRESH, nullable=False)
    is_authorized = Column(Boolean, default=True, nullable=False)

    # Observation History & Freshness Metrics
    first_observed_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    last_observed_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    consecutive_absences = Column(Integer, default=0, nullable=False)
    observation_count = Column(Integer, default=1, nullable=False)

    # Provenance digests and observation links
    evidence_hashes = Column(JSON, default=list, nullable=False)
    latest_observation_id = Column(String(36), ForeignKey("asset_observations.id", ondelete="SET NULL"), nullable=True)
    dedup_hash = Column(String(64), nullable=False)
    attributes = Column(JSON, default=dict, nullable=False)

    # Relationships
    project = relationship("Project")
    asset = relationship("Asset")
    latest_observation = relationship("AssetObservation")


class AssetInclusionProposal(Base, TimestampMixin):
    """
    Explicit Governance Proposal for Newly Discovered Assets (Prompt 46).
    Enforces strict anti-expansion boundaries: automatically discovered endpoints
    or subdomains can NEVER expand assessment scope without explicit human approval.
    """
    __tablename__ = "asset_inclusion_proposals"
    __table_args__ = (
        Index("ix_proposals_proj_status", "project_id", "status"),
        UniqueConstraint("project_id", "target_value", name="uq_project_proposed_target"),
    )

    id = Column(String(36), primary_key=True, default=generate_uuid)
    project_id = Column(String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)

    target_type = Column(SQLEnum(TargetType), nullable=False)
    target_value = Column(String(500), nullable=False, index=True)
    discovery_source = Column(String(100), nullable=False)  # e.g. "DNS_SAN_DISCOVERY", "CONNECTOR_IMPORT", "TLS_CERT_ISSUER"
    provenance_type = Column(SQLEnum(ObservationProvenanceType), default=ObservationProvenanceType.INFERRED_RELATIONSHIP, nullable=False)

    status = Column(SQLEnum(ProposalStatus), default=ProposalStatus.PENDING, nullable=False, index=True)
    rationale = Column(Text, nullable=True)

    discovered_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    evidence_hash = Column(String(64), nullable=True)
    is_simulated = Column(Boolean, default=False, nullable=False)

    # Reviewer tracking (Separation of duties / accountable approval)
    reviewed_by_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    reviewed_at = Column(DateTime(timezone=True), nullable=True)
    approval_notes = Column(Text, nullable=True)

    # Authorized Target Created upon approval
    resulting_scope_target_id = Column(String(36), ForeignKey("scope_targets.id", ondelete="SET NULL"), nullable=True)

    # Relationships
    project = relationship("Project")
    reviewed_by = relationship("User", foreign_keys=[reviewed_by_id])
    resulting_scope_target = relationship("ScopeTarget", foreign_keys=[resulting_scope_target_id])
