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
    Index,
)
from sqlalchemy.orm import relationship
from app.core.database import Base
from app.models.base import TimestampMixin, generate_uuid, utc_now


class AssetType(str, enum.Enum):
    HOST = "HOST"
    IP_ADDRESS = "IP_ADDRESS"
    DOMAIN = "DOMAIN"
    HOSTNAME = "HOSTNAME"
    SERVICE = "SERVICE"
    SOFTWARE_COMPONENT = "SOFTWARE_COMPONENT"
    WEB_APP = "WEB_APP"
    API_ENDPOINT = "API_ENDPOINT"
    CLOUD_RESOURCE = "CLOUD_RESOURCE"
    IDENTITY = "IDENTITY"
    DATA_STORE = "DATA_STORE"
    SECURITY_CONTROL = "SECURITY_CONTROL"


class AssetCriticality(str, enum.Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class AssetStatus(str, enum.Enum):
    ACTIVE = "ACTIVE"
    INACTIVE = "INACTIVE"
    DECOMMISSIONED = "DECOMMISSIONED"
    UNDER_REVIEW = "UNDER_REVIEW"


class Asset(Base, TimestampMixin):
    """
    Persistent normalized security asset tracked within an organization and project boundary.
    Represents authoritative current state supported by historical observations.
    """
    __tablename__ = "assets"
    __table_args__ = (
        UniqueConstraint("project_id", "asset_type", "canonical_identifier", name="uq_project_asset_type_canonical"),
        Index("ix_assets_proj_criticality_status", "project_id", "criticality", "status"),
    )

    id = Column(String(36), primary_key=True, default=generate_uuid)
    organization_id = Column(String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    project_id = Column(String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)

    asset_type = Column(Enum(AssetType), nullable=False, index=True)
    name = Column(String(255), nullable=False)
    canonical_identifier = Column(String(500), nullable=False, index=True)
    environment = Column(String(100), default="PRODUCTION", nullable=False)
    criticality = Column(Enum(AssetCriticality), default=AssetCriticality.MEDIUM, nullable=False, index=True)
    status = Column(Enum(AssetStatus), default=AssetStatus.ACTIVE, nullable=False, index=True)

    attributes = Column(JSON, default=dict, nullable=False)
    source = Column(String(100), default="ASSESSMENT", nullable=False)
    confidence = Column(Float, default=1.0, nullable=False)

    first_seen_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    last_seen_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)

    # Prompt 20: Explicit observation tracking, data freshness, and absence confirmation
    last_successful_observation_at = Column(DateTime(timezone=True), nullable=True)
    completeness_score = Column(Float, default=1.0, nullable=False)
    freshness_status = Column(String(50), default="FRESH", nullable=False)
    consecutive_absences = Column(Integer, default=0, nullable=False)
    confirmed_absent = Column(Boolean, default=False, nullable=False)

    is_ambiguous = Column(Boolean, default=False, nullable=False)
    ambiguity_reason = Column(Text, nullable=True)

    # Relationships
    project = relationship("Project")
    organization = relationship("Organization")
    observations = relationship(
        "AssetObservation",
        back_populates="asset",
        cascade="all, delete-orphan",
        order_by="AssetObservation.observed_at.desc()",
    )
    findings = relationship("VulnerabilityFinding", back_populates="asset")
    aliases = relationship(
        "AssetIdentifierAlias",
        back_populates="asset",
        cascade="all, delete-orphan",
        order_by="AssetIdentifierAlias.last_observed_at.desc()",
    )
    merge_records = relationship(
        "AssetIdentityMergeRecord",
        foreign_keys="AssetIdentityMergeRecord.target_asset_id",
        back_populates="target_asset",
        cascade="all, delete-orphan",
    )


class AssetIdentifierAlias(Base, TimestampMixin):
    """
    Historical and alternate identifier association for an asset (Prompt 20).
    Tracks IP addresses, hostnames, DNS names, and service netlocs without destructive merging.
    """
    __tablename__ = "asset_identifier_aliases"
    __table_args__ = (
        UniqueConstraint("project_id", "asset_id", "identifier_type", "identifier_value", name="uq_project_asset_alias"),
        Index("ix_asset_aliases_lookup", "project_id", "identifier_type", "identifier_value"),
    )

    id = Column(String(36), primary_key=True, default=generate_uuid)
    asset_id = Column(String(36), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True)
    project_id = Column(String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)

    identifier_type = Column(String(50), nullable=False, index=True)  # IP_ADDRESS, HOSTNAME, DOMAIN, NETLOC, DNS_CNAME
    identifier_value = Column(String(500), nullable=False, index=True)
    is_primary = Column(Boolean, default=False, nullable=False)
    confidence = Column(Float, default=1.0, nullable=False)
    evidence_ref = Column(String(64), nullable=True)

    first_observed_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    last_observed_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False, index=True)
    disassociation_reason = Column(Text, nullable=True)

    # Relationships
    asset = relationship("Asset", back_populates="aliases")
    project = relationship("Project")


class AssetIdentityMergeRecord(Base, TimestampMixin):
    """
    Reversible and auditable identity merge record (Prompt 20).
    Preserves provenance and a complete attribute snapshot when two asset representations
    are unified or revised.
    """
    __tablename__ = "asset_identity_merges"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    project_id = Column(String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    target_asset_id = Column(String(36), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True)

    merged_asset_id = Column(String(36), nullable=False, index=True)
    merged_canonical_identifier = Column(String(500), nullable=False)
    merged_asset_type = Column(String(50), nullable=False)
    merged_attributes_snapshot = Column(JSON, default=dict, nullable=False)

    merge_rationale = Column(Text, nullable=False)
    confidence = Column(Float, default=1.0, nullable=False)
    actor_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)

    is_reversed = Column(Boolean, default=False, nullable=False, index=True)
    reversed_at = Column(DateTime(timezone=True), nullable=True)
    reversed_by_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    reversal_notes = Column(Text, nullable=True)

    target_asset = relationship("Asset", foreign_keys=[target_asset_id], back_populates="merge_records")
    project = relationship("Project")
    actor = relationship("User", foreign_keys=[actor_id])
    reversed_by = relationship("User", foreign_keys=[reversed_by_id])


class AssetObservation(Base):
    """
    Time-stamped observation of an asset supporting provenance and historical change analysis.
    Preserves conflicting signals without overwriting earlier evidence.
    """
    __tablename__ = "asset_observations"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    asset_id = Column(String(36), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True)
    project_id = Column(String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    assessment_job_id = Column(String(36), ForeignKey("assessment_jobs.id", ondelete="SET NULL"), nullable=True, index=True)
    monitoring_run_id = Column(String(36), ForeignKey("monitoring_runs.id", ondelete="SET NULL"), nullable=True, index=True)

    observation_source = Column(String(100), nullable=False)
    adapter_version = Column(String(50), default="1.0.0", nullable=False)
    observed_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    observed_attributes = Column(JSON, default=dict, nullable=False)
    evidence_hash = Column(String(64), nullable=True)
    confidence = Column(Float, default=1.0, nullable=False)
    validation_status = Column(String(50), default="VALIDATED", nullable=False)

    # Prompt 20 additions
    authorization_context = Column(JSON, default=dict, nullable=False)
    is_simulated = Column(Boolean, default=False, nullable=False)
    completeness = Column(Float, default=1.0, nullable=False)
    collection_errors = Column(JSON, default=list, nullable=False)
    observation_schema_version = Column(String(20), default="1.0", nullable=False)
    is_successful_absence = Column(Boolean, default=False, nullable=False)
    dedup_hash = Column(String(64), nullable=True, index=True)

    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)

    # Relationships
    asset = relationship("Asset", back_populates="observations")
    assessment_job = relationship("AssessmentJob")
    monitoring_run = relationship("MonitoringRun")
