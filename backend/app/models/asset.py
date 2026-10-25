import enum
from sqlalchemy import Column, String, Float, Boolean, ForeignKey, Enum, DateTime, Text, JSON, UniqueConstraint
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

    is_ambiguous = Column(Boolean, default=False, nullable=False)
    ambiguity_reason = Column(Text, nullable=True)

    # Relationships
    project = relationship("Project")
    organization = relationship("Organization")
    observations = relationship("AssetObservation", back_populates="asset", cascade="all, delete-orphan", order_by="AssetObservation.observed_at.desc()")
    findings = relationship("VulnerabilityFinding", back_populates="asset")


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

    observation_source = Column(String(100), nullable=False)
    adapter_version = Column(String(50), default="1.0.0", nullable=False)
    observed_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    observed_attributes = Column(JSON, default=dict, nullable=False)
    evidence_hash = Column(String(64), nullable=True)
    confidence = Column(Float, default=1.0, nullable=False)
    validation_status = Column(String(50), default="VALIDATED", nullable=False)
    created_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)

    # Relationships
    asset = relationship("Asset", back_populates="observations")
    assessment_job = relationship("AssessmentJob")
