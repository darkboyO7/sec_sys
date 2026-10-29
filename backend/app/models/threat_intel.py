import enum
from sqlalchemy import (
    Column,
    String,
    Float,
    Integer,
    Boolean,
    ForeignKey,
    Enum,
    DateTime,
    Text,
    JSON,
    UniqueConstraint,
    Index,
)
from sqlalchemy.orm import relationship

from app.core.database import Base
from app.models.base import TimestampMixin, generate_uuid, utc_now


class FeedSyncStatus(str, enum.Enum):
    SYNCED = "SYNCED"
    SYNCING = "SYNCING"
    STALE = "STALE"
    ERROR = "ERROR"
    OFFLINE = "OFFLINE"


class MatchClassification(str, enum.Enum):
    CONFIRMED_MATCH = "CONFIRMED_MATCH"
    POSSIBLE_MATCH = "POSSIBLE_MATCH"
    CONFLICTING_DATA = "CONFLICTING_DATA"
    UNKNOWN_MATCH = "UNKNOWN_MATCH"


class ThreatIntelSource(str, enum.Enum):
    CISA_KEV = "CISA_KEV"
    NVD_CVE = "NVD_CVE"
    EPSS = "EPSS"
    VENDOR_ADVISORY = "VENDOR_ADVISORY"
    LOCAL_FIXTURE = "LOCAL_FIXTURE"


class ThreatIntelFeedRecord(Base, TimestampMixin):
    """
    Authoritative threat intelligence feed registration and freshness monitor (Prompt 35).
    Tracks external feed connectivity, sync timestamps, SHA-256 payload integrity, and staleness.
    """
    __tablename__ = "threat_intel_feeds"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    feed_name = Column(String(50), nullable=False, unique=True, index=True)
    feed_url = Column(String(500), nullable=False)
    is_authoritative = Column(Boolean, default=True, nullable=False)
    sync_status = Column(Enum(FeedSyncStatus), default=FeedSyncStatus.STALE, nullable=False, index=True)
    record_count = Column(Integer, default=0, nullable=False)

    last_sync_started_at = Column(DateTime(timezone=True), nullable=True)
    last_synced_at = Column(DateTime(timezone=True), nullable=True)
    last_sync_error = Column(Text, nullable=True)
    stale_after_days = Column(Integer, default=7, nullable=False)
    feed_checksum = Column(String(64), nullable=True)


class ThreatIntelligenceRecord(Base, TimestampMixin):
    """
    Normalized vulnerability and threat intelligence record (Prompt 35).
    Ingests CVE, CISA KEV, and EPSS metrics with strict source provenance and affected version boundaries.
    """
    __tablename__ = "threat_intelligence_records"
    __table_args__ = (
        UniqueConstraint("cve_id", "source", name="uq_threat_intel_cve_source"),
        Index("ix_threat_intel_product_vendor", "vendor", "product"),
        Index("ix_threat_intel_cve_exploited", "cve_id", "is_known_exploited"),
    )

    id = Column(String(36), primary_key=True, default=generate_uuid)
    cve_id = Column(String(50), nullable=False, index=True)
    source = Column(String(50), nullable=False, index=True)
    title = Column(String(255), nullable=True)
    description = Column(Text, nullable=True)

    vendor = Column(String(100), nullable=True, index=True)
    product = Column(String(100), nullable=True, index=True)
    cpe = Column(String(255), nullable=True, index=True)

    version_start_including = Column(String(50), nullable=True)
    version_end_excluding = Column(String(50), nullable=True)
    version_end_including = Column(String(50), nullable=True)
    affected_versions_list = Column(JSON, default=list, nullable=False)

    cvss_score = Column(Float, nullable=True)
    cvss_vector = Column(String(100), nullable=True)
    epss_score = Column(Float, nullable=True)
    epss_percentile = Column(Float, nullable=True)

    is_known_exploited = Column(Boolean, default=False, nullable=False, index=True)
    cisa_kev_due_date = Column(DateTime(timezone=True), nullable=True)
    cisa_kev_action = Column(Text, nullable=True)

    published_at = Column(DateTime(timezone=True), nullable=True)
    modified_at = Column(DateTime(timezone=True), nullable=True)
    retrieved_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=True)
    confidence = Column(Float, default=1.0, nullable=False)

    provenance_url = Column(String(500), nullable=True)
    raw_payload_checksum = Column(String(64), nullable=True)
    raw_payload = Column(JSON, default=dict, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)

    correlations = relationship("ThreatCorrelationRecord", back_populates="threat_intel", cascade="all, delete-orphan")


class ThreatCorrelationRecord(Base, TimestampMixin):
    """
    Evidence-grounded correlation binding a vulnerability finding to normalized threat intelligence (Prompt 35).
    Guarantees non-destructive risk enrichment without altering the finding's authoritative severity.
    """
    __tablename__ = "threat_correlations"
    __table_args__ = (
        UniqueConstraint("finding_id", "threat_intel_id", name="uq_finding_threat_intel"),
        Index("ix_threat_correlations_proj_class", "project_id", "match_classification"),
    )

    id = Column(String(36), primary_key=True, default=generate_uuid)
    project_id = Column(String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    finding_id = Column(String(36), ForeignKey("vulnerability_findings.id", ondelete="CASCADE"), nullable=False, index=True)
    threat_intel_id = Column(String(36), ForeignKey("threat_intelligence_records.id", ondelete="CASCADE"), nullable=False, index=True)

    match_classification = Column(Enum(MatchClassification), nullable=False, index=True)
    confidence_score = Column(Float, default=1.0, nullable=False)
    evidence_grounding = Column(JSON, default=dict, nullable=False)

    enriched_risk_score = Column(Float, nullable=False)
    risk_enrichment_factors = Column(JSON, default=dict, nullable=False)

    correlated_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    superseded_at = Column(DateTime(timezone=True), nullable=True)

    # Relationships
    project = relationship("Project")
    finding = relationship("VulnerabilityFinding")
    threat_intel = relationship("ThreatIntelligenceRecord", back_populates="correlations")
