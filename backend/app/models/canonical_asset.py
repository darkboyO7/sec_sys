import enum
from sqlalchemy import (
    Column,
    String,
    Float,
    ForeignKey,
    Enum,
    DateTime,
    Text,
    JSON,
    Index,
)
from sqlalchemy.orm import relationship
from app.core.database import Base
from app.models.base import TimestampMixin, generate_uuid, utc_now


class ResolutionMatchOutcome(str, enum.Enum):
    EXACT_MATCH = "EXACT_MATCH"
    STRONG_CORRELATION = "STRONG_CORRELATION"
    AMBIGUOUS_CONFLICT = "AMBIGUOUS_CONFLICT"
    UNMATCHED = "UNMATCHED"


class DeduplicationProposalStatus(str, enum.Enum):
    PROPOSED = "PROPOSED"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    REVERTED = "REVERTED"


class DataQualityIssueType(str, enum.Enum):
    ORPHANED_FINDING = "ORPHANED_FINDING"
    MISSING_ASSET_REFERENCE = "MISSING_ASSET_REFERENCE"
    DUPLICATE_IDENTIFIER = "DUPLICATE_IDENTIFIER"
    INCONSISTENT_TIMESTAMPS = "INCONSISTENT_TIMESTAMPS"
    INVALID_RELATIONSHIP = "INVALID_RELATIONSHIP"
    STALE_OBSERVATION = "STALE_OBSERVATION"


class DataQualityIssueStatus(str, enum.Enum):
    OPEN = "OPEN"
    RESOLVED = "RESOLVED"
    IGNORED = "IGNORED"


class AssetDeduplicationProposal(Base, TimestampMixin):
    """
    Reviewable deduplication merge and split workflow record (Prompt 37).
    Requires human review / Lead approval before merging assets.
    Preserves audit trail, dry run impact snapshot, and complete rollback capability.
    """
    __tablename__ = "asset_deduplication_proposals"
    __table_args__ = (
        Index("ix_asset_dedup_proj_status", "project_id", "status"),
    )

    id = Column(String(36), primary_key=True, default=generate_uuid)
    project_id = Column(String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    source_asset_id = Column(String(36), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True)
    target_asset_id = Column(String(36), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True)

    status = Column(Enum(DeduplicationProposalStatus), default=DeduplicationProposalStatus.PROPOSED, nullable=False, index=True)
    confidence_score = Column(Float, nullable=False)
    match_reasons = Column(JSON, default=list, nullable=False)
    conflicts_detected = Column(JSON, default=list, nullable=False)
    dry_run_impact = Column(JSON, default=dict, nullable=False)

    proposed_by_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    reviewed_by_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    review_comments = Column(Text, nullable=True)
    reviewed_at = Column(DateTime(timezone=True), nullable=True)

    reverted_at = Column(DateTime(timezone=True), nullable=True)
    reverted_by_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    merge_record_id = Column(String(36), ForeignKey("asset_identity_merges.id", ondelete="SET NULL"), nullable=True)

    # Relationships
    project = relationship("Project")
    source_asset = relationship("Asset", foreign_keys=[source_asset_id])
    target_asset = relationship("Asset", foreign_keys=[target_asset_id])
    proposed_by = relationship("User", foreign_keys=[proposed_by_id])
    reviewed_by = relationship("User", foreign_keys=[reviewed_by_id])
    reverted_by = relationship("User", foreign_keys=[reverted_by_id])
    merge_record = relationship("AssetIdentityMergeRecord")


class AssetDataQualityIssue(Base, TimestampMixin):
    """
    Identified data quality anomaly within the asset inventory (Prompt 37).
    Tracks orphaned findings, inconsistent timestamps, duplicate identifiers,
    invalid relationships, and stale observations.
    """
    __tablename__ = "asset_data_quality_issues"
    __table_args__ = (
        Index("ix_asset_dq_proj_type_status", "project_id", "issue_type", "status"),
    )

    id = Column(String(36), primary_key=True, default=generate_uuid)
    project_id = Column(String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)

    issue_type = Column(Enum(DataQualityIssueType), nullable=False, index=True)
    severity = Column(String(50), default="MEDIUM", nullable=False, index=True)
    affected_resource_type = Column(String(50), nullable=False)  # ASSET, FINDING, ALIAS, OBSERVATION, TARGET
    affected_resource_id = Column(String(36), nullable=False, index=True)
    details = Column(JSON, default=dict, nullable=False)

    status = Column(Enum(DataQualityIssueStatus), default=DataQualityIssueStatus.OPEN, nullable=False, index=True)
    detected_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    resolved_at = Column(DateTime(timezone=True), nullable=True)

    # Relationships
    project = relationship("Project")
