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
    Enum as SqlEnum,
    ForeignKey,
    JSON,
    Text,
    Index,
    UniqueConstraint,
)
from sqlalchemy.orm import relationship, backref

from app.core.database import Base
from app.models.base import TimestampMixin, generate_uuid, utc_now


class DriftType(str, enum.Enum):
    NEW_AUTHORIZED_ASSET = "NEW_AUTHORIZED_ASSET"
    ASSET_UNOBSERVED_WARNING = "ASSET_UNOBSERVED_WARNING"
    ASSET_CONFIRMED_ABSENT = "ASSET_CONFIRMED_ABSENT"
    IP_ASSOCIATION_CHANGED = "IP_ASSOCIATION_CHANGED"
    HOSTNAME_ASSOCIATION_CHANGED = "HOSTNAME_ASSOCIATION_CHANGED"
    SERVICE_ADDED = "SERVICE_ADDED"
    SERVICE_REMOVED = "SERVICE_REMOVED"
    SERVICE_METADATA_CHANGED = "SERVICE_METADATA_CHANGED"
    VERSION_CHANGED = "VERSION_CHANGED"
    SECURITY_CONFIG_CHANGED = "SECURITY_CONFIG_CHANGED"
    FINDING_APPEARED = "FINDING_APPEARED"
    FINDING_DISAPPEARED = "FINDING_DISAPPEARED"
    EVIDENCE_CONFIDENCE_CHANGED = "EVIDENCE_CONFIDENCE_CHANGED"


class DriftMateriality(str, enum.Enum):
    MATERIAL = "MATERIAL"
    IMMATERIAL = "IMMATERIAL"
    INCONCLUSIVE = "INCONCLUSIVE"


class ReassessmentPriority(str, enum.Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class ReassessmentStatus(str, enum.Enum):
    PROPOSED = "PROPOSED"
    DEFERRED = "DEFERRED"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    QUEUED = "QUEUED"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class ExposureDriftRecord(Base, TimestampMixin):
    """
    Persistent Exposure Drift Record (Prompt 20).
    Captures verified deltas between compatible observations:
    - Distinguishes real change from missing data, adapter failure, or partial coverage.
    - Classifies materiality (MATERIAL, IMMATERIAL, INCONCLUSIVE).
    - Preserves before-and-after observation linkages and cryptographic evidence references.
    """
    __tablename__ = "exposure_drift_records"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    project_id = Column(String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    asset_id = Column(String(36), ForeignKey("assets.id", ondelete="CASCADE"), nullable=True, index=True)

    drift_type = Column(SqlEnum(DriftType), nullable=False, index=True)
    materiality = Column(SqlEnum(DriftMateriality), default=DriftMateriality.MATERIAL, nullable=False, index=True)
    materiality_reason = Column(Text, nullable=False)

    target_resource = Column(String(500), nullable=False, index=True)
    title = Column(String(255), nullable=False)

    previous_observation_id = Column(String(36), ForeignKey("asset_observations.id", ondelete="SET NULL"), nullable=True)
    current_observation_id = Column(String(36), ForeignKey("asset_observations.id", ondelete="SET NULL"), nullable=True)

    previous_state = Column(JSON, default=dict, nullable=False)
    new_state = Column(JSON, default=dict, nullable=False)
    evidence_references = Column(JSON, default=list, nullable=False)

    confidence = Column(Float, default=1.0, nullable=False)
    is_resolved = Column(Boolean, default=False, nullable=False, index=True)
    security_impact_summary = Column(Text, nullable=True)
    reassessment_recommended = Column(Boolean, default=False, nullable=False, index=True)

    dedup_key = Column(String(64), nullable=True, index=True)
    detected_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    evaluated_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    acted_upon_at = Column(DateTime(timezone=True), nullable=True)

    # Relationships
    project = relationship("Project")
    asset = relationship("Asset")
    previous_observation = relationship("AssetObservation", foreign_keys=[previous_observation_id])
    current_observation = relationship("AssetObservation", foreign_keys=[current_observation_id])
    proposals = relationship("ReassessmentProposal", back_populates="drift_record", cascade="all, delete-orphan")

    __table_args__ = (
        Index("ix_exposure_drift_project_detected", "project_id", "detected_at"),
        Index("ix_exposure_drift_project_materiality", "project_id", "materiality"),
    )


class ReassessmentProposal(Base, TimestampMixin):
    """
    Policy-Constrained Reassessment Proposal (Prompt 20).
    Created when material exposure drift requires verification or re-scan.
    Enforces authorization re-validation at job claim boundary, prevents retry storms,
    and requires human approval for sensitive/restricted actions.
    """
    __tablename__ = "reassessment_proposals"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    project_id = Column(String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    asset_id = Column(String(36), ForeignKey("assets.id", ondelete="CASCADE"), nullable=True, index=True)
    drift_record_id = Column(String(36), ForeignKey("exposure_drift_records.id", ondelete="CASCADE"), nullable=True, index=True)

    target_input = Column(String(500), nullable=False, index=True)
    adapter_name = Column(String(100), default="live_network_auditor_adapter", nullable=False)
    fixture_profile = Column(String(100), default="LIVE_WEB_SECURITY_AUDIT", nullable=False)

    priority = Column(SqlEnum(ReassessmentPriority), default=ReassessmentPriority.MEDIUM, nullable=False, index=True)
    status = Column(SqlEnum(ReassessmentStatus), default=ReassessmentStatus.PROPOSED, nullable=False, index=True)
    rationale = Column(Text, nullable=False)

    scope_authorized = Column(Boolean, default=True, nullable=False)
    scope_validation_details = Column(JSON, default=dict, nullable=False)

    requires_human_approval = Column(Boolean, default=False, nullable=False)
    approved_by_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    approved_at = Column(DateTime(timezone=True), nullable=True)
    rejection_reason = Column(Text, nullable=True)

    scheduled_job_id = Column(String(36), ForeignKey("assessment_jobs.id", ondelete="SET NULL"), nullable=True)
    dedup_key = Column(String(64), nullable=False, index=True)
    attempt_count = Column(Integer, default=0, nullable=False)
    max_attempts = Column(Integer, default=3, nullable=False)
    last_error = Column(Text, nullable=True)

    # Relationships
    project = relationship("Project")
    asset = relationship("Asset")
    drift_record = relationship("ExposureDriftRecord", back_populates="proposals")
    approved_by = relationship("User", foreign_keys=[approved_by_id])
    scheduled_job = relationship("AssessmentJob", foreign_keys=[scheduled_job_id])

    __table_args__ = (
        Index("ix_reassessment_proposals_project_status", "project_id", "status"),
        Index("ix_reassessment_proposals_dedup", "project_id", "dedup_key"),
    )
