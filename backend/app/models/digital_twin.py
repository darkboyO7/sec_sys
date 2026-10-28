from sqlalchemy import Column, String, Integer, ForeignKey, JSON, DateTime
from sqlalchemy.orm import relationship, backref

from app.core.database import Base
from app.models.base import TimestampMixin, generate_uuid, utc_now


class SecuritySnapshot(Base, TimestampMixin):
    """
    Historical Security Digital Twin Snapshot.
    Stores immutable, point-in-time state of project assets, findings, evidence references,
    risk intelligence, remediation progress, and verification results.
    Enables historical state reconstruction and reproducible diffing across points in time.
    """
    __tablename__ = "security_snapshots"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    project_id = Column(String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    snapshot_label = Column(String(255), nullable=False)
    snapshot_timestamp = Column(DateTime(timezone=True), default=utc_now, nullable=False, index=True)
    captured_by_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)

    assets_count = Column(Integer, default=0, nullable=False)
    findings_count = Column(Integer, default=0, nullable=False)

    risk_summary = Column(JSON, nullable=False, default=dict)
    state_manifest = Column(JSON, nullable=False, default=dict)
    manifest_sha256 = Column(String(64), nullable=False, index=True)

    # Relationships
    project = relationship("Project", backref=backref("security_snapshots", cascade="all, delete-orphan"))
    captured_by = relationship("User", foreign_keys=[captured_by_id])
