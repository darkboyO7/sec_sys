import enum
from sqlalchemy import Column, String, Integer, ForeignKey, Enum as SqlEnum, DateTime
from sqlalchemy.orm import relationship, backref

from app.core.database import Base
from app.models.base import TimestampMixin, generate_uuid, utc_now


class ReportType(str, enum.Enum):
    EXECUTIVE = "EXECUTIVE"
    TECHNICAL = "TECHNICAL"
    GOVERNANCE = "GOVERNANCE"


class ReportFormat(str, enum.Enum):
    JSON = "JSON"
    CSV = "CSV"
    HTML = "HTML"


class ReportRecord(Base, TimestampMixin):
    """
    Immutable audit metadata for generated security reports.
    Tracks report type, format, cryptographic content hash (SHA-256), author, and generation timestamp.
    """
    __tablename__ = "report_records"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    project_id = Column(String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    report_type = Column(SqlEnum(ReportType), nullable=False, index=True)
    report_format = Column(SqlEnum(ReportFormat), nullable=False, index=True)
    title = Column(String(255), nullable=False)
    generated_by_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    report_sha256 = Column(String(64), nullable=False, index=True)
    item_count = Column(Integer, default=0, nullable=False)
    content_bytes = Column(Integer, default=0, nullable=False)
    generated_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)

    # Relationships
    project = relationship("Project", backref=backref("report_records", cascade="all, delete-orphan"))
    generated_by = relationship("User", foreign_keys=[generated_by_id])
