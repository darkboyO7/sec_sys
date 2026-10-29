import enum
from sqlalchemy import Column, String, Boolean, Enum, DateTime
from sqlalchemy.orm import relationship
from app.core.database import Base
from app.models.base import TimestampMixin, generate_uuid


class SystemRole(str, enum.Enum):
    ADMIN = "ADMIN"
    SECURITY_LEAD = "SECURITY_LEAD"
    SECURITY_TESTER = "SECURITY_TESTER"
    AUDITOR = "AUDITOR"
    VIEWER = "VIEWER"


class User(Base, TimestampMixin):
    __tablename__ = "users"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    email = Column(String(255), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    full_name = Column(String(255), nullable=False)
    system_role = Column(Enum(SystemRole), default=SystemRole.SECURITY_TESTER, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    token_revoked_before = Column(DateTime(timezone=True), nullable=True)

    # Relationships
    project_memberships = relationship("ProjectMember", back_populates="user", cascade="all, delete-orphan")
