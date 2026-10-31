import enum
from sqlalchemy import Column, String, Boolean, Enum, DateTime, Integer
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


class SystemBootstrapState(Base):
    """
    Database-enforced singleton record guaranteeing race-safe one-time administrator bootstrap.
    ID=1 primary key uniqueness ensures atomic bootstrap creation across concurrent requests and processes.
    """
    __tablename__ = "system_bootstrap_state"

    id = Column(Integer, primary_key=True, default=1)
    is_bootstrapped = Column(Boolean, default=True, nullable=False)
    bootstrap_user_id = Column(String(36), nullable=False)
    bootstrapped_at = Column(DateTime(timezone=True), nullable=False)

