import enum
from sqlalchemy import Column, String, ForeignKey, Enum, DateTime, Text
from sqlalchemy.orm import relationship
from app.core.database import Base
from app.models.base import TimestampMixin, generate_uuid


class TargetType(str, enum.Enum):
    IP_ADDRESS = "IP_ADDRESS"
    CIDR = "CIDR"
    DOMAIN = "DOMAIN"
    URL = "URL"


class AuthorizationStatus(str, enum.Enum):
    PENDING = "PENDING"
    AUTHORIZED = "AUTHORIZED"
    REVOKED = "REVOKED"
    EXPIRED = "EXPIRED"


class ScopeTarget(Base, TimestampMixin):
    __tablename__ = "scope_targets"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    project_id = Column(String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)

    target_type = Column(Enum(TargetType), nullable=False)
    # The normalized target value (e.g. 192.168.1.0/24, example.com, https://api.example.com)
    target_value = Column(String(500), nullable=False, index=True)
    description = Column(String(1000), default="", nullable=False)

    # Authorization status & provenance
    authorization_status = Column(Enum(AuthorizationStatus), default=AuthorizationStatus.PENDING, nullable=False, index=True)
    authorization_evidence = Column(Text, default="", nullable=False)  # Reference to ROE, Jira ticket, authorization memo

    authorized_by_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    authorized_at = Column(DateTime(timezone=True), nullable=True)
    expires_at = Column(DateTime(timezone=True), nullable=True)

    # Revocation tracking
    revocation_reason = Column(Text, nullable=True)
    revoked_by_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    revoked_at = Column(DateTime(timezone=True), nullable=True)

    # Creator tracking
    created_by_id = Column(String(36), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False)

    # Relationships
    project = relationship("Project", back_populates="scope_targets")
    authorized_by = relationship("User", foreign_keys=[authorized_by_id])
    revoked_by = relationship("User", foreign_keys=[revoked_by_id])
    created_by = relationship("User", foreign_keys=[created_by_id])


class ScopeExclusion(Base, TimestampMixin):
    __tablename__ = "scope_exclusions"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    project_id = Column(String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)

    target_type = Column(Enum(TargetType), nullable=False)
    target_value = Column(String(500), nullable=False, index=True)
    reason = Column(Text, nullable=False)  # e.g., "Out of scope third party gateway, production DB"

    created_by_id = Column(String(36), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False)

    # Relationships
    project = relationship("Project", back_populates="scope_exclusions")
    created_by = relationship("User", foreign_keys=[created_by_id])
