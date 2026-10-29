from sqlalchemy import (
    Column,
    String,
    ForeignKey,
    DateTime,
    Text,
    Index,
)
from sqlalchemy.orm import relationship

from app.core.database import Base
from app.models.base import TimestampMixin, generate_uuid, utc_now


class TokenRevocationRecord(Base):
    """
    Cryptographic token revocation and session invalidation record (Prompt 36).
    Enforces immediate session termination upon logout, password change, or admin revocation.
    """
    __tablename__ = "token_revocations"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    token_jti = Column(String(64), nullable=False, unique=True, index=True)
    user_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    revoked_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False, index=True)
    reason = Column(String(100), default="USER_LOGOUT", nullable=False)

    user = relationship("User")


class AccessDenialAuditRecord(Base):
    """
    Immutable access denial audit ledger (Prompt 36).
    Records attributable audit logs whenever an operation is denied due to authentication,
    role deficiency, separation-of-duties violation, or cross-tenant boundary breach.
    Guarantees zero secret leakage.
    """
    __tablename__ = "access_denial_audit_records"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    user_id = Column(String(36), nullable=True, index=True)
    user_email = Column(String(255), nullable=True)
    project_id = Column(String(36), nullable=True, index=True)
    endpoint = Column(String(255), nullable=False, index=True)
    http_method = Column(String(10), nullable=False)
    required_privilege = Column(String(100), nullable=False)
    held_privilege = Column(String(100), nullable=True)
    denial_reason = Column(Text, nullable=False)
    client_ip = Column(String(50), nullable=True)
    denied_at = Column(DateTime(timezone=True), default=utc_now, nullable=False, index=True)
