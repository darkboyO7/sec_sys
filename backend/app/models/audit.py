from sqlalchemy import Column, String, Integer, DateTime, JSON, Text, Index
from app.core.database import Base
from app.models.base import generate_uuid, utc_now


class AuditEvent(Base):
    """
    Immutable audit log entry.
    Records actor, action, target entity, timestamp, outcome, and structured details.
    """
    __tablename__ = "audit_events"

    __table_args__ = (
        Index("ix_audit_events_project_timestamp", "project_id", "timestamp"),
    )

    id = Column(String(36), primary_key=True, default=generate_uuid)
    sequence_number = Column(Integer, nullable=True, index=True)
    timestamp = Column(DateTime(timezone=True), default=utc_now, nullable=False, index=True)

    # Actor identity (actor_id can be null for anonymous unauthenticated attempts)
    actor_id = Column(String(36), nullable=True, index=True)
    actor_email = Column(String(255), nullable=True)

    # Action taxonomy (e.g. AUTH_LOGIN, SCOPE_TARGET_AUTHORIZE, SCOPE_TARGET_REVOKE, SCOPE_EXCLUSION_ADD)
    action = Column(String(100), nullable=False, index=True)

    # Target entity
    target_type = Column(String(100), nullable=False, index=True)
    target_id = Column(String(255), nullable=True, index=True)
    project_id = Column(String(36), nullable=True, index=True)

    # Network provenance and outcome
    ip_address = Column(String(45), nullable=True)  # Supports IPv4 and IPv6 string representations
    outcome = Column(String(20), nullable=False, index=True)  # SUCCESS, DENIED, FAILURE

    # Contextual structured metadata (strictly sanitized - no passwords, secrets, or full tokens)
    details = Column(JSON, default=dict, nullable=False)

    # Cryptographic tamper-evident hash chaining (Phase 8)
    prev_event_hash = Column(String(64), nullable=True, index=True)
    event_hash = Column(String(64), nullable=True, index=True)


class AuditChainHead(Base):
    """
    Dedicated partition chain-head and serialization record for audit event appending.
    Guarantees deterministic multi-process serialization and prevents concurrent chain forks.
    """
    __tablename__ = "audit_chain_heads"

    partition_key = Column(String(100), primary_key=True)  # project_id or '__GLOBAL__'
    last_sequence_number = Column(Integer, default=0, nullable=False)
    last_event_hash = Column(String(64), nullable=True)
    last_event_timestamp = Column(DateTime(timezone=True), nullable=True)
    updated_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)

