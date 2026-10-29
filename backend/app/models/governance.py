import enum
from sqlalchemy import (
    Column,
    String,
    Boolean,
    ForeignKey,
    Enum as SqlEnum,
    DateTime,
    Text,
    JSON,
    Index,
)
from sqlalchemy.orm import relationship, backref

from app.core.database import Base
from app.models.base import TimestampMixin, generate_uuid, utc_now


class ApprovalWorkflowType(str, enum.Enum):
    SCOPE_AUTHORIZATION = "SCOPE_AUTHORIZATION"
    SECURITY_DECISION = "SECURITY_DECISION"
    REMEDIATION_CHANGE = "REMEDIATION_CHANGE"
    RISK_ACCEPTANCE = "RISK_ACCEPTANCE"
    MODEL_PROMOTION = "MODEL_PROMOTION"
    DATA_PURGE = "DATA_PURGE"


class GovernanceApprovalStatus(str, enum.Enum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXECUTED = "EXECUTED"
    REVOKED = "REVOKED"
    INVALIDATED = "INVALIDATED"


class ProjectGovernancePolicy(Base, TimestampMixin):
    """
    Project-level governance policy configuration (Prompt 22).
    Governs Separation of Duties (SoD), multi-user approval gates,
    and single-operator local mode overrides.
    """
    __tablename__ = "project_governance_policies"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    project_id = Column(String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, unique=True, index=True)

    enforce_separation_of_duties = Column(Boolean, default=True, nullable=False)
    allow_self_approval_override = Column(Boolean, default=False, nullable=False)  # Single-operator local mode override
    require_two_person_rule_for_purge = Column(Boolean, default=True, nullable=False)
    require_lead_for_scope_authorization = Column(Boolean, default=True, nullable=False)
    require_lead_for_risk_acceptance = Column(Boolean, default=True, nullable=False)
    require_lead_for_remediation_approval = Column(Boolean, default=True, nullable=False)
    require_lead_for_model_promotion = Column(Boolean, default=True, nullable=False)
    policy_version = Column(String(50), default="v2026.2.0", nullable=False)

    # Relationships
    project = relationship("Project", backref=backref("governance_policy", uselist=False, cascade="all, delete-orphan"))


class ApprovalRequestRecord(Base, TimestampMixin):
    """
    Immutable, attributable record of an approval-controlled security workflow (Prompt 22).
    Binds approval directly to exact parameters/scope via parameter_hash,
    enforces Separation of Duties (requester != approver),
    and records execution vs approval state transitions.
    """
    __tablename__ = "approval_request_records"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    project_id = Column(String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)

    workflow_type = Column(SqlEnum(ApprovalWorkflowType), nullable=False, index=True)
    resource_type = Column(String(100), nullable=False, index=True)  # ScopeTarget, SecurityDecision, etc.
    resource_id = Column(String(255), nullable=False, index=True)

    status = Column(SqlEnum(GovernanceApprovalStatus), default=GovernanceApprovalStatus.PENDING, nullable=False, index=True)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)

    parameter_hash = Column(String(64), nullable=False, index=True)  # SHA-256 digest of parameters
    parameters_snapshot = Column(JSON, default=dict, nullable=False)

    requester_id = Column(String(36), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False, index=True)
    approver_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    executed_by_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)

    requested_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    decided_at = Column(DateTime(timezone=True), nullable=True)
    executed_at = Column(DateTime(timezone=True), nullable=True)
    invalidated_at = Column(DateTime(timezone=True), nullable=True)

    decision_reason = Column(Text, nullable=True)
    invalidation_reason = Column(Text, nullable=True)
    policy_version = Column(String(50), default="v2026.2.0", nullable=False)

    # Relationships
    project = relationship("Project", backref=backref("approval_requests", cascade="all, delete-orphan"))
    requester = relationship("User", foreign_keys=[requester_id])
    approver = relationship("User", foreign_keys=[approver_id])
    executor = relationship("User", foreign_keys=[executed_by_id])

    __table_args__ = (
        Index("ix_approval_project_workflow_status", "project_id", "workflow_type", "status"),
        Index("ix_approval_resource_lookup", "project_id", "resource_type", "resource_id"),
    )
