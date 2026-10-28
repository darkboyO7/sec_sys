import enum
from sqlalchemy import Column, String, Integer, Float, Boolean, DateTime, Enum as SqlEnum, ForeignKey, JSON, Text, Index
from sqlalchemy.orm import relationship, backref

from app.core.database import Base
from app.models.base import TimestampMixin, generate_uuid, utc_now


class ChangeType(str, enum.Enum):
    NEW_ASSET = "NEW_ASSET"
    CONFIG_CHANGED = "CONFIG_CHANGED"
    NEW_FINDING = "NEW_FINDING"
    RESOLVED_FINDING = "RESOLVED_FINDING"
    RECURRING_FINDING = "RECURRING_FINDING"
    RISK_SCORE_CHANGED = "RISK_SCORE_CHANGED"
    ATTACK_PATH_EXPOSED = "ATTACK_PATH_EXPOSED"
    REMEDIATION_OUTCOME = "REMEDIATION_OUTCOME"


class DecisionActionType(str, enum.Enum):
    REASSESS_CHANGED_ASSET = "REASSESS_CHANGED_ASSET"
    VALIDATE_UNCERTAIN_FINDING = "VALIDATE_UNCERTAIN_FINDING"
    INVESTIGATE_HIGH_IMPACT_EXPOSURE = "INVESTIGATE_HIGH_IMPACT_EXPOSURE"
    REFRESH_STALE_EVIDENCE = "REFRESH_STALE_EVIDENCE"
    PRIORITIZE_REMEDIATION = "PRIORITIZE_REMEDIATION"
    VERIFY_APPLIED_FIX = "VERIFY_APPLIED_FIX"
    RECALCULATE_RISK_AND_PATHS = "RECALCULATE_RISK_AND_PATHS"
    REQUEST_HUMAN_REVIEW = "REQUEST_HUMAN_REVIEW"


class DecisionStatus(str, enum.Enum):
    PROPOSED = "PROPOSED"
    APPROVED = "APPROVED"
    EXECUTED = "EXECUTED"
    REJECTED = "REJECTED"
    INCONCLUSIVE = "INCONCLUSIVE"


class PostureChangeRecord(Base, TimestampMixin):
    """
    Persistent Security Posture Change Record.
    Captures verified deltas across assessments:
    - Distinguishes confirmed changes from missing data, failed probes, or unreachable hosts.
    - Records previous state vs new state with evidence summaries.
    """
    __tablename__ = "posture_change_records"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    project_id = Column(String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)

    change_type = Column(SqlEnum(ChangeType), nullable=False, index=True)
    target_resource = Column(String(255), nullable=False, index=True)
    title = Column(String(255), nullable=False)

    previous_state = Column(JSON, nullable=False, default=dict)
    new_state = Column(JSON, nullable=False, default=dict)
    evidence_summary = Column(Text, nullable=False)

    confidence = Column(Float, default=1.0, nullable=False)
    is_confirmed = Column(Boolean, default=True, nullable=False, index=True)

    project = relationship("Project", backref=backref("posture_changes", cascade="all, delete-orphan"))

    __table_args__ = (
        Index("ix_posture_changes_project_type", "project_id", "change_type"),
    )


class SecurityDecisionRecord(Base, TimestampMixin):
    """
    Persistent Security Decision Record.
    Represents an evidence-backed autonomous recommendation or action:
    - Captures triggering observation and evidence considered.
    - Specifies required authorization/approval before execution.
    - Measures verified posture improvement before vs after execution.
    """
    __tablename__ = "security_decision_records"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    project_id = Column(String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)

    action_type = Column(SqlEnum(DecisionActionType), nullable=False, index=True)
    status = Column(SqlEnum(DecisionStatus), default=DecisionStatus.PROPOSED, nullable=False, index=True)

    title = Column(String(255), nullable=False)
    triggering_observation = Column(Text, nullable=False)
    evidence_considered = Column(JSON, nullable=False, default=dict)
    selected_action = Column(String(255), nullable=False)
    rationale = Column(Text, nullable=False)

    confidence = Column(Float, default=0.8, nullable=False)
    uncertainty = Column(Float, default=0.2, nullable=False)

    target_id = Column(String(255), nullable=True, index=True)  # finding_id, asset_id, target_url
    target_resource = Column(String(255), nullable=True, index=True)
    job_id = Column(String(36), ForeignKey("assessment_jobs.id", ondelete="SET NULL"), nullable=True)

    required_approval_role = Column(String(50), nullable=True)  # "LEAD", "ADMIN", or None if safe autonomous
    approved_by_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    approved_at = Column(DateTime(timezone=True), nullable=True)

    executed_at = Column(DateTime(timezone=True), nullable=True)
    execution_outcome = Column(JSON, nullable=True)
    posture_improvement_measured = Column(JSON, nullable=True)  # Delta risk score, resolved findings

    created_by_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)

    project = relationship("Project", backref=backref("security_decisions", cascade="all, delete-orphan"))
    job = relationship("AssessmentJob")
    approver = relationship("User", foreign_keys=[approved_by_id])
    creator = relationship("User", foreign_keys=[created_by_id])

    __table_args__ = (
        Index("ix_security_decisions_project_status", "project_id", "status"),
    )


class PlanStatus(str, enum.Enum):
    GENERATED = "GENERATED"
    PARTIALLY_EXECUTED = "PARTIALLY_EXECUTED"
    COMPLETED = "COMPLETED"
    SUPERSEDED = "SUPERSEDED"
    CANCELLED = "CANCELLED"


class AdaptiveAssessmentPlanRecord(Base, TimestampMixin):
    """
    Evidence-Driven Adaptive Assessment Plan (Prompt 10 / Section 3).
    Captures recommended and skipped assessment checks:
    - Balances freshness, configuration changes, failing probes, and high-risk finding verification.
    - Strictly enforces scope validation and scan budget boundaries.
    - Stores complete decision provenance for historical audit.
    """
    __tablename__ = "adaptive_assessment_plans"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    project_id = Column(String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)

    plan_name = Column(String(255), nullable=False)
    status = Column(SqlEnum(PlanStatus), default=PlanStatus.GENERATED, nullable=False, index=True)

    scan_budget = Column(Integer, default=10, nullable=False)
    total_recommended = Column(Integer, default=0, nullable=False)
    total_skipped = Column(Integer, default=0, nullable=False)

    recommended_checks = Column(JSON, nullable=False, default=list)
    skipped_checks = Column(JSON, nullable=False, default=list)
    execution_summary = Column(JSON, nullable=False, default=dict)

    created_by_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)

    project = relationship("Project", backref=backref("adaptive_plans", cascade="all, delete-orphan"))
    creator = relationship("User", foreign_keys=[created_by_id])

    __table_args__ = (
        Index("ix_adaptive_plans_project_status", "project_id", "status"),
    )


class AutonomyIntensity(str, enum.Enum):
    LOW = "LOW"
    NORMAL = "NORMAL"
    AGGRESSIVE = "AGGRESSIVE"


class AutonomousPolicyRecord(Base, TimestampMixin):
    """
    Project-level policy configuration governing autonomous assessment,
    remediation, rate limits, concurrency, budgets, and approval gates.
    """
    __tablename__ = "autonomous_policies"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    project_id = Column(String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, unique=True, index=True)

    policy_version = Column(String(50), default="v1.0.0", nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    is_suspended = Column(Boolean, default=False, nullable=False)
    suspension_reason = Column(String(500), nullable=True)
    suspended_at = Column(DateTime(timezone=True), nullable=True)
    suspended_by_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)

    # Scopes & Permitted Types
    permitted_assessment_types = Column(JSON, default=list, nullable=False)
    intensity = Column(SqlEnum(AutonomyIntensity), default=AutonomyIntensity.NORMAL, nullable=False)
    max_concurrency = Column(Integer, default=2, nullable=False)
    rate_limit_rps = Column(Float, default=10.0, nullable=False)
    permitted_time_windows = Column(JSON, default=list, nullable=False)

    # Budgets & Limits
    max_daily_budget = Column(Integer, default=20, nullable=False)
    daily_budget_spent = Column(Integer, default=0, nullable=False)
    last_budget_reset_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)

    # Remediation Autonomy & Gates
    permitted_remediation_actions = Column(JSON, default=list, nullable=False)
    require_approval_for_disruptive = Column(Boolean, default=True, nullable=False)
    require_approval_for_remediation = Column(Boolean, default=True, nullable=False)

    # Retry and Safety Thresholds
    max_retries = Column(Integer, default=2, nullable=False)
    failure_threshold = Column(Integer, default=3, nullable=False)
    consecutive_failures = Column(Integer, default=0, nullable=False)

    created_by_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)

    project = relationship("Project", backref=backref("autonomous_policy", uselist=False, cascade="all, delete-orphan"))
    created_by = relationship("User", foreign_keys=[created_by_id])
    suspended_by = relationship("User", foreign_keys=[suspended_by_id])


class DecisionLedgerType(str, enum.Enum):
    ASSESSMENT_SCHEDULED = "ASSESSMENT_SCHEDULED"
    TARGET_ACCEPTED = "TARGET_ACCEPTED"
    TARGET_REJECTED = "TARGET_REJECTED"
    FINDING_PRIORITIZED = "FINDING_PRIORITIZED"
    REMEDIATION_RECOMMENDED = "REMEDIATION_RECOMMENDED"
    REMEDIATION_EXECUTED = "REMEDIATION_EXECUTED"
    FINDING_RESOLVED = "FINDING_RESOLVED"
    FINDING_REOPENED = "FINDING_REOPENED"
    LEARNING_ACCEPTED = "LEARNING_ACCEPTED"
    LEARNING_REJECTED = "LEARNING_REJECTED"
    AUTONOMY_SUSPENDED = "AUTONOMY_SUSPENDED"
    AUTONOMY_RESUMED = "AUTONOMY_RESUMED"
    AUTONOMY_CANCELLED = "AUTONOMY_CANCELLED"
    POLICY_EVALUATION = "POLICY_EVALUATION"


class SecurityDecisionLedgerRecord(Base, TimestampMixin):
    """
    Persistent, auditable security decision ledger.
    Captures why assessments were scheduled, targets accepted/rejected, findings prioritized,
    remediations recommended/executed, findings resolved/reopened, and autonomous actions paused/cancelled.
    Preserves historical decisions even when policies, models, or findings mutate.
    """
    __tablename__ = "security_decision_ledger"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    project_id = Column(String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)

    decision_type = Column(SqlEnum(DecisionLedgerType), nullable=False, index=True)
    decision_outcome = Column(String(50), nullable=False, index=True)
    initiating_event = Column(String(100), nullable=False, index=True)

    target_type = Column(String(50), nullable=False)
    target_id = Column(String(255), nullable=True, index=True)
    target_resource = Column(String(255), nullable=True)

    policy_version = Column(String(50), default="v1.0.0", nullable=False)
    reason = Column(Text, nullable=False)
    evidence_references = Column(JSON, default=list, nullable=False)
    details = Column(JSON, default=dict, nullable=False)

    actor_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)

    project = relationship("Project", backref=backref("decision_ledger_records", cascade="all, delete-orphan"))
    actor = relationship("User", foreign_keys=[actor_id])

    __table_args__ = (
        Index("ix_decision_ledger_project_type", "project_id", "decision_type"),
        Index("ix_decision_ledger_project_created", "project_id", "created_at"),
    )


class OperationalSLOConfig(Base, TimestampMixin):
    """
    Project-level SLO target objectives and alert thresholds.
    """
    __tablename__ = "operational_slo_configs"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    project_id = Column(String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, unique=True, index=True)

    min_assessment_completion_rate = Column(Float, default=95.0, nullable=False)
    max_queue_delay_seconds = Column(Float, default=300.0, nullable=False)
    min_evidence_completeness_rate = Column(Float, default=90.0, nullable=False)
    max_inconclusive_rate = Column(Float, default=10.0, nullable=False)
    min_remediation_completion_rate = Column(Float, default=80.0, nullable=False)
    min_verification_pass_rate = Column(Float, default=85.0, nullable=False)
    min_asset_coverage_rate = Column(Float, default=90.0, nullable=False)
    coverage_stale_days = Column(Integer, default=14, nullable=False)

    project = relationship("Project", backref=backref("slo_config", uselist=False, cascade="all, delete-orphan"))

