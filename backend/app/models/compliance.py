"""
Compliance Intelligence, Security Baselines & Configuration Drift Governance (Prompt 33).
Domain persistence models for versioned controls, baseline profiles, evaluation runs,
control results, configuration drift tracking, and controlled exceptions.
"""
import enum
from sqlalchemy import Column, String, Integer, Float, Boolean, ForeignKey, Enum as SqlEnum, DateTime, Text, JSON, Index
from sqlalchemy.orm import relationship, backref

from app.core.database import Base
from app.models.base import TimestampMixin, generate_uuid, utc_now


class ComplianceEvaluationStatus(str, enum.Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    PARTIAL = "PARTIAL"
    UNKNOWN = "UNKNOWN"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    ERROR = "ERROR"


class ComplianceExceptionStatus(str, enum.Enum):
    REQUESTED = "REQUESTED"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"


class ComplianceDriftType(str, enum.Enum):
    REGRESSION_FAIL = "REGRESSION_FAIL"
    EVIDENCE_DISAPPEARED_UNKNOWN = "EVIDENCE_DISAPPEARED_UNKNOWN"
    NEW_CONTROL_UNSATISFIED = "NEW_CONTROL_UNSATISFIED"
    REMEDIATED_PASS = "REMEDIATED_PASS"
    EXCEPTION_EXPIRED = "EXCEPTION_EXPIRED"


class ComplianceControlRecord(Base, TimestampMixin):
    """
    Versioned, immutable security requirement definition.
    Changes to control criteria produce a new version, preserving historical evaluations.
    """
    __tablename__ = "compliance_controls"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    control_id = Column(String(50), nullable=False, index=True)
    version = Column(String(20), default="1.0.0", nullable=False)
    category = Column(String(50), nullable=False, index=True)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    requirement_statement = Column(Text, nullable=False)
    framework = Column(String(100), default="NIST_CSF_2.0", nullable=False, index=True)
    framework_reference = Column(String(50), nullable=True)
    applicability_criteria = Column(JSON, default=dict, nullable=False)
    required_evidence_types = Column(JSON, default=list, nullable=False)
    evaluation_rule = Column(String(100), nullable=False)
    severity = Column(String(20), default="HIGH", nullable=False)
    remediation_guidance = Column(Text, nullable=False)
    evaluation_limitations = Column(Text, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)

    __table_args__ = (
        Index("uq_compliance_controls_control_version", "control_id", "version", unique=True),
    )


class BaselineProfileRecord(Base, TimestampMixin):
    """
    Configurable, versioned security baseline profile selecting controls for an environment.
    """
    __tablename__ = "compliance_baseline_profiles"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    project_id = Column(String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    profile_key = Column(String(100), nullable=False, index=True)
    version = Column(String(20), default="1.0.0", nullable=False)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    target_applicability = Column(String(100), default="WEB_APPLICATION", nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    control_ids = Column(JSON, default=list, nullable=False)
    parameters = Column(JSON, default=dict, nullable=False)
    created_by_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)

    project = relationship("Project")
    created_by = relationship("User", foreign_keys=[created_by_id])

    __table_args__ = (
        Index("uq_compliance_baselines_proj_key_version", "project_id", "profile_key", "version", unique=True),
    )


class ComplianceEvaluationRun(Base, TimestampMixin):
    """
    Immutable snapshot of an evidence-backed baseline compliance evaluation.
    """
    __tablename__ = "compliance_evaluation_runs"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    project_id = Column(String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    baseline_profile_id = Column(String(36), ForeignKey("compliance_baseline_profiles.id", ondelete="RESTRICT"), nullable=False, index=True)
    assessment_id = Column(String(36), ForeignKey("assessment_jobs.id", ondelete="SET NULL"), nullable=True, index=True)
    run_status = Column(String(50), default="COMPLETED", nullable=False)
    pass_count = Column(Integer, default=0, nullable=False)
    fail_count = Column(Integer, default=0, nullable=False)
    partial_count = Column(Integer, default=0, nullable=False)
    unknown_count = Column(Integer, default=0, nullable=False)
    not_applicable_count = Column(Integer, default=0, nullable=False)
    error_count = Column(Integer, default=0, nullable=False)
    total_controls_evaluated = Column(Integer, default=0, nullable=False)
    provenance_digest = Column(String(64), nullable=False, index=True)
    evaluated_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    evaluated_by_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)

    project = relationship("Project")
    baseline_profile = relationship("BaselineProfileRecord")
    assessment = relationship("AssessmentJob", foreign_keys=[assessment_id])
    evaluated_by = relationship("User", foreign_keys=[evaluated_by_id])
    control_results = relationship("ComplianceControlResultRecord", back_populates="run", cascade="all, delete-orphan")


class ComplianceControlResultRecord(Base, TimestampMixin):
    """
    Individual evidence-backed control outcome within a compliance evaluation run.
    """
    __tablename__ = "compliance_control_results"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    run_id = Column(String(36), ForeignKey("compliance_evaluation_runs.id", ondelete="CASCADE"), nullable=False, index=True)
    project_id = Column(String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    control_id = Column(String(50), nullable=False, index=True)
    control_version = Column(String(20), default="1.0.0", nullable=False)
    status = Column(SqlEnum(ComplianceEvaluationStatus), nullable=False, index=True)
    asset_id = Column(String(36), ForeignKey("assets.id", ondelete="SET NULL"), nullable=True, index=True)
    evidence_refs = Column(JSON, default=list, nullable=False)
    evidence_digests = Column(JSON, default=list, nullable=False)
    reasoning = Column(Text, nullable=False)
    missing_evidence_types = Column(JSON, default=list, nullable=False)
    confidence_score = Column(Float, default=1.0, nullable=False)
    limitations = Column(Text, nullable=True)
    has_exception = Column(Boolean, default=False, nullable=False)
    exception_id = Column(String(36), nullable=True)

    run = relationship("ComplianceEvaluationRun", back_populates="control_results")
    project = relationship("Project")
    asset = relationship("Asset", foreign_keys=[asset_id])


class ComplianceDriftEventRecord(Base, TimestampMixin):
    """
    Idempotent record of detected security baseline or evidence drift.
    """
    __tablename__ = "compliance_drift_events"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    project_id = Column(String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    control_id = Column(String(50), nullable=False, index=True)
    asset_id = Column(String(36), ForeignKey("assets.id", ondelete="SET NULL"), nullable=True)
    drift_type = Column(SqlEnum(ComplianceDriftType), nullable=False, index=True)
    previous_status = Column(SqlEnum(ComplianceEvaluationStatus), nullable=False)
    new_status = Column(SqlEnum(ComplianceEvaluationStatus), nullable=False)
    previous_run_id = Column(String(36), nullable=True)
    current_run_id = Column(String(36), ForeignKey("compliance_evaluation_runs.id", ondelete="CASCADE"), nullable=False, index=True)
    reason = Column(Text, nullable=False)
    detected_at = Column(DateTime(timezone=True), default=utc_now, nullable=False)
    deduplication_hash = Column(String(64), unique=True, nullable=False, index=True)

    project = relationship("Project")
    current_run = relationship("ComplianceEvaluationRun")


class ComplianceExceptionRecord(Base, TimestampMixin):
    """
    Authorized, time-bounded security baseline exception with separation of duties enforcement.
    """
    __tablename__ = "compliance_exceptions"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    project_id = Column(String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    control_id = Column(String(50), nullable=False, index=True)
    asset_id = Column(String(36), ForeignKey("assets.id", ondelete="SET NULL"), nullable=True)
    justification = Column(Text, nullable=False)
    risk_assessment = Column(Text, nullable=False)
    compensating_controls = Column(Text, nullable=False)
    requester_id = Column(String(36), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False)
    approver_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    status = Column(SqlEnum(ComplianceExceptionStatus), default=ComplianceExceptionStatus.REQUESTED, nullable=False, index=True)
    expires_at = Column(DateTime(timezone=True), nullable=False, index=True)
    approved_at = Column(DateTime(timezone=True), nullable=True)
    revoked_at = Column(DateTime(timezone=True), nullable=True)
    review_notes = Column(Text, nullable=True)

    project = relationship("Project")
    requester = relationship("User", foreign_keys=[requester_id])
    approver = relationship("User", foreign_keys=[approver_id])
