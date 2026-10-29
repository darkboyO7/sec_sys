"""
VAPT Platform — Evidence Lifecycle Governance & Data Retention Schemas (Prompt 29).
Defines typed models for data classification, retention policy definitions,
legal/investigation holds, deletion suppression tombstones, and redaction.
"""
from typing import Optional, List, Dict, Any
from datetime import datetime, timezone
import enum
from pydantic import BaseModel, Field


class DataClassification(str, enum.Enum):
    OPERATIONAL_METADATA = "OPERATIONAL_METADATA"
    ASSET_CONFIG = "ASSET_CONFIG"
    FINDINGS_AND_RISK = "FINDINGS_AND_RISK"
    RAW_EVIDENCE = "RAW_EVIDENCE"
    CREDENTIALS_AND_SECRETS = "CREDENTIALS_AND_SECRETS"
    AUDIT_RECORDS = "AUDIT_RECORDS"
    AUTH_AND_IDENTITY = "AUTH_AND_IDENTITY"
    DERIVED_ANALYTICS = "DERIVED_ANALYTICS"


class RetentionActionType(str, enum.Enum):
    RETAIN = "RETAIN"
    ARCHIVE = "ARCHIVE"
    REDACT = "REDACT"
    DELETE = "DELETE"


class HoldType(str, enum.Enum):
    LEGAL_HOLD = "LEGAL_HOLD"
    REGULATORY_HOLD = "REGULATORY_HOLD"
    INVESTIGATION_HOLD = "INVESTIGATION_HOLD"


class HoldStatus(str, enum.Enum):
    ACTIVE = "ACTIVE"
    RELEASED = "RELEASED"


class RetentionPolicyModel(BaseModel):
    policy_id: str
    classification: DataClassification
    retention_days: int
    action: RetentionActionType
    requires_approval: bool
    is_active: bool = True
    description: str
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class LegalHoldModel(BaseModel):
    hold_id: str
    hold_type: HoldType
    target_scope: str  # "PROJECT", "FINDING", or "EVIDENCE"
    target_id: str  # ID of the project, finding, or evidence
    reason: str
    status: HoldStatus
    placed_by_id: str
    placed_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    released_by_id: Optional[str] = None
    released_at: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class LegalHoldCreate(BaseModel):
    hold_type: HoldType = HoldType.INVESTIGATION_HOLD
    target_scope: str
    target_id: str
    reason: str


class DeletionTombstoneModel(BaseModel):
    tombstone_id: str
    evidence_id: str
    original_sha256_hash: str
    classification: DataClassification
    policy_id: str
    deleted_by_id: str
    deleted_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    tombstone_digest: str  # HMAC-SHA256 signature guaranteeing provenance
    reason: str


class RetentionPreviewItem(BaseModel):
    record_id: str
    classification: DataClassification
    entity_type: str  # "FindingEvidence", "AuditLog", etc.
    created_at: str
    age_days: int
    applicable_policy_id: str
    recommended_action: RetentionActionType
    is_held: bool = False
    hold_reason: Optional[str] = None
    has_dependent_records: bool = False
    eligible_for_execution: bool


class RetentionPreviewReport(BaseModel):
    preview_id: str
    generated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    total_scanned_records: int
    eligible_records_count: int
    excluded_by_hold_count: int
    excluded_by_dependency_count: int
    preview_items: List[RetentionPreviewItem]
    dry_run_hash: str  # Proof of state preview consistency


class RetentionExecutionRequest(BaseModel):
    preview_id: str
    dry_run_hash: str
    classification_filter: Optional[DataClassification] = None
    confirmed_by_lead: bool = False


class RetentionExecutionResult(BaseModel):
    execution_id: str
    preview_id: str
    executed_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    archived_count: int
    redacted_count: int
    deleted_count: int
    tombstones_created_count: int
    skipped_count: int
    status: str  # "COMPLETED", "PARTIAL_FAILURE"
    audit_event_id: str
    tombstones: List[DeletionTombstoneModel] = Field(default_factory=list)


class EvidenceRedactionRequest(BaseModel):
    evidence_id: str
    secret_patterns: Optional[List[str]] = None
    redaction_reason: str = "Automated credential & token masking"


class EvidenceRedactionResult(BaseModel):
    evidence_id: str
    redacted: bool
    secrets_masked_count: int
    original_sha256_hash: str
    sanitized_preview: str
    redacted_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
