"""
Pydantic Schemas for Forensic Evidence Preservation & Chain of Custody (Prompt 48).
"""
from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field

from app.models.forensic_evidence import (
    EvidenceLifecycleState,
    VerificationOutcome,
    ContradictionStatus,
    CustodyEventType,
)


class EvidenceIngestRequest(BaseModel):
    project_id: str = Field(..., description="Target project identifier")
    finding_id: Optional[str] = Field(None, description="Optional associated finding ID")
    job_id: Optional[str] = Field(None, description="Optional assessment job ID")
    evidence_type: str = Field(..., description="Evidence category (e.g. RAW_HTTP, NETWORK_CAPTURE, BANNER)")
    raw_payload: str = Field(..., min_length=1, description="Untouched raw evidence payload")
    source_identity: str = Field(..., description="Sensor, scanner, or analyst identity")
    adapter_version: str = Field(..., description="Adapter software version")
    collection_time: datetime = Field(..., description="Timestamp when evidence was observed on target")
    assessment_context: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Execution parameters & target scope")
    signing_key_id: Optional[str] = Field("KEY-DEFAULT-ED25519", description="Attestation key identifier")
    classification: Optional[str] = Field("RESTRICTED", description="Data sensitivity classification")


class EvidenceNormalizeRequest(BaseModel):
    normalized_payload: Dict[str, Any] = Field(..., description="Parsed or structured representation")
    transformer_identity: str = Field(..., description="Transformer component or analyst ID")
    adapter_version: str = Field(..., description="Transformation tool version")
    reason: str = Field(..., description="Rationale for normalization")


class EvidenceContradictionRequest(BaseModel):
    contradictory_payload: str = Field(..., min_length=1, description="New observation payload")
    source_identity: str = Field(..., description="Sensor or analyst identity")
    adapter_version: str = Field(..., description="Adapter software version")
    collection_time: datetime = Field(..., description="Observation timestamp")
    notes: str = Field(..., description="Explanation of contradiction or state divergence")
    supersedes_previous: bool = Field(False, description="Whether this correction formally supersedes the earlier record")
    assessment_context: Optional[Dict[str, Any]] = Field(default_factory=dict)
    signing_key_id: Optional[str] = Field("KEY-DEFAULT-ED25519")


class EvidenceVerificationRequest(BaseModel):
    verify_raw_digest: bool = Field(True, description="Verify cryptographic SHA-256 match against payload")
    verify_origin_signature: bool = Field(True, description="Verify cryptographic digital origin signature")
    verify_custody_chain: bool = Field(True, description="Verify Merkle continuity of custody hash chain")


class ForensicVerificationReportItem(BaseModel):
    evidence_id: str
    status: VerificationOutcome
    raw_digest_match: bool
    signature_valid: bool
    custody_chain_valid: bool
    artifacts_present: bool
    contradiction_status: ContradictionStatus
    discrepancies: List[str] = Field(default_factory=list)


class ForensicVerificationReport(BaseModel):
    timestamp: datetime
    total_records: int
    verified_count: int
    failed_count: int
    unavailable_count: int
    not_checked_count: int
    items: List[ForensicVerificationReportItem] = Field(default_factory=list)


class EvidenceCustodyEventRead(BaseModel):
    id: str
    evidence_id: str
    event_type: str
    actor_id: str
    actor_role: str
    timestamp: datetime
    action_details: Dict[str, Any]
    prev_custody_hash: str
    custody_hash: str

    class Config:
        from_attributes = True


class ForensicEvidenceRecordRead(BaseModel):
    id: str
    finding_id: Optional[str] = None
    job_id: Optional[str] = None
    project_id: str
    evidence_type: str
    raw_payload: str
    raw_digest_sha256: str
    normalized_payload: Optional[Dict[str, Any]] = None
    normalized_digest_sha256: Optional[str] = None
    source_identity: str
    adapter_version: str
    collection_time: datetime
    ingestion_time: datetime
    assessment_context: Dict[str, Any]
    transformation_history: List[Dict[str, Any]]
    origin_signature: str
    signing_key_id: str
    signature_algorithm: str
    lifecycle_state: EvidenceLifecycleState
    last_verification_status: VerificationOutcome
    last_verified_at: Optional[datetime] = None
    last_verified_by: Optional[str] = None
    verification_details: Optional[Dict[str, Any]] = None
    contradiction_status: ContradictionStatus
    superseded_by_id: Optional[str] = None
    prior_evidence_id: Optional[str] = None
    is_contradictory: bool
    contradiction_notes: Optional[str] = None
    classification: str
    is_redacted: bool
    is_archived: bool
    is_deleted: bool
    deleted_at: Optional[datetime] = None
    deleted_by: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    custody_events: Optional[List[EvidenceCustodyEventRead]] = None

    class Config:
        from_attributes = True


class EvidenceExportBundle(BaseModel):
    export_version: str = "1.0"
    exported_at: datetime
    exported_by: str
    record_count: int
    records: List[Dict[str, Any]]
    custody_events: List[Dict[str, Any]]
    bundle_digest_sha256: str
    bundle_signature: str
    signing_key_id: str


class EvidenceImportRequest(BaseModel):
    bundle: EvidenceExportBundle
    target_project_id: str


class EvidenceImportResult(BaseModel):
    imported_count: int
    verification_passed: bool
    evidence_ids: List[str]
    warnings: List[str] = Field(default_factory=list)
