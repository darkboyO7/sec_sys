from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class MerkleProofStep(BaseModel):
    position: str = Field(description="'left' or 'right' indicating sibling node position")
    hash: str = Field(description="SHA-256 hash of the sibling node")


class MerkleProofResponse(BaseModel):
    job_id: str
    evidence_id: str
    leaf_hash: str
    merkle_root: str
    proof: List[MerkleProofStep]


class EvidenceRecordSummary(BaseModel):
    id: str
    finding_id: str
    evidence_type: str
    sha256_hash: str
    raw_sha256_hash: Optional[str] = None
    is_truncated: bool = False
    is_valid: bool


class EvidenceVerificationResponse(BaseModel):
    job_id: str
    total_evidence_checked: int
    is_valid: bool
    corrupted_evidence_ids: List[str]
    merkle_root: str
    evidence_records: List[EvidenceRecordSummary]
    summary: str


class AuditVerificationResponse(BaseModel):
    project_id: str
    total_events_checked: int
    is_valid: bool
    tampered_event_ids: List[str]
    merkle_root: str
    timestamp_range: Dict[str, Optional[str]]
    summary: str
