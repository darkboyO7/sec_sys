"""
Attack Surface and Exposure Governance Schemas (Prompt 46).
Pydantic contracts for authorized attack-surface inventory, service exposures,
timeline progression, discovery proposals, and asset-level evidence views.
"""
from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field

from app.models.attack_surface import (
    ExposureClassification,
    ObservationProvenanceType,
    ExposureFreshness,
    ProposalStatus,
)
from app.models.scope import TargetType


class CertificateDetails(BaseModel):
    subject: Optional[str] = None
    issuer: Optional[str] = None
    valid_from: Optional[str] = None
    valid_to: Optional[str] = None
    fingerprint_sha256: Optional[str] = None
    san_entries: List[str] = Field(default_factory=list)
    is_expired: bool = False


class AttackSurfaceExposureRead(BaseModel):
    id: str
    project_id: str
    asset_id: str
    canonical_identifier: str
    service_name: str
    port: int
    protocol: str
    transport_security: str
    certificate_details: Dict[str, Any]
    relevant_hostnames: List[str]
    exposure_classification: ExposureClassification
    provenance_type: ObservationProvenanceType
    freshness: ExposureFreshness
    is_authorized: bool
    first_observed_at: datetime
    last_observed_at: datetime
    consecutive_absences: int
    observation_count: int
    evidence_hashes: List[str]
    latest_observation_id: Optional[str] = None
    dedup_hash: str
    attributes: Dict[str, Any]
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class AttackSurfaceExposureCreate(BaseModel):
    asset_id: str
    canonical_identifier: str
    service_name: str = "unknown"
    port: int = 0
    protocol: str = "tcp"
    transport_security: str = "PLAINTEXT"
    certificate_details: Dict[str, Any] = Field(default_factory=dict)
    relevant_hostnames: List[str] = Field(default_factory=list)
    exposure_classification: ExposureClassification = ExposureClassification.INTERNET_FACING
    provenance_type: ObservationProvenanceType = ObservationProvenanceType.VERIFIED_OBSERVATION
    evidence_hash: Optional[str] = None
    attributes: Dict[str, Any] = Field(default_factory=dict)
    is_simulated: bool = False


class AssetInclusionProposalRead(BaseModel):
    id: str
    project_id: str
    target_type: TargetType
    target_value: str
    discovery_source: str
    provenance_type: ObservationProvenanceType
    status: ProposalStatus
    rationale: Optional[str] = None
    discovered_at: datetime
    evidence_hash: Optional[str] = None
    is_simulated: bool
    reviewed_by_id: Optional[str] = None
    reviewed_at: Optional[datetime] = None
    approval_notes: Optional[str] = None
    resulting_scope_target_id: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class AssetInclusionProposalCreate(BaseModel):
    target_type: TargetType
    target_value: str = Field(..., min_length=1, max_length=500)
    discovery_source: str = Field(..., min_length=2, max_length=100)
    provenance_type: ObservationProvenanceType = ObservationProvenanceType.INFERRED_RELATIONSHIP
    evidence_hash: Optional[str] = None
    rationale: Optional[str] = None
    is_simulated: bool = False


class ProposalApprovalRequest(BaseModel):
    approval_notes: str = Field("Approved for active penetration testing and monitoring scope.", min_length=3)
    authorized_evidence: str = Field("Asset inclusion approved via Exposure Governance workflow.", min_length=3)


class ProposalRejectionRequest(BaseModel):
    rejection_reason: str = Field(..., min_length=3, description="Audit reason for rejecting discovered asset from scope inclusion")


class AttackSurfaceInventoryResponse(BaseModel):
    project_id: str
    total_exposures: int
    internet_facing_count: int
    internal_restricted_count: int
    cloud_edge_count: int
    fresh_count: int
    stale_count: int
    unverified_absent_count: int
    items: List[AttackSurfaceExposureRead]


class AttackSurfaceTimelineItem(BaseModel):
    event_id: str
    event_type: str  # "NEW_SERVICE", "CHANGED_CERTIFICATE", "CHANGED_HOSTNAME", "EXPOSURE_ABSENCE", "NEW_EXPOSURE"
    occurred_at: datetime
    canonical_identifier: str
    port: int
    protocol: str
    title: str
    details: Dict[str, Any]
    provenance_type: str
    evidence_hash: Optional[str] = None


class AttackSurfaceTimelineResponse(BaseModel):
    project_id: str
    total_events: int
    events: List[AttackSurfaceTimelineItem]


class AssetExposureEvidenceResponse(BaseModel):
    project_id: str
    asset_id: str
    canonical_identifier: str
    is_authorized: bool
    freshness: str
    total_observations: int
    active_services: List[Dict[str, Any]]
    tls_certificates: List[Dict[str, Any]]
    associated_hostnames: List[str]
    evidence_digests: List[str]
    last_observed_at: Optional[datetime] = None
