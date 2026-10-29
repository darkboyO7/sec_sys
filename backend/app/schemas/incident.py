from typing import Optional, Dict, Any, List
from datetime import datetime
from pydantic import BaseModel, Field


class CreateCaseRequest(BaseModel):
    title: str = Field(..., min_length=3, max_length=255)
    description: Optional[str] = None
    severity: Optional[str] = "MEDIUM"
    lead_investigator_id: Optional[str] = None
    assigned_team: Optional[str] = None


class LinkAssetRequest(BaseModel):
    asset_id: str
    relationship_type: Optional[str] = "OBSERVED_CORRELATION"
    confidence: Optional[float] = 0.5
    is_contradictory: Optional[bool] = False
    notes: Optional[str] = None


class LinkFindingRequest(BaseModel):
    finding_id: str
    correlation_type: Optional[str] = "PROBABLE_CORRELATION"
    confidence: Optional[float] = 0.5
    rationale: Optional[str] = None


class AttachEvidenceRequest(BaseModel):
    evidence_summary: str = Field(..., min_length=5)
    finding_evidence_id: Optional[str] = None
    is_contradictory: Optional[bool] = False
    provenance_details: Optional[Dict[str, Any]] = None


class TransitionStatusRequest(BaseModel):
    to_status: str
    reason: str = Field(..., min_length=3)
    closure_summary: Optional[str] = None
    reopening_rationale: Optional[str] = None
    root_cause_hypothesis: Optional[str] = None
    is_containment_verified: Optional[bool] = None


class AddCaseNoteRequest(BaseModel):
    content: str = Field(..., min_length=3)
    note_type: Optional[str] = "ANALYST_OBSERVATION"
    is_alternative_hypothesis: Optional[bool] = False


class LinkedAssetItem(BaseModel):
    id: str
    asset_id: str
    relationship_type: str
    confidence: float
    is_contradictory: bool
    notes: Optional[str] = None
    created_at: datetime

    class Config:
        from_attributes = True


class LinkedFindingItem(BaseModel):
    id: str
    finding_id: str
    correlation_type: str
    confidence: float
    rationale: Optional[str] = None
    created_at: datetime

    class Config:
        from_attributes = True


class LinkedEvidenceItem(BaseModel):
    id: str
    finding_evidence_id: Optional[str] = None
    evidence_digest: str
    evidence_summary: str
    is_contradictory: bool
    created_at: datetime

    class Config:
        from_attributes = True


class CaseTransitionItem(BaseModel):
    id: str
    from_status: str
    to_status: str
    transitioned_by_id: Optional[str] = None
    reason: str
    created_at: datetime

    class Config:
        from_attributes = True


class CaseNoteItem(BaseModel):
    id: str
    author_id: Optional[str] = None
    note_type: str
    content: str
    is_alternative_hypothesis: bool
    created_at: datetime

    class Config:
        from_attributes = True


class IncidentCaseSummary(BaseModel):
    id: str
    project_id: str
    case_number: str
    title: str
    severity: str
    status: str
    lead_investigator_id: Optional[str] = None
    assigned_team: Optional[str] = None
    opened_at: datetime
    closed_at: Optional[datetime] = None
    is_containment_verified: bool
    created_at: datetime

    class Config:
        from_attributes = True


class IncidentCaseDetail(BaseModel):
    id: str
    project_id: str
    case_number: str
    title: str
    description: Optional[str] = None
    severity: str
    status: str
    lead_investigator_id: Optional[str] = None
    assigned_team: Optional[str] = None
    opened_at: datetime
    closed_at: Optional[datetime] = None
    reopened_at: Optional[datetime] = None
    root_cause_hypothesis: Optional[str] = None
    alternative_explanations: List[Dict[str, Any]] = []
    is_containment_verified: bool
    closure_summary: Optional[str] = None
    closure_approved_by_id: Optional[str] = None
    reopening_rationale: Optional[str] = None
    linked_assets: List[LinkedAssetItem] = []
    linked_findings: List[LinkedFindingItem] = []
    linked_evidence: List[LinkedEvidenceItem] = []
    transitions: List[CaseTransitionItem] = []
    notes: List[CaseNoteItem] = []
    created_at: datetime

    class Config:
        from_attributes = True


class CorrelationExplanationResponse(BaseModel):
    case_id: str
    case_number: str
    total_linked_findings: int
    total_linked_assets: int
    confirmed_causation: List[Dict[str, Any]] = []
    probable_correlations: List[Dict[str, Any]] = []
    temporal_coincidences: List[Dict[str, Any]] = []
    contradictory_findings: List[Dict[str, Any]] = []
    contradictory_evidence_count: int
    alternative_hypotheses_count: int
    correlation_summary: str


class TimelineEventResponse(BaseModel):
    event_type: str
    timestamp: datetime
    actor_id: Optional[str] = None
    summary: str
    details: Dict[str, Any] = {}
