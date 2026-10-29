from typing import List, Optional, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field

from app.models.threat_intel import (
    FeedSyncStatus,
    MatchClassification,
    ThreatIntelSource,
)


class ThreatFeedResponse(BaseModel):
    id: str
    feed_name: str
    feed_url: str
    is_authoritative: bool
    sync_status: FeedSyncStatus
    record_count: int
    last_sync_started_at: Optional[datetime] = None
    last_synced_at: Optional[datetime] = None
    last_sync_error: Optional[str] = None
    stale_after_days: int
    is_stale: bool
    feed_checksum: Optional[str] = None

    class Config:
        from_attributes = True


class ThreatFeedSyncRequest(BaseModel):
    force_local: bool = True
    custom_payload: Optional[Dict[str, Any]] = None


class ThreatFeedSyncResponse(BaseModel):
    feed_name: str
    records_ingested: int
    records_updated: int
    sync_status: FeedSyncStatus
    checksum: str
    message: str


class ThreatIntelligenceResponse(BaseModel):
    id: str
    cve_id: str
    source: str
    title: Optional[str] = None
    description: Optional[str] = None
    vendor: Optional[str] = None
    product: Optional[str] = None
    cpe: Optional[str] = None
    version_start_including: Optional[str] = None
    version_end_excluding: Optional[str] = None
    version_end_including: Optional[str] = None
    affected_versions_list: List[str] = Field(default_factory=list)
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    epss_score: Optional[float] = None
    epss_percentile: Optional[float] = None
    is_known_exploited: bool = False
    cisa_kev_due_date: Optional[datetime] = None
    cisa_kev_action: Optional[str] = None
    published_at: Optional[datetime] = None
    modified_at: Optional[datetime] = None
    retrieved_at: datetime
    confidence: float
    provenance_url: Optional[str] = None

    class Config:
        from_attributes = True


class ThreatCorrelationResponse(BaseModel):
    id: str
    project_id: str
    finding_id: str
    finding_title: str
    finding_severity: str
    threat_intel_id: str
    cve_id: str
    match_classification: MatchClassification
    confidence_score: float
    evidence_grounding: Dict[str, Any] = Field(default_factory=dict)
    enriched_risk_score: float
    risk_enrichment_factors: Dict[str, Any] = Field(default_factory=dict)
    is_known_exploited: bool = False
    epss_score: Optional[float] = None
    correlated_at: datetime

    class Config:
        from_attributes = True


class ThreatCorrelationRunRequest(BaseModel):
    force_recorrelate: bool = False


class ThreatCorrelationRunResponse(BaseModel):
    project_id: str
    findings_evaluated: int
    correlations_created: int
    confirmed_matches: int
    possible_matches: int
    conflicting_data: int
    unknown_or_rejected: int
    message: str


class ThreatIntelSummaryResponse(BaseModel):
    total_cves: int
    known_exploited_count: int
    active_feeds_count: int
    stale_feeds_count: int
    total_project_correlations: int
    confirmed_correlations_count: int
    possible_correlations_count: int
    conflicting_correlations_count: int
