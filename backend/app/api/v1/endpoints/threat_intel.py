"""
Evidence-Grounded Threat Intelligence and Vulnerability Correlation Endpoints (Prompt 35).
REST APIs for threat intelligence feeds, CVE records, evidence-grounded correlation,
non-destructive risk enrichment, and freshness tracking.
"""
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from sqlalchemy import or_, desc

from app.core.database import get_db
from app.core.exceptions import NotFoundError, ValidationError, AuthorizationError
from app.models.user import User, SystemRole
from app.models.project import ProjectRole
from app.models.threat_intel import (
    FeedSyncStatus,
    MatchClassification,
    ThreatIntelFeedRecord,
    ThreatIntelligenceRecord,
    ThreatCorrelationRecord,
)
from app.schemas.threat_intel import (
    ThreatFeedResponse,
    ThreatFeedSyncRequest,
    ThreatFeedSyncResponse,
    ThreatIntelligenceResponse,
    ThreatCorrelationResponse,
    ThreatCorrelationRunRequest,
    ThreatCorrelationRunResponse,
    ThreatIntelSummaryResponse,
)
from app.services.threat_intel_service import ThreatIntelService
from app.api.deps import get_current_user, verify_project_access, require_system_roles

router = APIRouter()


# ---------------------------------------------------------------------------
# Feeds & Ingestion Endpoints
# ---------------------------------------------------------------------------

@router.get("/threat-intel/feeds", response_model=List[ThreatFeedResponse], tags=["Threat Intelligence"])
def list_feeds(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List all registered threat intelligence feeds and their synchronization status."""
    feeds = ThreatIntelService.get_or_create_feeds(db)
    results = []
    for f in feeds:
        is_stale = ThreatIntelService.check_feed_freshness(f)
        results.append(
            ThreatFeedResponse(
                id=f.id,
                feed_name=f.feed_name,
                feed_url=f.feed_url,
                is_authoritative=f.is_authoritative,
                sync_status=f.sync_status,
                record_count=f.record_count,
                last_sync_started_at=f.last_sync_started_at,
                last_synced_at=f.last_synced_at,
                last_sync_error=f.last_sync_error,
                stale_after_days=f.stale_after_days,
                is_stale=is_stale,
                feed_checksum=f.feed_checksum,
            )
        )
    return results


@router.post("/threat-intel/feeds/{feed_name}/sync", response_model=ThreatFeedSyncResponse, tags=["Threat Intelligence"])
def sync_threat_feed(
    feed_name: str,
    req: ThreatFeedSyncRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Synchronize a threat intelligence feed from local fixtures or custom payload.
    Requires ADMIN or active tester role.
    """
    try:
        res = ThreatIntelService.sync_feed(
            db=db,
            feed_name=feed_name,
            force_local=req.force_local,
            custom_payload=req.custom_payload,
        )
        return ThreatFeedSyncResponse(**res)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Feed synchronization failed: {str(e)}",
        )


# ---------------------------------------------------------------------------
# Threat Intelligence Query Endpoints
# ---------------------------------------------------------------------------

@router.get("/threat-intel/records", response_model=List[ThreatIntelligenceResponse], tags=["Threat Intelligence"])
def search_threat_records(
    cve_id: Optional[str] = Query(None, description="Search by CVE identifier"),
    vendor: Optional[str] = Query(None, description="Search by vendor"),
    product: Optional[str] = Query(None, description="Search by product"),
    is_known_exploited: Optional[bool] = Query(None, description="Filter for CISA KEV entries"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Search and browse normalized vulnerability and threat intelligence records."""
    q = db.query(ThreatIntelligenceRecord).filter(ThreatIntelligenceRecord.is_active == True)
    if cve_id:
        q = q.filter(ThreatIntelligenceRecord.cve_id.ilike(f"%{cve_id}%"))
    if vendor:
        q = q.filter(ThreatIntelligenceRecord.vendor.ilike(f"%{vendor}%"))
    if product:
        q = q.filter(ThreatIntelligenceRecord.product.ilike(f"%{product}%"))
    if is_known_exploited is not None:
        q = q.filter(ThreatIntelligenceRecord.is_known_exploited == is_known_exploited)

    records = q.order_by(desc(ThreatIntelligenceRecord.is_known_exploited), desc(ThreatIntelligenceRecord.retrieved_at)).offset(offset).limit(limit).all()
    return records


@router.get("/threat-intel/cve/{cve_id}", response_model=List[ThreatIntelligenceResponse], tags=["Threat Intelligence"])
def get_cve_intel(
    cve_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Retrieve normalized threat intelligence for a specific CVE across all sources."""
    records = db.query(ThreatIntelligenceRecord).filter(
        ThreatIntelligenceRecord.cve_id == cve_id.strip()
    ).all()
    if not records:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No threat intelligence found for CVE '{cve_id}'",
        )
    return records


# ---------------------------------------------------------------------------
# Project Correlation & Non-Destructive Enrichment Endpoints
# ---------------------------------------------------------------------------

@router.get("/projects/{project_id}/threat-intel/correlations", response_model=List[ThreatCorrelationResponse], tags=["Threat Intelligence"])
def get_project_correlations(
    project_id: str,
    match_classification: Optional[MatchClassification] = Query(None),
    is_known_exploited: Optional[bool] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    List threat intelligence correlations for findings in the specified project.
    Displays non-destructive risk enrichment alongside unaltered finding severity.
    """
    verify_project_access(project_id, current_user, db, [ProjectRole.VIEWER, ProjectRole.TESTER, ProjectRole.LEAD])

    q = db.query(ThreatCorrelationRecord).filter(
        ThreatCorrelationRecord.project_id == project_id,
        ThreatCorrelationRecord.is_active == True,
    )
    if match_classification:
        q = q.filter(ThreatCorrelationRecord.match_classification == match_classification)

    correlations = q.order_by(desc(ThreatCorrelationRecord.enriched_risk_score)).all()

    results = []
    for c in correlations:
        if is_known_exploited is not None and c.threat_intel.is_known_exploited != is_known_exploited:
            continue

        results.append(
            ThreatCorrelationResponse(
                id=c.id,
                project_id=c.project_id,
                finding_id=c.finding_id,
                finding_title=c.finding.title if c.finding else "Unknown Finding",
                finding_severity=c.finding.severity.value if c.finding else "UNKNOWN",
                threat_intel_id=c.threat_intel_id,
                cve_id=c.threat_intel.cve_id if c.threat_intel else "UNKNOWN",
                match_classification=c.match_classification,
                confidence_score=c.confidence_score,
                evidence_grounding=c.evidence_grounding,
                enriched_risk_score=c.enriched_risk_score,
                risk_enrichment_factors=c.risk_enrichment_factors,
                is_known_exploited=c.threat_intel.is_known_exploited if c.threat_intel else False,
                epss_score=c.threat_intel.epss_score if c.threat_intel else None,
                correlated_at=c.correlated_at,
            )
        )
    return results


@router.get("/projects/{project_id}/threat-intel/summary", response_model=ThreatIntelSummaryResponse, tags=["Threat Intelligence"])
def get_threat_intel_summary(
    project_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Retrieve operational KPIs for threat intelligence feeds and project correlations."""
    verify_project_access(project_id, current_user, db, [ProjectRole.VIEWER, ProjectRole.TESTER, ProjectRole.LEAD])

    total_cves = db.query(ThreatIntelligenceRecord.cve_id).distinct().count()
    known_exploited = db.query(ThreatIntelligenceRecord.cve_id).filter(
        ThreatIntelligenceRecord.is_known_exploited == True
    ).distinct().count()

    feeds = ThreatIntelService.get_or_create_feeds(db)
    active_feeds = sum(1 for f in feeds if f.sync_status == FeedSyncStatus.SYNCED)
    stale_feeds = sum(1 for f in feeds if ThreatIntelService.check_feed_freshness(f))

    correlations = db.query(ThreatCorrelationRecord).filter(
        ThreatCorrelationRecord.project_id == project_id,
        ThreatCorrelationRecord.is_active == True,
    ).all()

    confirmed = sum(1 for c in correlations if c.match_classification == MatchClassification.CONFIRMED_MATCH)
    possible = sum(1 for c in correlations if c.match_classification == MatchClassification.POSSIBLE_MATCH)
    conflicting = sum(1 for c in correlations if c.match_classification == MatchClassification.CONFLICTING_DATA)

    return ThreatIntelSummaryResponse(
        total_cves=total_cves,
        known_exploited_count=known_exploited,
        active_feeds_count=active_feeds,
        stale_feeds_count=stale_feeds,
        total_project_correlations=len(correlations),
        confirmed_correlations_count=confirmed,
        possible_correlations_count=possible,
        conflicting_correlations_count=conflicting,
    )


@router.post("/projects/{project_id}/threat-intel/correlate", response_model=ThreatCorrelationRunResponse, tags=["Threat Intelligence"])
def run_project_correlation(
    project_id: str,
    req: ThreatCorrelationRunRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Trigger evidence-grounded threat intelligence correlation for all active findings in project.
    Requires TESTER or LEAD role.
    """
    verify_project_access(project_id, current_user, db, [ProjectRole.TESTER, ProjectRole.LEAD])

    res = ThreatIntelService.correlate_project_findings(
        db=db,
        project_id=project_id,
        user=current_user,
        force_recorrelate=req.force_recorrelate,
    )
    return ThreatCorrelationRunResponse(**res)
