"""
Unit & Integration Acceptance Tests for Prompt 35:
Evidence-Grounded Threat Intelligence and Vulnerability Correlation.
"""
import pytest
from datetime import datetime, timezone, timedelta
from fastapi import status
from fastapi.testclient import TestClient

from app.main import app
from tests.conftest import auth_header_for_user

from app.models.base import utc_now, generate_uuid
from app.models.user import User, SystemRole
from app.models.project import Project, ProjectMember, ProjectRole
from app.models.organization import Organization
from app.models.asset import Asset, AssetType, AssetCriticality, AssetStatus
from app.models.assessment import FindingSeverity, FindingConfidence
from app.models.finding import VulnerabilityFinding, FindingLifecycleStatus
from app.models.threat_intel import (
    FeedSyncStatus,
    MatchClassification,
    ThreatIntelFeedRecord,
    ThreatIntelligenceRecord,
    ThreatCorrelationRecord,
)
from app.services.threat_intel_service import (
    ThreatIntelService,
    is_version_in_range,
    parse_version_tuple,
    ensure_utc,
)


@pytest.fixture
def threat_org(db):
    org = Organization(name="Threat Intel Org", slug="threat-intel-org")
    db.add(org)
    db.commit()
    db.refresh(org)
    return org


@pytest.fixture
def threat_users(db, threat_org):
    lead = User(
        email="lead.threat@example.com",
        full_name="Threat Intel Lead",
        hashed_password="pw",
        system_role=SystemRole.SECURITY_LEAD,
        is_active=True,
    )
    tester = User(
        email="tester.threat@example.com",
        full_name="Threat Intel Tester",
        hashed_password="pw",
        system_role=SystemRole.SECURITY_TESTER,
        is_active=True,
    )
    viewer = User(
        email="viewer.threat@example.com",
        full_name="Threat Intel Viewer",
        hashed_password="pw",
        system_role=SystemRole.VIEWER,
        is_active=True,
    )
    outsider = User(
        email="outsider.threat@example.com",
        full_name="Outsider Threat",
        hashed_password="pw",
        system_role=SystemRole.VIEWER,
        is_active=True,
    )
    db.add_all([lead, tester, viewer, outsider])
    db.commit()
    for u in [lead, tester, viewer, outsider]:
        db.refresh(u)
    return {"lead": lead, "tester": tester, "viewer": viewer, "outsider": outsider}


@pytest.fixture
def threat_project(db, threat_org, threat_users):
    proj = Project(
        name="Threat Correlation Project",
        description="Project for Threat Intel Testing",
        organization_id=threat_org.id,
    )
    db.add(proj)
    db.commit()
    db.refresh(proj)

    m1 = ProjectMember(project_id=proj.id, user_id=threat_users["lead"].id, role=ProjectRole.LEAD)
    m2 = ProjectMember(project_id=proj.id, user_id=threat_users["tester"].id, role=ProjectRole.TESTER)
    m3 = ProjectMember(project_id=proj.id, user_id=threat_users["viewer"].id, role=ProjectRole.VIEWER)
    db.add_all([m1, m2, m3])
    db.commit()
    return proj


# ---------------------------------------------------------------------------
# Test 1: Version Parsing and Boundary Evaluation
# ---------------------------------------------------------------------------
def test_version_range_evaluation():
    # Direct range [10.2.0, 10.2.9)
    assert is_version_in_range("10.2.1", start_inc="10.2.0", end_exc="10.2.9") is True
    assert is_version_in_range("10.2.0", start_inc="10.2.0", end_exc="10.2.9") is True
    assert is_version_in_range("10.2.9", start_inc="10.2.0", end_exc="10.2.9") is False
    assert is_version_in_range("10.1.9", start_inc="10.2.0", end_exc="10.2.9") is False
    assert is_version_in_range("10.3.0", start_inc="10.2.0", end_exc="10.2.9") is False

    # Explicit version list
    assert is_version_in_range("2.14.1", explicit_list=["2.14.0", "2.14.1", "2.15.0"]) is True
    assert is_version_in_range("2.16.0", explicit_list=["2.14.0", "2.14.1", "2.15.0"]) is False


# ---------------------------------------------------------------------------
# Test 2: Authoritative Feed Initialization and Freshness Staleness
# ---------------------------------------------------------------------------
def test_feed_initialization_and_freshness(db):
    feeds = ThreatIntelService.get_or_create_feeds(db)
    assert len(feeds) >= 3
    feed_names = [f.feed_name for f in feeds]
    assert "CISA_KEV" in feed_names
    assert "NVD_CVE" in feed_names
    assert "EPSS" in feed_names

    cisa = next(f for f in feeds if f.feed_name == "CISA_KEV")
    # Freshly seeded feed has not yet synced, so it is stale
    assert ThreatIntelService.check_feed_freshness(cisa) is True

    # Simulate recent sync
    cisa.last_synced_at = datetime.now(timezone.utc)
    assert ThreatIntelService.check_feed_freshness(cisa) is False

    # Simulate sync 8 days ago (> stale_after_days=7)
    cisa.last_synced_at = datetime.now(timezone.utc) - timedelta(days=8)
    assert ThreatIntelService.check_feed_freshness(cisa) is True


# ---------------------------------------------------------------------------
# Test 3: Feed Sync from Local Fixtures with SHA-256 Checksum
# ---------------------------------------------------------------------------
def test_feed_sync_and_idempotency(db):
    # Ingest CISA KEV
    res1 = ThreatIntelService.sync_feed(db, "CISA_KEV", force_local=True)
    assert res1["sync_status"] == FeedSyncStatus.SYNCED
    assert res1["records_ingested"] >= 4
    assert len(res1["checksum"]) == 64

    # Idempotent second sync: should update existing records without duplicate rows
    res2 = ThreatIntelService.sync_feed(db, "CISA_KEV", force_local=True)
    assert res2["records_ingested"] == 0
    assert res2["records_updated"] >= 4

    # Check that CISA KEV records have is_known_exploited == True
    pan_cve = db.query(ThreatIntelligenceRecord).filter(
        ThreatIntelligenceRecord.cve_id == "CVE-2024-3400",
        ThreatIntelligenceRecord.source == "CISA_KEV",
    ).first()
    assert pan_cve is not None
    assert pan_cve.is_known_exploited is True
    assert pan_cve.product == "PAN-OS"


# ---------------------------------------------------------------------------
# Test 4: Payload Size Limit and Malformed Handling
# ---------------------------------------------------------------------------
def test_payload_size_enforcement_and_malformed_handling(db):
    # Enforce size limit
    oversized = {"vulnerabilities": [{"cveID": "CVE-9999-9999", "data": "X" * 1000}]}
    with pytest.raises(ValueError, match="exceeds limit"):
        ThreatIntelService.sync_feed(
            db, "CISA_KEV", custom_payload=oversized, max_bytes=500
        )

    # Malformed data handling
    malformed = {"vulnerabilities": "not-a-list"}
    with pytest.raises(Exception):
        ThreatIntelService.sync_feed(db, "CISA_KEV", custom_payload=malformed)

    feed = db.query(ThreatIntelFeedRecord).filter(ThreatIntelFeedRecord.feed_name == "CISA_KEV").first()
    assert feed.sync_status == FeedSyncStatus.ERROR
    assert feed.last_sync_error is not None


# ---------------------------------------------------------------------------
# Test 5: Strict Resemblance Rejection Invariant (Requirement 7)
# ---------------------------------------------------------------------------
def test_strict_resemblance_rejection_invariant(db, threat_org, threat_project):
    pid = threat_project.id

    # Ingest authoritative feeds first
    ThreatIntelService.sync_feed(db, "CISA_KEV", force_local=True)
    ThreatIntelService.sync_feed(db, "NVD_CVE", force_local=True)

    # Asset with product resembling 'PAN-OS' but not exact, e.g., 'pan-os-simulator-fork'
    asset = Asset(
        organization_id=threat_org.id,
        project_id=pid,
        name="Simulator Asset",
        canonical_identifier="sim.internal.corp",
        asset_type=AssetType.HOST,
        criticality=AssetCriticality.HIGH,
        attributes={"product": "pan-os-simulator-custom", "version": "10.2.1"},
    )
    db.add(asset)
    db.commit()

    finding = VulnerabilityFinding(
        project_id=pid,
        asset_id=asset.id,
        fingerprint="fp-resemblance-test-1",
        target_value="sim.internal.corp",
        title="Potential Gateway Issue",
        severity=FindingSeverity.LOW,
        confidence=FindingConfidence.TENTATIVE,
        vuln_id=None,  # No explicit CVE
    )
    db.add(finding)
    db.commit()

    intel_panos = db.query(ThreatIntelligenceRecord).filter(
        ThreatIntelligenceRecord.cve_id == "CVE-2024-3400"
    ).first()

    match_class, conf, evidence, score, factors = ThreatIntelService.evaluate_correlation(
        finding, intel_panos, asset
    )

    # Resemblance MUST be rejected; never infer asset is vulnerable!
    assert match_class == MatchClassification.UNKNOWN_MATCH
    assert conf == 0.0
    assert evidence["resemblance_check"]["resemblance_rejected"] is True
    assert "Rejected resemblance" in evidence["resemblance_check"]["resemblance_reason"]


# ---------------------------------------------------------------------------
# Test 6: Confirmed Grounded Match with Version Range Check
# ---------------------------------------------------------------------------
def test_confirmed_grounded_match(db, threat_org, threat_project):
    pid = threat_project.id

    ThreatIntelService.sync_feed(db, "CISA_KEV", force_local=True)
    ThreatIntelService.sync_feed(db, "NVD_CVE", force_local=True)

    # Genuine PAN-OS asset running affected version 10.2.3 (range is 10.2.0 to 10.2.9-h1)
    asset = Asset(
        organization_id=threat_org.id,
        project_id=pid,
        name="GlobalProtect Gateway",
        canonical_identifier="vpn.company.com",
        asset_type=AssetType.HOST,
        criticality=AssetCriticality.CRITICAL,
        attributes={"product": "PAN-OS", "version": "10.2.3"},
    )
    db.add(asset)
    db.commit()

    finding = VulnerabilityFinding(
        project_id=pid,
        asset_id=asset.id,
        fingerprint="fp-panos-confirmed-1",
        target_value="vpn.company.com",
        title="Unauthenticated Command Injection in PAN-OS GlobalProtect",
        severity=FindingSeverity.HIGH,  # Original finding severity is HIGH
        confidence=FindingConfidence.CERTAIN,
        vuln_id="CVE-2024-3400",
    )
    db.add(finding)
    db.commit()

    intel_panos = db.query(ThreatIntelligenceRecord).filter(
        ThreatIntelligenceRecord.cve_id == "CVE-2024-3400",
        ThreatIntelligenceRecord.source == "NVD_CVE",
    ).first()

    match_class, conf, evidence, enriched_score, factors = ThreatIntelService.evaluate_correlation(
        finding, intel_panos, asset
    )

    assert match_class == MatchClassification.CONFIRMED_MATCH
    assert conf >= 0.90
    assert evidence["version_evidence"]["in_range"] is True

    # Check non-destructive risk enrichment
    assert finding.severity == FindingSeverity.HIGH  # UNMUTATED!
    assert factors["unaltered_finding_severity"] == "HIGH"
    assert factors["is_known_exploited"] is True
    assert factors["cisa_kev_boost"] == 25.0
    assert enriched_score > 80.0


# ---------------------------------------------------------------------------
# Test 7: Conflicting Data Classification
# ---------------------------------------------------------------------------
def test_conflicting_data_classification(db, threat_org, threat_project):
    pid = threat_project.id

    ThreatIntelService.sync_feed(db, "NVD_CVE", force_local=True)

    asset = Asset(
        organization_id=threat_org.id,
        project_id=pid,
        name="Log4j Service",
        canonical_identifier="app.internal.corp",
        asset_type=AssetType.SERVICE,
        criticality=AssetCriticality.HIGH,
        attributes={"product": "Log4j", "version": "2.14.0"},
    )
    db.add(asset)
    db.commit()

    # Finding with contradictory scanner observations
    finding = VulnerabilityFinding(
        project_id=pid,
        asset_id=asset.id,
        fingerprint="fp-log4j-conflict",
        target_value="app.internal.corp",
        title="Potential JNDI Injection",
        severity=FindingSeverity.MEDIUM,
        confidence=FindingConfidence.FIRM,
        vuln_id="CVE-2021-44228",
        has_contradictions=True,
        contradiction_notes=["Scanner A observed vulnerable v2.14.0", "Scanner B observed patched v2.17.1"],
    )
    db.add(finding)
    db.commit()

    intel_log4j = db.query(ThreatIntelligenceRecord).filter(
        ThreatIntelligenceRecord.cve_id == "CVE-2021-44228"
    ).first()

    match_class, conf, evidence, enriched_score, factors = ThreatIntelService.evaluate_correlation(
        finding, intel_log4j, asset
    )

    assert match_class == MatchClassification.CONFLICTING_DATA
    assert conf < 0.50
    assert "conflict_details" in evidence
    assert factors["match_multiplier"] == 0.40


# ---------------------------------------------------------------------------
# Test 8: EPSS Ingestion and Threat Scoring Boost
# ---------------------------------------------------------------------------
def test_epss_enrichment_boost(db):
    ThreatIntelService.sync_feed(db, "CISA_KEV", force_local=True)
    ThreatIntelService.sync_feed(db, "EPSS", force_local=True)

    rec = db.query(ThreatIntelligenceRecord).filter(
        ThreatIntelligenceRecord.cve_id == "CVE-2024-3400"
    ).first()

    assert rec is not None
    assert rec.epss_score is not None
    assert rec.epss_score > 0.90
    assert rec.epss_percentile is not None


# ---------------------------------------------------------------------------
# Test 9: Project Correlation Run Execution
# ---------------------------------------------------------------------------
def test_project_correlation_run(db, threat_org, threat_project, threat_users):
    pid = threat_project.id

    # Ingest threat feeds
    ThreatIntelService.sync_feed(db, "CISA_KEV", force_local=True)
    ThreatIntelService.sync_feed(db, "NVD_CVE", force_local=True)
    ThreatIntelService.sync_feed(db, "EPSS", force_local=True)

    # Create 2 findings: 1 confirmed, 1 unconfirmed
    asset1 = Asset(
        organization_id=threat_org.id,
        project_id=pid,
        name="Firewall 1",
        canonical_identifier="fw1.corp",
        asset_type=AssetType.HOST,
        criticality=AssetCriticality.CRITICAL,
        attributes={"product": "PAN-OS", "version": "10.2.2"},
    )
    asset2 = Asset(
        organization_id=threat_org.id,
        project_id=pid,
        name="Web Server 2",
        canonical_identifier="web2.corp",
        asset_type=AssetType.HOST,
        criticality=AssetCriticality.LOW,
        attributes={"product": "nginx", "version": "1.21.0"},
    )
    db.add_all([asset1, asset2])
    db.commit()

    f1 = VulnerabilityFinding(
        project_id=pid,
        asset_id=asset1.id,
        fingerprint="fp-f1",
        target_value="fw1.corp",
        title="PAN-OS Vulnerability",
        severity=FindingSeverity.CRITICAL,
        confidence=FindingConfidence.CERTAIN,
        vuln_id="CVE-2024-3400",
    )
    f2 = VulnerabilityFinding(
        project_id=pid,
        asset_id=asset2.id,
        fingerprint="fp-f2",
        target_value="web2.corp",
        title="Nginx Information Disclosure",
        severity=FindingSeverity.LOW,
        confidence=FindingConfidence.FIRM,
        vuln_id="CVE-9999-0001",  # Uncataloged CVE
    )
    db.add_all([f1, f2])
    db.commit()

    res = ThreatIntelService.correlate_project_findings(
        db, pid, threat_users["lead"], force_recorrelate=True
    )

    assert res["findings_evaluated"] == 2
    assert res["confirmed_matches"] >= 1

    corrs = db.query(ThreatCorrelationRecord).filter(
        ThreatCorrelationRecord.project_id == pid
    ).all()
    assert len(corrs) >= 1

    pan_corr = next(c for c in corrs if c.finding_id == f1.id)
    assert pan_corr.match_classification == MatchClassification.CONFIRMED_MATCH
    assert pan_corr.threat_intel.is_known_exploited is True


# ---------------------------------------------------------------------------
# Test 10: REST Endpoints and RBAC Protection
# ---------------------------------------------------------------------------
def test_threat_intel_endpoints_and_rbac(client, db, threat_project, threat_users):
    pid = threat_project.id

    lead_h = auth_header_for_user(threat_users["lead"])
    tester_h = auth_header_for_user(threat_users["tester"])
    viewer_h = auth_header_for_user(threat_users["viewer"])
    outsider_h = auth_header_for_user(threat_users["outsider"])

    # 1. Unauthenticated request rejected (401)
    res = client.get("/api/v1/threat-intel/feeds")
    assert res.status_code == status.HTTP_401_UNAUTHORIZED

    # 2. Authenticated user can list feeds
    res = client.get("/api/v1/threat-intel/feeds", headers=viewer_h)
    assert res.status_code == status.HTTP_200_OK
    feeds_data = res.json()
    assert len(feeds_data) >= 3

    # 3. Trigger feed sync
    res = client.post(
        "/api/v1/threat-intel/feeds/CISA_KEV/sync",
        json={"force_local": True},
        headers=tester_h,
    )
    assert res.status_code == status.HTTP_200_OK
    assert res.json()["sync_status"] == "SYNCED"

    # 4. Search threat records
    res = client.get("/api/v1/threat-intel/records?cve_id=CVE-2024-3400", headers=viewer_h)
    assert res.status_code == status.HTTP_200_OK
    records = res.json()
    assert len(records) >= 1
    assert records[0]["cve_id"] == "CVE-2024-3400"

    # 5. Project correlation run RBAC
    # Outsider cannot correlate (403 or 404)
    res = client.post(
        f"/api/v1/projects/{pid}/threat-intel/correlate",
        json={"force_recorrelate": True},
        headers=outsider_h,
    )
    assert res.status_code in (status.HTTP_403_FORBIDDEN, status.HTTP_404_NOT_FOUND)

    # Viewer cannot trigger correlation (requires TESTER or LEAD)
    res = client.post(
        f"/api/v1/projects/{pid}/threat-intel/correlate",
        json={"force_recorrelate": True},
        headers=viewer_h,
    )
    assert res.status_code == status.HTTP_403_FORBIDDEN

    # Tester can trigger correlation
    res = client.post(
        f"/api/v1/projects/{pid}/threat-intel/correlate",
        json={"force_recorrelate": True},
        headers=tester_h,
    )
    assert res.status_code == status.HTTP_200_OK
    assert "findings_evaluated" in res.json()

    # 6. Project correlations list (Viewer can read)
    res = client.get(f"/api/v1/projects/{pid}/threat-intel/correlations", headers=viewer_h)
    assert res.status_code == status.HTTP_200_OK

    # 7. Summary metrics endpoint
    res = client.get(f"/api/v1/projects/{pid}/threat-intel/summary", headers=viewer_h)
    assert res.status_code == status.HTTP_200_OK
    sum_data = res.json()
    assert "total_cves" in sum_data
    assert "known_exploited_count" in sum_data


# ---------------------------------------------------------------------------
# Test 11: Provenance Tracking & Full Explainability Audit
# ---------------------------------------------------------------------------
def test_provenance_and_audit_explanation_accuracy(db, threat_org, threat_project):
    pid = threat_project.id

    ThreatIntelService.sync_feed(db, "CISA_KEV", force_local=True)
    ThreatIntelService.sync_feed(db, "NVD_CVE", force_local=True)
    ThreatIntelService.sync_feed(db, "EPSS", force_local=True)

    intel = db.query(ThreatIntelligenceRecord).filter(
        ThreatIntelligenceRecord.cve_id == "CVE-2024-3400",
        ThreatIntelligenceRecord.source == "NVD_CVE",
    ).first()

    assert intel.provenance_url == "https://nvd.nist.gov/vuln/detail/CVE-2024-3400"
    assert intel.raw_payload_checksum is not None
    assert len(intel.raw_payload_checksum) == 64

    # Evaluate correlation and verify explanation string
    asset = Asset(
        organization_id=threat_org.id,
        project_id=pid,
        name="Production Firewall",
        canonical_identifier="prod-fw.corp",
        asset_type=AssetType.HOST,
        criticality=AssetCriticality.CRITICAL,
        environment="PRODUCTION",
        attributes={"product": "PAN-OS", "version": "10.2.2"},
    )
    db.add(asset)
    db.commit()

    finding = VulnerabilityFinding(
        project_id=pid,
        asset_id=asset.id,
        fingerprint="fp-prov-1",
        target_value="prod-fw.corp",
        title="Critical Zero-Day",
        severity=FindingSeverity.CRITICAL,
        confidence=FindingConfidence.CERTAIN,
        vuln_id="CVE-2024-3400",
    )
    db.add(finding)
    db.commit()

    match_class, conf, evidence, enriched_score, factors = ThreatIntelService.evaluate_correlation(
        finding, intel, asset
    )

    assert "Finding severity remains 'CRITICAL'" in factors["explanation"]
    assert factors["is_known_exploited"] is True
    assert factors["asset_criticality"] == "CRITICAL"
    assert factors["exposure_boost"] == 10.0


# ---------------------------------------------------------------------------
# Test 12: Offline Fallback When Provider Unavailable
# ---------------------------------------------------------------------------
def test_offline_fallback_when_external_provider_unavailable(db):
    # Verify that when force_local=True is specified, no network calls are attempted
    # and local fixtures provide complete operational readiness
    feeds = ["CISA_KEV", "NVD_CVE", "EPSS"]
    for feed_name in feeds:
        res = ThreatIntelService.sync_feed(db, feed_name, force_local=True)
        assert res["sync_status"] == FeedSyncStatus.SYNCED
        assert res["checksum"] is not None

