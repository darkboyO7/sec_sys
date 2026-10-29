import uuid
from datetime import datetime, timezone, timedelta
import pytest
from fastapi import status

from app.models.organization import Organization
from app.models.user import User, SystemRole
from app.models.project import Project, ProjectMember, ProjectRole
from app.models.scope import ScopeTarget, TargetType, AuthorizationStatus
from app.models.asset import (
    Asset,
    AssetObservation,
    AssetType,
    AssetCriticality,
    AssetStatus,
    AssetIdentifierAlias,
    AssetIdentityMergeRecord,
)
from app.models.finding import VulnerabilityFinding, FindingSeverity, FindingConfidence
from app.models.canonical_asset import (
    ResolutionMatchOutcome,
    DeduplicationProposalStatus,
    DataQualityIssueType,
    DataQualityIssueStatus,
    AssetDeduplicationProposal,
    AssetDataQualityIssue,
)
from app.core.security import create_access_token, hash_password
from app.services.canonical_identity_service import CanonicalIdentityService


def auth_header_for_user(user: User) -> dict:
    token = create_access_token(
        subject=user.id,
        claims={"role": user.system_role.value, "email": user.email},
    )
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def asset_org(db):
    org = Organization(name="Asset Identity Corp", slug=f"asset-corp-{uuid.uuid4().hex[:6]}")
    db.add(org)
    db.commit()
    db.refresh(org)
    return org


@pytest.fixture
def asset_users(db, asset_org):
    u_lead = User(
        email=f"lead.asset.{uuid.uuid4().hex[:6]}@example.com",
        hashed_password=hash_password("leadPass123!"),
        full_name="Lead Asset Assessor",
        system_role=SystemRole.SECURITY_LEAD,
        is_active=True,
    )
    u_tester = User(
        email=f"tester.asset.{uuid.uuid4().hex[:6]}@example.com",
        hashed_password=hash_password("testerPass123!"),
        full_name="Staff Asset Tester",
        system_role=SystemRole.SECURITY_TESTER,
        is_active=True,
    )
    u_viewer = User(
        email=f"viewer.asset.{uuid.uuid4().hex[:6]}@example.com",
        hashed_password=hash_password("viewerPass123!"),
        full_name="Read-Only Asset Viewer",
        system_role=SystemRole.VIEWER,
        is_active=True,
    )
    db.add_all([u_lead, u_tester, u_viewer])
    db.commit()
    for u in (u_lead, u_tester, u_viewer):
        db.refresh(u)
    return {"lead": u_lead, "tester": u_tester, "viewer": u_viewer}


@pytest.fixture
def asset_project(db, asset_org, asset_users):
    proj = Project(
        name="Asset Identity Assessment Project",
        description="Prompt 37 canonical entity resolution and quality testing",
        organization_id=asset_org.id,
    )
    db.add(proj)
    db.commit()
    db.refresh(proj)

    m1 = ProjectMember(project_id=proj.id, user_id=asset_users["lead"].id, role=ProjectRole.LEAD)
    m2 = ProjectMember(project_id=proj.id, user_id=asset_users["tester"].id, role=ProjectRole.TESTER)
    m3 = ProjectMember(project_id=proj.id, user_id=asset_users["viewer"].id, role=ProjectRole.VIEWER)
    db.add_all([m1, m2, m3])
    db.commit()
    return proj


# ---------------------------------------------------------------------------
# Test 1: Confidence-Aware Entity Resolution (Exact Match & Cloud ARN)
# ---------------------------------------------------------------------------
def test_confidence_aware_entity_resolution(db, asset_project, asset_org):
    pid = asset_project.id
    now = datetime.now(timezone.utc)

    # Asset A: Web App
    asset_a = Asset(
        project_id=pid,
        organization_id=asset_org.id,
        asset_type=AssetType.WEB_APP,
        name="Production Portal",
        canonical_identifier="https://portal.example.com",
        status=AssetStatus.ACTIVE,
        criticality=AssetCriticality.HIGH,
        attributes={"cloud_resource_id": "arn:aws:ec2:us-east-1:123456789012:instance/i-0abcdef1234567890"},
        first_seen_at=now,
        last_seen_at=now,
    )
    db.add(asset_a)
    db.commit()

    # 1. Exact match on URL
    res_exact = CanonicalIdentityService.resolve_entity(
        db=db,
        project_id=pid,
        candidate_target="https://portal.example.com/",
    )
    assert res_exact.outcome == ResolutionMatchOutcome.EXACT_MATCH
    assert res_exact.confidence == 1.0
    assert res_exact.matched_asset.id == asset_a.id
    assert "Exact canonical key match" in res_exact.match_reasons[0]

    # 2. Strong match on unique cloud ARN
    res_cloud = CanonicalIdentityService.resolve_entity(
        db=db,
        project_id=pid,
        candidate_target="https://internal-ip.ec2.internal",
        attributes={"cloud_resource_id": "arn:aws:ec2:us-east-1:123456789012:instance/i-0abcdef1234567890"},
    )
    assert res_cloud.outcome == ResolutionMatchOutcome.STRONG_CORRELATION
    assert res_cloud.confidence == 0.95
    assert res_cloud.matched_asset.id == asset_a.id
    assert "Strong unique cloud resource match" in res_cloud.match_reasons[0]


# ---------------------------------------------------------------------------
# Test 2: IP Address Reuse & Ephemeral Reassignment Prevention (Req 4, 14)
# ---------------------------------------------------------------------------
def test_ip_reuse_temporal_ephemeral_reassignment_prevention(db, asset_project, asset_org):
    pid = asset_project.id
    now = datetime.now(timezone.utc)
    fifteen_days_ago = now - timedelta(days=15)

    # Asset A had an IP alias observed 15 days ago
    asset_a = Asset(
        project_id=pid,
        organization_id=asset_org.id,
        asset_type=AssetType.HOST,
        name="Ephemeral Worker 1",
        canonical_identifier="worker-1.corp.internal",
        status=AssetStatus.ACTIVE,
        first_seen_at=fifteen_days_ago,
        last_seen_at=fifteen_days_ago,
    )
    db.add(asset_a)
    db.commit()

    alias_old = AssetIdentifierAlias(
        asset_id=asset_a.id,
        project_id=pid,
        identifier_type="IP_ADDRESS",
        identifier_value="198.51.100.42",
        is_primary=False,
        confidence=1.0,
        first_observed_at=fifteen_days_ago,
        last_observed_at=fifteen_days_ago,
        is_active=True,
    )
    db.add(alias_old)
    db.commit()

    # New observation arrives today claiming 198.51.100.42
    # Must NOT automatically merge into asset_a; must detect IP reuse conflict (> 7 days)
    res = CanonicalIdentityService.resolve_entity(
        db=db,
        project_id=pid,
        candidate_target="198.51.100.42",
        observed_at=now,
    )
    assert res.outcome == ResolutionMatchOutcome.AMBIGUOUS_CONFLICT
    assert res.confidence < 0.50
    assert any("IP address reuse suspected" in c for c in res.conflicts_detected)


# ---------------------------------------------------------------------------
# Test 3: Shared IP & Resemblance Rejection (Req 7, 14 & Invariants)
# ---------------------------------------------------------------------------
def test_shared_ip_and_fuzzy_hostname_resemblance_rejection(db, asset_project, asset_org):
    pid = asset_project.id
    now = datetime.now(timezone.utc)

    asset_b = Asset(
        project_id=pid,
        organization_id=asset_org.id,
        asset_type=AssetType.DOMAIN,
        name="Production API Gateway",
        canonical_identifier="api.example.com",
        status=AssetStatus.ACTIVE,
        first_seen_at=now,
        last_seen_at=now,
    )
    db.add(asset_b)
    db.commit()

    # Active IP alias observed recently (e.g. 1 hour ago)
    alias_recent = AssetIdentifierAlias(
        asset_id=asset_b.id,
        project_id=pid,
        identifier_type="IP_ADDRESS",
        identifier_value="203.0.113.10",
        is_primary=False,
        confidence=1.0,
        first_observed_at=now - timedelta(hours=1),
        last_observed_at=now - timedelta(hours=1),
        is_active=True,
    )
    db.add(alias_recent)
    db.commit()

    # Rule: Never merge solely because of shared IP without cert/hardware confirmation
    res_ip = CanonicalIdentityService.resolve_entity(
        db=db,
        project_id=pid,
        candidate_target="203.0.113.10",
        observed_at=now,
    )
    assert res_ip.outcome == ResolutionMatchOutcome.AMBIGUOUS_CONFLICT
    assert any("Single IP match without cryptographic fingerprint is ambiguous" in c for c in res_ip.conflicts_detected)

    # Rule: Hostname resemblance / prefix match must not auto-merge
    res_host = CanonicalIdentityService.resolve_entity(
        db=db,
        project_id=pid,
        candidate_target="api.example.com.dev.internal",
    )
    assert res_host.outcome == ResolutionMatchOutcome.AMBIGUOUS_CONFLICT
    assert any("resemblance" in c for c in res_host.conflicts_detected)


# ---------------------------------------------------------------------------
# Test 4: Dry-Run Deduplication Analysis (Req 11)
# ---------------------------------------------------------------------------
def test_dry_run_deduplication_analysis(db, asset_project, asset_org):
    pid = asset_project.id
    now = datetime.now(timezone.utc)

    source = Asset(
        project_id=pid,
        organization_id=asset_org.id,
        asset_type=AssetType.WEB_APP,
        name="Legacy App",
        canonical_identifier="https://legacy.example.com",
        status=AssetStatus.ACTIVE,
        first_seen_at=now,
        last_seen_at=now,
    )
    target = Asset(
        project_id=pid,
        organization_id=asset_org.id,
        asset_type=AssetType.WEB_APP,
        name="Modern App",
        canonical_identifier="https://modern.example.com",
        status=AssetStatus.ACTIVE,
        first_seen_at=now,
        last_seen_at=now,
    )
    db.add_all([source, target])
    db.commit()

    # Attach findings and aliases to source
    f1 = VulnerabilityFinding(
        project_id=pid,
        asset_id=source.id,
        fingerprint="fp-dry-run-1",
        target_value="https://legacy.example.com",
        title="SQL Injection",
        severity=FindingSeverity.HIGH,
        confidence=FindingConfidence.CERTAIN,
    )
    a1 = AssetIdentifierAlias(
        asset_id=source.id,
        project_id=pid,
        identifier_type="HOSTNAME",
        identifier_value="legacy.internal",
        is_primary=False,
    )
    db.add_all([f1, a1])
    db.commit()

    # Run dry run
    impact = CanonicalIdentityService.evaluate_dry_run_impact(
        db=db,
        project_id=pid,
        source_asset_id=source.id,
        target_asset_id=target.id,
    )
    assert impact["findings_to_repoint"] == 1
    assert impact["aliases_to_transfer"] == 1
    assert impact["safe_to_merge"] is True
    assert impact["source_canonical_identifier"] == "https://legacy.example.com"
    assert impact["target_canonical_identifier"] == "https://modern.example.com"


# ---------------------------------------------------------------------------
# Test 5: Reviewable Deduplication Proposal, Approval & Merge Integrity (Req 8, 9)
# ---------------------------------------------------------------------------
def test_deduplication_proposal_approval_and_merge(db, asset_project, asset_org, asset_users):
    pid = asset_project.id
    lead = asset_users["lead"]
    tester = asset_users["tester"]
    now = datetime.now(timezone.utc)

    source = Asset(
        project_id=pid,
        organization_id=asset_org.id,
        asset_type=AssetType.WEB_APP,
        name="Duplicate Source",
        canonical_identifier="https://dup-source.example.com",
        status=AssetStatus.ACTIVE,
        first_seen_at=now,
        last_seen_at=now,
    )
    target = Asset(
        project_id=pid,
        organization_id=asset_org.id,
        asset_type=AssetType.WEB_APP,
        name="Authoritative Target",
        canonical_identifier="https://canonical-target.example.com",
        status=AssetStatus.ACTIVE,
        first_seen_at=now,
        last_seen_at=now,
    )
    db.add_all([source, target])
    db.commit()

    finding = VulnerabilityFinding(
        project_id=pid,
        asset_id=source.id,
        fingerprint="fp-dup-finding-1",
        target_value="https://dup-source.example.com",
        title="Cross-Site Scripting",
        severity=FindingSeverity.MEDIUM,
        confidence=FindingConfidence.CERTAIN,
    )
    db.add(finding)
    db.commit()

    # 1. Propose deduplication (Tester)
    proposal = CanonicalIdentityService.propose_deduplication(
        db=db,
        project_id=pid,
        source_asset_id=source.id,
        target_asset_id=target.id,
        proposed_by_id=tester.id,
        rationale="Hostnames resolve to identical service endpoint",
    )
    assert proposal.status == DeduplicationProposalStatus.PROPOSED
    assert proposal.dry_run_impact["findings_to_repoint"] == 1

    # 2. Approve deduplication (Lead)
    approved = CanonicalIdentityService.approve_deduplication(
        db=db,
        project_id=pid,
        proposal_id=proposal.id,
        reviewer_id=lead.id,
        review_comments="Verified identical service deployment",
    )
    assert approved.status == DeduplicationProposalStatus.APPROVED
    assert approved.merge_record_id is not None

    # Verify merge results:
    # Finding must be repointed to target
    db.refresh(finding)
    assert finding.asset_id == target.id

    # Source asset is DECOMMISSIONED with provenance
    db.refresh(source)
    assert source.status == AssetStatus.DECOMMISSIONED
    assert source.attributes.get("_merged_into") == target.id


# ---------------------------------------------------------------------------
# Test 6: Deduplication Reversal / Split Rollback Workflow (Req 8, 9, 14)
# ---------------------------------------------------------------------------
def test_deduplication_reversal_and_split_rollback(db, asset_project, asset_org, asset_users):
    pid = asset_project.id
    lead = asset_users["lead"]
    now = datetime.now(timezone.utc)

    source = Asset(
        project_id=pid,
        organization_id=asset_org.id,
        asset_type=AssetType.HOST,
        name="Temporary Server",
        canonical_identifier="srv-temp.corp",
        status=AssetStatus.ACTIVE,
        first_seen_at=now,
        last_seen_at=now,
    )
    target = Asset(
        project_id=pid,
        organization_id=asset_org.id,
        asset_type=AssetType.HOST,
        name="Main Server",
        canonical_identifier="srv-main.corp",
        status=AssetStatus.ACTIVE,
        first_seen_at=now,
        last_seen_at=now,
    )
    db.add_all([source, target])
    db.commit()

    finding = VulnerabilityFinding(
        project_id=pid,
        asset_id=source.id,
        fingerprint="fp-split-test-1",
        target_value="srv-temp.corp",
        title="Unquoted Service Path",
        severity=FindingSeverity.LOW,
        confidence=FindingConfidence.FIRM,
    )
    db.add(finding)
    db.commit()

    # Propose and Approve merge
    prop = CanonicalIdentityService.propose_deduplication(
        db=db,
        project_id=pid,
        source_asset_id=source.id,
        target_asset_id=target.id,
        proposed_by_id=lead.id,
        rationale="Mistaken deduplication for testing reversal",
    )
    CanonicalIdentityService.approve_deduplication(
        db=db,
        project_id=pid,
        proposal_id=prop.id,
        reviewer_id=lead.id,
    )
    db.refresh(finding)
    assert finding.asset_id == target.id

    # Revert proposal (Split workflow)
    reverted = CanonicalIdentityService.revert_deduplication(
        db=db,
        project_id=pid,
        proposal_id=prop.id,
        revert_user_id=lead.id,
        reversal_notes="Reverting merge: systems operate distinct applications",
    )
    assert reverted.status == DeduplicationProposalStatus.REVERTED

    # Source asset restored to ACTIVE
    db.refresh(source)
    assert source.status == AssetStatus.ACTIVE

    # Finding restored to source asset
    db.refresh(finding)
    assert finding.asset_id == source.id


# ---------------------------------------------------------------------------
# Test 7: Data Quality Audit Engine (Req 10)
# ---------------------------------------------------------------------------
def test_data_quality_audit_engine(db, asset_project, asset_org, asset_users):
    pid = asset_project.id
    now = datetime.now(timezone.utc)

    # 1. Inject Orphaned Finding (references None asset_id)
    f_orphaned = VulnerabilityFinding(
        project_id=pid,
        asset_id=None,
        fingerprint="fp-dq-orphan-1",
        target_value="https://missing-asset.com",
        title="Orphaned Vulnerability",
        severity=FindingSeverity.HIGH,
        confidence=FindingConfidence.CERTAIN,
    )

    # 2. Inject Missing Asset Reference (Scope target without canonical asset)
    target_unresolved = ScopeTarget(
        project_id=pid,
        target_type=TargetType.URL,
        target_value="https://unresolved-target.example.com",
        authorization_status=AuthorizationStatus.AUTHORIZED,
        created_by_id=asset_users["lead"].id,
    )

    # 3. Inject Inconsistent Timestamps (last_seen_at < first_seen_at)
    asset_inconsistent = Asset(
        project_id=pid,
        organization_id=asset_org.id,
        asset_type=AssetType.HOST,
        name="Clock Skew Asset",
        canonical_identifier="skew.corp",
        status=AssetStatus.ACTIVE,
        first_seen_at=now,
        last_seen_at=now - timedelta(days=5),
    )

    # 4. Inject Stale Observation (Active asset with no observation in 45 days)
    asset_stale = Asset(
        project_id=pid,
        organization_id=asset_org.id,
        asset_type=AssetType.HOST,
        name="Abandoned Server",
        canonical_identifier="stale-server.corp",
        status=AssetStatus.ACTIVE,
        first_seen_at=now - timedelta(days=60),
        last_seen_at=now - timedelta(days=45),
        confirmed_absent=False,
    )

    db.add_all([f_orphaned, target_unresolved, asset_inconsistent, asset_stale])
    db.commit()

    # Run Data Quality Audit
    issues = CanonicalIdentityService.run_data_quality_audit(db=db, project_id=pid)
    assert len(issues) >= 4

    issue_types = {iss.issue_type for iss in issues}
    assert DataQualityIssueType.ORPHANED_FINDING in issue_types
    assert DataQualityIssueType.MISSING_ASSET_REFERENCE in issue_types
    assert DataQualityIssueType.INCONSISTENT_TIMESTAMPS in issue_types
    assert DataQualityIssueType.STALE_OBSERVATION in issue_types


# ---------------------------------------------------------------------------
# Test 8: Data Quality Issue Lifecycle Resolution
# ---------------------------------------------------------------------------
def test_data_quality_issue_lifecycle_resolution(db, asset_project):
    pid = asset_project.id
    now = datetime.now(timezone.utc)

    issue = AssetDataQualityIssue(
        project_id=pid,
        issue_type=DataQualityIssueType.ORPHANED_FINDING,
        severity="HIGH",
        affected_resource_type="FINDING",
        affected_resource_id=str(uuid.uuid4()),
        details={"reason": "Test anomaly"},
        status=DataQualityIssueStatus.OPEN,
        detected_at=now,
    )
    db.add(issue)
    db.commit()

    # Resolve issue
    resolved = CanonicalIdentityService.resolve_data_quality_issue(
        db=db,
        project_id=pid,
        issue_id=issue.id,
        new_status=DataQualityIssueStatus.RESOLVED,
    )
    assert resolved.status == DataQualityIssueStatus.RESOLVED
    assert resolved.resolved_at is not None


# ---------------------------------------------------------------------------
# Test 9: REST Endpoints and Multi-Tenant RBAC Boundary
# ---------------------------------------------------------------------------
def test_canonical_identity_rest_endpoints_and_rbac(client, db, asset_project, asset_org, asset_users):
    pid = asset_project.id
    lead_h = auth_header_for_user(asset_users["lead"])
    viewer_h = auth_header_for_user(asset_users["viewer"])

    # 1. Resolve Entity endpoint (Accessible by Viewer & Lead)
    res_resolve = client.post(
        f"/api/v1/projects/{pid}/asset-identity/resolve",
        json={"candidate_target": "https://api-gateway.corp.com"},
        headers=viewer_h,
    )
    assert res_resolve.status_code == status.HTTP_200_OK
    assert res_resolve.json()["outcome"] in ["EXACT_MATCH", "STRONG_CORRELATION", "AMBIGUOUS_CONFLICT", "UNMATCHED"]

    # 2. List Data Quality Issues (Viewer accessible)
    res_issues = client.get(
        f"/api/v1/projects/{pid}/asset-identity/data-quality/issues",
        headers=viewer_h,
    )
    assert res_issues.status_code == status.HTTP_200_OK
    assert isinstance(res_issues.json(), list)

    # 3. Create Asset pair for deduplication API test
    now = datetime.now(timezone.utc)
    a1 = Asset(
        project_id=pid,
        organization_id=asset_org.id,
        asset_type=AssetType.HOST,
        name="Host Alpha",
        canonical_identifier="alpha.corp.net",
        status=AssetStatus.ACTIVE,
        first_seen_at=now,
        last_seen_at=now,
    )
    a2 = Asset(
        project_id=pid,
        organization_id=asset_org.id,
        asset_type=AssetType.HOST,
        name="Host Beta",
        canonical_identifier="beta.corp.net",
        status=AssetStatus.ACTIVE,
        first_seen_at=now,
        last_seen_at=now,
    )
    db.add_all([a1, a2])
    db.commit()

    # 4. Propose Deduplication (Viewer forbidden 403, Lead succeeds 201)
    res_prop_v = client.post(
        f"/api/v1/projects/{pid}/asset-identity/deduplication/proposals",
        json={"source_asset_id": a1.id, "target_asset_id": a2.id, "rationale": "Same host"},
        headers=viewer_h,
    )
    assert res_prop_v.status_code == status.HTTP_403_FORBIDDEN

    res_prop_l = client.post(
        f"/api/v1/projects/{pid}/asset-identity/deduplication/proposals",
        json={"source_asset_id": a1.id, "target_asset_id": a2.id, "rationale": "Identical hardware deployment"},
        headers=lead_h,
    )
    assert res_prop_l.status_code == status.HTTP_201_CREATED
    prop_id = res_prop_l.json()["id"]

    # 5. Approve proposal via API (Lead)
    res_app = client.post(
        f"/api/v1/projects/{pid}/asset-identity/deduplication/proposals/{prop_id}/approve",
        json={"comments": "Approved after hardware validation"},
        headers=lead_h,
    )
    assert res_app.status_code == status.HTTP_200_OK
    assert res_app.json()["status"] == "APPROVED"

    # 6. Revert proposal via API (Lead)
    res_rev = client.post(
        f"/api/v1/projects/{pid}/asset-identity/deduplication/proposals/{prop_id}/revert",
        json={"comments": "Split back to independent servers"},
        headers=lead_h,
    )
    assert res_rev.status_code == status.HTTP_200_OK
    assert res_rev.json()["status"] == "REVERTED"
