"""
Prompt 46 Acceptance Test Suite:
Authorized Attack-Surface Inventory and Exposure Governance.

Verifies:
1. Exposure inventory recording authorized assets, observed services, hostnames, and TLS certs.
2. Provenance classification (verified, imported, simulated, inferred).
3. Deduplication with provenance preservation and evidence accumulation.
4. Meaningful change detection (new service, changed certificate, changed hostname).
5. Freshness tracking and absence handling (unverified absent vs confirmed decommissioned).
6. Strict preflight scope revalidation and anti-expansion guard.
7. Explicit discovery inclusion proposal approval workflow.
8. Discovery proposal rejection workflow.
9. Exposure timeline and asset-level evidence views.
"""
import copy
import hashlib
from datetime import datetime, timezone, timedelta
import pytest
from fastapi.testclient import TestClient

from app.core.database import SessionLocal
from app.models.user import User, SystemRole
from app.models.organization import Organization
from app.models.project import Project
from app.models.asset import Asset, AssetType, AssetStatus
from app.models.scope import ScopeTarget, ScopeExclusion, TargetType, AuthorizationStatus
from app.models.attack_surface import (
    ExposureClassification,
    ObservationProvenanceType,
    ExposureFreshness,
    ProposalStatus,
    AttackSurfaceExposure,
    AssetInclusionProposal,
)
from app.services.attack_surface_service import AttackSurfaceService
from app.services.scope_engine import ScopeEngine
from app.main import app

client = TestClient(app)


@pytest.fixture(scope="module")
def setup_prompt46_fixtures():
    db = SessionLocal()
    try:
        # Organization
        org = db.query(Organization).filter(Organization.name == "Prompt 46 Exposure Org").first()
        if not org:
            org = Organization(name="Prompt 46 Exposure Org", slug="prompt-46-exposure-org")
            db.add(org)
            db.commit()
            db.refresh(org)

        # User
        user = db.query(User).filter(User.email == "exposure_lead@test.corp").first()
        if not user:
            user = User(
                email="exposure_lead@test.corp",
                full_name="Exposure Security Lead",
                hashed_password="hashed_pw_fixture_123456",
                system_role=SystemRole.SECURITY_LEAD,
            )
            db.add(user)
            db.commit()
            db.refresh(user)

        # Project
        project = db.query(Project).filter(Project.name == "Prompt 46 Attack Surface Project").first()
        if not project:
            project = Project(
                name="Prompt 46 Attack Surface Project",
                description="Governed attack surface project",
                organization_id=org.id,
            )
            db.add(project)
            db.commit()
            db.refresh(project)

        # Authorized Scope Target: api.authorized.corp
        target = db.query(ScopeTarget).filter(
            ScopeTarget.project_id == project.id,
            ScopeTarget.target_value == "api.authorized.corp",
        ).first()
        if not target:
            target = ScopeTarget(
                project_id=project.id,
                target_type=TargetType.DOMAIN,
                target_value="api.authorized.corp",
                authorization_status=AuthorizationStatus.AUTHORIZED,
                authorization_evidence="ROE-PROMPT46-APPROVED",
                created_by_id=user.id,
                authorized_by_id=user.id,
            )
            db.add(target)
            db.commit()
            db.refresh(target)

        # Excluded Target: restricted.authorized.corp
        exclusion = db.query(ScopeExclusion).filter(
            ScopeExclusion.project_id == project.id,
            ScopeExclusion.target_value == "restricted.authorized.corp",
        ).first()
        if not exclusion:
            exclusion = ScopeExclusion(
                project_id=project.id,
                target_type=TargetType.DOMAIN,
                target_value="restricted.authorized.corp",
                reason="Production sensitive gateway out of scope",
                created_by_id=user.id,
            )
            db.add(exclusion)
            db.commit()
            db.refresh(exclusion)

        # Asset: api.authorized.corp
        asset = db.query(Asset).filter(
            Asset.project_id == project.id,
            Asset.canonical_identifier == "api.authorized.corp",
        ).first()
        if not asset:
            asset = Asset(
                organization_id=org.id,
                project_id=project.id,
                asset_type=AssetType.DOMAIN,
                name="api.authorized.corp",
                canonical_identifier="api.authorized.corp",
                status=AssetStatus.ACTIVE,
            )
            db.add(asset)
            db.commit()
            db.refresh(asset)

        # Clean up any leftover test records for this project
        db.query(AttackSurfaceExposure).filter(AttackSurfaceExposure.project_id == project.id).delete()
        db.query(AssetInclusionProposal).filter(AssetInclusionProposal.project_id == project.id).delete()
        db.query(ScopeTarget).filter(
            ScopeTarget.project_id == project.id,
            ScopeTarget.target_value != "api.authorized.corp",
        ).delete()
        db.query(Asset).filter(
            Asset.project_id == project.id,
            Asset.canonical_identifier != "api.authorized.corp",
        ).delete()
        db.commit()

        yield {
            "org_id": org.id,
            "user_id": user.id,
            "project_id": project.id,
            "asset_id": asset.id,
        }
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Test 1: Ingestion of Authorized Exposure Inventory
# ---------------------------------------------------------------------------
def test_01_ingest_authorized_exposure_inventory(setup_prompt46_fixtures):
    """Verifies that authorized asset exposure is recorded with services, certs, and classifications."""
    db = SessionLocal()
    try:
        p_id = setup_prompt46_fixtures["project_id"]
        a_id = setup_prompt46_fixtures["asset_id"]

        cert = {
            "subject": "CN=api.authorized.corp",
            "issuer": "Let's Encrypt Authority X3",
            "fingerprint_sha256": "aaaa1111bbbb2222cccc3333dddd4444",
            "is_expired": False,
        }

        exposure, proposal, changes = AttackSurfaceService.ingest_exposure_observation(
            db=db,
            project_id=p_id,
            asset_id=a_id,
            canonical_identifier="api.authorized.corp",
            service_name="https",
            port=443,
            protocol="tcp",
            transport_security="TLS_1_3",
            certificate_details=cert,
            relevant_hostnames=["api.authorized.corp", "gateway.authorized.corp"],
            exposure_classification=ExposureClassification.INTERNET_FACING,
            provenance_type=ObservationProvenanceType.VERIFIED_OBSERVATION,
            evidence_hash="sha256_evidence_digest_001",
        )

        assert exposure is not None
        assert proposal is None
        assert exposure.is_authorized is True
        assert exposure.port == 443
        assert exposure.transport_security == "TLS_1_3"
        assert exposure.freshness == ExposureFreshness.FRESH
        assert exposure.observation_count == 1
        assert "sha256_evidence_digest_001" in exposure.evidence_hashes
        assert any("NEW_SERVICE" in c for c in changes)

    finally:
        db.close()


# ---------------------------------------------------------------------------
# Test 2: Provenance Type Distinctions
# ---------------------------------------------------------------------------
def test_02_provenance_type_distinctions(setup_prompt46_fixtures):
    """Verifies that verified, imported, simulated, and inferred provenance are distinguished."""
    db = SessionLocal()
    try:
        p_id = setup_prompt46_fixtures["project_id"]
        a_id = setup_prompt46_fixtures["asset_id"]

        # Ingest simulated result
        exp_sim, _, _ = AttackSurfaceService.ingest_exposure_observation(
            db=db,
            project_id=p_id,
            asset_id=a_id,
            canonical_identifier="api.authorized.corp",
            service_name="ssh",
            port=22,
            provenance_type=ObservationProvenanceType.SIMULATED_RESULT,
            is_simulated=True,
        )
        assert exp_sim.provenance_type == ObservationProvenanceType.SIMULATED_RESULT

        # Ingest imported result
        exp_imp, _, _ = AttackSurfaceService.ingest_exposure_observation(
            db=db,
            project_id=p_id,
            asset_id=a_id,
            canonical_identifier="api.authorized.corp",
            service_name="http",
            port=80,
            provenance_type=ObservationProvenanceType.IMPORTED_OBSERVATION,
        )
        assert exp_imp.provenance_type == ObservationProvenanceType.IMPORTED_OBSERVATION

    finally:
        db.close()


# ---------------------------------------------------------------------------
# Test 3: Deduplication with Provenance Preservation & Evidence Accumulation
# ---------------------------------------------------------------------------
def test_03_deduplication_preserves_provenance(setup_prompt46_fixtures):
    """Verifies that duplicate observations increment telemetry without creating duplicate records."""
    db = SessionLocal()
    try:
        p_id = setup_prompt46_fixtures["project_id"]
        a_id = setup_prompt46_fixtures["asset_id"]

        cert = {
            "subject": "CN=api.authorized.corp",
            "issuer": "Let's Encrypt Authority X3",
            "fingerprint_sha256": "aaaa1111bbbb2222cccc3333dddd4444",
        }

        # Second observation of port 443 with new evidence digest
        exp_updated, proposal, changes = AttackSurfaceService.ingest_exposure_observation(
            db=db,
            project_id=p_id,
            asset_id=a_id,
            canonical_identifier="api.authorized.corp",
            service_name="https",
            port=443,
            protocol="tcp",
            transport_security="TLS_1_3",
            certificate_details=cert,
            evidence_hash="sha256_evidence_digest_002",
        )

        assert exp_updated.observation_count == 2
        assert "sha256_evidence_digest_001" in exp_updated.evidence_hashes
        assert "sha256_evidence_digest_002" in exp_updated.evidence_hashes
        assert exp_updated.consecutive_absences == 0

        # Total port 443 records for this project should still be 1
        count = db.query(AttackSurfaceExposure).filter(
            AttackSurfaceExposure.project_id == p_id,
            AttackSurfaceExposure.port == 443,
        ).count()
        assert count == 1

    finally:
        db.close()


# ---------------------------------------------------------------------------
# Test 4: Meaningful Change Detection (Certificate Rotation & Hostnames)
# ---------------------------------------------------------------------------
def test_04_meaningful_change_detection(setup_prompt46_fixtures):
    """Verifies detection of certificate renewals and newly observed hostname associations."""
    db = SessionLocal()
    try:
        p_id = setup_prompt46_fixtures["project_id"]
        a_id = setup_prompt46_fixtures["asset_id"]

        new_cert = {
            "subject": "CN=api.authorized.corp",
            "issuer": "DigiCert Global Root CA",
            "fingerprint_sha256": "ffff9999eeee8888dddd7777cccc6666",  # Changed fingerprint
        }

        exp, _, changes = AttackSurfaceService.ingest_exposure_observation(
            db=db,
            project_id=p_id,
            asset_id=a_id,
            canonical_identifier="api.authorized.corp",
            service_name="https",
            port=443,
            protocol="tcp",
            certificate_details=new_cert,
            relevant_hostnames=["api.authorized.corp", "new-subdomain.authorized.corp"],
        )

        # Must flag certificate change
        assert any("CHANGED_CERTIFICATE" in c for c in changes)
        # Must flag hostname association change
        assert any("CHANGED_HOSTNAME_ASSOCIATION" in c for c in changes)
        assert "new-subdomain.authorized.corp" in exp.relevant_hostnames

    finally:
        db.close()


# ---------------------------------------------------------------------------
# Test 5: Freshness Tracking & Absence Distinct from Removal
# ---------------------------------------------------------------------------
def test_05_absence_distinct_from_confirmed_removal(setup_prompt46_fixtures):
    """Verifies that consecutive absences mark exposure as UNVERIFIED_ABSENT, not DECOMMISSIONED."""
    db = SessionLocal()
    try:
        p_id = setup_prompt46_fixtures["project_id"]

        # Record 1st absence
        exp = AttackSurfaceService.record_exposure_absence(
            db=db,
            project_id=p_id,
            canonical_identifier="api.authorized.corp",
            port=80,
            protocol="tcp",
        )
        assert exp.consecutive_absences == 1
        assert exp.freshness == ExposureFreshness.AGING

        # Record 2nd and 3rd absences
        AttackSurfaceService.record_exposure_absence(db, p_id, "api.authorized.corp", 80)
        exp3 = AttackSurfaceService.record_exposure_absence(db, p_id, "api.authorized.corp", 80)

        assert exp3.consecutive_absences == 3
        # Must transition to UNVERIFIED_ABSENT, never falsely declared DECOMMISSIONED (Req 5)
        assert exp3.freshness == ExposureFreshness.UNVERIFIED_ABSENT
        assert exp3.freshness != ExposureFreshness.CONFIRMED_DECOMMISSIONED

    finally:
        db.close()


# ---------------------------------------------------------------------------
# Test 6: Anti-Expansion Guard & Excluded Target Handling
# ---------------------------------------------------------------------------
def test_06_anti_expansion_guard_and_excluded_targets(setup_prompt46_fixtures):
    """Verifies that out-of-scope discoveries cannot expand scope and are routed to proposals."""
    db = SessionLocal()
    try:
        p_id = setup_prompt46_fixtures["project_id"]
        a_id = setup_prompt46_fixtures["asset_id"]

        # 1. Candidate is not authorized: rogue-discovered.corp
        exp, proposal, changes = AttackSurfaceService.ingest_exposure_observation(
            db=db,
            project_id=p_id,
            asset_id=a_id,
            canonical_identifier="rogue-discovered.corp",
            port=8080,
        )

        assert exp is None
        assert proposal is not None
        assert proposal.target_value == "rogue-discovered.corp"
        assert proposal.status == ProposalStatus.PENDING
        assert "UNAUTHORIZED_TARGET_PROPOSED_FOR_INCLUSION" in changes

        # 2. Candidate is strictly excluded: restricted.authorized.corp
        exp_excl, proposal_excl, changes_excl = AttackSurfaceService.ingest_exposure_observation(
            db=db,
            project_id=p_id,
            asset_id=a_id,
            canonical_identifier="restricted.authorized.corp",
            port=443,
        )

        assert exp_excl is None
        assert proposal_excl is not None
        # Rationale must record strict exclusion reason
        assert "strictly excluded" in proposal_excl.rationale

    finally:
        db.close()


# ---------------------------------------------------------------------------
# Test 7: Explicit Discovery Inclusion Approval Workflow
# ---------------------------------------------------------------------------
def test_07_approval_workflow_for_discovered_asset(setup_prompt46_fixtures):
    """Verifies that operator approval of a proposed asset authorizes testing and registers scope target."""
    db = SessionLocal()
    try:
        p_id = setup_prompt46_fixtures["project_id"]
        u_id = setup_prompt46_fixtures["user_id"]
        reviewer = db.query(User).filter(User.id == u_id).first()

        # Create proposal for staging-api.authorized.corp
        proposal = AttackSurfaceService.propose_discovered_asset(
            db=db,
            project_id=p_id,
            target_value="staging-api.authorized.corp",
            discovery_source="CERTIFICATE_TRANSPARENCY",
            rationale="Discovered from Subject Alternative Name SAN list",
        )
        assert proposal.status == ProposalStatus.PENDING

        # Preflight scope check before approval must fail
        scope_before = ScopeEngine.validate_target_in_scope(db, p_id, "staging-api.authorized.corp")
        assert scope_before["is_authorized"] is False

        # Approve proposal
        approved_proposal, scope_target = AttackSurfaceService.approve_inclusion_proposal(
            db=db,
            project_id=p_id,
            proposal_id=proposal.id,
            reviewer=reviewer,
            approval_notes="Approved after verifying ownership with DevOps team.",
            authorized_evidence="ROE-EXP-2026-009",
        )

        assert approved_proposal.status == ProposalStatus.APPROVED
        assert approved_proposal.reviewed_by_id == reviewer.id
        assert scope_target.authorization_status == AuthorizationStatus.AUTHORIZED
        assert scope_target.target_value == "staging-api.authorized.corp"

        # Preflight scope check after approval must SUCCEED
        scope_after = ScopeEngine.validate_target_in_scope(db, p_id, "staging-api.authorized.corp")
        assert scope_after["is_authorized"] is True

        # Ingestion for newly authorized target now succeeds!
        exp, _, _ = AttackSurfaceService.ingest_exposure_observation(
            db=db,
            project_id=p_id,
            asset_id=approved_proposal.id,  # Will look up by canonical identifier
            canonical_identifier="staging-api.authorized.corp",
            port=443,
            service_name="https",
        )
        assert exp is not None
        assert exp.is_authorized is True

    finally:
        db.close()


# ---------------------------------------------------------------------------
# Test 8: Discovery Proposal Rejection Workflow
# ---------------------------------------------------------------------------
def test_08_rejection_workflow_for_discovered_asset(setup_prompt46_fixtures):
    """Verifies that rejecting a proposal prevents authorization and stops further testing."""
    db = SessionLocal()
    try:
        p_id = setup_prompt46_fixtures["project_id"]
        u_id = setup_prompt46_fixtures["user_id"]
        reviewer = db.query(User).filter(User.id == u_id).first()

        proposal = AttackSurfaceService.propose_discovered_asset(
            db=db,
            project_id=p_id,
            target_value="third-party-vendor-gateway.corp",
            discovery_source="DNS_CNAME_INFERENCE",
        )

        # Reject proposal
        rejected_prop = AttackSurfaceService.reject_inclusion_proposal(
            db=db,
            project_id=p_id,
            proposal_id=proposal.id,
            reviewer=reviewer,
            rejection_reason="Third-party vendor SaaS domain; out of penetration testing scope.",
        )

        assert rejected_prop.status == ProposalStatus.REJECTED
        assert "REJECTED: Third-party vendor SaaS domain" in rejected_prop.approval_notes

        # Re-check scope: must remain strictly unauthorized
        scope_eval = ScopeEngine.validate_target_in_scope(db, p_id, "third-party-vendor-gateway.corp")
        assert scope_eval["is_authorized"] is False

    finally:
        db.close()


# ---------------------------------------------------------------------------
# Test 9: Attack Surface Inventory, Timeline, and Asset Evidence Queries
# ---------------------------------------------------------------------------
def test_09_inventory_timeline_and_asset_evidence_queries(setup_prompt46_fixtures):
    """Verifies querying inventory summary, timeline event aggregation, and asset-level evidence."""
    db = SessionLocal()
    try:
        p_id = setup_prompt46_fixtures["project_id"]
        a_id = setup_prompt46_fixtures["asset_id"]

        # 1. Inventory Summary
        inv = AttackSurfaceService.get_inventory(db, p_id)
        assert inv["total_exposures"] >= 2
        assert inv["internet_facing_count"] >= 1

        # 2. Timeline Aggregation
        timeline = AttackSurfaceService.get_timeline(db, p_id, limit=20)
        assert len(timeline) >= 2
        assert all("event_id" in ev and "canonical_identifier" in ev for ev in timeline)

        # 3. Asset-level Evidence Breakdown
        evidence_view = AttackSurfaceService.get_asset_exposure_evidence(db, p_id, a_id)
        assert evidence_view["canonical_identifier"] == "api.authorized.corp"
        assert len(evidence_view["active_services"]) >= 1
        assert len(evidence_view["evidence_digests"]) >= 1
        assert "api.authorized.corp" in evidence_view["associated_hostnames"]

    finally:
        db.close()
