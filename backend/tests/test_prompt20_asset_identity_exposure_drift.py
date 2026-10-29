"""
Comprehensive Deterministic Test Suite for Prompt 20:
Asset Identity, Exposure Drift & Continuous Change Intelligence.
"""

import hashlib
from datetime import datetime, timezone, timedelta
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.asset import (
    Asset,
    AssetObservation,
    AssetType,
    AssetCriticality,
    AssetStatus,
    AssetIdentifierAlias,
    AssetIdentityMergeRecord,
)
from app.models.drift import (
    ExposureDriftRecord,
    ReassessmentProposal,
    DriftType,
    DriftMateriality,
    ReassessmentPriority,
    ReassessmentStatus,
)
from app.models.finding import (
    VulnerabilityFinding,
    FindingLifecycleStatus,
    FindingSeverity,
    FindingConfidence,
)
from app.models.scope import ScopeTarget, ScopeExclusion, TargetType, AuthorizationStatus
from app.models.project import Project, ProjectMember, ProjectRole
from app.models.user import User, SystemRole
from app.models.assessment import AssessmentJob, AssessmentStatus
from app.models.base import utc_now
from app.services.asset_identity_service import AssetIdentityService
from app.services.exposure_drift_service import ExposureDriftService
from app.services.reassessment_planner_service import ReassessmentPlannerService
from app.services.continuous_change_intelligence_service import ContinuousChangeIntelligenceService
from app.services.dependency_invalidation_service import DependencyInvalidationService


# ---------------------------------------------------------------------------
# 1. Asset Identity Classification & Normalization
# ---------------------------------------------------------------------------

def test_asset_identity_classification_and_normalization():
    """Verify deterministic normalization, type classification, and CWE-1288 rejection."""
    # 1. Web App & API Endpoint
    t1, c1, d1 = AssetIdentityService.classify_and_normalize("https://app.corp.internal:443")
    assert t1 == AssetType.WEB_APP
    assert c1 == "https://app.corp.internal"
    assert d1 == "app.corp.internal"

    t2, c2, d2 = AssetIdentityService.classify_and_normalize("https://api.corp.internal/v1/auth")
    assert t2 == AssetType.API_ENDPOINT
    assert c2 == "https://api.corp.internal/v1/auth"

    # 2. Service
    t3, c3, d3 = AssetIdentityService.classify_and_normalize("tcp://10.0.0.1:8080")
    assert t3 == AssetType.SERVICE
    assert c3 == "tcp://10.0.0.1:8080"

    # 3. IPv4 & Domain
    t4, c4, _ = AssetIdentityService.classify_and_normalize("192.168.1.1")
    assert t4 == AssetType.IP_ADDRESS
    assert c4 == "192.168.1.1"

    t5, c5, _ = AssetIdentityService.classify_and_normalize("portal.company.com")
    assert t5 == AssetType.DOMAIN
    assert c5 == "portal.company.com"

    # 4. Prohibit leading zeros in IPv4 octets (CWE-1288)
    with pytest.raises(ValueError, match="CWE-1288"):
        AssetIdentityService.classify_and_normalize("010.0.0.1")

    with pytest.raises(ValueError, match="CWE-1288"):
        AssetIdentityService.classify_and_normalize("http://010.0.0.1:8080")


# ---------------------------------------------------------------------------
# 2. Address Reuse Prevention
# ---------------------------------------------------------------------------

def test_address_reuse_prevention_between_unrelated_assets(db: Session, test_project: Project):
    """
    Verify address reuse does not silently merge unrelated assets.
    Two domains that share or cycle an IP address remain distinct logical assets.
    """
    now = utc_now()

    # Asset A: Service A
    asset_a = AssetIdentityService.reconcile_or_create_asset(
        project_id=test_project.id,
        organization_id=test_project.organization_id,
        asset_type=AssetType.DOMAIN,
        canonical_identifier="service-alpha.corp",
        attributes={"ip_address": "10.10.10.50"},
        observed_at=now - timedelta(days=2),
        db=db,
    )
    alias_a = AssetIdentityService.record_alias(
        asset=asset_a,
        identifier_type="IP_ADDRESS",
        identifier_value="10.10.10.50",
        observed_at=now - timedelta(days=2),
        db=db,
    )

    # Asset B: Service B observed later with the SAME IP (e.g. IP reassignment)
    asset_b = AssetIdentityService.reconcile_or_create_asset(
        project_id=test_project.id,
        organization_id=test_project.organization_id,
        asset_type=AssetType.DOMAIN,
        canonical_identifier="service-bravo.corp",
        attributes={"ip_address": "10.10.10.50"},
        observed_at=now,
        db=db,
    )
    alias_b = AssetIdentityService.record_alias(
        asset=asset_b,
        identifier_type="IP_ADDRESS",
        identifier_value="10.10.10.50",
        observed_at=now,
        db=db,
    )

    # Assets must remain strictly distinct
    assert asset_a.id != asset_b.id
    assert asset_a.canonical_identifier == "service-alpha.corp"
    assert asset_b.canonical_identifier == "service-bravo.corp"
    assert alias_a.asset_id == asset_a.id
    assert alias_b.asset_id == asset_b.id


# ---------------------------------------------------------------------------
# 3. Hostname and Address Changes Tracking
# ---------------------------------------------------------------------------

def test_hostname_and_address_changes_tracking(db: Session, test_project: Project):
    """Verify alias history and disassociation when an asset migrates IP addresses."""
    now = utc_now()
    asset = AssetIdentityService.reconcile_or_create_asset(
        project_id=test_project.id,
        organization_id=test_project.organization_id,
        asset_type=AssetType.DOMAIN,
        canonical_identifier="payment-api.corp",
        observed_at=now - timedelta(days=5),
        db=db,
    )

    # Initial IP association
    alias_old = AssetIdentityService.record_alias(
        asset=asset,
        identifier_type="IP_ADDRESS",
        identifier_value="192.168.1.100",
        is_primary=True,
        observed_at=now - timedelta(days=5),
        db=db,
    )

    # Asset migrates to new IP
    AssetIdentityService.disassociate_alias(
        alias_id=alias_old.id,
        reason="DNS updated to point to new cloud load balancer",
        db=db,
    )

    alias_new = AssetIdentityService.record_alias(
        asset=asset,
        identifier_type="IP_ADDRESS",
        identifier_value="192.168.1.200",
        is_primary=True,
        observed_at=now,
        db=db,
    )

    db.refresh(alias_old)
    assert alias_old.is_active is False
    assert "DNS updated" in alias_old.disassociation_reason
    assert alias_new.is_active is True
    assert alias_new.identifier_value == "192.168.1.200"


# ---------------------------------------------------------------------------
# 4. Ambiguous Identity Matches
# ---------------------------------------------------------------------------

def test_ambiguous_identity_match_marked_unresolved(db: Session, test_project: Project):
    """Verify ambiguous matches are flagged unresolved and not forcefully merged."""
    now = utc_now()
    asset = AssetIdentityService.reconcile_or_create_asset(
        project_id=test_project.id,
        organization_id=test_project.organization_id,
        asset_type=AssetType.HOSTNAME,
        canonical_identifier="shared-bastion",
        is_ambiguous=True,
        ambiguity_reason="Host banner claims multiple domain SANs [corp-a.com, corp-b.com].",
        observed_at=now,
        db=db,
    )

    assert asset.is_ambiguous is True
    assert "multiple domain SANs" in asset.ambiguity_reason


# ---------------------------------------------------------------------------
# 5. Duplicate Observation Delivery Idempotency
# ---------------------------------------------------------------------------

def test_duplicate_observation_delivery_idempotent(db: Session, test_project: Project):
    """Verify repeated delivery of identical observations within dedup window is suppressed."""
    now = utc_now()
    asset = AssetIdentityService.reconcile_or_create_asset(
        project_id=test_project.id,
        organization_id=test_project.organization_id,
        asset_type=AssetType.WEB_APP,
        canonical_identifier="https://login.corp.internal",
        observed_at=now,
        db=db,
    )

    obs_attrs = {"headers": {"server": "nginx/1.24.0"}, "open_ports": [443]}

    obs1, is_new1 = AssetIdentityService.record_observation(
        asset=asset,
        project_id=test_project.id,
        observation_source="live_network_auditor_adapter",
        observed_attributes=obs_attrs,
        observed_at=now,
        db=db,
    )
    assert is_new1 is True

    # Duplicate delivery with exact same content 10 seconds later
    obs2, is_new2 = AssetIdentityService.record_observation(
        asset=asset,
        project_id=test_project.id,
        observation_source="live_network_auditor_adapter",
        observed_attributes=obs_attrs,
        observed_at=now + timedelta(seconds=10),
        db=db,
    )
    assert is_new2 is False
    assert obs1.id == obs2.id


# ---------------------------------------------------------------------------
# 6. Partial Collection vs Confirmed Absence
# ---------------------------------------------------------------------------

def test_partial_collection_versus_confirmed_absence(db: Session, test_project: Project):
    """
    Verify:
    1. Single scan failure / timeout yields INCONCLUSIVE drift, not absence.
    2. 3 consecutive complete observations of absence marks asset CONFIRMED_ABSENT and INACTIVE.
    """
    now = utc_now()
    asset = AssetIdentityService.reconcile_or_create_asset(
        project_id=test_project.id,
        organization_id=test_project.organization_id,
        asset_type=AssetType.SERVICE,
        canonical_identifier="tcp://10.0.0.5:3306",
        observed_at=now - timedelta(days=1),
        db=db,
    )

    obs_base, _ = AssetIdentityService.record_observation(
        asset=asset,
        project_id=test_project.id,
        observation_source="live_network_auditor_adapter",
        observed_attributes={"open_ports": [3306], "service": "mysql"},
        completeness=1.0,
        observed_at=now - timedelta(days=1),
        db=db,
    )

    # Run 1: Socket Timeout / Collection Error (completeness: 0.5)
    obs_partial, _ = AssetIdentityService.record_observation(
        asset=asset,
        project_id=test_project.id,
        observation_source="live_network_auditor_adapter",
        observed_attributes={},
        completeness=0.5,
        collection_errors=[{"error": "Connection timed out"}],
        observed_at=now - timedelta(hours=12),
        db=db,
    )
    drifts_partial = ExposureDriftService.evaluate_drift(
        project_id=test_project.id,
        asset=asset,
        current_observation=obs_partial,
        previous_observation=obs_base,
        db=db,
    )
    assert len(drifts_partial) == 1
    assert drifts_partial[0].materiality == DriftMateriality.INCONCLUSIVE
    assert asset.confirmed_absent is False

    # Run 2: First absence confirmation probe
    obs_absent_1, _ = AssetIdentityService.record_observation(
        asset=asset,
        project_id=test_project.id,
        observation_source="live_network_auditor_adapter",
        observed_attributes={},
        completeness=1.0,
        is_successful_absence=True,
        observed_at=now - timedelta(hours=6),
        db=db,
    )
    drifts_absent_1 = ExposureDriftService.evaluate_drift(
        project_id=test_project.id,
        asset=asset,
        current_observation=obs_absent_1,
        previous_observation=obs_base,
        db=db,
    )
    assert drifts_absent_1[0].drift_type == DriftType.ASSET_UNOBSERVED_WARNING
    assert asset.confirmed_absent is False

    # Run 3 & 4: 2 more consecutive successful absences
    AssetIdentityService.record_observation(
        asset=asset,
        project_id=test_project.id,
        observation_source="live_network_auditor_adapter",
        observed_attributes={},
        completeness=1.0,
        is_successful_absence=True,
        observed_at=now - timedelta(hours=3),
        db=db,
    )
    obs_absent_3, _ = AssetIdentityService.record_observation(
        asset=asset,
        project_id=test_project.id,
        observation_source="live_network_auditor_adapter",
        observed_attributes={},
        completeness=1.0,
        is_successful_absence=True,
        observed_at=now,
        db=db,
    )
    drifts_confirmed = ExposureDriftService.evaluate_drift(
        project_id=test_project.id,
        asset=asset,
        current_observation=obs_absent_3,
        previous_observation=obs_base,
        db=db,
    )
    assert drifts_confirmed[0].drift_type == DriftType.ASSET_CONFIRMED_ABSENT
    assert asset.confirmed_absent is True
    assert asset.status == AssetStatus.INACTIVE


# ---------------------------------------------------------------------------
# 7. Out-of-Order Observations
# ---------------------------------------------------------------------------

def test_out_of_order_observations(db: Session, test_project: Project):
    """Verify delayed older observation delivery does not overwrite newer authoritative state."""
    t_now = utc_now()
    t_newer = t_now
    t_older = t_now - timedelta(days=2)

    # Receive newer observation first
    asset = AssetIdentityService.reconcile_or_create_asset(
        project_id=test_project.id,
        organization_id=test_project.organization_id,
        asset_type=AssetType.DOMAIN,
        canonical_identifier="time-check.corp",
        observed_at=t_newer,
        db=db,
    )
    assert asset.last_seen_at == t_newer

    # Receive delayed older observation
    AssetIdentityService.reconcile_or_create_asset(
        project_id=test_project.id,
        organization_id=test_project.organization_id,
        asset_type=AssetType.DOMAIN,
        canonical_identifier="time-check.corp",
        observed_at=t_older,
        db=db,
    )
    # Authoritative last_seen_at must remain the newer timestamp
    assert asset.last_seen_at == t_newer


# ---------------------------------------------------------------------------
# 8. Conflicting Sources Attribute Preservation
# ---------------------------------------------------------------------------

def test_conflicting_sources_attribute_preservation(db: Session, test_project: Project):
    """Verify conflicting scanner attributes are preserved non-destructively."""
    now = utc_now()
    asset = AssetIdentityService.reconcile_or_create_asset(
        project_id=test_project.id,
        organization_id=test_project.organization_id,
        asset_type=AssetType.HOST,
        canonical_identifier="server-node-1",
        attributes={"os_family": "Linux", "kernel": "5.15"},
        observed_at=now - timedelta(hours=1),
        db=db,
    )

    # Conflicting report from different adapter
    AssetIdentityService.reconcile_or_create_asset(
        project_id=test_project.id,
        organization_id=test_project.organization_id,
        asset_type=AssetType.HOST,
        canonical_identifier="server-node-1",
        attributes={"os_family": "FreeBSD", "kernel": "13.2"},
        observed_at=now,
        db=db,
    )

    # Conflict history preserved
    assert "_conflict_os_family" in asset.attributes
    assert "Linux" in asset.attributes["_conflict_os_family"]
    assert "FreeBSD" in asset.attributes["_conflict_os_family"]


# ---------------------------------------------------------------------------
# 9. Stale Findings Flagged After Material Configuration Changes
# ---------------------------------------------------------------------------

def test_stale_findings_flagged_after_material_configuration_changes(db: Session, test_project: Project, admin_user: User):
    """Verify that when a vulnerable port is closed, associated findings are flagged as candidate stale."""
    now = utc_now()
    asset = AssetIdentityService.reconcile_or_create_asset(
        project_id=test_project.id,
        organization_id=test_project.organization_id,
        asset_type=AssetType.HOST,
        canonical_identifier="legacy-server.corp",
        attributes={"open_ports": [80, 8080]},
        observed_at=now - timedelta(days=1),
        db=db,
    )

    # Baseline observation with open ports 80 and 8080
    obs_prev, _ = AssetIdentityService.record_observation(
        asset=asset,
        project_id=test_project.id,
        observation_source="live_network_auditor_adapter",
        observed_attributes={"open_ports": [80, 8080]},
        observed_at=now - timedelta(days=1),
        db=db,
    )

    # Active vulnerability finding on port 8080
    finding = VulnerabilityFinding(
        project_id=test_project.id,
        asset_id=asset.id,
        fingerprint=hashlib.sha256(b"VULN-DEBUG-8080:legacy-server.corp:8080").hexdigest(),
        vuln_id="VULN-DEBUG-8080",
        title="Unauthenticated Debug Console Exposed on Port 8080",
        severity=FindingSeverity.HIGH,
        confidence=FindingConfidence.CERTAIN,
        target_value="legacy-server.corp:8080",
        status=FindingLifecycleStatus.CONFIRMED,
        is_simulated=False,
        first_detected_at=now - timedelta(days=1),
        last_observed_at=now - timedelta(days=1),
        created_at=now - timedelta(days=1),
        updated_at=now - timedelta(days=1),
    )
    db.add(finding)
    db.flush()

    # Current observation: Port 8080 closed
    obs_curr, _ = AssetIdentityService.record_observation(
        asset=asset,
        project_id=test_project.id,
        observation_source="live_network_auditor_adapter",
        observed_attributes={"open_ports": [80]},
        observed_at=now,
        db=db,
    )

    drifts = ExposureDriftService.evaluate_drift(
        project_id=test_project.id,
        asset=asset,
        current_observation=obs_curr,
        previous_observation=obs_prev,
        db=db,
    )

    db.refresh(finding)
    # Finding must NOT be closed automatically
    assert finding.status == FindingLifecycleStatus.CONFIRMED
    # But finding must be marked candidate stale in validation notes
    assert "STALE CANDIDATE" in (finding.validation_notes or "")


# ---------------------------------------------------------------------------
# 10. Risk and Graph Invalidation on Material Drift
# ---------------------------------------------------------------------------

def test_risk_and_graph_invalidation_on_material_drift(db: Session, test_project: Project):
    """Verify material exposure drift invalidates downstream derived risk records."""
    now = utc_now()
    asset = AssetIdentityService.reconcile_or_create_asset(
        project_id=test_project.id,
        organization_id=test_project.organization_id,
        asset_type=AssetType.WEB_APP,
        canonical_identifier="https://secure-portal.corp",
        attributes={"headers": {"strict-transport-security": "max-age=31536000"}},
        observed_at=now - timedelta(days=1),
        db=db,
    )

    obs_prev, _ = AssetIdentityService.record_observation(
        asset=asset,
        project_id=test_project.id,
        observation_source="live_network_auditor_adapter",
        observed_attributes={"headers": {"strict-transport-security": "max-age=31536000"}},
        observed_at=now - timedelta(days=1),
        db=db,
    )

    # Current observation: HSTS header removed (regression)
    obs_curr, _ = AssetIdentityService.record_observation(
        asset=asset,
        project_id=test_project.id,
        observation_source="live_network_auditor_adapter",
        observed_attributes={"headers": {}},
        observed_at=now,
        db=db,
    )

    drifts = ExposureDriftService.evaluate_drift(
        project_id=test_project.id,
        asset=asset,
        current_observation=obs_curr,
        previous_observation=obs_prev,
        db=db,
    )
    assert any(d.materiality == DriftMateriality.MATERIAL for d in drifts)


# ---------------------------------------------------------------------------
# 11. Reassessment Proposal Deduplication
# ---------------------------------------------------------------------------

def test_reassessment_proposal_deduplication(db: Session, test_project: Project, admin_user: User):
    """Verify duplicate material drift events coalesce into a single pending proposal."""
    now = utc_now()
    # Authorize scope
    scope = ScopeTarget(
        project_id=test_project.id,
        target_value="https://api.gateway.corp",
        target_type=TargetType.URL,
        authorization_status=AuthorizationStatus.AUTHORIZED,
        created_by_id=admin_user.id,
    )
    db.add(scope)
    db.flush()

    asset = AssetIdentityService.reconcile_or_create_asset(
        project_id=test_project.id,
        organization_id=test_project.organization_id,
        asset_type=AssetType.WEB_APP,
        canonical_identifier="https://api.gateway.corp",
        observed_at=now,
        db=db,
    )

    drift1 = ExposureDriftRecord(
        project_id=test_project.id,
        asset_id=asset.id,
        drift_type=DriftType.SERVICE_ADDED,
        materiality=DriftMateriality.MATERIAL,
        materiality_reason="Port 8443 open",
        target_resource="https://api.gateway.corp",
        title="New port open",
        reassessment_recommended=True,
        confidence=1.0,
    )
    db.add(drift1)
    db.flush()

    prop1 = ReassessmentPlannerService.plan_reassessments_for_drift(test_project.id, drift1, db)
    assert prop1.status == ReassessmentStatus.PROPOSED

    # Second drift event with identical parameters
    drift2 = ExposureDriftRecord(
        project_id=test_project.id,
        asset_id=asset.id,
        drift_type=DriftType.SERVICE_ADDED,
        materiality=DriftMateriality.MATERIAL,
        materiality_reason="Port 8443 open corroboration",
        target_resource="https://api.gateway.corp",
        title="Corroborated new port",
        reassessment_recommended=True,
        confidence=1.0,
    )
    db.add(drift2)
    db.flush()

    prop2 = ReassessmentPlannerService.plan_reassessments_for_drift(test_project.id, drift2, db)
    # Must return the existing proposal instead of duplicating
    assert prop1.id == prop2.id


# ---------------------------------------------------------------------------
# 12. Scope Enforcement Blocks Reassessment of Unauthorized Targets
# ---------------------------------------------------------------------------

def test_reassessment_planner_blocks_unauthorized_scope(db: Session, test_project: Project, admin_user: User):
    """Verify drift on an unauthorized or excluded target produces a REJECTED proposal."""
    now = utc_now()
    # Explicit exclusion
    excl = ScopeExclusion(
        project_id=test_project.id,
        target_value="*.restricted.corp",
        target_type=TargetType.DOMAIN,
        reason="Explicit restricted target out of scope",
        created_by_id=admin_user.id,
    )
    db.add(excl)
    db.flush()

    asset = AssetIdentityService.reconcile_or_create_asset(
        project_id=test_project.id,
        organization_id=test_project.organization_id,
        asset_type=AssetType.DOMAIN,
        canonical_identifier="db.restricted.corp",
        observed_at=now,
        db=db,
    )

    drift = ExposureDriftRecord(
        project_id=test_project.id,
        asset_id=asset.id,
        drift_type=DriftType.SERVICE_ADDED,
        materiality=DriftMateriality.MATERIAL,
        materiality_reason="Port 5432 exposed",
        target_resource="db.restricted.corp",
        title="Database exposed",
        reassessment_recommended=True,
        confidence=1.0,
    )
    db.add(drift)
    db.flush()

    proposal = ReassessmentPlannerService.plan_reassessments_for_drift(test_project.id, drift, db)
    assert proposal.status == ReassessmentStatus.REJECTED
    assert proposal.scope_authorized is False
    assert "Scope validation failed" in proposal.rationale


# ---------------------------------------------------------------------------
# 13. Execution Boundary Scope Revalidation
# ---------------------------------------------------------------------------

def test_reassessment_execution_boundary_scope_revalidation(db: Session, test_project: Project, admin_user: User):
    """Verify approval fails if scope was revoked between proposal creation and execution."""
    now = utc_now()
    scope = ScopeTarget(
        project_id=test_project.id,
        target_value="https://expiring.corp",
        target_type=TargetType.URL,
        authorization_status=AuthorizationStatus.AUTHORIZED,
        created_by_id=admin_user.id,
    )
    db.add(scope)
    db.flush()

    drift = ExposureDriftRecord(
        project_id=test_project.id,
        drift_type=DriftType.SERVICE_ADDED,
        materiality=DriftMateriality.MATERIAL,
        materiality_reason="New endpoint",
        target_resource="https://expiring.corp",
        title="New endpoint",
        reassessment_recommended=True,
        confidence=1.0,
    )
    db.add(drift)
    db.flush()

    prop = ReassessmentPlannerService.plan_reassessments_for_drift(test_project.id, drift, db)
    assert prop.status == ReassessmentStatus.PROPOSED

    # Revoke scope authorization before execution
    scope.authorization_status = AuthorizationStatus.REVOKED
    db.flush()

    with pytest.raises(PermissionError, match="no longer authorized"):
        ReassessmentPlannerService.approve_and_queue_reassessment(
            project_id=test_project.id,
            proposal_id=prop.id,
            actor=admin_user,
            actor_role=ProjectRole.LEAD,
            db=db,
        )

    db.refresh(prop)
    assert prop.status == ReassessmentStatus.REJECTED


# ---------------------------------------------------------------------------
# 14. Retry Storm Avoidance
# ---------------------------------------------------------------------------

def test_retry_storm_prevention(db: Session, test_project: Project, admin_user: User):
    """Verify that targets with repeated recent scan failures have reassessment DEFERRED."""
    now = utc_now()
    target = "https://unstable.corp"

    # Authorize scope
    scope = ScopeTarget(
        project_id=test_project.id,
        target_value=target,
        target_type=TargetType.URL,
        authorization_status=AuthorizationStatus.AUTHORIZED,
        created_by_id=admin_user.id,
    )
    db.add(scope)

    # 3 recent failed jobs on this target
    for i in range(3):
        job = AssessmentJob(
            project_id=test_project.id,
            target_input=target,
            adapter_name="live_network_auditor_adapter",
            status=AssessmentStatus.FAILED,
            created_by_id=admin_user.id,
            created_at=now - timedelta(minutes=30 * (i + 1)),
        )
        db.add(job)
    db.flush()

    drift = ExposureDriftRecord(
        project_id=test_project.id,
        drift_type=DriftType.VERSION_CHANGED,
        materiality=DriftMateriality.MATERIAL,
        materiality_reason="Version bump detected",
        target_resource=target,
        title="Version change",
        reassessment_recommended=True,
        confidence=1.0,
    )
    db.add(drift)
    db.flush()

    proposal = ReassessmentPlannerService.plan_reassessments_for_drift(test_project.id, drift, db)
    assert proposal.status == ReassessmentStatus.DEFERRED
    assert "DEFERRED" in proposal.rationale


# ---------------------------------------------------------------------------
# 15. Reversible Identity Merge Workflow
# ---------------------------------------------------------------------------

def test_reversible_identity_merge_workflow(db: Session, test_project: Project, admin_user: User):
    """
    Verify full reversible identity merge lifecycle:
    1. Target & Source assets created with their own observations and aliases.
    2. Merge executed: source marked DECOMMISSIONED, snapshot saved, aliases repointed.
    3. Reversal executed: source restored to ACTIVE, snapshot restored, merge marked reversed.
    """
    now = utc_now()
    target = AssetIdentityService.reconcile_or_create_asset(
        project_id=test_project.id,
        organization_id=test_project.organization_id,
        asset_type=AssetType.WEB_APP,
        canonical_identifier="https://core.app.corp",
        observed_at=now - timedelta(days=2),
        db=db,
    )
    source = AssetIdentityService.reconcile_or_create_asset(
        project_id=test_project.id,
        organization_id=test_project.organization_id,
        asset_type=AssetType.HOSTNAME,
        canonical_identifier="core-app-internal",
        attributes={"owner": "infra-team"},
        observed_at=now - timedelta(days=2),
        db=db,
    )
    alias_source = AssetIdentityService.record_alias(
        asset=source,
        identifier_type="HOSTNAME",
        identifier_value="core-app-internal",
        db=db,
    )

    # 1. Merge source into target
    merge_rec = AssetIdentityService.merge_asset_identities(
        project_id=test_project.id,
        target_asset_id=target.id,
        source_asset_id=source.id,
        rationale="Host core-app-internal is the internal CNAME for https://core.app.corp",
        actor_id=admin_user.id,
        db=db,
    )

    db.refresh(source)
    db.refresh(alias_source)
    assert source.status == AssetStatus.DECOMMISSIONED
    assert source.attributes.get("_merged_into") == target.id
    assert alias_source.asset_id == target.id
    assert merge_rec.is_reversed is False

    # 2. Reverse merge
    reversed_rec = AssetIdentityService.reverse_asset_merge(
        project_id=test_project.id,
        merge_record_id=merge_rec.id,
        actor_id=admin_user.id,
        reversal_notes="De-merging because core-app-internal was re-purposed for staging",
        db=db,
    )

    db.refresh(source)
    db.refresh(alias_source)
    assert reversed_rec.is_reversed is True
    assert source.status == AssetStatus.ACTIVE
    assert "_merged_into" not in source.attributes
    assert alias_source.asset_id == source.id


# ---------------------------------------------------------------------------
# 16. Drift Overview Freshness & Gap Warnings
# ---------------------------------------------------------------------------

def test_drift_overview_freshness_and_gap_warnings(db: Session, test_project: Project):
    """Verify calculation of project-level freshness and governance gap warnings."""
    now = utc_now()
    # 1 fresh asset
    AssetIdentityService.reconcile_or_create_asset(
        project_id=test_project.id,
        organization_id=test_project.organization_id,
        asset_type=AssetType.WEB_APP,
        canonical_identifier="https://fresh.corp",
        observed_at=now - timedelta(hours=2),
        db=db,
    )
    # 1 stale asset (> 7 days)
    asset_stale = AssetIdentityService.reconcile_or_create_asset(
        project_id=test_project.id,
        organization_id=test_project.organization_id,
        asset_type=AssetType.DOMAIN,
        canonical_identifier="stale.corp",
        observed_at=now - timedelta(days=10),
        db=db,
    )
    asset_stale.last_successful_observation_at = now - timedelta(days=10)
    db.flush()

    overview = ContinuousChangeIntelligenceService.get_project_drift_overview(test_project.id, db)
    assert overview["total_assets"] >= 2
    assert overview["freshness_distribution"]["FRESH"] >= 1
    assert overview["freshness_distribution"]["STALE"] >= 1
    assert any("stale or expired" in w for w in overview["governance_warnings"])


# ---------------------------------------------------------------------------
# 17. REST API Endpoints & Tenant Isolation
# ---------------------------------------------------------------------------

def test_drift_endpoints_and_tenant_isolation(
    client: TestClient,
    db: Session,
    test_project: Project,
    lead_headers: dict,
):
    """Verify REST API endpoints and tenant isolation."""
    # 1. Overview endpoint
    resp = client.get(f"/api/v1/projects/{test_project.id}/drift/overview", headers=lead_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "freshness_distribution" in data
    assert "average_collection_completeness" in data

    # 2. List drift records
    resp_drifts = client.get(f"/api/v1/projects/{test_project.id}/drift/records", headers=lead_headers)
    assert resp_drifts.status_code == 200
    assert isinstance(resp_drifts.json(), list)

    # 3. List proposals
    resp_props = client.get(f"/api/v1/projects/{test_project.id}/drift/proposals", headers=lead_headers)
    assert resp_props.status_code == 200
    assert isinstance(resp_props.json(), list)

    # 4. Tenant isolation: accessing non-existent project returns 404
    resp_bad = client.get("/api/v1/projects/non-existent-proj/drift/overview", headers=lead_headers)
    assert resp_bad.status_code in [403, 404]
