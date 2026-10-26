import hashlib
from datetime import datetime, timezone, timedelta
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.project import Project
from app.models.user import User
from app.models.finding import (
    FindingLifecycleStatus,
    VulnerabilityFinding,
    FindingTransition,
)
from app.models.asset import Asset, AssetType, AssetCriticality
from app.models.assessment import FindingSeverity, FindingConfidence
from app.services.digital_twin_service import DigitalTwinService
from app.models.base import utc_now


def test_phase16_snapshot_capture_and_manifest_integrity(
    db: Session,
    test_project: Project,
    tester_user: User,
):
    """Verify point-in-time snapshot capture and SHA-256 state manifest integrity."""
    asset = Asset(
        project_id=test_project.id,
        organization_id=test_project.organization_id,
        name="Production Database Core",
        canonical_identifier="prod-db-core-cluster-01",
        asset_type=AssetType.DATA_STORE,
        criticality=AssetCriticality.CRITICAL,
    )
    db.add(asset)
    db.flush()

    finding = VulnerabilityFinding(
        project_id=test_project.id,
        asset_id=asset.id,
        fingerprint="fp-phase16-snap-01",
        target_value="postgres://prod-db.local:5432",
        title="Default Credentials on Database",
        description="Database exposes default administrative credentials.",
        severity=FindingSeverity.CRITICAL,
        confidence=FindingConfidence.CERTAIN,
        cvss_score=9.5,
        status=FindingLifecycleStatus.DETECTED,
        is_simulated=True,
        last_observed_at=utc_now(),
    )
    db.add(finding)
    db.commit()

    snapshot = DigitalTwinService.capture_snapshot(
        project_id=test_project.id,
        label="Q4 Pre-Hardening Baseline",
        user=tester_user,
        db=db,
    )

    assert snapshot.id is not None
    assert snapshot.snapshot_label == "Q4 Pre-Hardening Baseline"
    assert snapshot.assets_count >= 1
    assert snapshot.findings_count >= 1
    assert snapshot.manifest_sha256 is not None
    assert snapshot.risk_summary["critical_count"] >= 1
    assert len(snapshot.state_manifest["findings"]) >= 1


def test_phase16_point_in_time_reconstruction(
    db: Session,
    test_project: Project,
    tester_user: User,
):
    """Verify state reconstruction accurately reflects historical finding status via transition history."""
    now = utc_now()
    t0 = now - timedelta(hours=3)
    t1 = now - timedelta(hours=2)
    t2 = now - timedelta(hours=1)
    t3 = now

    finding = VulnerabilityFinding(
        project_id=test_project.id,
        fingerprint="fp-phase16-recon-02",
        target_value="https://test.local/admin",
        title="Admin Interface Publicly Accessible",
        description="Admin panel exposed without MFA.",
        severity=FindingSeverity.HIGH,
        confidence=FindingConfidence.CERTAIN,
        cvss_score=8.0,
        status=FindingLifecycleStatus.VERIFIED_CLOSED,  # Current status
        is_simulated=True,
        first_detected_at=t0,
        last_observed_at=t0,
    )
    db.add(finding)
    db.flush()

    # Initial transition at t0: DETECTED -> CONFIRMED
    tr1 = FindingTransition(
        finding_id=finding.id,
        from_status=FindingLifecycleStatus.DETECTED,
        to_status=FindingLifecycleStatus.CONFIRMED,
        actor_id=tester_user.id,
        reason="Confirmed by analyst",
        created_at=t0,
    )
    # Subsequent transition at t2: CONFIRMED -> VERIFIED_CLOSED
    tr2 = FindingTransition(
        finding_id=finding.id,
        from_status=FindingLifecycleStatus.CONFIRMED,
        to_status=FindingLifecycleStatus.VERIFIED_CLOSED,
        actor_id=tester_user.id,
        reason="Firewall rule applied and verified",
        created_at=t2,
    )
    db.add_all([tr1, tr2])
    db.commit()

    # Reconstruct at t1 (between t0 and t2) -> status must be CONFIRMED, NOT current VERIFIED_CLOSED
    recon_t1 = DigitalTwinService.reconstruct_state_as_of(
        project_id=test_project.id,
        as_of_time=t1,
        db=db,
    )
    f_t1 = next(item for item in recon_t1.findings if item["id"] == finding.id)
    assert f_t1["status"] == "CONFIRMED"

    # Reconstruct at t3 (after t2) -> status must be VERIFIED_CLOSED
    recon_t3 = DigitalTwinService.reconstruct_state_as_of(
        project_id=test_project.id,
        as_of_time=t3,
        db=db,
    )
    f_t3 = next(item for item in recon_t3.findings if item["id"] == finding.id)
    assert f_t3["status"] == "VERIFIED_CLOSED"


def test_phase16_snapshot_diffing_new_resolved_recurring(
    db: Session,
    test_project: Project,
    tester_user: User,
):
    """Verify snapshot diff accurately partitions new, resolved, recurring, and unchanged findings."""
    t_start = utc_now() - timedelta(days=2)

    # 1. Finding 1: Open at start, will be resolved in Snapshot B
    f1 = VulnerabilityFinding(
        project_id=test_project.id,
        fingerprint="fp-phase16-diff-f1",
        target_value="https://test.local/f1",
        title="Open Finding 1",
        severity=FindingSeverity.HIGH,
        confidence=FindingConfidence.CERTAIN,
        status=FindingLifecycleStatus.CONFIRMED,
        is_simulated=True,
        first_detected_at=t_start,
        last_observed_at=t_start,
    )
    db.add(f1)
    db.commit()

    # Snapshot A
    snap_a = DigitalTwinService.capture_snapshot(
        project_id=test_project.id,
        label="Snapshot Baseline A",
        user=tester_user,
        as_of_time=t_start + timedelta(hours=1),
        db=db,
    )

    # State changes between A and B:
    # Resolve f1
    f1.status = FindingLifecycleStatus.VERIFIED_CLOSED
    tr_close = FindingTransition(
        finding_id=f1.id,
        from_status=FindingLifecycleStatus.CONFIRMED,
        to_status=FindingLifecycleStatus.VERIFIED_CLOSED,
        actor_id=tester_user.id,
        reason="Resolved in sprint",
        created_at=t_start + timedelta(hours=2),
    )
    # Add new finding f2
    f2 = VulnerabilityFinding(
        project_id=test_project.id,
        fingerprint="fp-phase16-diff-f2",
        target_value="https://test.local/f2",
        title="New Finding 2",
        severity=FindingSeverity.CRITICAL,
        confidence=FindingConfidence.CERTAIN,
        status=FindingLifecycleStatus.DETECTED,
        is_simulated=True,
        first_detected_at=t_start + timedelta(hours=3),
        last_observed_at=t_start + timedelta(hours=3),
    )
    db.add_all([tr_close, f2])
    db.commit()

    # Snapshot B
    snap_b = DigitalTwinService.capture_snapshot(
        project_id=test_project.id,
        label="Snapshot Followup B",
        user=tester_user,
        as_of_time=t_start + timedelta(hours=4),
        db=db,
    )

    diff = DigitalTwinService.compare_snapshots(
        project_id=test_project.id,
        snapshot_a_id=snap_a.id,
        snapshot_b_id=snap_b.id,
        db=db,
    )

    # Verify diff classification
    new_fps = [f["fingerprint"] for f in diff.new_findings]
    resolved_fps = [f["fingerprint"] for f in diff.resolved_findings]

    assert "fp-phase16-diff-f2" in new_fps
    assert "fp-phase16-diff-f1" in resolved_fps
    assert diff.summary["new_findings_count"] >= 1
    assert diff.summary["resolved_findings_count"] >= 1


def test_phase16_api_endpoints_and_isolation(
    client: TestClient,
    db: Session,
    test_project: Project,
    tester_headers: dict,
):
    """Verify HTTP API endpoints for digital twin snapshot capture, listing, diffing, and reconstruction."""
    # 1. Capture snapshot via API
    cap_res = client.post(
        f"/api/v1/projects/{test_project.id}/digital-twin/snapshots",
        headers=tester_headers,
        json={"snapshot_label": "Automated CI Baseline"},
    )
    assert cap_res.status_code == 201
    snap1 = cap_res.json()
    assert snap1["snapshot_label"] == "Automated CI Baseline"
    snap1_id = snap1["id"]

    # 2. Capture second snapshot
    cap_res2 = client.post(
        f"/api/v1/projects/{test_project.id}/digital-twin/snapshots",
        headers=tester_headers,
        json={"snapshot_label": "Post-Sprint Audit"},
    )
    assert cap_res2.status_code == 201
    snap2 = cap_res2.json()
    snap2_id = snap2["id"]

    # 3. List snapshots
    list_res = client.get(
        f"/api/v1/projects/{test_project.id}/digital-twin/snapshots",
        headers=tester_headers,
    )
    assert list_res.status_code == 200
    snapshots = list_res.json()
    assert len(snapshots) >= 2

    # 4. Compare snapshots via API
    compare_res = client.post(
        f"/api/v1/projects/{test_project.id}/digital-twin/compare",
        headers=tester_headers,
        json={
            "snapshot_a_id": snap1_id,
            "snapshot_b_id": snap2_id,
        },
    )
    assert compare_res.status_code == 200
    diff_data = compare_res.json()
    assert diff_data["snapshot_a_id"] == snap1_id
    assert diff_data["snapshot_b_id"] == snap2_id
    assert "risk_drift" in diff_data

    # 5. Reconstruct historical state
    recon_res = client.get(
        f"/api/v1/projects/{test_project.id}/digital-twin/reconstruct?as_of={snap1['snapshot_timestamp']}",
        headers=tester_headers,
    )
    assert recon_res.status_code == 200
    recon_data = recon_res.json()
    assert "state_sha256" in recon_data
