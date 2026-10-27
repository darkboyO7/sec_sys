import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from app.models.project import Project, ProjectMember, ProjectRole
from app.models.user import User, SystemRole
from app.models.scope import ScopeTarget, TargetType, AuthorizationStatus

def test_digital_twin_snapshot_accepts_name_and_label(
    client: TestClient,
    lead_headers: dict,
    test_project: Project,
):
    # Test with "name" field (what frontend previously sent)
    resp = client.post(
        f"/api/v1/projects/{test_project.id}/digital-twin/snapshots",
        json={"name": "Baseline Test Snapshot", "description": "Verification snapshot"},
        headers=lead_headers,
    )
    assert resp.status_code == 201, f"Failed with name: {resp.text}"
    data = resp.json()
    assert data["snapshot_label"] == "Baseline Test Snapshot"

    # Test with "snapshot_label" field (standard schema)
    resp2 = client.post(
        f"/api/v1/projects/{test_project.id}/digital-twin/snapshots",
        json={"snapshot_label": "Secondary Test Snapshot"},
        headers=lead_headers,
    )
    assert resp2.status_code == 201, f"Failed with snapshot_label: {resp2.text}"
    assert resp2.json()["snapshot_label"] == "Secondary Test Snapshot"


def test_attack_paths_accepts_empty_and_omitted_body(
    client: TestClient,
    lead_headers: dict,
    test_project: Project,
):
    # Test with empty body (json={})
    resp = client.post(
        f"/api/v1/projects/{test_project.id}/risk/attack-paths",
        json={},
        headers=lead_headers,
    )
    assert resp.status_code == 200, f"Failed with empty body: {resp.text}"
    assert "paths" in resp.json()

    # Test with omitted body
    resp2 = client.post(
        f"/api/v1/projects/{test_project.id}/risk/attack-paths",
        headers=lead_headers,
    )
    assert resp2.status_code == 200, f"Failed with omitted body: {resp2.text}"
    assert "paths" in resp2.json()


def test_scope_validation_contract_and_boundary(
    client: TestClient,
    lead_headers: dict,
    lead_user: User,
    test_project: Project,
    db: Session,
):
    # Register and authorize a target
    t = ScopeTarget(
        project_id=test_project.id,
        target_type=TargetType.IP_ADDRESS,
        target_value="172.16.0.50",
        description="Internal Service",
        authorization_status=AuthorizationStatus.AUTHORIZED,
        authorization_evidence="Signed Charter #ROE-100",
        created_by_id=lead_user.id,
    )
    db.add(t)
    db.commit()

    resp = client.post(
        f"/api/v1/projects/{test_project.id}/validate",
        json={"target": "172.16.0.50"},
        headers=lead_headers,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["is_authorized"] is True
    assert data["status"] == "AUTHORIZED"
