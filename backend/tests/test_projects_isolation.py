from fastapi.testclient import TestClient
from app.models.project import Project


def test_project_creation_and_membership(client: TestClient, tester_headers: dict):
    payload = {
        "name": "Project Blackbox",
        "description": "External edge infrastructure test"
    }
    response = client.post("/api/v1/projects/", json=payload, headers=tester_headers)
    assert response.status_code == 201
    data = response.json()
    assert data["name"] == "Project Blackbox"
    assert data["member_count"] == 1


def test_project_isolation_outsider_denied(
    client: TestClient,
    test_project: Project,
    outsider_headers: dict,
    tester_headers: dict,
    admin_headers: dict,
):
    # Assigned tester can view project
    res_tester = client.get(f"/api/v1/projects/{test_project.id}", headers=tester_headers)
    assert res_tester.status_code == 200
    assert res_tester.json()["id"] == test_project.id

    # Admin can view project
    res_admin = client.get(f"/api/v1/projects/{test_project.id}", headers=admin_headers)
    assert res_admin.status_code == 200

    # Unassigned outsider is denied and receives 404 (failing closed without leaking project existence)
    res_outsider = client.get(f"/api/v1/projects/{test_project.id}", headers=outsider_headers)
    assert res_outsider.status_code == 404
    assert res_outsider.json()["detail"] == "Project not found"

    # Outsider cannot register targets in unauthorized project
    target_payload = {"target_value": "192.168.10.5", "description": "Illegal injection"}
    res_inject = client.post(
        f"/api/v1/projects/{test_project.id}/targets",
        json=target_payload,
        headers=outsider_headers,
    )
    assert res_inject.status_code == 404


def test_project_listing_respects_membership(
    client: TestClient,
    test_project: Project,
    outsider_headers: dict,
    tester_headers: dict,
    admin_headers: dict,
):
    # Outsider sees empty list
    res_outsider = client.get("/api/v1/projects/", headers=outsider_headers)
    assert res_outsider.status_code == 200
    project_ids = [p["id"] for p in res_outsider.json()]
    assert test_project.id not in project_ids

    # Tester sees test_project
    res_tester = client.get("/api/v1/projects/", headers=tester_headers)
    assert res_tester.status_code == 200
    tester_ids = [p["id"] for p in res_tester.json()]
    assert test_project.id in tester_ids
