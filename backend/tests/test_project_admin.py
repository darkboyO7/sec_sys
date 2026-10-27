import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from app.models.user import User, SystemRole
from app.models.project import Project, ProjectMember, ProjectRole
from app.core.security import hash_password


def test_list_organization_users(client: TestClient, db: Session, lead_user: User, lead_headers: dict):
    # Add a second active user
    u2 = User(
        email="auditor.bob@vapt.corp",
        full_name="Bob Auditor",
        hashed_password=hash_password("BobSecurePass2026!"),
        system_role=SystemRole.AUDITOR,
        is_active=True,
    )
    db.add(u2)
    db.commit()

    resp = client.get("/api/v1/auth/users", headers=lead_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) >= 2
    emails = [u["email"] for u in data]
    assert lead_user.email in emails
    assert "auditor.bob@vapt.corp" in emails


def test_update_project_metadata(client: TestClient, db: Session, lead_headers: dict, test_project: Project):
    update_payload = {
        "name": "Updated Enterprise Shield Project",
        "description": "Comprehensive hardened assessment workspace",
        "is_active": True,
    }

    resp = client.put(f"/api/v1/projects/{test_project.id}", json=update_payload, headers=lead_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["name"] == "Updated Enterprise Shield Project"
    assert data["description"] == "Comprehensive hardened assessment workspace"

    # Verify persisted in database
    db.refresh(test_project)
    assert test_project.name == "Updated Enterprise Shield Project"


def test_project_member_lifecycle(client: TestClient, db: Session, lead_headers: dict, test_project: Project):
    # Create target user to add as member
    target_user = User(
        email="tester.alice@vapt.corp",
        full_name="Alice Tester",
        hashed_password=hash_password("AliceSecurePass2026!"),
        system_role=SystemRole.SECURITY_TESTER,
        is_active=True,
    )
    db.add(target_user)
    db.commit()

    # 1. Add member
    add_resp = client.post(
        f"/api/v1/projects/{test_project.id}/members",
        json={"user_id": target_user.id, "role": "TESTER"},
        headers=lead_headers,
    )
    assert add_resp.status_code == 201
    add_data = add_resp.json()
    assert add_data["user_email"] == "tester.alice@vapt.corp"
    assert add_data["role"] == "TESTER"

    # 2. List members
    list_resp = client.get(f"/api/v1/projects/{test_project.id}/members", headers=lead_headers)
    assert list_resp.status_code == 200
    members = list_resp.json()
    assert any(m["user_id"] == target_user.id for m in members)

    # 3. Update member role to AUDITOR
    update_role_resp = client.put(
        f"/api/v1/projects/{test_project.id}/members/{target_user.id}",
        json={"user_id": target_user.id, "role": "AUDITOR"},
        headers=lead_headers,
    )
    assert update_role_resp.status_code == 200
    assert update_role_resp.json()["role"] == "AUDITOR"

    # 4. Remove member
    del_resp = client.delete(
        f"/api/v1/projects/{test_project.id}/members/{target_user.id}",
        headers=lead_headers,
    )
    assert del_resp.status_code == 204

    # 5. Verify member is removed
    post_del_list = client.get(f"/api/v1/projects/{test_project.id}/members", headers=lead_headers)
    assert not any(m["user_id"] == target_user.id for m in post_del_list.json())


def test_cannot_remove_last_project_lead(client: TestClient, db: Session, lead_user: User, lead_headers: dict, test_project: Project):
    # Ensure lead_user is the ONLY LEAD
    db.query(ProjectMember).filter(ProjectMember.project_id == test_project.id).delete()
    lead_member = ProjectMember(project_id=test_project.id, user_id=lead_user.id, role=ProjectRole.LEAD)
    db.add(lead_member)
    db.commit()

    del_resp = client.delete(
        f"/api/v1/projects/{test_project.id}/members/{lead_user.id}",
        headers=lead_headers,
    )
    assert del_resp.status_code == 400
    assert "Cannot remove the last project LEAD" in del_resp.json()["detail"]
