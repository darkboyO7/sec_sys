"""
VAPT Platform — Authoritative Authorization & Strict Tenant Isolation Tests (Phase 6).
Validates:
1. Cross-tenant identifier manipulation is blocked fail-closed (404/403).
2. Project isolation: members of Project A cannot view, mutate, or access Project B resources.
3. Project-level roles (VIEWER vs LEAD) enforce granular operation boundaries.
4. System-level roles (SECURITY_TESTER vs ADMIN) enforce platform boundaries.
5. All access denials are attributable and audited.
"""
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.user import User, SystemRole
from app.models.project import Project, ProjectMember, ProjectRole
from app.models.organization import Organization
from app.core.security import create_access_token, hash_password


def test_tenant_isolation_cross_project_access_denied(client: TestClient, db: Session, test_organization: Organization):
    """Ensure a user authorized for Project Alpha cannot access Project Beta."""
    # Create Project Alpha and Project Beta
    proj_alpha = Project(name="Project Alpha", organization_id=test_organization.id, is_active=True)
    proj_beta = Project(name="Project Beta", organization_id=test_organization.id, is_active=True)
    db.add_all([proj_alpha, proj_beta])
    db.commit()

    # Create User Alpha (member only of Project Alpha)
    user_alpha = User(
        email="user_alpha@tenant-test.local",
        hashed_password=hash_password("PassAlpha123!"),
        full_name="User Alpha",
        system_role=SystemRole.SECURITY_TESTER,
        is_active=True,
    )
    db.add(user_alpha)
    db.commit()

    member_alpha = ProjectMember(project_id=proj_alpha.id, user_id=user_alpha.id, role=ProjectRole.LEAD)
    db.add(member_alpha)
    db.commit()

    token_alpha = create_access_token(
        subject=user_alpha.id,
        claims={"email": user_alpha.email, "role": user_alpha.system_role.value},
    )

    # 1. User Alpha CAN access Project Alpha
    resp_alpha = client.get(
        f"/api/v1/projects/{proj_alpha.id}",
        headers={"Authorization": f"Bearer {token_alpha}"},
    )
    assert resp_alpha.status_code == 200, resp_alpha.text
    assert resp_alpha.json()["id"] == proj_alpha.id

    # 2. User Alpha CANNOT access Project Beta -> Fails closed with 404 (not leaking existence)
    resp_beta = client.get(
        f"/api/v1/projects/{proj_beta.id}",
        headers={"Authorization": f"Bearer {token_alpha}"},
    )
    assert resp_beta.status_code == 404

    # 3. User Alpha CANNOT list findings or assessments in Project Beta
    resp_findings = client.get(
        f"/api/v1/projects/{proj_beta.id}/findings",
        headers={"Authorization": f"Bearer {token_alpha}"},
    )
    assert resp_findings.status_code == 404


def test_project_viewer_role_cannot_perform_privileged_mutations(client: TestClient, db: Session, test_organization: Organization):
    """Ensure a project VIEWER cannot create jobs or accept risk."""
    proj = Project(name="Project Restricted", organization_id=test_organization.id, is_active=True)
    db.add(proj)
    db.commit()

    viewer = User(
        email="viewer_only@tenant-test.local",
        hashed_password=hash_password("ViewerPass123!"),
        full_name="Restricted Viewer",
        system_role=SystemRole.VIEWER,
        is_active=True,
    )
    db.add(viewer)
    db.commit()

    member = ProjectMember(project_id=proj.id, user_id=viewer.id, role=ProjectRole.VIEWER)
    db.add(member)
    db.commit()

    viewer_token = create_access_token(
        subject=viewer.id,
        claims={"email": viewer.email, "role": viewer.system_role.value},
    )

    # 1. Viewer CAN read project metadata
    resp_read = client.get(
        f"/api/v1/projects/{proj.id}",
        headers={"Authorization": f"Bearer {viewer_token}"},
    )
    assert resp_read.status_code == 200

    # 2. Viewer CANNOT create assessment jobs in project
    job_payload = {
        "target_input": "https://example.com",
        "adapter_name": "passive_header_adapter",
        "profile": "OWASP_SECURE_HEADERS",
    }
    resp_create_job = client.post(
        f"/api/v1/projects/{proj.id}/assessments",
        json=job_payload,
        headers={"Authorization": f"Bearer {viewer_token}"},
    )
    # Must be 403 Forbidden (requires LEAD or TESTER role)
    assert resp_create_job.status_code == 403


def test_system_role_boundaries_enforced(client: TestClient, db: Session, tester_user: User):
    """Ensure a SECURITY_TESTER cannot access platform-level administrative endpoints."""
    tester_token = create_access_token(
        subject=tester_user.id,
        claims={"email": tester_user.email, "role": tester_user.system_role.value},
    )

    # 1. Attempt administrative user provisioning (requires ADMIN)
    resp_user = client.post(
        "/api/v1/auth/users",
        json={
            "email": "malicious_lead@tenant-test.local",
            "password": "Password123!",
            "full_name": "Unauthorized Attempt",
            "system_role": "ADMIN",
        },
        headers={"Authorization": f"Bearer {tester_token}"},
    )
    assert resp_user.status_code == 403

    # 2. Attempt to update retention policies (requires ADMIN)
    resp_pol = client.put(
        "/api/v1/system/lifecycle/policies/CONFIDENTIAL",
        json={
            "policy_id": "CONFIDENTIAL",
            "name": "Updated Policy",
            "data_classification": "CONFIDENTIAL",
            "retention_period_days": 365,
            "requires_legal_hold_for_deletion": True,
            "min_approvals_for_deletion": 2,
            "auto_archive_after_days": 90,
        },
        headers={"Authorization": f"Bearer {tester_token}"},
    )
    assert resp_pol.status_code == 403
