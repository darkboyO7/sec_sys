"""
Unit & Integration Acceptance Tests for Prompt 36:
Identity Security, Authorization Consistency and Privileged-Action Governance.
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
from app.models.scope import ScopeTarget, TargetType, AuthorizationStatus
from app.models.finding import VulnerabilityFinding, FindingLifecycleStatus
from app.models.assessment import FindingSeverity, FindingConfidence
from app.models.authorization import TokenRevocationRecord, AccessDenialAuditRecord
from app.core.security import create_access_token, hash_password, verify_password
from app.core.permissions import (
    Permission,
    has_permission,
    get_granted_permissions,
    SYSTEM_ROLE_PERMISSIONS,
    PROJECT_ROLE_PERMISSIONS,
)
from app.services.authorization_service import (
    AuthorizationService,
    redact_sensitive_strings,
)
from app.api.deps import verify_resource_ownership


@pytest.fixture
def auth_org(db):
    org = Organization(name="Identity Governance Org", slug="id-gov-org")
    db.add(org)
    db.commit()
    db.refresh(org)
    return org


@pytest.fixture
def auth_users(db, auth_org):
    admin = User(
        email="admin.id@example.com",
        full_name="Platform Admin",
        hashed_password=hash_password("adminPass123!"),
        system_role=SystemRole.ADMIN,
        is_active=True,
    )
    lead = User(
        email="lead.id@example.com",
        full_name="Project Lead",
        hashed_password=hash_password("leadPass123!"),
        system_role=SystemRole.SECURITY_LEAD,
        is_active=True,
    )
    tester = User(
        email="tester.id@example.com",
        full_name="Project Tester",
        hashed_password=hash_password("testerPass123!"),
        system_role=SystemRole.SECURITY_TESTER,
        is_active=True,
    )
    viewer = User(
        email="viewer.id@example.com",
        full_name="Project Viewer",
        hashed_password=hash_password("viewerPass123!"),
        system_role=SystemRole.VIEWER,
        is_active=True,
    )
    outsider = User(
        email="outsider.id@example.com",
        full_name="Tenant Outsider",
        hashed_password=hash_password("outsiderPass123!"),
        system_role=SystemRole.VIEWER,
        is_active=True,
    )
    db.add_all([admin, lead, tester, viewer, outsider])
    db.commit()
    for u in [admin, lead, tester, viewer, outsider]:
        db.refresh(u)
    return {
        "admin": admin,
        "lead": lead,
        "tester": tester,
        "viewer": viewer,
        "outsider": outsider,
    }


@pytest.fixture
def auth_project(db, auth_org, auth_users):
    proj = Project(
        name="Primary Secured Project",
        description="Project for Auth Testing",
        organization_id=auth_org.id,
    )
    db.add(proj)
    db.commit()
    db.refresh(proj)

    m1 = ProjectMember(project_id=proj.id, user_id=auth_users["lead"].id, role=ProjectRole.LEAD)
    m2 = ProjectMember(project_id=proj.id, user_id=auth_users["tester"].id, role=ProjectRole.TESTER)
    m3 = ProjectMember(project_id=proj.id, user_id=auth_users["viewer"].id, role=ProjectRole.VIEWER)
    db.add_all([m1, m2, m3])
    db.commit()
    return proj


@pytest.fixture
def foreign_project(db, auth_org, auth_users):
    foreign_proj = Project(
        name="Isolated Foreign Project",
        description="Cross-tenant isolation test",
        organization_id=auth_org.id,
    )
    db.add(foreign_proj)
    db.commit()
    db.refresh(foreign_proj)
    return foreign_proj


# ---------------------------------------------------------------------------
# Test 1: Horizontal Privilege Escalation Prevention (Cross-Tenant Boundary)
# ---------------------------------------------------------------------------
def test_horizontal_privilege_escalation_prevention(client, db, auth_project, foreign_project, auth_users):
    pid_foreign = foreign_project.id
    lead_h = auth_header_for_user(auth_users["lead"])

    # Lead is member of auth_project, but NOT of foreign_project
    # Attempting to read foreign project targets must fail closed (404)
    res = client.get(f"/api/v1/projects/{pid_foreign}/targets", headers=lead_h)
    assert res.status_code == status.HTTP_404_NOT_FOUND

    # Access denial must be recorded in access_denial_audit_records
    denials = db.query(AccessDenialAuditRecord).filter(
        AccessDenialAuditRecord.project_id == pid_foreign,
        AccessDenialAuditRecord.user_id == auth_users["lead"].id,
    ).all()
    assert len(denials) >= 1
    assert "not an authorized member" in denials[0].denial_reason


# ---------------------------------------------------------------------------
# Test 2: Vertical Privilege Escalation Prevention (Role Boundary)
# ---------------------------------------------------------------------------
def test_vertical_privilege_escalation_prevention(client, db, auth_project, auth_users):
    pid = auth_project.id
    viewer_h = auth_header_for_user(auth_users["viewer"])

    # Viewer attempts privileged actions (requires TESTER or LEAD)
    # 1. Scope target creation
    res1 = client.post(
        f"/api/v1/projects/{pid}/targets",
        json={"target_type": "URL", "target_value": "https://unauthorized.corp"},
        headers=viewer_h,
    )
    assert res1.status_code == status.HTTP_403_FORBIDDEN

    # 2. Scheduling dispatch
    res2 = client.post(
        f"/api/v1/projects/{pid}/scheduling/dispatch-next",
        headers=viewer_h,
    )
    assert res2.status_code == status.HTTP_403_FORBIDDEN

    # 3. Threat correlation trigger
    res3 = client.post(
        f"/api/v1/projects/{pid}/threat-intel/correlate",
        json={"force_recorrelate": True},
        headers=viewer_h,
    )
    assert res3.status_code == status.HTTP_403_FORBIDDEN

    # Verify denial records capture held role 'VIEWER' and required privileges
    denials = db.query(AccessDenialAuditRecord).filter(
        AccessDenialAuditRecord.project_id == pid,
        AccessDenialAuditRecord.user_id == auth_users["viewer"].id,
    ).all()
    assert len(denials) >= 3
    for d in denials:
        assert d.held_privilege == "VIEWER"
        assert d.denial_reason != ""


# ---------------------------------------------------------------------------
# Test 3: Session Revocation upon Logout
# ---------------------------------------------------------------------------
def test_token_revocation_on_logout(client, db, auth_project, auth_users):
    pid = auth_project.id
    tester = auth_users["tester"]

    # Login to acquire active token
    login_res = client.post(
        "/api/v1/auth/login",
        json={"email": tester.email, "password": "testerPass123!"},
    )
    assert login_res.status_code == status.HTTP_200_OK
    token = login_res.json()["access_token"]
    auth_h = {"Authorization": f"Bearer {token}"}

    # Verify token works
    res_before = client.get(f"/api/v1/projects/{pid}/targets", headers=auth_h)
    assert res_before.status_code == status.HTTP_200_OK

    # Logout
    logout_res = client.post("/api/v1/auth/logout", headers=auth_h)
    assert logout_res.status_code == status.HTTP_200_OK
    assert logout_res.json()["status"] == "SUCCESS"

    # Next request with revoked token must be rejected (401)
    res_after = client.get(f"/api/v1/projects/{pid}/targets", headers=auth_h)
    assert res_after.status_code == status.HTTP_401_UNAUTHORIZED
    assert "token has been revoked" in res_after.json()["detail"].lower()


# ---------------------------------------------------------------------------
# Test 4: Global Token Invalidation Across All Devices
# ---------------------------------------------------------------------------
def test_revoke_all_user_sessions(client, db, auth_project, auth_users):
    pid = auth_project.id
    tester = auth_users["tester"]

    # Issue token 1
    t1 = create_access_token(subject=tester.id, claims={"role": tester.system_role.value})
    h1 = {"Authorization": f"Bearer {t1}"}

    # Issue token 2
    t2 = create_access_token(subject=tester.id, claims={"role": tester.system_role.value})
    h2 = {"Authorization": f"Bearer {t2}"}

    # Verify token 1 works
    assert client.get(f"/api/v1/projects/{pid}/targets", headers=h1).status_code == status.HTTP_200_OK

    # Invalidate all sessions
    res = client.post("/api/v1/auth/revoke-all", headers=h1)
    assert res.status_code == status.HTTP_200_OK
    assert "revoked successfully" in res.json()["message"]

    # Both tokens must now be rejected
    assert client.get(f"/api/v1/projects/{pid}/targets", headers=h1).status_code == status.HTTP_401_UNAUTHORIZED
    assert client.get(f"/api/v1/projects/{pid}/targets", headers=h2).status_code == status.HTTP_401_UNAUTHORIZED


# ---------------------------------------------------------------------------
# Test 5: Deactivated Account Immediate Rejection (403)
# ---------------------------------------------------------------------------
def test_deactivated_account_immediate_rejection(client, db, auth_project, auth_users):
    pid = auth_project.id
    tester = auth_users["tester"]
    h = auth_header_for_user(tester)

    # Deactivate account
    tester.is_active = False
    db.commit()

    res = client.get(f"/api/v1/projects/{pid}/targets", headers=h)
    assert res.status_code == status.HTTP_403_FORBIDDEN
    assert "inactive" in res.json()["detail"].lower()

    # Restore active state for subsequent tests
    tester.is_active = True
    db.commit()


# ---------------------------------------------------------------------------
# Test 6: Object-Level Authorization & Project Boundary Containment
# ---------------------------------------------------------------------------
def test_object_level_ownership_enforcement(db, auth_org, auth_project, foreign_project):
    pid_auth = auth_project.id
    pid_foreign = foreign_project.id

    # Create finding in foreign project
    f_foreign = VulnerabilityFinding(
        project_id=pid_foreign,
        fingerprint="fp-foreign-1",
        target_value="https://foreign.corp",
        title="Foreign Vulnerability",
        severity=FindingSeverity.HIGH,
        confidence=FindingConfidence.CERTAIN,
    )
    db.add(f_foreign)
    db.commit()

    # Attempting to access f_foreign in auth_project must fail closed
    with pytest.raises(Exception) as exc_info:
        verify_resource_ownership(
            model_class=VulnerabilityFinding,
            resource_id=f_foreign.id,
            project_id=pid_auth,
            db=db,
            resource_name="Vulnerability Finding",
        )
    assert "404" in str(exc_info.value)


# ---------------------------------------------------------------------------
# Test 7: Zero Secret Leakage in Logs and Redaction
# ---------------------------------------------------------------------------
def test_credential_and_token_redaction():
    sample_text = (
        'Authorization failure for Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjMifQ.abc '
        'with request payload {"password": "SuperSecretPassword123!", "current_password": "OldPassword!"}'
    )
    redacted = redact_sensitive_strings(sample_text)
    assert "SuperSecretPassword123!" not in redacted
    assert "OldPassword!" not in redacted
    assert "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" not in redacted
    assert "[REDACTED_JWT]" in redacted
    assert '"password": "[REDACTED]"' in redacted


# ---------------------------------------------------------------------------
# Test 8: Permission Matrix Catalog Endpoint
# ---------------------------------------------------------------------------
def test_permission_matrix_catalog(client, auth_users):
    h = auth_header_for_user(auth_users["viewer"])
    res = client.get("/api/v1/system/permissions/matrix", headers=h)
    assert res.status_code == status.HTTP_200_OK

    data = res.json()
    assert "available_permissions" in data
    assert len(data["available_permissions"]) >= 15
    assert "system_roles" in data
    assert "project_roles" in data

    p_roles = {item["role"]: item["granted_permissions"] for item in data["project_roles"]}
    assert "LEAD" in p_roles
    assert "TESTER" in p_roles
    assert "VIEWER" in p_roles

    # Verify least privilege: VIEWER has fewer permissions than LEAD
    assert len(p_roles["VIEWER"]) < len(p_roles["LEAD"])
    assert "scheduling:manage" in p_roles["LEAD"]
    assert "scheduling:manage" not in p_roles["VIEWER"]


# ---------------------------------------------------------------------------
# Test 9: Password Change and Session Rotation
# ---------------------------------------------------------------------------
def test_password_change_and_session_rotation(client, db, auth_users):
    user = auth_users["lead"]
    old_token = create_access_token(subject=user.id)
    h_old = {"Authorization": f"Bearer {old_token}"}

    # Change password
    res = client.post(
        "/api/v1/auth/change-password",
        json={"current_password": "leadPass123!", "new_password": "newSecurePass456!"},
        headers=h_old,
    )
    assert res.status_code == status.HTTP_200_OK
    assert "All previous sessions have been invalidated" in res.json()["message"]

    # Old token is now invalidated
    res_old = client.get("/api/v1/auth/me", headers=h_old)
    assert res_old.status_code == status.HTTP_401_UNAUTHORIZED

    # Login with new password succeeds
    login_new = client.post(
        "/api/v1/auth/login",
        json={"email": user.email, "password": "newSecurePass456!"},
    )
    assert login_new.status_code == status.HTTP_200_OK
    new_token = login_new.json()["access_token"]
    h_new = {"Authorization": f"Bearer {new_token}"}
    assert client.get("/api/v1/auth/me", headers=h_new).status_code == status.HTTP_200_OK


# ---------------------------------------------------------------------------
# Test 10: Access Denial Ledger REST Endpoints
# ---------------------------------------------------------------------------
def test_access_denial_ledger_endpoints(client, db, auth_project, auth_users):
    pid = auth_project.id
    lead_h = auth_header_for_user(auth_users["lead"])
    viewer_h = auth_header_for_user(auth_users["viewer"])

    # 1. Project-scoped access denials (Requires LEAD)
    # Viewer cannot list project denials (403)
    res_v = client.get(f"/api/v1/projects/{pid}/governance/access-denials", headers=viewer_h)
    assert res_v.status_code == status.HTTP_403_FORBIDDEN

    # Lead can list project denials
    res_l = client.get(f"/api/v1/projects/{pid}/governance/access-denials", headers=lead_h)
    assert res_l.status_code == status.HTTP_200_OK
    assert isinstance(res_l.json(), list)

    # 2. System-wide denials (Requires ADMIN or AUDITOR)
    admin_h = auth_header_for_user(auth_users["admin"])
    res_adm = client.get("/api/v1/system/governance/access-denials", headers=admin_h)
    assert res_adm.status_code == status.HTTP_200_OK
    assert isinstance(res_adm.json(), list)
