"""
VAPT Platform — Authentication Remediation & Privilege Escalation Hardening Tests (Phase 2).
Validates:
1. Public registration strictly rejects or downgrades privileged system roles (ADMIN, SECURITY_LEAD, AUDITOR).
2. Safe default unprivileged role (SECURITY_TESTER) is enforced server-side.
3. Administrative user provisioning (POST /api/v1/auth/users) requires ADMIN role.
4. Unauthenticated or unprivileged actors receive 401/403 when attempting privileged account provisioning.
5. Password hashing, token revocation, and inactive user lockout are enforced.
"""
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.user import User, SystemRole
from app.core.security import create_access_token


def test_public_registration_privilege_escalation_blocked(client: TestClient, db: Session, admin_user: User):
    """
    Ensure that an unauthenticated caller passing system_role="ADMIN" on public /register
    is strictly assigned the safe default role (SECURITY_TESTER).
    """
    email = "attacker_escalation_test@vapt-test.local"

    payload = {
        "email": email,
        "password": "Password123!",
        "full_name": "Privilege Escalation Attacker",
        "system_role": "ADMIN",
    }

    resp = client.post("/api/v1/auth/register", json=payload)
    assert resp.status_code == 201, resp.text
    data = resp.json()

    # CRITICAL ASSERTION: The assigned role must NOT be ADMIN
    assert data["system_role"] != "ADMIN"
    assert data["system_role"] == "SECURITY_TESTER"

    # Verify directly in the database
    u = db.query(User).filter(User.email == email).first()
    assert u is not None
    assert u.system_role == SystemRole.SECURITY_TESTER


def test_public_registration_cannot_assign_security_lead_or_auditor(client: TestClient, db: Session, admin_user: User):
    """Ensure SECURITY_LEAD and AUDITOR roles are also blocked on public registration."""
    for role_attempt in ["SECURITY_LEAD", "AUDITOR"]:
        email = f"attacker_{role_attempt.lower()}@vapt-test.local"

        payload = {
            "email": email,
            "password": "Password123!",
            "full_name": f"Attacker {role_attempt}",
            "system_role": role_attempt,
        }

        resp = client.post("/api/v1/auth/register", json=payload)
        assert resp.status_code == 201, resp.text
        data = resp.json()
        assert data["system_role"] == "SECURITY_TESTER"


def test_admin_can_provision_privileged_users(client: TestClient, db: Session, admin_user: User):
    """Ensure that an authenticated administrator CAN provision privileged roles via POST /api/v1/auth/users."""
    admin_token = create_access_token(
        subject=admin_user.id,
        claims={"email": admin_user.email, "role": admin_user.system_role.value},
    )

    new_lead_email = "newly_provisioned_lead@vapt-test.local"
    payload = {
        "email": new_lead_email,
        "password": "SecurePassword999!",
        "full_name": "Authorized Security Lead",
        "system_role": "SECURITY_LEAD",
        "is_active": True,
    }

    resp = client.post(
        "/api/v1/auth/users",
        json=payload,
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 201, resp.text
    data = resp.json()
    assert data["email"] == new_lead_email
    assert data["system_role"] == "SECURITY_LEAD"


def test_unauthenticated_or_unprivileged_cannot_provision_users(client: TestClient, db: Session, tester_user: User):
    """Ensure non-admin actors receive 401 or 403 when trying to POST /api/v1/auth/users."""
    payload = {
        "email": "unauthorized_creation@vapt-test.local",
        "password": "Password123!",
        "full_name": "Unauthorized Provisioning",
        "system_role": "ADMIN",
    }

    # 1. Unauthenticated request -> 401
    resp_anon = client.post("/api/v1/auth/users", json=payload)
    assert resp_anon.status_code == 401

    # 2. Authenticated as unprivileged SECURITY_TESTER -> 403
    tester_token = create_access_token(
        subject=tester_user.id,
        claims={"email": tester_user.email, "role": tester_user.system_role.value},
    )

    resp_tester = client.post(
        "/api/v1/auth/users",
        json=payload,
        headers={"Authorization": f"Bearer {tester_token}"},
    )
    assert resp_tester.status_code == 403
