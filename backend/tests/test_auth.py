import pytest
from fastapi.testclient import TestClient
from app.models.user import User
from app.core.security import verify_password


def test_user_registration_success(client: TestClient, db):
    payload = {
        "email": "new_operative@sec.local",
        "password": "StrongPassword123!",
        "full_name": "New Operative",
        "system_role": "SECURITY_TESTER"
    }
    response = client.post("/api/v1/auth/register", json=payload)
    assert response.status_code == 201
    data = response.json()
    assert data["email"] == "new_operative@sec.local"
    assert data["full_name"] == "New Operative"
    assert "hashed_password" not in data

    # Verify password was actually hashed with bcrypt
    db_user = db.query(User).filter(User.email == "new_operative@sec.local").first()
    assert db_user is not None
    assert db_user.hashed_password.startswith("$2")
    assert verify_password("StrongPassword123!", db_user.hashed_password)


def test_duplicate_user_registration_fails(client: TestClient, admin_user: User):
    payload = {
        "email": admin_user.email,
        "password": "AnotherPassword123!",
        "full_name": "Impostor Admin",
    }
    response = client.post("/api/v1/auth/register", json=payload)
    assert response.status_code == 400
    assert "already exists" in response.json()["detail"]


def test_login_successful_and_me_endpoint(client: TestClient, admin_user: User):
    login_data = {
        "email": admin_user.email,
        "password": "SuperSecretAdminPass123!"
    }
    response = client.post("/api/v1/auth/login", json=login_data)
    assert response.status_code == 200
    token_data = response.json()
    assert "access_token" in token_data
    assert token_data["token_type"] == "bearer"
    assert token_data["user"]["email"] == admin_user.email

    # Verify /me endpoint with received bearer token
    token = token_data["access_token"]
    me_resp = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me_resp.status_code == 200
    assert me_resp.json()["id"] == admin_user.id


def test_login_invalid_password_fails(client: TestClient, admin_user: User):
    login_data = {
        "email": admin_user.email,
        "password": "WrongPasswordBadAttempt!"
    }
    response = client.post("/api/v1/auth/login", json=login_data)
    assert response.status_code == 401
    assert "Incorrect email or password" in response.json()["detail"]


def test_unauthenticated_request_rejected(client: TestClient):
    response = client.get("/api/v1/auth/me")
    assert response.status_code == 401


def test_tampered_token_rejected(client: TestClient):
    headers = {"Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.invalidpayload.invalidsignature"}
    response = client.get("/api/v1/auth/me", headers=headers)
    assert response.status_code == 401
