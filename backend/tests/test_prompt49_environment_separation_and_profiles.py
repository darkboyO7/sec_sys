"""
Prompt 49 Integration Tests: Environment Separation, Deployment Profiles & Safe Runtime Configuration.
Verifies:
1. Explicit profile validation and normalization (development, testing, staging, production).
2. Fail-closed rejection of invalid profiles with secret-free error messages.
3. Production hardening: rejection of DEBUG mode, default secrets, SQLite, and wildcard CORS.
4. Database and evidence path isolation for automated test execution (never mutating vapt.db).
5. Comprehensive readiness probe reporting actual component readiness.
6. Traceback and internal error masking in production/staging.
"""
import os
import pytest
from pathlib import Path
from pydantic import ValidationError
from fastapi.testclient import TestClient
from fastapi import FastAPI, Request
from sqlalchemy.orm import Session

from app.core.config import Settings, EnvironmentType, settings
from app.core.database import get_effective_database_url
from app.api.v1.endpoints.health import router as health_router
from app.main import app as main_app


STRONG_PROD_KEY = "K9#mP$2vL@8wQ!5zR&4xT*7yU^1bN%3cD)0eF(6gH"


def test_01_valid_profiles_accepted_and_normalized():
    """Verify that all four explicit profiles are accepted and case-normalized."""
    for valid in ["development", "DEVELOPMENT", "testing", "TESTING", "staging", "STAGING", "production", "PRODUCTION"]:
        s = Settings(
            ENVIRONMENT=valid,
            DEBUG=False if valid.lower() in ("staging", "production") else True,
            DATABASE_URL="postgresql://valid_user:ValidPassword123!@db.internal:5432/vapt_db" if valid.lower() in ("staging", "production") else "sqlite:///./data/vapt.db",
            SECRET_KEY=STRONG_PROD_KEY if valid.lower() in ("staging", "production") else "dev_insecure_secret_key_change_in_production_min_32_bytes_long",
            ALLOWED_ORIGINS="https://app.vapt.internal" if valid.lower() in ("staging", "production") else "http://localhost:5173",
        )
        assert s.ENVIRONMENT == valid.lower()
        assert s.ENVIRONMENT in [e.value for e in EnvironmentType]


def test_02_invalid_profile_rejected_with_actionable_error():
    """Verify that undefined or unsafe profile names are rejected with clean error."""
    for invalid in ["invalid_env", "hack_mode", "local_prod", "demo", "sandbox123"]:
        with pytest.raises(ValidationError) as exc_info:
            Settings(ENVIRONMENT=invalid)
        err_msg = str(exc_info.value)
        assert f"Invalid ENVIRONMENT profile '{invalid}'" in err_msg
        assert "Must be one of: development, production, staging, testing" in err_msg
        # Ensure zero secrets leaked in validation message
        assert "SECRET_KEY" not in err_msg
        assert "password" not in err_msg.lower()


def test_03_production_rejects_debug_mode():
    """Verify that DEBUG=True is strictly rejected in production and staging."""
    for env in ["production", "staging"]:
        with pytest.raises(ValidationError) as exc_info:
            Settings(
                ENVIRONMENT=env,
                DEBUG=True,
                DATABASE_URL="postgresql://valid_user:ValidPassword123!@db.internal:5432/vapt_db",
                SECRET_KEY=STRONG_PROD_KEY,
                ALLOWED_ORIGINS="https://app.vapt.internal",
            )
        assert f"DEBUG mode must be set to False in {env}" in str(exc_info.value)


def test_04_production_rejects_weak_and_default_secret_keys():
    """Verify that development default keys and low-entropy keys are rejected in production."""
    bad_keys = [
        "dev_insecure_secret_key_change_in_production_min_32_bytes_long",
        "changeme_changeme_changeme_changeme_123",
        "sample_default_password_key_for_testing_purposes",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",  # Low entropy
        "12345678123456781234567812345678",          # Low entropy
    ]
    for bad_key in bad_keys:
        with pytest.raises(ValidationError) as exc_info:
            Settings(
                ENVIRONMENT="production",
                DEBUG=False,
                DATABASE_URL="postgresql://valid_user:ValidPassword123!@db.internal:5432/vapt_db",
                SECRET_KEY=bad_key,
                ALLOWED_ORIGINS="https://app.vapt.internal",
            )
        err_str = str(exc_info.value)
        assert "SECRET_KEY" in err_str
        assert any(term in err_str.lower() for term in ["default or insecure", "insufficient character entropy"])


def test_05_production_accepts_strong_secret_key():
    """Verify that a compliant high-entropy secret key is accepted in production."""
    s = Settings(
        ENVIRONMENT="production",
        DEBUG=False,
        DATABASE_URL="postgresql://vapt_admin:SecureProdPass_2026!@pg.vapt.internal:5432/vapt_prod",
        SECRET_KEY=STRONG_PROD_KEY,
        ALLOWED_ORIGINS="https://security.vapt.internal,https://admin.vapt.internal",
    )
    assert s.ENVIRONMENT == "production"
    assert s.DEBUG is False
    assert len(s.SECRET_KEY) >= 32


def test_06_production_rejects_sqlite_database():
    """Verify that SQLite engine is strictly forbidden in production and staging."""
    for env in ["production", "staging"]:
        with pytest.raises(ValidationError) as exc_info:
            Settings(
                ENVIRONMENT=env,
                DEBUG=False,
                DATABASE_URL="sqlite:///D:/alt/backend/data/vapt.db",
                SECRET_KEY=STRONG_PROD_KEY,
                ALLOWED_ORIGINS="https://app.vapt.internal",
            )
        assert f"SQLite database is forbidden in {env} mode" in str(exc_info.value)


def test_07_production_rejects_default_postgres_credentials_and_empty_pass():
    """Verify that default postgres:postgres and empty passwords are forbidden."""
    # 1. Default postgres:postgres
    with pytest.raises(ValidationError) as exc_info:
        Settings(
            ENVIRONMENT="production",
            DEBUG=False,
            DATABASE_URL="postgresql://postgres:postgres@localhost:5432/vapt_db",
            SECRET_KEY=STRONG_PROD_KEY,
            ALLOWED_ORIGINS="https://app.vapt.internal",
        )
    assert "Default 'postgres:postgres' credentials in DATABASE_URL are forbidden" in str(exc_info.value)

    # 2. Empty password
    with pytest.raises(ValidationError) as exc_info:
        Settings(
            ENVIRONMENT="production",
            DEBUG=False,
            DATABASE_URL="postgresql://vapt_user:@db.internal:5432/vapt_db",
            SECRET_KEY=STRONG_PROD_KEY,
            ALLOWED_ORIGINS="https://app.vapt.internal",
        )
    assert "DATABASE_URL is missing a non-empty database password" in str(exc_info.value)


def test_08_production_rejects_wildcard_cors_and_localhost():
    """Verify that wildcard origins and localhost are strictly forbidden in production."""
    # 1. Wildcard
    with pytest.raises(ValidationError) as exc_info:
        Settings(
            ENVIRONMENT="production",
            DEBUG=False,
            DATABASE_URL="postgresql://vapt_admin:SecurePass123!@db.internal:5432/vapt_db",
            SECRET_KEY=STRONG_PROD_KEY,
            ALLOWED_ORIGINS="*",
        )
    assert "Wildcard '*' in ALLOWED_ORIGINS is strictly forbidden" in str(exc_info.value)

    # 2. Localhost
    with pytest.raises(ValidationError) as exc_info:
        Settings(
            ENVIRONMENT="production",
            DEBUG=False,
            DATABASE_URL="postgresql://vapt_admin:SecurePass123!@db.internal:5432/vapt_db",
            SECRET_KEY=STRONG_PROD_KEY,
            ALLOWED_ORIGINS="http://localhost:3000",
        )
    assert "Localhost/127.0.0.1 origins in ALLOWED_ORIGINS are forbidden" in str(exc_info.value)


def test_09_testing_profile_isolates_database_from_user_data():
    """
    Acceptance Criteria: Test execution must not mutate the user's working database.
    Verifies that testing profile automatically redirects working vapt.db to vapt_test.db.
    """
    s_dev = Settings(ENVIRONMENT="development", DATABASE_URL="sqlite:///D:/alt/backend/data/vapt.db")
    dev_url = get_effective_database_url(s_dev)
    assert "vapt.db" in dev_url
    assert "vapt_test.db" not in dev_url

    s_test = Settings(ENVIRONMENT="testing", DATABASE_URL="sqlite:///D:/alt/backend/data/vapt.db")
    test_url = get_effective_database_url(s_test)
    assert "vapt_test.db" in test_url
    assert test_url != dev_url


def test_10_evidence_directory_isolation(tmp_path):
    """Verify that testing profile routes evidence storage to isolated directory."""
    s_dev = Settings(ENVIRONMENT="development")
    dev_path = s_dev.get_evidence_path()
    assert "test_evidence" not in str(dev_path).lower()

    s_test = Settings(ENVIRONMENT="testing")
    test_path = s_test.get_evidence_path()
    assert "test_evidence" in str(test_path).lower()
    assert test_path != dev_path


def test_11_readiness_probe_reports_actual_component_readiness(client: TestClient):
    """
    Verify that readiness probe actively verifies database, schema, storage,
    evidence directory, and profile compliance.
    """
    resp = client.get("/api/v1/health/ready")
    assert resp.status_code == 200
    data = resp.json()

    assert data["status"] == "ready"
    assert data["checks"]["database"] is True
    assert data["checks"]["migrations"] is True
    assert data["checks"]["storage_writable"] is True
    assert data["checks"]["evidence_writable"] is True
    assert data["checks"]["profile_valid"] is True
    assert data["checks"]["profile"] in ["development", "testing"]
    assert data["checks"]["details"]["database"] == "reachable"
    assert data["checks"]["details"]["schema"] == "initialized"
    assert data["checks"]["details"]["storage"] == "writable"
    assert data["checks"]["details"]["evidence_storage"] == "writable"
    assert data["checks"]["details"]["profile_compliance"] == "compliant"


def test_12_unhandled_exception_masks_tracebacks_in_prod_and_staging(monkeypatch):
    """
    Verify that in production/staging or when DEBUG=False, unhandled 500 exceptions
    return a generic error message without disclosing server file paths or stack traces.
    """
    monkeypatch.setattr(settings, "DEBUG", False)
    monkeypatch.setattr(settings, "ENVIRONMENT", "production")

    test_app = FastAPI()

    # Mount exception handlers from main app
    for exc_cls, handler in main_app.exception_handlers.items():
        test_app.add_exception_handler(exc_cls, handler)

    @test_app.get("/trigger-crash")
    def trigger_crash():
        raise RuntimeError("CRITICAL_INTERNAL_FAILURE: Sensitive query failed at D:/secret/keys/db.key")

    c = TestClient(test_app, raise_server_exceptions=False)
    resp = c.get("/trigger-crash")
    assert resp.status_code == 500
    err_body = resp.json()

    # Must NOT disclose internal path or runtime error message
    assert "D:/secret/keys" not in str(err_body)
    assert "CRITICAL_INTERNAL_FAILURE" not in str(err_body)
    assert err_body["error_code"] == "INTERNAL_ERROR"
    assert "An internal error occurred" in err_body["message"]
