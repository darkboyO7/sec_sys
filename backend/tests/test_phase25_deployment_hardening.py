import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.core.config import Settings
from app.main import app


def test_production_secret_key_validation():
    """
    Verify production mode rejects weak, default, or short secrets.
    """
    # 1. Reject short key (< 32 chars)
    with pytest.raises(ValidationError, match="at least 32 characters"):
        Settings(
            ENVIRONMENT="production",
            SECRET_KEY="short_key",
            ALLOWED_ORIGINS="https://vapt.example.com",
            DEBUG=False,
        )

    # 2. Reject default dev secret in production mode
    with pytest.raises(ValidationError, match="strictly forbidden in production"):
        Settings(
            ENVIRONMENT="production",
            SECRET_KEY="dev_insecure_secret_key_change_in_production_min_32_bytes_long",
            ALLOWED_ORIGINS="https://vapt.example.com",
            DEBUG=False,
        )

    # 3. Accept strong secret in production mode
    valid_settings = Settings(
        ENVIRONMENT="production",
        SECRET_KEY="a" * 64,
        ALLOWED_ORIGINS="https://vapt.example.com",
        DEBUG=False,
    )
    assert valid_settings.SECRET_KEY == "a" * 64


def test_production_debug_mode_forbidden():
    """
    Verify production mode rejects DEBUG=True.
    """
    with pytest.raises(ValidationError, match="DEBUG mode must be set to False"):
        Settings(
            ENVIRONMENT="production",
            SECRET_KEY="b" * 64,
            ALLOWED_ORIGINS="https://vapt.example.com",
            DEBUG=True,
        )


def test_production_cors_wildcard_forbidden():
    """
    Verify production mode rejects wildcard '*' CORS origin.
    """
    with pytest.raises(ValidationError, match=r"Wildcard '\*' in ALLOWED_ORIGINS is strictly forbidden"):
        Settings(
            ENVIRONMENT="production",
            SECRET_KEY="c" * 64,
            ALLOWED_ORIGINS="*",
            DEBUG=False,
        )


def test_security_headers_middleware(client: TestClient):
    """
    Verify all OWASP defense-in-depth security headers are injected into HTTP responses.
    """
    res = client.get("/health")
    assert res.status_code == 200

    headers = res.headers
    assert headers.get("X-Frame-Options") == "DENY"
    assert headers.get("X-Content-Type-Options") == "nosniff"
    assert headers.get("X-XSS-Protection") == "1; mode=block"
    assert headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"
    assert "camera=()" in headers.get("Permissions-Policy", "")
    assert "frame-ancestors 'none'" in headers.get("Content-Security-Policy", "")
    assert "default-src 'self'" in headers.get("Content-Security-Policy", "")


def test_api_cache_control_headers(client: TestClient):
    """
    Verify API responses include strict Cache-Control headers to protect vulnerability data.
    """
    res = client.get("/api/v1/health")
    assert res.status_code == 200

    headers = res.headers
    assert "no-store" in headers.get("Cache-Control", "")
    assert "no-cache" in headers.get("Cache-Control", "")
    assert headers.get("Pragma") == "no-cache"


def test_health_and_readiness_probes(client: TestClient):
    """
    Verify both root-level and API-level liveness and readiness probes respond accurately.
    """
    # 1. Root liveness
    root_health = client.get("/health")
    assert root_health.status_code == 200
    assert root_health.json()["status"] == "ok"

    # 2. Root readiness
    root_ready = client.get("/ready")
    assert root_ready.status_code == 200
    ready_data = root_ready.json()
    assert ready_data["status"] == "ready"
    assert ready_data["checks"]["database"] is True
    assert ready_data["checks"]["migrations"] is True
    assert ready_data["checks"]["storage_writable"] is True

    # 3. API v1 readiness
    api_ready = client.get("/api/v1/ready")
    assert api_ready.status_code == 200
    assert api_ready.json()["status"] == "ready"
