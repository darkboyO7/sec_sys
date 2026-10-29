"""
Comprehensive Deterministic Test Suite for Prompt 24:
VAPT System API Security, Contract Governance & Integration Reliability.

Covers:
1. Standardized error model on schema validation failures (422 Unprocessable Entity).
2. Standardized error model on missing/expired credentials (401 Unauthorized).
3. Standardized error model on insufficient role/permission (403 Forbidden).
4. Standardized error model on non-existent resource (404 Not Found).
5. Payload size limiting middleware (413 Payload Too Large).
6. Outbound SSRF protection: loopback addresses blocked (127.0.0.1, ::1).
7. Outbound SSRF protection: cloud metadata destinations blocked (169.254.169.254, metadata.google.internal).
8. Outbound SSRF protection: non-HTTP schemes blocked (file://, gopher://, ftp://).
9. Outbound SSRF protection: embedded user credentials in URL prohibited.
10. Valid outbound public destination successfully passes verification.
11. Safe outbound HTTP dispatch enforces mandatory TLS verification.
12. Safe outbound HTTP dispatch enforces response size bounds (OversizedResponseError).
13. Thread-safe sliding window rate limiting engine behavior.
14. Sensitive endpoint abuse defense: login brute-force triggers 429 Too Many Requests.
15. Correlation ID propagation across request, state, response headers, and error bodies.
16. Automated API contract verification tool detects zero schema or enum drift.
17. Tenant isolation fails closed with 404 to avoid leaking resource existence.
"""

import sys
import subprocess
import pytest
from pathlib import Path
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.security import create_access_token
from app.models.user import User, SystemRole
from app.models.organization import Organization
from app.models.project import Project, ProjectMember, ProjectRole
from app.services.network_security_service import (
    OutboundNetworkSecurityService,
    DestinationRestrictedError,
    OversizedResponseError,
    NetworkSecurityTimeoutError,
)
from app.services.rate_limit_service import rate_limiter
from app.schemas.error import APIErrorCode


@pytest.fixture(autouse=True)
def reset_rate_limits():
    """Ensure rate limit counters are clean before each test."""
    rate_limiter.reset()
    yield
    rate_limiter.reset()


def auth_headers(user: User, request_id: str = None) -> dict:
    token = create_access_token(subject=user.id, claims={"email": user.email, "role": user.system_role.value})
    h = {"Authorization": f"Bearer {token}"}
    if request_id:
        h["X-Request-ID"] = request_id
    return h


# ---------------------------------------------------------------------------
# Test 1: Standardized Error Model on Validation Failure (422)
# ---------------------------------------------------------------------------

def test_01_standardized_error_format_on_validation_failure(client: TestClient, admin_user: User):
    """
    Submitting invalid body fields must return HTTP 422 with standardized APIErrorResponse:
    error_code=VALIDATION_ERROR, request_id, detail, message, and details list.
    """
    headers = auth_headers(admin_user, "test-req-val-001")

    # ProjectCreate requires 'name'; sending empty payload
    response = client.post("/api/v1/projects", json={}, headers=headers)
    assert response.status_code == 422
    data = response.json()

    assert data["error_code"] == APIErrorCode.VALIDATION_ERROR.value
    assert data["request_id"] == "test-req-val-001"
    assert "detail" in data
    assert "message" in data
    assert isinstance(data["details"], list)
    assert len(data["details"]) > 0
    assert response.headers.get("X-Request-ID") == "test-req-val-001"


# ---------------------------------------------------------------------------
# Test 2: Standardized Error Model on Unauthenticated (401)
# ---------------------------------------------------------------------------

def test_02_standardized_error_format_on_unauthorized(client: TestClient):
    """
    Protected route access without credentials must return HTTP 401 with UNAUTHENTICATED error code.
    """
    response = client.get("/api/v1/projects", headers={"X-Request-ID": "test-req-auth-401"})
    assert response.status_code == 401
    data = response.json()

    assert data["error_code"] == APIErrorCode.UNAUTHENTICATED.value
    assert data["request_id"] == "test-req-auth-401"
    assert "detail" in data
    assert "message" in data


# ---------------------------------------------------------------------------
# Test 3: Standardized Error Model on Insufficient Role (403)
# ---------------------------------------------------------------------------

def test_03_standardized_error_format_on_forbidden_role(
    client: TestClient,
    tester_user: User,
    test_project: Project,
):
    """
    Non-admin user attempting admin-only disaster recovery operation must receive HTTP 403
    with PERMISSION_DENIED error code.
    """
    headers = auth_headers(tester_user, "test-req-perm-403")

    response = client.post("/api/v1/recovery/bundles", headers=headers)
    assert response.status_code == 403
    data = response.json()

    assert data["error_code"] == APIErrorCode.PERMISSION_DENIED.value
    assert data["request_id"] == "test-req-perm-403"
    assert "administrator" in data["detail"].lower() or "privilege" in data["detail"].lower()


# ---------------------------------------------------------------------------
# Test 4: Standardized Error Model on Not Found (404)
# ---------------------------------------------------------------------------

def test_04_standardized_error_format_on_not_found(client: TestClient, admin_user: User):
    """
    Accessing a non-existent resource must return HTTP 404 with RESOURCE_NOT_FOUND error code.
    """
    headers = auth_headers(admin_user, "test-req-notfound-404")

    response = client.get("/api/v1/projects/00000000-0000-0000-0000-000000000000", headers=headers)
    assert response.status_code == 404
    data = response.json()

    assert data["error_code"] == APIErrorCode.RESOURCE_NOT_FOUND.value
    assert data["request_id"] == "test-req-notfound-404"
    assert "not found" in data["detail"].lower()


# ---------------------------------------------------------------------------
# Test 5: Payload Too Large Rejection (413)
# ---------------------------------------------------------------------------

def test_05_payload_too_large_rejection(client: TestClient, admin_user: User):
    """
    Requests claiming a Content-Length exceeding the tightened 2MB limit on JSON endpoints
    must be immediately rejected with HTTP 413 and PAYLOAD_TOO_LARGE.
    """
    headers = auth_headers(admin_user, "test-req-payload-413")
    headers["Content-Length"] = "3145728"  # 3 MB > 2 MB
    headers["Content-Type"] = "application/json"

    response = client.post("/api/v1/projects", content=b"{}", headers=headers)
    assert response.status_code == 413
    data = response.json()

    assert data["error_code"] == APIErrorCode.PAYLOAD_TOO_LARGE.value
    assert data["request_id"] == "test-req-payload-413"
    assert "exceeds maximum permitted limit" in data["detail"]


# ---------------------------------------------------------------------------
# Test 6: Outbound SSRF Protection — Loopback Addresses Blocked
# ---------------------------------------------------------------------------

def test_06_ssrf_destination_loopback_blocked(client: TestClient, admin_user: User, test_project: Project):
    """
    Outbound destinations resolving to loopback addresses (127.0.0.1, localhost, ::1)
    must be strictly blocked with DestinationRestrictedError and HTTP 400.
    """
    # Direct service test
    with pytest.raises(DestinationRestrictedError) as exc_info:
        OutboundNetworkSecurityService.validate_destination_url("http://127.0.0.1:8080/internal/admin")
    assert "loopback" in str(exc_info.value).lower()

    # API pre-flight endpoint test
    headers = auth_headers(admin_user)
    payload = {"url": "http://127.0.0.1:9090/webhook", "allow_private": False}

    response = client.post(
        f"/api/v1/projects/{test_project.id}/integrations/destinations/validate",
        json=payload,
        headers=headers,
    )
    assert response.status_code == 400
    data = response.json()
    assert data["error_code"] == APIErrorCode.DESTINATION_RESTRICTED.value
    assert "loopback" in data["detail"].lower()

    response = client.post(
        f"/api/v1/projects/{test_project.id}/integrations/destinations/validate",
        json=payload,
        headers=headers,
    )
    assert response.status_code == 400
    data = response.json()
    assert data["error_code"] == APIErrorCode.DESTINATION_RESTRICTED.value
    assert "loopback" in data["detail"].lower()


# ---------------------------------------------------------------------------
# Test 7: Outbound SSRF Protection — Cloud Metadata Blocked
# ---------------------------------------------------------------------------

def test_07_ssrf_destination_cloud_metadata_blocked():
    """
    Outbound requests targeting AWS/GCP/Azure link-local metadata endpoints
    (169.254.169.254, metadata.google.internal) must be unconditionally prohibited.
    """
    metadata_targets = [
        "http://169.254.169.254/latest/meta-data/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://instance-data/latest/meta-data/",
    ]

    for target in metadata_targets:
        with pytest.raises(DestinationRestrictedError) as exc_info:
            OutboundNetworkSecurityService.validate_destination_url(target)
        err = str(exc_info.value).lower()
        assert "metadata" in err or "link-local" in err or "prohibited" in err


# ---------------------------------------------------------------------------
# Test 8: Outbound SSRF Protection — Non-HTTP Schemes Blocked
# ---------------------------------------------------------------------------

def test_08_ssrf_destination_unsupported_scheme_blocked():
    """
    Outbound destinations using non-HTTP schemes (file://, gopher://, ftp://) must be rejected.
    """
    forbidden_schemes = [
        "file:///etc/shadow",
        "gopher://127.0.0.1:6379/_INFO",
        "ftp://mirror.corp/backup.tar",
        "data:text/plain;base64,SGVsbG8=",
    ]

    for target in forbidden_schemes:
        with pytest.raises(DestinationRestrictedError) as exc_info:
            OutboundNetworkSecurityService.validate_destination_url(target)
        assert "unsupported url scheme" in str(exc_info.value).lower()


# ---------------------------------------------------------------------------
# Test 9: Outbound SSRF Protection — Embedded Credentials Prohibited
# ---------------------------------------------------------------------------

def test_09_ssrf_destination_credentials_in_url_blocked():
    """
    Destination URLs with embedded credentials (e.g. http://user:pass@example.com)
    must be rejected to prevent credential leaks across network boundaries.
    """
    with pytest.raises(DestinationRestrictedError) as exc_info:
        OutboundNetworkSecurityService.validate_destination_url("https://admin:SuperSecretToken@target.example.com/api")
    assert "user credentials embedded" in str(exc_info.value).lower()


# ---------------------------------------------------------------------------
# Test 10: Valid Public FQDN Passes Destination Policy
# ---------------------------------------------------------------------------

def test_10_ssrf_destination_public_fqdn_permitted(client: TestClient, admin_user: User, test_project: Project):
    """
    Legitimate public FQDNs with HTTPS pass destination policy and return resolved IPs.
    """
    headers = auth_headers(admin_user)
    payload = {"url": "https://www.cisa.gov/known-exploited-vulnerabilities", "allow_private": False}

    response = client.post(
        f"/api/v1/projects/{test_project.id}/integrations/destinations/validate",
        json=payload,
        headers=headers,
    )
    assert response.status_code == 200
    data = response.json()
    assert data["valid"] is True
    assert data["scheme"] == "https"
    assert "cisa.gov" in data["hostname"]
    assert len(data["resolved_ips"]) > 0


# ---------------------------------------------------------------------------
# Test 11: Outbound Safe Dispatch Enforces Mandatory TLS Validation
# ---------------------------------------------------------------------------

def test_11_outbound_safe_dispatch_enforces_tls_verification(monkeypatch):
    """
    Safe outbound dispatch must strictly enforce verify=True for all TLS connections.
    """
    captured_verify = []

    import httpx
    original_client_init = httpx.Client.__init__

    def mock_client_init(self, *args, **kwargs):
        captured_verify.append(kwargs.get("verify"))
        original_client_init(self, *args, **kwargs)

    monkeypatch.setattr(httpx.Client, "__init__", mock_client_init)

    # Validate that verify=True was supplied to the underlying client
    try:
        OutboundNetworkSecurityService.execute_safe_dispatch(
            url="https://www.cisa.gov/robots.txt",
            method="GET",
        )
    except Exception:
        pass  # Network transport might fail offline, but Client init captured kwargs

    assert len(captured_verify) > 0
    assert captured_verify[0] is True, "TLS verification must be strictly True"


# ---------------------------------------------------------------------------
# Test 12: Outbound Response Size Limit Enforcement
# ---------------------------------------------------------------------------

def test_12_outbound_oversized_response_protection(monkeypatch):
    """
    Responses exceeding the maximum configured byte limit must raise OversizedResponseError.
    """
    import httpx

    class MockResponse:
        status_code = 200
        headers = {"Content-Length": "20971520"}  # 20 MB > 10 MB limit
        content = b"X" * 1024
        is_redirect = False
        has_redirect_location = False

    class MockClient:
        def __init__(self, **kwargs):
            pass
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass
        def request(self, *args, **kwargs):
            return MockResponse()

    monkeypatch.setattr(httpx, "Client", MockClient)

    with pytest.raises(OversizedResponseError) as exc_info:
        OutboundNetworkSecurityService.execute_safe_dispatch(
            url="https://www.cisa.gov/large-dataset.json",
            max_response_bytes=10 * 1024 * 1024,
        )
    assert "exceeds limit" in str(exc_info.value).lower()


# ---------------------------------------------------------------------------
# Test 13: Thread-Safe Sliding Window Rate Limiting Engine
# ---------------------------------------------------------------------------

def test_13_rate_limiting_engine_sliding_window():
    """
    The rate limiting engine must track counts, reject calls exceeding limit,
    and compute accurate retry-after seconds.
    """
    key = "client-ip-198.51.100.1"
    bucket = "TEST_BUCKET"

    # Limit = 3 requests per 60 seconds
    for i in range(3):
        allowed, remaining, retry_after = rate_limiter.is_allowed(
            key=key, bucket=bucket, custom_limit=3, custom_window=60
        )
        assert allowed is True
        assert remaining == (2 - i)
        assert retry_after == 0

    # 4th request must be denied
    allowed, remaining, retry_after = rate_limiter.is_allowed(
        key=key, bucket=bucket, custom_limit=3, custom_window=60
    )
    assert allowed is False
    assert remaining == 0
    assert retry_after > 0

    # Reset clears counters
    rate_limiter.reset()
    allowed, remaining, _ = rate_limiter.is_allowed(
        key=key, bucket=bucket, custom_limit=3, custom_window=60
    )
    assert allowed is True
    assert remaining == 2


# ---------------------------------------------------------------------------
# Test 14: Sensitive Endpoint Abuse Defense — Login Brute-Force Throttling
# ---------------------------------------------------------------------------

def test_14_api_abuse_login_rate_limiting(client: TestClient):
    """
    Repeated authentication attempts from an IP exceeding the configured threshold
    must trigger HTTP 429 Too Many Requests with RATE_LIMIT_EXCEEDED error code.
    """
    client_ip = "203.0.113.42"
    headers = {"X-Forwarded-For": client_ip, "X-Request-ID": "test-req-login-brute"}

    # Exhaust limit for this IP using custom limit
    for _ in range(30):
        rate_limiter.is_allowed(key=client_ip, bucket="AUTH_LOGIN")

    response = client.post(
        "/api/v1/auth/login",
        json={"email": "attacker@vapt.local", "password": "wrong_password_attempt"},
        headers=headers,
    )

    assert response.status_code == 429
    data = response.json()
    assert data["error_code"] == APIErrorCode.RATE_LIMIT_EXCEEDED.value
    assert data["retryable"] is True
    assert "Retry-After" in response.headers
    assert int(response.headers["Retry-After"]) > 0


# ---------------------------------------------------------------------------
# Test 15: Correlation ID Propagation Across Request, Headers & Error Bodies
# ---------------------------------------------------------------------------

def test_15_correlation_id_propagation(client: TestClient):
    """
    X-Request-ID and X-Correlation-ID headers must be preserved and reflected in
    response headers and standardized error response models.
    """
    custom_corr_id = "corr-uuid-777-888-999"
    headers = {"X-Request-ID": custom_corr_id}

    response = client.get("/api/v1/projects", headers=headers)
    assert response.headers.get("X-Request-ID") == custom_corr_id
    assert response.headers.get("X-Correlation-ID") == custom_corr_id

    # Error body must also contain the exact correlation ID
    data = response.json()
    assert data["request_id"] == custom_corr_id


# ---------------------------------------------------------------------------
# Test 16: Automated Contract Verification Script Passes with Zero Drift
# ---------------------------------------------------------------------------

def test_16_contract_verification_script_runs_clean():
    """
    Executing scripts/verify_api_contracts.py must confirm 100% route matching
    and enum synchronicity between backend OpenAPI spec and frontend TypeScript client.
    """
    repo_root = Path(__file__).resolve().parents[2]
    script_path = repo_root / "scripts" / "verify_api_contracts.py"

    proc = subprocess.run(
        [sys.executable, str(script_path)],
        cwd=str(repo_root),
        capture_output=True,
        text=True,
    )

    assert proc.returncode == 0, f"Contract verification script failed: {proc.stderr}\n{proc.stdout}"
    assert "CONTRACT VERIFICATION RESULT: PASSED" in proc.stdout
    assert "Route matching:" in proc.stdout and "verified" in proc.stdout


# ---------------------------------------------------------------------------
# Test 17: Tenant Isolation Fails Closed (404) on Cross-Project Access
# ---------------------------------------------------------------------------

def test_17_fail_closed_project_isolation(
    client: TestClient,
    db: Session,
    tester_user: User,
    test_project: Project,
    test_organization: Organization,
):
    """
    User belonging only to Project A attempting to access Project B's endpoints
    must receive HTTP 404 (Fail Closed) without leaking Project B's existence.
    """
    # Create isolated Project B that tester_user is NOT a member of
    proj_b = Project(
        name="Project Secret Beta",
        organization_id=test_organization.id,
        is_active=True,
    )
    db.add(proj_b)
    db.commit()
    db.refresh(proj_b)

    headers = auth_headers(tester_user, "test-req-isolate-001")

    # Attempt to access Project B's findings
    response = client.get(f"/api/v1/projects/{proj_b.id}/findings", headers=headers)
    assert response.status_code == 404
    data = response.json()
    assert data["error_code"] == APIErrorCode.RESOURCE_NOT_FOUND.value
    assert data["detail"] == "Project not found"
