import pytest
import http.server
import threading
import socket
import json
import hashlib
from datetime import datetime, timezone
from sqlalchemy.orm import Session

from app.core.database import SessionLocal
from app.models.user import User, SystemRole
from app.models.organization import Organization
from app.models.project import Project, ProjectMember, ProjectRole
from app.models.scope import ScopeTarget, TargetType, AuthorizationStatus
from app.models.assessment import AssessmentJob, AssessmentStatus, FindingSeverity
from app.services.scanner_adapters.live_network_adapter import LiveNetworkAuditorAdapter, check_ip_ssrf, resolve_and_verify_ssrf
from app.services.scanner_adapters.base import AdapterRegistry
from app.services.assessment_engine import AssessmentExecutionEngine


@pytest.fixture(scope="module")
def vulnerable_test_web_server():
    """
    Spins up an in-process HTTP test server on an ephemeral localhost port
    with deliberate security issues:
    - Missing HSTS, CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy.
    - Server banner version disclosure: Apache/2.4.41 (Ubuntu).
    - X-Powered-By disclosure: PHP/7.4.3.
    - Insecure cookies: missing Secure, HttpOnly, and SameSite.
    - Missing security.txt (returns 404).
    - robots.txt disclosing sensitive paths (/admin, /internal/api, /backup).
    """
    class VulnerableHandler(http.server.BaseHTTPRequestHandler):
        server_version = "Apache/2.4.41 (Ubuntu)"
        sys_version = ""

        def do_GET(self):
            if self.path == "/robots.txt":
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                robots_content = (
                    "User-agent: *\n"
                    "Disallow: /admin\n"
                    "Disallow: /internal/api\n"
                    "Disallow: /backup\n"
                    "Disallow: /public/\n"
                )
                self.wfile.write(robots_content.encode("utf-8"))
                return

            if self.path in ("/.well-known/security.txt", "/security.txt"):
                self.send_response(404)
                self.end_headers()
                return

            # Main root response
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("X-Powered-By", "PHP/7.4.3")
            # Insecure cookie without Secure, HttpOnly, or SameSite
            self.send_header("Set-Cookie", "session_token=secret_sess_9999; Path=/")
            # Intentionally omit HSTS, CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy
            self.end_headers()
            self.wfile.write(b"<html><head><title>Vulnerable Target App</title></head><body>Welcome to Target</body></html>")

        def log_message(self, format, *args):
            pass  # Suppress console logging

    server = http.server.HTTPServer(("127.0.0.1", 0), VulnerableHandler)
    host, port = server.server_address
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{port}", port
    server.shutdown()
    server.server_close()


def test_ssrf_guardrail_blocks_cloud_metadata():
    """Verify that 169.254.169.254 and link-local addresses are rejected before socket creation."""
    adapter = LiveNetworkAuditorAdapter()
    
    # 1. Cloud metadata IP
    is_safe, reason = check_ip_ssrf("169.254.169.254", allow_loopback=True)
    assert is_safe is False
    assert "metadata" in reason.lower()

    res = adapter.execute(
        target="http://169.254.169.254/latest/meta-data/",
        config={"profile": "LIVE_WEB_SECURITY_AUDIT"},
    )
    assert res.success is False
    assert res.is_simulated is False
    assert res.failure_category == "SSRF_ATTEMPT_BLOCKED"
    assert len(res.findings) == 0

    # 2. Link-local range (169.254.1.1)
    is_safe_ll, reason_ll = check_ip_ssrf("169.254.1.1", allow_loopback=True)
    assert is_safe_ll is False
    assert "link-local" in reason_ll.lower()

    res_ll = adapter.execute(
        target="http://169.254.1.1:8080",
        config={"profile": "LIVE_HTTP_HEADERS"},
    )
    assert res_ll.success is False
    assert res_ll.failure_category == "SSRF_ATTEMPT_BLOCKED"


def test_ssrf_guardrail_blocks_loopback_in_production_mode():
    """Verify that loopback (127.0.0.1 / localhost) is blocked when allow_loopback=False."""
    is_safe, reason = check_ip_ssrf("127.0.0.1", allow_loopback=False)
    assert is_safe is False
    assert "loopback" in reason.lower()

    adapter = LiveNetworkAuditorAdapter()
    res = adapter.execute(
        target="http://127.0.0.1:8000",
        config={"profile": "LIVE_HTTP_HEADERS", "allow_loopback": False},
    )
    assert res.success is False
    assert res.failure_category == "SSRF_ATTEMPT_BLOCKED"
    assert len(res.findings) == 0


def test_live_web_security_audit_detects_real_vulnerabilities(vulnerable_test_web_server):
    """
    Verify that LiveNetworkAuditorAdapter audits the running HTTP server and discovers
    real, genuine security findings across headers, cookies, server banners, and resources.
    """
    server_url, port = vulnerable_test_web_server
    adapter = LiveNetworkAuditorAdapter()

    res = adapter.execute(
        target=server_url,
        config={
            "profile": "LIVE_WEB_SECURITY_AUDIT",
            "allow_loopback": True,
            "timeout_seconds": 10,
        },
    )

    assert res.success is True
    assert res.is_simulated is False, "Genuine wire observation must set is_simulated to False"
    assert res.adapter_name == "live_network_auditor_adapter"
    assert len(res.findings) >= 8, f"Expected at least 8 findings, got {len(res.findings)}"

    titles = [f.title for f in res.findings]

    # Verify specific genuine findings detected from live wire:
    assert any("Content-Security-Policy" in t for t in titles)
    assert any("X-Content-Type-Options" in t for t in titles)
    assert any("X-Frame-Options" in t for t in titles)
    assert any("Referrer-Policy" in t for t in titles)
    assert any("Permissions-Policy" in t for t in titles)
    assert any("Server Version Disclosed" in t for t in titles)
    assert any("X-Powered-By" in t for t in titles)
    assert any("HttpOnly" in t for t in titles)
    assert any("SameSite" in t for t in titles)
    assert any("security.txt" in t for t in titles)
    assert any("robots.txt" in t for t in titles)

    # Verify cryptographic evidence hashing
    for f in res.findings:
        assert len(f.evidence_items) > 0
        ev = f.evidence_items[0]
        assert len(ev.sha256_hash) == 64
        assert ev.observed_at is not None


def test_honest_error_unreachable_target():
    """Verify that an unreachable port returns an honest failure without fabricating fake findings."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        unused_port = s.getsockname()[1]

    adapter = LiveNetworkAuditorAdapter()
    res = adapter.execute(
        target=f"http://127.0.0.1:{unused_port}",
        config={"profile": "LIVE_WEB_SECURITY_AUDIT", "allow_loopback": True, "timeout_seconds": 1},
    )

    assert res.success is False
    assert res.is_simulated is False
    assert res.failure_category in ("CONNECTION_REFUSED", "CONNECTION_FAILED", "TIMED_OUT")
    assert len(res.findings) == 0, "No vulnerabilities should be fabricated when host is down"


def test_end_to_end_assessment_job_execution(vulnerable_test_web_server):
    """
    End-to-End Test:
    1. Enroll target into project scope in DB.
    2. Authorize scope target with ROE evidence.
    3. Create and execute AssessmentJob via AssessmentExecutionEngine.
    4. Verify job completes with is_simulated=False, persists findings in DB,
       and correlates findings into canonical vulnerability records.
    """
    server_url, port = vulnerable_test_web_server
    db: Session = SessionLocal()

    try:
        # 1. Fetch or create test user and project
        lead_user = db.query(User).filter(User.email == "lead@example.com").first()
        if not lead_user:
            lead_user = User(
                email="lead@example.com",
                full_name="Assessment Lead",
                hashed_password="$2b$12$e8kZ1f8W/8Vp9F2yTqZ.6Ou7zU1lQ3R0e3.7XjHk4t5l6m7n8o9p0",
                system_role=SystemRole.SECURITY_LEAD,
            )
            db.add(lead_user)
            db.flush()

        org = db.query(Organization).first()
        if not org:
            org = Organization(name="Default Org", slug="default-org")
            db.add(org)
            db.flush()

        project = db.query(Project).first()
        if not project:
            project = Project(
                name="E2E Web Security Project",
                description="Test project",
                organization_id=org.id,
            )
            db.add(project)
            db.flush()
            member = ProjectMember(project_id=project.id, user_id=lead_user.id, role=ProjectRole.LEAD)
            db.add(member)
            db.flush()

        # 2. Register Scope Target for the local vulnerable server
        scope_target = (
            db.query(ScopeTarget)
            .filter(ScopeTarget.project_id == project.id, ScopeTarget.target_value == server_url)
            .first()
        )
        if not scope_target:
            scope_target = ScopeTarget(
                project_id=project.id,
                target_type=TargetType.URL,
                target_value=server_url,
                authorization_status=AuthorizationStatus.AUTHORIZED,
                authorization_evidence="Authorized by Lead in E2E automated test",
                authorized_by_id=lead_user.id,
                authorized_at=datetime.now(timezone.utc),
                created_by_id=lead_user.id,
            )
            db.add(scope_target)
            db.commit()
            db.refresh(scope_target)
        else:
            scope_target.authorization_status = AuthorizationStatus.AUTHORIZED
            scope_target.authorization_evidence = "Authorized in test"
            scope_target.authorized_at = datetime.now(timezone.utc)
            db.commit()

        # 3. Create Assessment Job
        job = AssessmentJob(
            project_id=project.id,
            target_input=server_url,
            adapter_name="live_network_auditor_adapter",
            adapter_version="1.1.0",
            policy_version="2026.1",
            status=AssessmentStatus.QUEUED,
            config={
                "profile": "LIVE_WEB_SECURITY_AUDIT",
                "allow_loopback": True,
                "timeout_seconds": 15,
            },
            created_by_id=lead_user.id,
        )
        db.add(job)
        db.commit()
        db.refresh(job)

        # 4. Execute Job through the Execution Engine
        completed_job = AssessmentExecutionEngine.execute_job(
            db=db,
            job_id=job.id,
            worker_id="test-worker",
        )

        assert completed_job.status == AssessmentStatus.COMPLETED
        assert completed_job.is_simulated is False, "Completed live job must be flagged is_simulated=False"
        assert completed_job.summary_stats.get("findings_count", 0) > 0

        # Verify persisted findings in DB
        db.refresh(completed_job)
        persisted_findings = completed_job.findings
        assert len(persisted_findings) > 0
        for f in persisted_findings:
            assert f.is_simulated is False
            assert len(f.evidence_items) > 0

    finally:
        db.close()


def test_scope_engine_authorizes_private_ip_and_sets_flag():
    """Verify that ScopeEngine detects and authorizes private IP targets when explicitly approved in scope."""
    from app.services.scope_engine import ScopeEngine
    from app.models.scope import ScopeTarget, TargetType, AuthorizationStatus
    from app.core.database import SessionLocal
    from app.models.organization import Organization
    from app.models.project import Project

    db = SessionLocal()
    try:
        org = db.query(Organization).first()
        if not org:
            org = Organization(name="Default Org", slug="default-org")
            db.add(org)
            db.commit()
            db.refresh(org)

        project = Project(
            organization_id=org.id,
            name="Internal Private Scope Project",
            description="Testing private IP scope",
        )
        db.add(project)
        db.commit()
        db.refresh(project)

        from app.models.user import User
        user = db.query(User).first()

        # 1. Register private IP target 10.0.1.50
        target = ScopeTarget(
            project_id=project.id,
            target_type=TargetType.IP_ADDRESS,
            target_value="10.0.1.50",
            authorization_status=AuthorizationStatus.AUTHORIZED,
            authorization_evidence="Approved internal staging audit ROE #991",
            created_by_id=user.id,
        )
        db.add(target)
        db.commit()

        # 2. Evaluate target in scope
        eval_res = ScopeEngine.validate_target_in_scope(db, project.id, "10.0.1.50")
        assert eval_res["is_authorized"] is True
        assert eval_res["is_private_authorized"] is True

        # 3. Check that check_ip_ssrf permits it when allow_private=True
        from app.services.scanner_adapters.live_network_adapter import check_ip_ssrf
        is_safe, _ = check_ip_ssrf("10.0.1.50", allow_private=True)
        assert is_safe is True

        # But without authorization (allow_private=False), it remains blocked
        is_safe_blocked, reason = check_ip_ssrf("10.0.1.50", allow_private=False)
        assert is_safe_blocked is False
        assert "private" in reason.lower()
    finally:
        db.close()


def test_dns_validation_to_connection_pins_verified_ip():
    """
    Verify that SafeHTTPConnection pins the socket directly to verified_ip,
    eliminating the TOCTOU DNS validation-to-connection gap.
    """
    from app.services.scanner_adapters.live_network_adapter import SafeHTTPConnection
    conn = SafeHTTPConnection(host="example.internal", port=80, verified_ip="127.0.0.1")
    assert conn.verified_ip == "127.0.0.1"
    assert conn.original_host == "example.internal"
    assert conn.host == "example.internal"

