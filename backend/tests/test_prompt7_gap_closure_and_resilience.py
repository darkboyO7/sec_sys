"""
Prompt 7: Comprehensive Gap Closure, New Responsible Scanner Checks, and Failure Resilience Tests.
Validates:
1. Responsible new security checks: TRACE method, password field over HTTP, .git/HEAD exposure, .env exposure, crossdomain.xml wildcard.
2. Failure and recovery resilience: target unreachable, redirect SSRF boundary, stale worker recovery, duplicate claim safety, inconclusive verification.
"""

import http.server
import threading
import pytest
from datetime import datetime, timezone, timedelta
from sqlalchemy.orm import Session

from app.models.user import User, SystemRole
from app.models.organization import Organization
from app.models.project import Project, ProjectMember, ProjectRole
from app.models.scope import ScopeTarget, TargetType, AuthorizationStatus
from app.models.assessment import AssessmentJob, AssessmentStatus, FindingSeverity, FindingConfidence
from app.models.finding import VulnerabilityFinding, FindingLifecycleStatus
from app.models.verification import RemediationVerification, VerificationOutcome, VerificationMethod
from app.services.scanner_adapters.live_network_adapter import (
    LiveNetworkAuditorAdapter,
    BoundedRedirectHandler,
    check_ip_ssrf,
)
from app.services.assessment_engine import AssessmentExecutionEngine
from app.services.remediation_verification_service import RemediationVerificationService
from app.services.scope_engine import ScopeEngine


@pytest.fixture(scope="module")
def extended_vuln_server():
    """
    Test HTTP server demonstrating the new detected security risks:
    - OPTIONS method returning Allow with TRACE
    - Cleartext password input in HTML body
    - /.git/HEAD exposure with valid ref: refs/heads/main
    - /.env exposure with DB_PASSWORD and SECRET_KEY
    - /crossdomain.xml with wildcard domain="*"
    """
    class ExtendedVulnHandler(http.server.BaseHTTPRequestHandler):
        def do_OPTIONS(self):
            self.send_response(200)
            self.send_header("Allow", "GET, POST, OPTIONS, TRACE")
            self.send_header("Content-Length", "0")
            self.end_headers()

        def do_GET(self):
            if self.path == "/.git/HEAD":
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(b"ref: refs/heads/main\n")))
                self.end_headers()
                self.wfile.write(b"ref: refs/heads/main\n")
                return

            if self.path == "/.env":
                env_body = b"APP_ENV=production\nDB_PASSWORD=SuperSecretPass123!\nSECRET_KEY=k9f023j0f2\n"
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(env_body)))
                self.end_headers()
                self.wfile.write(env_body)
                return

            if self.path == "/crossdomain.xml":
                cd_body = b'<?xml version="1.0"?><cross-domain-policy><allow-access-from domain="*" /></cross-domain-policy>'
                self.send_response(200)
                self.send_header("Content-Type", "application/xml")
                self.send_header("Content-Length", str(len(cd_body)))
                self.end_headers()
                self.wfile.write(cd_body)
                return

            if self.path == "/robots.txt":
                robots_body = b"User-agent: *\nDisallow: /admin\n"
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(robots_body)))
                self.end_headers()
                self.wfile.write(robots_body)
                return

            # Default root response with cleartext password form
            root_body = (
                b"<html><body><h2>Login</h2>"
                b"<form action='/login' method='POST'>"
                b"<input type='text' name='username'>"
                b"<input type='password' name='user_password'>"
                b"<button type='submit'>Sign In</button>"
                b"</form></body></html>"
            )
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(root_body)))
            self.end_headers()
            self.wfile.write(root_body)

        def log_message(self, format, *args):
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), ExtendedVulnHandler)
    host, port = server.server_address
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{port}", port
    server.shutdown()
    server.server_close()


# ==============================================================================
# SECTION 1: NEW RESPONSIBLE CHECK DETECTIONS
# ==============================================================================

def test_options_trace_method_detection(extended_vuln_server):
    """Verify that HTTP OPTIONS probe detects TRACE method and reports CWE-200 / XST risk."""
    server_url, _ = extended_vuln_server
    adapter = LiveNetworkAuditorAdapter()
    res = adapter.execute(
        target=server_url,
        config={"profile": "LIVE_HTTP_HEADERS", "allow_loopback": True},
    )
    assert res.success is True
    titles = [f.title for f in res.findings]
    assert any("Insecure HTTP Method Enabled: TRACE" in t for f in res.findings for t in [f.title]), f"Got: {titles}"
    trace_f = next(f for f in res.findings if "TRACE" in f.title)
    assert trace_f.severity == FindingSeverity.MEDIUM
    assert trace_f.vuln_id == "CWE-200"


def test_cleartext_password_form_detection(extended_vuln_server):
    """Verify that cleartext password inputs on unencrypted HTTP are flagged as HIGH severity (CWE-319)."""
    server_url, _ = extended_vuln_server
    adapter = LiveNetworkAuditorAdapter()
    res = adapter.execute(
        target=server_url,
        config={"profile": "LIVE_HTTP_HEADERS", "allow_loopback": True},
    )
    assert res.success is True
    pw_findings = [f for f in res.findings if "Cleartext Transmission of Sensitive Password Field" in f.title]
    assert len(pw_findings) == 1
    assert pw_findings[0].severity == FindingSeverity.HIGH
    assert pw_findings[0].vuln_id == "CWE-319"


def test_exposed_git_head_detection(extended_vuln_server):
    """Verify that /.git/HEAD exposure with valid git ref is detected as HIGH severity (CWE-538)."""
    server_url, _ = extended_vuln_server
    adapter = LiveNetworkAuditorAdapter()
    res = adapter.execute(
        target=server_url,
        config={"profile": "LIVE_SECURITY_RESOURCES", "allow_loopback": True},
    )
    assert res.success is True
    git_findings = [f for f in res.findings if ".git/HEAD" in f.title]
    assert len(git_findings) == 1
    assert git_findings[0].severity == FindingSeverity.HIGH
    assert git_findings[0].vuln_id == "CWE-538"
    assert "ref: refs/heads/main" in git_findings[0].evidence_items[0].payload


def test_exposed_env_configuration_detection(extended_vuln_server):
    """Verify that /.env exposure is detected as CRITICAL (CWE-552) with secret values redacted."""
    server_url, _ = extended_vuln_server
    adapter = LiveNetworkAuditorAdapter()
    res = adapter.execute(
        target=server_url,
        config={"profile": "LIVE_SECURITY_RESOURCES", "allow_loopback": True},
    )
    assert res.success is True
    env_findings = [f for f in res.findings if "Environment Configuration (.env)" in f.title]
    assert len(env_findings) == 1
    assert env_findings[0].severity == FindingSeverity.CRITICAL
    assert env_findings[0].vuln_id == "CWE-552"
    payload = env_findings[0].evidence_items[0].payload
    assert "DB_PASSWORD=[REDACTED]" in payload
    assert "SuperSecretPass123!" not in payload  # Secret value must NEVER be leaked in evidence payload


def test_permissive_crossdomain_xml_detection(extended_vuln_server):
    """Verify that /crossdomain.xml with wildcard domain='*' is detected as MEDIUM (CWE-942)."""
    server_url, _ = extended_vuln_server
    adapter = LiveNetworkAuditorAdapter()
    res = adapter.execute(
        target=server_url,
        config={"profile": "LIVE_SECURITY_RESOURCES", "allow_loopback": True},
    )
    assert res.success is True
    cd_findings = [f for f in res.findings if "crossdomain.xml Wildcard" in f.title]
    assert len(cd_findings) == 1
    assert cd_findings[0].severity == FindingSeverity.MEDIUM
    assert cd_findings[0].vuln_id == "CWE-942"


# ==============================================================================
# SECTION 2: FAILURE AND RECOVERY RESILIENCE VALIDATIONS
# ==============================================================================

def test_failure_target_unavailable_reports_honest_failure_and_zero_findings():
    """Verify that scanning a non-existent port reports CONNECTION_REFUSED, success=False, and 0 findings."""
    adapter = LiveNetworkAuditorAdapter()
    # Ephemeral unused high port on loopback
    res = adapter.execute(
        target="http://127.0.0.1:59998",
        config={"profile": "LIVE_HTTP_HEADERS", "allow_loopback": True, "timeout_seconds": 2},
    )
    assert res.success is False
    assert len(res.findings) == 0
    assert res.failure_category in ("CONNECTION_REFUSED", "CONNECTION_FAILED", "TIMED_OUT")


def test_failure_redirect_to_restricted_destination_aborts():
    """Verify that BoundedRedirectHandler aborts when target attempts redirect to cloud metadata IP."""
    handler = BoundedRedirectHandler(
        target_host="target.example.com",
        allow_loopback=False,
        allow_private=False,
        max_redirects=3,
    )
    # Redirecting to AWS metadata
    with pytest.raises(Exception) as exc_info:
        handler.redirect_request(
            req=None,
            fp=None,
            code=302,
            msg="Found",
            headers={},
            newurl="http://169.254.169.254/latest/meta-data/",
        )
    assert "blocked" in str(exc_info.value).lower() or "403" in str(exc_info.value)


def test_failure_stale_worker_recovery(db, test_project, lead_user):
    """Verify that abandoned jobs in RUNNING state beyond heartbeat timeout are recovered to FAILED."""
    # Job stuck in RUNNING with heartbeat from 10 minutes ago
    ten_minutes_ago = datetime.now(timezone.utc) - timedelta(minutes=10)
    stuck_job = AssessmentJob(
        project_id=test_project.id,
        created_by_id=lead_user.id,
        target_input="http://127.0.0.1:8080",
        adapter_name="live_network_auditor_adapter",
        status=AssessmentStatus.RUNNING,
        claimed_by="abandoned-worker-999",
        started_at=ten_minutes_ago,
        heartbeat_at=ten_minutes_ago,
    )
    db.add(stuck_job)
    db.commit()

    recovered = AssessmentExecutionEngine.recover_stale_workers(
        db=db,
        heartbeat_timeout_seconds=60,
    )
    db.refresh(stuck_job)

    assert stuck_job.id in [j.id for j in recovered]
    # Stale workers are self-healed by resetting the job to QUEUED and releasing worker claims
    assert stuck_job.status == AssessmentStatus.QUEUED
    assert stuck_job.claimed_by is None


def test_failure_duplicate_job_claim_is_mutually_exclusive(db, test_project, lead_user):
    """Verify that two workers attempting to claim the same queued job cannot both succeed."""
    queued_job = AssessmentJob(
        project_id=test_project.id,
        created_by_id=lead_user.id,
        target_input="http://127.0.0.1:8080",
        adapter_name="live_network_auditor_adapter",
        status=AssessmentStatus.QUEUED,
    )
    db.add(queued_job)
    db.commit()

    # Worker 1 claims
    job1 = AssessmentExecutionEngine.claim_next_available_job(db=db, worker_id="worker-alpha")
    assert job1 is not None
    assert job1.id == queued_job.id
    assert job1.status == AssessmentStatus.PREFLIGHT
    assert job1.claimed_by == "worker-alpha"

    # Worker 2 attempts to claim while Alpha is running
    job2 = AssessmentExecutionEngine.claim_next_available_job(db=db, worker_id="worker-beta")
    # Must be None because no other queued jobs exist
    assert job2 is None


def test_failure_inconclusive_verification_does_not_close_finding(db, test_project, lead_user):
    """Verify that an INCONCLUSIVE verification outcome never closes a finding."""
    finding = VulnerabilityFinding(
        project_id=test_project.id,
        fingerprint="test-inconclusive-fp-12345",
        target_value="http://127.0.0.1:8080",
        title="Test Inconclusive Finding",
        description="Testing inconclusive verification behavior",
        status=FindingLifecycleStatus.REMEDIATION_ATTEMPTED,
        severity=FindingSeverity.HIGH,
        confidence=FindingConfidence.CERTAIN,
    )
    db.add(finding)
    db.commit()

    # Record INCONCLUSIVE verification
    ver = RemediationVerificationService.record_verification(
        project_id=test_project.id,
        finding_id=finding.id,
        outcome=VerificationOutcome.INCONCLUSIVE,
        verification_criteria="Target must return HSTS max-age >= 31536000",
        verification_evidence_summary="Target timed out during verification scan",
        notes="Target was unreachable; verification could not be confirmed.",
        verifier=lead_user,
        verifier_role=ProjectRole.LEAD,
        db=db,
    )

    db.refresh(finding)
    # The finding MUST NOT be closed!
    assert finding.status != FindingLifecycleStatus.VERIFIED_CLOSED
    assert finding.status == FindingLifecycleStatus.REMEDIATION_ATTEMPTED
    assert "INCONCLUSIVE" in finding.verification_notes
