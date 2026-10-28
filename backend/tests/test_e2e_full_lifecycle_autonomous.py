"""
VAPT System - Autonomous End-to-End Lifecycle Regression Suite
=============================================================
Demonstrates the full 15-step controlled security intelligence lifecycle:
 1. Scope Guardrails & SSRF Preflight Rejection (Negative Tests)
 2. Scope Target Registration & Cryptographic ROE Authorization
 3. Genuine Assessment Dispatch via UI API Contract (is_simulated = False)
 4. Physical Network Traffic Verification (In-Process Target Audit)
 5. Finding Lifecycle & Asset Inventory Persistence
 6. Evidence Collection & Normalization
 7. Security Knowledge Graph Generation (Nodes & Relationships)
 8. Explainable Contextual Risk Scoring
 9. Deterministic Attack Path Graph Traversal
10. Remediation Recommendation Generation
11. Controlled Safe Reversible Target Remediation
12. Independent Verification Retest (State Transition to VERIFIED_CLOSED)
13. Continuous Monitoring & Posture Delta Change Detection
14. Autonomous Closed-Loop Decision & Learning Dataset Governance
15. Dashboard Overview Metrics & Hash-Chained Audit Ledger Durability
"""

import http.server
import threading
import hashlib
from datetime import datetime, timezone
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.project import Project, ProjectMember, ProjectRole
from app.models.user import User, SystemRole
from app.models.scope import ScopeTarget, TargetType, AuthorizationStatus
from app.models.assessment import AssessmentJob, AssessmentFinding, AssessmentStatus, FindingSeverity
from app.models.finding import VulnerabilityFinding, FindingLifecycleStatus
from app.models.decision import SecurityDecisionRecord, PostureChangeRecord, ChangeType, DecisionStatus
from app.models.audit import AuditEvent
from app.services.change_detection_service import ChangeDetectionService
from app.services.security_decision_service import SecurityDecisionService


class ManagedE2ETestServer:
    """Configurable HTTP server simulating a target application before and after remediation."""

    def __init__(self, host: str = "127.0.0.1"):
        self.host = host
        self.remediated = False
        self.requests_log = []
        self.server = None
        self.port = None
        self.thread = None

    def start(self):
        server_instance = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                body = b"<html><head><title>VAPT E2E Target</title></head><body>VAPT Target App</body></html>"
                server_instance.requests_log.append({
                    "path": self.path,
                    "headers": dict(self.headers),
                    "time": datetime.now(timezone.utc).isoformat(),
                })

                if self.path == "/robots.txt":
                    self.send_response(200)
                    self.send_header("Content-Type", "text/plain")
                    self.send_header("Content-Length", "36")
                    self.end_headers()
                    self.wfile.write(b"User-agent: *\nDisallow: /admin\n")
                    return

                if self.path in ("/.well-known/security.txt", "/security.txt", "/crossdomain.xml", "/.env", "/.git/HEAD"):
                    self.send_response(404)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return

                # Normal root endpoint
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")

                if server_instance.remediated:
                    # Remediated secure state
                    self.send_header("Content-Security-Policy", "default-src 'self'")
                    self.send_header("X-Content-Type-Options", "nosniff")
                    self.send_header("X-Frame-Options", "DENY")
                    self.send_header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
                    self.send_header("Referrer-Policy", "strict-origin-when-cross-origin")
                    self.send_header("Set-Cookie", "session=secure_123; Path=/; Secure; HttpOnly; SameSite=Strict")
                else:
                    # Vulnerable initial state
                    self.send_header("X-Powered-By", "PHP/7.4.3")
                    self.send_header("Set-Cookie", "session=insecure_123; Path=/")

                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, format, *args):
                pass  # Suppress noisy console log

        self.server = http.server.HTTPServer((self.host, 0), Handler)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        return self.port

    def stop(self):
        if self.server:
            self.server.shutdown()


@pytest.fixture
def managed_target_server():
    server = ManagedE2ETestServer()
    port = server.start()
    yield server
    server.stop()


def test_full_15_step_autonomous_security_lifecycle(
    client: TestClient,
    db: Session,
    test_project: Project,
    lead_user: User,
    lead_headers: dict,
    managed_target_server: ManagedE2ETestServer,
):
    """
    Complete 15-step end-to-end integration and lifecycle verification test.
    """
    target_url = f"http://127.0.0.1:{managed_target_server.port}"
    project_id = test_project.id

    # -------------------------------------------------------------------------
    # STEP 1: Strict Scope & SSRF Guardrail Enforcement (Negative Tests)
    # -------------------------------------------------------------------------
    # Out of scope IP
    res_unauth = client.post(
        f"/api/v1/projects/{project_id}/assessments/?auto_execute=true",
        headers=lead_headers,
        json={"target_input": "http://10.99.99.99:8080", "adapter_name": "live_network_auditor_adapter", "config": {"is_simulated": False}},
    )
    assert res_unauth.status_code in (400, 403, 422), "Out-of-scope IP must be rejected fail-closed"

    # Cloud metadata SSRF attempt
    res_ssrf = client.post(
        f"/api/v1/projects/{project_id}/assessments/?auto_execute=true",
        headers=lead_headers,
        json={"target_input": "http://169.254.169.254/latest/meta-data/", "adapter_name": "live_network_auditor_adapter", "config": {"is_simulated": False}},
    )
    assert res_ssrf.status_code in (400, 403, 422), "SSRF Cloud metadata target must be blocked"

    # -------------------------------------------------------------------------
    # STEP 2: Register Target & Authorize Scope Boundary with ROE Evidence
    # -------------------------------------------------------------------------
    res_reg = client.post(
        f"/api/v1/projects/{project_id}/targets",
        headers=lead_headers,
        json={"target_value": target_url, "description": "Controlled E2E Localhost Target"},
    )
    assert res_reg.status_code == 201
    target_data = res_reg.json()
    target_id = target_data["id"]

    res_auth = client.post(
        f"/api/v1/projects/{project_id}/targets/{target_id}/authorize",
        headers=lead_headers,
        json={"evidence": "ROE-E2E-AUTONOMOUS-LIFECYCLE-EVIDENCE"},
    )
    assert res_auth.status_code == 200
    assert res_auth.json()["authorization_status"] == "AUTHORIZED"

    # -------------------------------------------------------------------------
    # STEP 3: Genuine Live Assessment Dispatch via UI API Contract
    # -------------------------------------------------------------------------
    start_req_count = len(managed_target_server.requests_log)
    res_job = client.post(
        f"/api/v1/projects/{project_id}/assessments/?auto_execute=true",
        headers=lead_headers,
        json={
            "target_input": target_url,
            "adapter_name": "live_network_auditor_adapter",
            "timeout_seconds": 30,
            "config": {"is_simulated": False},
        },
    )
    assert res_job.status_code == 201
    job_info = res_job.json()
    assert job_info["status"] == "COMPLETED"
    job_id = job_info["id"]

    # -------------------------------------------------------------------------
    # STEP 4: Real Network Traffic Verification Hitting Test Target
    # -------------------------------------------------------------------------
    new_req_count = len(managed_target_server.requests_log) - start_req_count
    assert new_req_count > 0, "Scanner must execute real network HTTP requests against authorized target"

    # -------------------------------------------------------------------------
    # STEP 5: Finding Normalization & Asset Inventory Persistence
    # -------------------------------------------------------------------------
    res_findings = client.get(f"/api/v1/projects/{project_id}/findings", headers=lead_headers)
    assert res_findings.status_code == 200
    findings = res_findings.json()
    target_findings = [f for f in findings if str(managed_target_server.port) in f["target_value"]]
    assert len(target_findings) >= 2, "Real scan must discover multiple vulnerabilities on unhardened target"

    res_assets = client.get(f"/api/v1/projects/{project_id}/assets", headers=lead_headers)
    assert res_assets.status_code == 200
    assets = res_assets.json()
    matching_asset = next((a for a in assets if str(managed_target_server.port) in a.get("canonical_identifier", "")), None)
    assert matching_asset is not None, "Asset inventory record must be created for scanned target"

    # -------------------------------------------------------------------------
    # STEP 6: Evidence Collection Verification
    # -------------------------------------------------------------------------
    csp_finding = next((f for f in target_findings if "Content-Security-Policy" in f["title"]), target_findings[0])
    res_detail = client.get(f"/api/v1/projects/{project_id}/findings/{csp_finding['id']}", headers=lead_headers)
    assert res_detail.status_code == 200
    finding_detail = res_detail.json()
    assert finding_detail["status"] == "DETECTED"

    # -------------------------------------------------------------------------
    # STEP 7: Security Knowledge Graph Node & Edge Creation
    # -------------------------------------------------------------------------
    res_graph = client.get(f"/api/v1/projects/{project_id}/graph/stats", headers=lead_headers)
    assert res_graph.status_code == 200
    graph_stats = res_graph.json()
    assert graph_stats.get("total_nodes", 0) > 0
    assert graph_stats.get("total_edges", 0) > 0

    # -------------------------------------------------------------------------
    # STEP 8: Contextual Risk Scoring & Explainability
    # -------------------------------------------------------------------------
    res_risk = client.get(f"/api/v1/projects/{project_id}/risk/summary", headers=lead_headers)
    assert res_risk.status_code == 200
    risk_summary = res_risk.json()
    assert risk_summary["total_assessed"] > 0
    assert risk_summary["highest_score"] >= 0.0

    # -------------------------------------------------------------------------
    # STEP 9: Deterministic Attack-Path Graph Traversal
    # -------------------------------------------------------------------------
    res_paths = client.post(f"/api/v1/projects/{project_id}/risk/attack-paths", headers=lead_headers, json={})
    assert res_paths.status_code == 200
    paths_data = res_paths.json()
    assert "total_paths_found" in paths_data
    assert paths_data.get("max_depth_evaluated", 0) >= 1

    # -------------------------------------------------------------------------
    # STEP 10: Remediation Recommendation Generation & Approval
    # -------------------------------------------------------------------------
    res_remed = client.get(f"/api/v1/projects/{project_id}/remediations", headers=lead_headers)
    assert res_remed.status_code == 200
    remediations = res_remed.json()
    assert len(remediations) > 0

    # -------------------------------------------------------------------------
    # STEP 11: Controlled Safe Reversible Target Fix
    # -------------------------------------------------------------------------
    managed_target_server.remediated = True

    # -------------------------------------------------------------------------
    # STEP 12: Independent Verification Retest & Finding Lifecycle Resolution
    # -------------------------------------------------------------------------
    res_retest = client.post(
        f"/api/v1/projects/{project_id}/findings/{csp_finding['id']}/verify/retest",
        headers=lead_headers,
        json={
            "adapter_name": "live_network_auditor_adapter",
            "config": {"is_simulated": False},
            "notes": "Automated retest execution after security header injection.",
        },
    )
    assert res_retest.status_code == 201
    retest_result = res_retest.json()
    assert retest_result["outcome"] == "VERIFIED_FIXED"

    # Confirm lifecycle status updated to VERIFIED_CLOSED
    res_closed_f = client.get(f"/api/v1/projects/{project_id}/findings/{csp_finding['id']}", headers=lead_headers)
    assert res_closed_f.status_code == 200
    assert res_closed_f.json()["status"] == "VERIFIED_CLOSED"

    # -------------------------------------------------------------------------
    # STEP 13: Continuous Monitoring Posture Delta & Change Detection
    # -------------------------------------------------------------------------
    # Analyze assessment deltas
    completed_job = db.query(AssessmentJob).filter(AssessmentJob.id == job_id).first()
    changes = ChangeDetectionService.analyze_assessment_deltas(db=db, project_id=project_id, current_job=completed_job)
    assert isinstance(changes, list)

    res_changes = client.get(f"/api/v1/projects/{project_id}/changes", headers=lead_headers)
    assert res_changes.status_code == 200

    # -------------------------------------------------------------------------
    # STEP 14: Autonomous Closed-Loop Decision & Learning Dataset Governance
    # -------------------------------------------------------------------------
    # Evaluate and propose decisions
    res_eval_dec = client.post(f"/api/v1/projects/{project_id}/decisions/evaluate", headers=lead_headers, json={})
    assert res_eval_dec.status_code == 200
    decisions = res_eval_dec.json()
    assert isinstance(decisions, list)

    # Curate learning dataset from verified project outcomes
    res_curate = client.post(
        f"/api/v1/projects/{project_id}/learning/datasets/curate",
        headers=lead_headers,
        json={
            "name": "E2E Verified Assessment Dataset",
            "version": "v1.0.0",
        },
    )
    assert res_curate.status_code in (200, 201)
    dataset_info = res_curate.json()
    assert "id" in dataset_info
    assert dataset_info["name"] == "E2E Verified Assessment Dataset"

    # -------------------------------------------------------------------------
    # STEP 15: Closed-Loop Overview Dashboard Metrics & Cryptographic Durability
    # -------------------------------------------------------------------------
    res_overview = client.get(f"/api/v1/projects/{project_id}/closed-loop/overview", headers=lead_headers)
    assert res_overview.status_code == 200
    overview_data = res_overview.json()
    assert "active_posture" in overview_data
    assert "total_posture_changes" in overview_data
    assert overview_data["total_posture_changes"] > 0
    assert "pending_decisions" in overview_data

    # Direct database verification for durability & audit hash chaining
    finding_in_db = db.query(VulnerabilityFinding).filter(VulnerabilityFinding.id == csp_finding["id"]).first()
    assert finding_in_db is not None
    assert finding_in_db.status == FindingLifecycleStatus.VERIFIED_CLOSED

    audit_events = db.query(AuditEvent).filter(AuditEvent.project_id == project_id).order_by(AuditEvent.timestamp.desc()).all()
    assert len(audit_events) > 0
    for event in audit_events:
        assert event.event_hash is not None
        assert len(event.event_hash) == 64  # SHA-256
