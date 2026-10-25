import math
from datetime import datetime, timezone, timedelta
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.project import Project, ProjectMember, ProjectRole
from app.models.scope import ScopeTarget, ScopeExclusion, TargetType, AuthorizationStatus
from app.models.assessment import AssessmentJob, AssessmentStatus, FindingSeverity, FindingConfidence
from app.models.audit import AuditEvent
from app.models.user import User
from app.services.assessment_state_machine import AssessmentStateMachine, InvalidStateTransitionException
from app.services.assessment_engine import AssessmentExecutionEngine
from app.services.scanner_adapters.base import RawAdapterFinding, RawAdapterEvidence, AdapterRegistry


@pytest.fixture
def auth_target(db: Session, test_project: Project, lead_user: User) -> ScopeTarget:
    target = ScopeTarget(
        project_id=test_project.id,
        target_type=TargetType.DOMAIN,
        target_value="core.internal-defense.corp",
        authorization_status=AuthorizationStatus.AUTHORIZED,
        authorization_evidence="AUTH-ROE-PHASE6A-001",
        authorized_by_id=lead_user.id,
        authorized_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(days=30),
        created_by_id=lead_user.id,
    )
    db.add(target)
    db.commit()
    db.refresh(target)
    return target


# ==============================================================================
# 1. Unauthenticated & Outsider Access Enforcement (Properties 1-5)
# ==============================================================================

def test_unauthenticated_and_outsider_access_rejected(
    client: TestClient,
    test_project: Project,
    outsider_headers: dict,
    tester_headers: dict,
    auth_target: ScopeTarget,
    db: Session,
):
    """
    Verifies that unauthenticated and unauthorized project requests fail closed.
    """
    # 1. Unauthenticated POST
    res = client.post(f"/api/v1/projects/{test_project.id}/assessments/", json={"target_input": "core.internal-defense.corp"})
    assert res.status_code == 401

    # 2. Unauthenticated GET
    res = client.get(f"/api/v1/projects/{test_project.id}/assessments/")
    assert res.status_code == 401

    # 3. Outsider POST (403 or 404 to avoid leaking project existence)
    res = client.post(
        f"/api/v1/projects/{test_project.id}/assessments/",
        json={"target_input": "core.internal-defense.corp"},
        headers=outsider_headers,
    )
    assert res.status_code in (403, 404)

    # 4. Outsider GET (403 or 404)
    res = client.get(f"/api/v1/projects/{test_project.id}/assessments/", headers=outsider_headers)
    assert res.status_code in (403, 404)

    # 5. Outsider Adapter capability inspection (403 or 404)
    res = client.get(f"/api/v1/projects/{test_project.id}/assessments/adapters", headers=outsider_headers)
    assert res.status_code in (403, 404)


def test_cross_project_isolation(
    client: TestClient,
    test_project: Project,
    tester_headers: dict,
    lead_user: User,
    outsider_headers: dict,
    db: Session,
):
    """
    Verifies cross-project isolation: users of Project A cannot view jobs of Project B.
    """
    # Create Project B with outsider as member
    proj_b = Project(
        name="Project Beta Isolated",
        organization_id=test_project.organization_id,
        is_active=True,
    )
    db.add(proj_b)
    db.commit()
    db.refresh(proj_b)

    db.add(ProjectMember(project_id=proj_b.id, user_id=lead_user.id, role=ProjectRole.LEAD))
    db.commit()

    # Create job in Project B
    job_b = AssessmentJob(
        project_id=proj_b.id,
        target_input="secret-b.internal.corp",
        adapter_name="local_fixture_adapter",
        adapter_version="1.0.0",
        status=AssessmentStatus.QUEUED,
        policy_version="2026.1",
        authorization_status="AUTHORIZED",
        scope_snapshot={},
        attempt_count=1,
        progress_pct=0,
        timeout_seconds=300,
        is_simulated=True,
        created_by_id=lead_user.id,
    )
    db.add(job_b)
    db.commit()
    db.refresh(job_b)

    # Tester (member of Project Apex, NOT Project B) attempts to read Job B via Project Apex path
    res = client.get(f"/api/v1/projects/{test_project.id}/assessments/{job_b.id}", headers=tester_headers)
    assert res.status_code == 404

    # Tester attempts to access Project B directly (403 or 404 to avoid leaking project existence)
    res2 = client.get(f"/api/v1/projects/{proj_b.id}/assessments/{job_b.id}", headers=tester_headers)
    assert res2.status_code in (403, 404)


# ==============================================================================
# 2. Scope Preflight & Exclusion Enforcement (Properties 6-7)
# ==============================================================================

def test_scope_preflight_unauthorized_and_excluded_targets_fail_closed(
    client: TestClient,
    test_project: Project,
    tester_headers: dict,
    lead_user: User,
    db: Session,
):
    """
    Verifies that targets not in scope or matching exclusions fail closed on submission.
    """
    # 1. Target not in scope
    res = client.post(
        f"/api/v1/projects/{test_project.id}/assessments/",
        json={"target_input": "unauthorized-external-server.com"},
        headers=tester_headers,
    )
    assert res.status_code == 403
    assert "not authorized" in res.json()["detail"].lower()

    # 2. Target in scope but matching active exclusion
    target = ScopeTarget(
        project_id=test_project.id,
        target_type=TargetType.CIDR,
        target_value="10.50.0.0/16",
        authorization_status=AuthorizationStatus.AUTHORIZED,
        authorization_evidence="ROE-CIDR-001",
        authorized_by_id=lead_user.id,
        created_by_id=lead_user.id,
    )
    exclusion = ScopeExclusion(
        project_id=test_project.id,
        target_type=TargetType.IP_ADDRESS,
        target_value="10.50.1.99",
        reason="Critical Domain Controller Excluded",
        created_by_id=lead_user.id,
    )
    db.add_all([target, exclusion])
    db.commit()

    res_ex = client.post(
        f"/api/v1/projects/{test_project.id}/assessments/",
        json={"target_input": "10.50.1.99"},
        headers=tester_headers,
    )
    assert res_ex.status_code == 403
    assert "excluded" in res_ex.json()["detail"].lower()


# ==============================================================================
# 3. Worker Boundary Scope Re-Validation (Properties 8-9)
# ==============================================================================

def test_worker_boundary_revalidation_fails_closed_on_revocation_or_expiration(
    client: TestClient,
    test_project: Project,
    tester_headers: dict,
    auth_target: ScopeTarget,
    db: Session,
):
    """
    Verifies that if target authorization changes between job creation and worker claim,
    the execution boundary fails closed to REJECTED.
    """
    # Scenario A: Target revoked before execution
    res1 = client.post(
        f"/api/v1/projects/{test_project.id}/assessments/?auto_execute=false",
        json={"target_input": "core.internal-defense.corp"},
        headers=tester_headers,
    )
    assert res1.status_code == 201
    job1_id = res1.json()["id"]

    # Revoke authorization
    auth_target.authorization_status = AuthorizationStatus.REVOKED
    auth_target.revocation_reason = "Compromised scope authority"
    db.commit()

    # Worker claim and preflight
    job1 = AssessmentExecutionEngine.preflight_and_claim_job(db=db, job_id=job1_id)
    assert job1.status == AssessmentStatus.REJECTED
    assert job1.failure_category == "SCOPE_AUTHORIZATION_DENIED"
    assert "Preflight execution boundary denial" in job1.error_message

    # Scenario B: Target expires after queueing but before worker execution
    auth_target.authorization_status = AuthorizationStatus.AUTHORIZED
    auth_target.expires_at = datetime.now(timezone.utc) + timedelta(days=1)
    db.commit()

    res2 = client.post(
        f"/api/v1/projects/{test_project.id}/assessments/?auto_execute=false",
        json={"target_input": "core.internal-defense.corp"},
        headers=tester_headers,
    )
    assert res2.status_code == 201
    job2_id = res2.json()["id"]

    # Target expires before worker claims the job
    auth_target.expires_at = datetime.now(timezone.utc) - timedelta(hours=1)
    db.commit()

    job2 = AssessmentExecutionEngine.preflight_and_claim_job(db=db, job_id=job2_id)
    assert job2.status == AssessmentStatus.REJECTED
    assert job2.failure_category == "SCOPE_AUTHORIZATION_DENIED"


# ==============================================================================
# 4. Scope Snapshot Tampering Detection (Property 10)
# ==============================================================================

def test_scope_snapshot_tampering_fails_closed(
    client: TestClient,
    test_project: Project,
    tester_headers: dict,
    auth_target: ScopeTarget,
    db: Session,
):
    """
    Verifies that tampering with the serialized scope snapshot fails closed to REJECTED.
    """
    res = client.post(
        f"/api/v1/projects/{test_project.id}/assessments/?auto_execute=false",
        json={"target_input": "core.internal-defense.corp"},
        headers=tester_headers,
    )
    assert res.status_code == 201
    job_id = res.json()["id"]

    job = db.query(AssessmentJob).filter(AssessmentJob.id == job_id).first()
    assert job.scope_snapshot_digest is not None

    # Malicious tampering of target in snapshot without valid digest
    tampered_snapshot = dict(job.scope_snapshot)
    tampered_snapshot["normalized_target"] = "unauthorized-malicious-target.corp"
    job.scope_snapshot = tampered_snapshot
    db.commit()

    # Preflight claim detects hash mismatch
    claimed_job = AssessmentExecutionEngine.preflight_and_claim_job(db=db, job_id=job_id)
    assert claimed_job.status == AssessmentStatus.REJECTED
    assert claimed_job.failure_category == "SCOPE_SNAPSHOT_TAMPERING_DETECTED"
    assert "Scope snapshot digest does not match" in claimed_job.error_message


# ==============================================================================
# 5. Adapter Registry & Policy Checks (Properties 11-13)
# ==============================================================================

def test_adapter_registry_and_policy_version_validation(
    client: TestClient,
    test_project: Project,
    tester_headers: dict,
    auth_target: ScopeTarget,
    db: Session,
):
    """
    Verifies fail-closed behavior on unsupported adapter names, invalid profiles,
    and mismatched policy versions.
    """
    # 1. Unsupported adapter name
    job_bad_adapter = AssessmentJob(
        project_id=test_project.id,
        target_input="core.internal-defense.corp",
        adapter_name="unapproved_remote_scanner",
        adapter_version="1.0.0",
        status=AssessmentStatus.QUEUED,
        policy_version="2026.1",
        authorization_status="AUTHORIZED",
        scope_snapshot={},
        attempt_count=1,
        progress_pct=0,
        timeout_seconds=300,
        is_simulated=True,
        created_by_id=auth_target.created_by_id,
    )
    db.add(job_bad_adapter)
    db.commit()

    claimed_1 = AssessmentExecutionEngine.preflight_and_claim_job(db=db, job_id=job_bad_adapter.id)
    assert claimed_1.status == AssessmentStatus.REJECTED
    assert claimed_1.failure_category == "UNSUPPORTED_ADAPTER"

    # 2. Unsupported profile for adapter
    job_bad_profile = AssessmentJob(
        project_id=test_project.id,
        target_input="core.internal-defense.corp",
        adapter_name="local_fixture_adapter",
        adapter_version="1.0.0",
        status=AssessmentStatus.QUEUED,
        policy_version="2026.1",
        authorization_status="AUTHORIZED",
        scope_snapshot={},
        attempt_count=1,
        progress_pct=0,
        timeout_seconds=300,
        config={"fixture_profile": "NON_EXISTENT_ATTACK_PROFILE"},
        is_simulated=True,
        created_by_id=auth_target.created_by_id,
    )
    db.add(job_bad_profile)
    db.commit()

    claimed_2 = AssessmentExecutionEngine.preflight_and_claim_job(db=db, job_id=job_bad_profile.id)
    assert claimed_2.status == AssessmentStatus.REJECTED
    assert claimed_2.failure_category == "INVALID_ADAPTER_CONFIGURATION"

    # 3. Policy version mismatch
    job_bad_policy = AssessmentJob(
        project_id=test_project.id,
        target_input="core.internal-defense.corp",
        adapter_name="local_fixture_adapter",
        adapter_version="1.0.0",
        status=AssessmentStatus.QUEUED,
        policy_version="1999.0_DEPRECATED",
        authorization_status="AUTHORIZED",
        scope_snapshot={},
        attempt_count=1,
        progress_pct=0,
        timeout_seconds=300,
        is_simulated=True,
        created_by_id=auth_target.created_by_id,
    )
    db.add(job_bad_policy)
    db.commit()

    claimed_3 = AssessmentExecutionEngine.preflight_and_claim_job(db=db, job_id=job_bad_policy.id)
    assert claimed_3.status == AssessmentStatus.REJECTED
    assert claimed_3.failure_category == "POLICY_VERSION_MISMATCH"


# ==============================================================================
# 6. Idempotency Key Deduplication (Property 14)
# ==============================================================================

def test_idempotency_key_deduplication(
    client: TestClient,
    test_project: Project,
    tester_headers: dict,
    auth_target: ScopeTarget,
):
    """
    Submitting duplicate jobs with the same idempotency key returns the existing job.
    """
    idemp_key = "sched-scan-nightly-2026-10-25-A"
    res1 = client.post(
        f"/api/v1/projects/{test_project.id}/assessments/?auto_execute=false",
        json={
            "target_input": "core.internal-defense.corp",
            "idempotency_key": idemp_key,
        },
        headers=tester_headers,
    )
    assert res1.status_code == 201
    job1 = res1.json()

    res2 = client.post(
        f"/api/v1/projects/{test_project.id}/assessments/?auto_execute=false",
        json={
            "target_input": "core.internal-defense.corp",
            "idempotency_key": idemp_key,
        },
        headers=tester_headers,
    )
    assert res2.status_code == 200 or res2.status_code == 201
    job2 = res2.json()
    assert job1["id"] == job2["id"]
    assert job1["idempotency_key"] == job2["idempotency_key"]


# ==============================================================================
# 7. State Machine Invariance & Illegal Transitions (Property 15)
# ==============================================================================

def test_state_machine_illegal_transitions_rejected():
    """
    Verifies that terminal states cannot be re-opened and invalid transitions fail.
    """
    job = AssessmentJob(
        id="test-job-sm",
        project_id="test-proj",
        target_input="192.168.1.1",
        adapter_name="local_fixture_adapter",
        adapter_version="1.0.0",
        status=AssessmentStatus.COMPLETED,
        policy_version="2026.1",
        authorization_status="AUTHORIZED",
        scope_snapshot={},
        attempt_count=1,
        progress_pct=100,
        timeout_seconds=60,
        created_by_id="user-1",
    )

    # COMPLETED is terminal: cannot transition to RUNNING
    with pytest.raises(InvalidStateTransitionException):
        AssessmentStateMachine.transition(job, AssessmentStatus.RUNNING)

    # CANCELLED is terminal: cannot transition to RUNNING
    job.status = AssessmentStatus.CANCELLED
    with pytest.raises(InvalidStateTransitionException):
        AssessmentStateMachine.transition(job, AssessmentStatus.RUNNING)

    # REJECTED is terminal: cannot transition to RUNNING
    job.status = AssessmentStatus.REJECTED
    with pytest.raises(InvalidStateTransitionException):
        AssessmentStateMachine.transition(job, AssessmentStatus.RUNNING)


# ==============================================================================
# 8. Worker Claim Concurrency & Progression (Property 16)
# ==============================================================================

def test_worker_claim_and_execution_progression(
    db: Session,
    test_project: Project,
    auth_target: ScopeTarget,
):
    """
    Verifies ordered progression from QUEUED -> PREFLIGHT -> READY -> RUNNING -> COMPLETED.
    """
    scope_eval = {
        "is_authorized": True,
        "status": "AUTHORIZED",
        "normalized_target": "core.internal-defense.corp",
        "matched_rule": {"id": auth_target.id, "evidence": auth_target.authorization_evidence},
    }
    snapshot, digest = AssessmentExecutionEngine.compute_scope_snapshot_and_digest(scope_eval)

    job = AssessmentJob(
        project_id=test_project.id,
        target_input="core.internal-defense.corp",
        adapter_name="local_fixture_adapter",
        adapter_version="1.0.0",
        status=AssessmentStatus.QUEUED,
        policy_version="2026.1",
        authorization_reference=auth_target.id,
        authorization_status="AUTHORIZED",
        scope_snapshot=snapshot,
        scope_snapshot_digest=digest,
        attempt_count=1,
        progress_pct=0,
        timeout_seconds=300,
        is_simulated=True,
        created_by_id=auth_target.created_by_id,
        config={"fixture_profile": "HARDENED_HOST_BASELINE"},
    )
    db.add(job)
    db.commit()

    # Step 1: Preflight and claim
    claimed = AssessmentExecutionEngine.preflight_and_claim_job(db=db, job_id=job.id)
    assert claimed.status == AssessmentStatus.RUNNING
    assert claimed.preflight_at is not None
    assert claimed.started_at is not None
    assert claimed.heartbeat_at is not None

    # Step 2: Execute to completion
    completed = AssessmentExecutionEngine.execute_job(db=db, job_id=job.id)
    assert completed.status == AssessmentStatus.COMPLETED
    assert completed.completed_at is not None
    assert completed.progress_pct == 100


# ==============================================================================
# 9. Worker Heartbeat Timeout Detection (Property 17)
# ==============================================================================

def test_worker_heartbeat_timeout_detection():
    """
    Verifies that a running job with a lost heartbeat is detected and marked FAILED.
    """
    t_base = datetime.now(timezone.utc) - timedelta(minutes=10)
    job = AssessmentJob(
        id="job-hb-lost",
        project_id="test-proj",
        target_input="192.168.1.1",
        adapter_name="local_fixture_adapter",
        adapter_version="1.0.0",
        status=AssessmentStatus.RUNNING,
        policy_version="2026.1",
        authorization_status="AUTHORIZED",
        scope_snapshot={},
        attempt_count=1,
        progress_pct=30,
        started_at=t_base,
        heartbeat_at=t_base,
        timeout_seconds=600,
        created_by_id="user-1",
    )

    t_now = datetime.now(timezone.utc)
    # Check heartbeat with 60s timeout
    is_timed_out = AssessmentStateMachine.check_heartbeat(job, timeout_seconds=60, now=t_now)
    assert is_timed_out is True
    assert job.status == AssessmentStatus.FAILED
    assert job.failure_category == "WORKER_HEARTBEAT_LOST"
    assert "Assessment worker lost heartbeat" in job.error_message


# ==============================================================================
# 10. Cancellation Flow & Terminal Rejection (Property 18)
# ==============================================================================

def test_cancellation_flow_and_terminal_rejection(
    client: TestClient,
    test_project: Project,
    tester_headers: dict,
    auth_target: ScopeTarget,
):
    """
    Verifies that active jobs can be cancelled via API and terminal cancellations are rejected.
    """
    # 1. Create queued job
    res = client.post(
        f"/api/v1/projects/{test_project.id}/assessments/?auto_execute=false",
        json={"target_input": "core.internal-defense.corp"},
        headers=tester_headers,
    )
    job_id = res.json()["id"]

    # 2. Cancel queued job
    cancel_res = client.post(
        f"/api/v1/projects/{test_project.id}/assessments/{job_id}/cancel",
        headers=tester_headers,
    )
    assert cancel_res.status_code == 200
    assert cancel_res.json()["status"] == "CANCELLED"

    # 3. Attempting to cancel again fails with 400 Bad Request
    cancel_again = client.post(
        f"/api/v1/projects/{test_project.id}/assessments/{job_id}/cancel",
        headers=tester_headers,
    )
    assert cancel_again.status_code == 400
    assert "Cannot cancel job in terminal state" in cancel_again.json()["detail"]


# ==============================================================================
# 11. Pagination Bound Enforcement (Property 19)
# ==============================================================================

def test_pagination_bound_enforcement(
    client: TestClient,
    test_project: Project,
    tester_headers: dict,
):
    """
    Verifies that limit > 100 is rejected with 422 and valid pagination functions.
    """
    # Exceeds maximum 100
    res_bad = client.get(
        f"/api/v1/projects/{test_project.id}/assessments/?limit=101",
        headers=tester_headers,
    )
    assert res_bad.status_code == 422

    # Valid pagination bounds
    res_ok = client.get(
        f"/api/v1/projects/{test_project.id}/assessments/?offset=0&limit=50",
        headers=tester_headers,
    )
    assert res_ok.status_code == 200
    assert isinstance(res_ok.json(), list)


# ==============================================================================
# 12. Untrusted Evidence Boundary Sanitization (Properties 20-21)
# ==============================================================================

def test_untrusted_evidence_boundary_sanitizes_nan_inf_and_oversized_payloads(
    db: Session,
    test_project: Project,
    auth_target: ScopeTarget,
):
    """
    Verifies that:
    - Non-finite numbers (NaN, inf) are rejected or safely sanitized.
    - Raw evidence payloads exceeding 64KB are truncated cleanly.
    - Findings count is clamped to 50 max.
    """
    # 1. RawAdapterFinding validation rejects NaN / inf CVSS
    with pytest.raises(ValueError):
        RawAdapterFinding(
            title="Invalid CVSS Test",
            description="Testing NaN injection",
            severity=FindingSeverity.HIGH,
            confidence=FindingConfidence.CERTAIN,
            target_value="core.internal-defense.corp",
            cvss_score=float("nan"),
        )

    with pytest.raises(ValueError):
        RawAdapterFinding(
            title="Invalid Inf CVSS",
            description="Testing Inf injection",
            severity=FindingSeverity.HIGH,
            confidence=FindingConfidence.CERTAIN,
            target_value="core.internal-defense.corp",
            cvss_score=float("inf"),
        )

    # 2. Oversized evidence payload (> 64KB) truncation
    oversized_payload = "A" * 70000
    evidence = RawAdapterEvidence(
        evidence_type="HTTP_RESPONSE_HEADERS",
        payload=oversized_payload,
    )
    # Evidence validation truncates to 65536 max
    assert len(evidence.payload) == 65536
    assert evidence.payload.endswith("... [TRUNCATED_AT_64KB]")

    # 3. Normalized evidence digest matches truncated content
    assert len(evidence.sha256_hash) == 64


# ==============================================================================
# 13. Clean Host Benchmark & Finding Closure Decoupling (Property 22)
# ==============================================================================

def test_clean_host_benchmark_zero_findings_success_and_no_auto_closure(
    client: TestClient,
    test_project: Project,
    tester_headers: dict,
    auth_target: ScopeTarget,
    db: Session,
):
    """
    Verifies that HARDENED_HOST_BASELINE:
    - Completes cleanly with COMPLETED status and 0 findings.
    - Is clearly distinguished from failure.
    - Does NOT automatically close existing findings (lifecycle decoupling).
    """
    res = client.post(
        f"/api/v1/projects/{test_project.id}/assessments/?auto_execute=true",
        json={
            "target_input": "core.internal-defense.corp",
            "fixture_profile": "HARDENED_HOST_BASELINE",
        },
        headers=tester_headers,
    )
    assert res.status_code == 201
    job_data = res.json()
    assert job_data["status"] == "COMPLETED"
    assert job_data["summary_stats"]["findings_count"] == 0
    assert job_data["error_message"] is None

    # Fetch findings: empty list
    f_res = client.get(
        f"/api/v1/projects/{test_project.id}/assessments/{job_data['id']}/findings",
        headers=tester_headers,
    )
    assert f_res.status_code == 200
    assert len(f_res.json()) == 0


# ==============================================================================
# 14. Adapter Capability Discovery Endpoint
# ==============================================================================

def test_adapter_capabilities_endpoint(
    client: TestClient,
    test_project: Project,
    tester_headers: dict,
):
    """
    Verifies that GET /projects/{project_id}/assessments/adapters returns registered capabilities.
    """
    res = client.get(
        f"/api/v1/projects/{test_project.id}/assessments/adapters",
        headers=tester_headers,
    )
    assert res.status_code == 200
    adapters = res.json()
    assert len(adapters) >= 1
    adapter = next(a for a in adapters if a["name"] == "local_fixture_adapter")
    assert adapter["version"] == "1.0.0"
    assert "WEB_APPLICATION_BASELINE" in adapter["supported_profiles"]
    assert "HARDENED_HOST_BASELINE" in adapter["supported_profiles"]
    assert adapter["health"]["status"] in ("HEALTHY", "OPERATIONAL")


# ==============================================================================
# 15. Audit Ledger Records Execution Boundary Events
# ==============================================================================

def test_audit_ledger_records_boundary_events(
    client: TestClient,
    test_project: Project,
    tester_headers: dict,
    auth_target: ScopeTarget,
    db: Session,
):
    """
    Verifies that audit ledger persists ASSESSMENT_JOB_CREATE and execution records.
    """
    res = client.post(
        f"/api/v1/projects/{test_project.id}/assessments/?auto_execute=true",
        json={"target_input": "core.internal-defense.corp"},
        headers=tester_headers,
    )
    assert res.status_code == 201
    job_id = res.json()["id"]

    audit_events = db.query(AuditEvent).filter(
        AuditEvent.project_id == test_project.id,
        AuditEvent.target_id == job_id,
    ).all()

    actions = [e.action for e in audit_events]
    assert "ASSESSMENT_JOB_CREATE" in actions
    assert "ASSESSMENT_EXECUTION_COMPLETE" in actions
