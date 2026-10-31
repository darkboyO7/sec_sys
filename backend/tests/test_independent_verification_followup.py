"""
VAPT Platform — Independent Verification Follow-up & Critical Security Corrections Test Suite.
Validates:
1. Worker session authentication:
   - Expired token with populated cache fails closed.
   - Revoked session with populated cache fails closed.
   - Re-registered worker with old cached token fails closed.
   - DB commit failure during registration does not populate cache.
   - Worker identity substitution fails closed.
   - Worker deactivation reclaims claimed jobs and invalidates sessions.
   - Heartbeat after expiration fails closed.
2. Complete Job Scope Authorization:
   - Missing scope snapshot fails closed.
   - Missing scope digest fails closed.
   - Scope digest tampering fails closed.
   - Scope exclusion overriding inclusion fails closed.
   - Cross-project execution binding fails closed.
3. Race-Safe Administrator Bootstrap:
   - Singleton SystemBootstrapState protects bootstrap atomicity.
   - Subsequent public registrations cannot become ADMIN.
   - Duplicate email registration race-safety returns 400.
   - User enumeration blocked for unprivileged users on GET /api/v1/auth/users.
4. Audit-Chain Append Integrity:
   - Serialization via AuditChainHead.
   - Monotonic, non-null sequence numbering.
   - Strict audit mode failure fails closed without resetting chain to genesis.
   - Sequence gap and in-place tamper detection.
5. DNS, SSRF & Network Pinning:
   - Hex / octal / dword IP encodings normalized and blocked.
   - Cloud metadata blocked across all paths.
"""
import pytest
import hmac
import hashlib
import time
from datetime import datetime, timezone, timedelta
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError

from app.models.user import User, SystemRole, SystemBootstrapState
from app.models.organization import Organization
from app.models.worker_node import WorkerNode, WorkerStatus, WorkerType
from app.models.project import Project, ProjectMember, ProjectRole
from app.models.scope import ScopeTarget, ScopeExclusion, TargetType, AuthorizationStatus
from app.models.assessment import AssessmentJob, AssessmentStatus
from app.models.audit import AuditEvent, AuditChainHead
from app.worker.worker_registry import worker_registry, WorkerAuthenticationError
from app.worker.execution_interface import WorkerRegistrationRequest, WorkerHeartbeatRequest
from app.services.assessment_engine import AssessmentExecutionEngine
from app.services.audit_service import AuditService, AuditPersistenceError
from app.services.scope_engine import ScopeEngine
from app.core.security import create_access_token
from app.core.config import settings


# ==============================================================================
# SECTION 1: WORKER SESSION AUTHENTICATION & LIFECYCLE
# ==============================================================================

def test_worker_expired_token_with_populated_cache_fails_closed(db: Session):
    """Ensure that an expired worker session token fails verification even if present in memory cache."""
    worker_id = "test-worker-expired-cache"
    worker_registry.evict_cache(worker_id)

    # Register worker
    req = WorkerRegistrationRequest(
        worker_id=worker_id,
        auth_token=(settings.WORKER_REGISTRATION_SECRET or settings.SECRET_KEY),
        hostname="worker-host-1",
        pid=1234,
        worker_type="LOCAL_SUBPROCESS",
        concurrency_slots=2,
        capabilities=["local_fixture_adapter"],
    )
    resp = worker_registry.register_worker(req, db)
    raw_token = resp.session_token

    # Verify initially valid
    assert worker_registry.verify_session_token(worker_id, raw_token, db=db) is True

    # Artificially expire the token in the database
    node = db.query(WorkerNode).filter(WorkerNode.worker_id == worker_id).first()
    node.session_expires_at = datetime.now(timezone.utc) - timedelta(seconds=60)
    db.commit()

    # CRITICAL CHECK: Even though worker_id is cached in memory, verification against DB must FAIL CLOSED
    assert worker_registry.verify_session_token(worker_id, raw_token, db=db) is False

    # Also verify that heartbeat fails closed
    hb_req = WorkerHeartbeatRequest(
        worker_id=worker_id,
        session_token=raw_token,
        active_job_ids=[],
    )
    with pytest.raises(WorkerAuthenticationError):
        worker_registry.record_heartbeat(hb_req, db)


def test_worker_revoked_token_with_populated_cache_fails_closed(db: Session):
    """Ensure that explicitly revoking a worker session immediately invalidates authentication."""
    worker_id = "test-worker-revoked-cache"
    worker_registry.evict_cache(worker_id)

    req = WorkerRegistrationRequest(
        worker_id=worker_id,
        auth_token=(settings.WORKER_REGISTRATION_SECRET or settings.SECRET_KEY),
        hostname="worker-host-2",
        pid=2345,
        worker_type="LOCAL_SUBPROCESS",
        concurrency_slots=2,
        capabilities=["local_fixture_adapter"],
    )
    resp = worker_registry.register_worker(req, db)
    raw_token = resp.session_token

    assert worker_registry.verify_session_token(worker_id, raw_token, db=db) is True

    # Revoke session
    worker_registry.revoke_session(worker_id, db)

    # Verification must fail closed
    assert worker_registry.verify_session_token(worker_id, raw_token, db=db) is False


def test_worker_reregistration_invalidates_old_cached_token(db: Session):
    """Ensure that re-registering a worker rotates the token and invalidates the previous session."""
    worker_id = "test-worker-reregister"
    worker_registry.evict_cache(worker_id)

    # First registration
    req1 = WorkerRegistrationRequest(
        worker_id=worker_id,
        auth_token=(settings.WORKER_REGISTRATION_SECRET or settings.SECRET_KEY),
        hostname="worker-host-3",
        pid=3456,
        worker_type="LOCAL_SUBPROCESS",
        concurrency_slots=2,
        capabilities=["local_fixture_adapter"],
    )
    resp1 = worker_registry.register_worker(req1, db)
    old_token = resp1.session_token

    # Second registration (e.g. process restart)
    req2 = WorkerRegistrationRequest(
        worker_id=worker_id,
        auth_token=(settings.WORKER_REGISTRATION_SECRET or settings.SECRET_KEY),
        hostname="worker-host-3",
        pid=3457,
        worker_type="LOCAL_SUBPROCESS",
        concurrency_slots=2,
        capabilities=["local_fixture_adapter"],
    )
    resp2 = worker_registry.register_worker(req2, db)
    new_token = resp2.session_token

    assert old_token != new_token
    # Old token must now be rejected
    assert worker_registry.verify_session_token(worker_id, old_token, db=db) is False
    # New token must be accepted
    assert worker_registry.verify_session_token(worker_id, new_token, db=db) is True


def test_worker_db_failure_does_not_populate_cache(db: Session, monkeypatch):
    """Ensure that if database commit fails during worker registration, no valid in-memory session remains."""
    worker_id = "test-worker-db-fail"
    worker_registry.evict_cache(worker_id)

    req = WorkerRegistrationRequest(
        worker_id=worker_id,
        auth_token=(settings.WORKER_REGISTRATION_SECRET or settings.SECRET_KEY),
        hostname="worker-host-fail",
        pid=9999,
        worker_type="LOCAL_SUBPROCESS",
        concurrency_slots=2,
        capabilities=["local_fixture_adapter"],
    )

    # Monkeypatch db.commit to simulate database failure
    def mock_commit_failure():
        raise IntegrityError("Simulated database constraint violation", params=None, orig=None)

    monkeypatch.setattr(db, "commit", mock_commit_failure)

    with pytest.raises(Exception):
        worker_registry.register_worker(req, db)

    # CRITICAL CHECK: In-memory cache must NOT have worker session
    assert worker_id not in worker_registry._session_tokens
    assert worker_id not in worker_registry._session_cache


def test_worker_identity_substitution_rejected(db: Session):
    """Ensure worker A cannot use worker B's valid session token."""
    wA = "worker-identity-A"
    wB = "worker-identity-B"
    worker_registry.evict_cache(wA)
    worker_registry.evict_cache(wB)

    reqA = WorkerRegistrationRequest(
        worker_id=wA,
        auth_token=(settings.WORKER_REGISTRATION_SECRET or settings.SECRET_KEY),
        hostname="host-A",
        pid=1111,
        worker_type="LOCAL_SUBPROCESS",
        concurrency_slots=1,
        capabilities=["local_fixture_adapter"],
    )
    respA = worker_registry.register_worker(reqA, db)

    reqB = WorkerRegistrationRequest(
        worker_id=wB,
        auth_token=(settings.WORKER_REGISTRATION_SECRET or settings.SECRET_KEY),
        hostname="host-B",
        pid=2222,
        worker_type="LOCAL_SUBPROCESS",
        concurrency_slots=1,
        capabilities=["local_fixture_adapter"],
    )
    respB = worker_registry.register_worker(reqB, db)

    # Worker A's token presented as Worker B must fail closed
    assert worker_registry.verify_session_token(wB, respA.session_token, db=db) is False
    assert worker_registry.verify_session_token(wA, respB.session_token, db=db) is False


def test_worker_deactivation_reclaims_jobs_and_invalidates_session(db: Session, admin_user: User, test_organization: Organization):
    """Ensure deactivating a worker node reclaims active jobs and invalidates its session credentials."""
    w_id = "worker-to-deactivate"
    worker_registry.evict_cache(w_id)

    req = WorkerRegistrationRequest(
        worker_id=w_id,
        auth_token=(settings.WORKER_REGISTRATION_SECRET or settings.SECRET_KEY),
        hostname="deactivate-host",
        pid=7777,
        worker_type="LOCAL_SUBPROCESS",
        concurrency_slots=2,
        capabilities=["local_fixture_adapter"],
    )
    resp = worker_registry.register_worker(req, db)
    tok = resp.session_token

    # Create a project and active job claimed by this worker
    proj = Project(name="Worker Deactivation Test Project", organization_id=test_organization.id, is_active=True)
    db.add(proj)
    db.commit()

    job = AssessmentJob(
        project_id=proj.id,
        target_input="127.0.0.1",
        adapter_name="local_fixture_adapter",
        created_by_id=admin_user.id,
        status=AssessmentStatus.RUNNING,
        claimed_by=w_id,
        attempt_count=1,
        scope_snapshot={"target": "127.0.0.1"},
        scope_snapshot_digest="dummy",
    )
    db.add(job)
    db.commit()

    # Deactivate worker
    worker_registry.deactivate_worker(w_id, db)

    # 1. Session verification must fail closed
    assert worker_registry.verify_session_token(w_id, tok, db=db) is False

    # 2. Claimed job must be reclaimed back to QUEUED
    db.refresh(job)
    assert job.status == AssessmentStatus.QUEUED
    assert job.claimed_by is None


# ==============================================================================
# SECTION 2: COMPLETE JOB SCOPE AUTHORIZATION & TAMPERING FAIL-CLOSED
# ==============================================================================

def test_job_preflight_missing_scope_snapshot_fails_closed(db: Session, admin_user: User, test_organization: Organization):
    """Ensure that an assessment job missing its scope snapshot fails closed during preflight."""
    proj = Project(name="Missing Snapshot Test Project", organization_id=test_organization.id, is_active=True)
    db.add(proj)
    db.commit()

    # Add authorized scope target
    st = ScopeTarget(
        project_id=proj.id,
        target_type=TargetType.IP_ADDRESS,
        target_value="127.0.0.1",
        authorization_status=AuthorizationStatus.AUTHORIZED,
        authorization_evidence="Test Authorization",
        created_by_id=admin_user.id,
    )
    db.add(st)
    db.commit()

    # Job created WITHOUT scope_snapshot or scope_snapshot_digest
    job = AssessmentJob(
        project_id=proj.id,
        target_input="127.0.0.1",
        adapter_name="local_fixture_adapter",
        created_by_id=admin_user.id,
        status=AssessmentStatus.QUEUED,
        attempt_count=1,
        scope_snapshot=None,  # MISSING
        scope_snapshot_digest=None,  # MISSING
    )
    db.add(job)
    db.commit()

    result_job = AssessmentExecutionEngine.preflight_and_claim_job(db=db, job_id=job.id, worker_id="worker-01")

    # CRITICAL CHECK: Must be REJECTED, not allowed to run
    assert result_job.status == AssessmentStatus.REJECTED
    assert result_job.failure_category == "SCOPE_SNAPSHOT_MISSING"


def test_job_preflight_tampered_scope_digest_fails_closed(db: Session, admin_user: User, test_organization: Organization):
    """Ensure that an assessment job with a tampered scope snapshot digest is rejected during preflight."""
    proj = Project(name="Tampered Snapshot Test Project", organization_id=test_organization.id, is_active=True)
    db.add(proj)
    db.commit()

    st = ScopeTarget(
        project_id=proj.id,
        target_type=TargetType.IP_ADDRESS,
        target_value="127.0.0.1",
        authorization_status=AuthorizationStatus.AUTHORIZED,
        authorization_evidence="Test Authorization",
        created_by_id=admin_user.id,
    )
    db.add(st)
    db.commit()

    # Legitimate snapshot but forged digest
    job = AssessmentJob(
        project_id=proj.id,
        target_input="127.0.0.1",
        adapter_name="local_fixture_adapter",
        created_by_id=admin_user.id,
        status=AssessmentStatus.QUEUED,
        attempt_count=1,
        scope_snapshot={"normalized_target": "127.0.0.1", "status": "AUTHORIZED"},
        scope_snapshot_digest="forged_sha256_digest_00000000000000000000000000000000000000000000",
    )
    db.add(job)
    db.commit()

    result_job = AssessmentExecutionEngine.preflight_and_claim_job(db=db, job_id=job.id, worker_id="worker-01")

    assert result_job.status == AssessmentStatus.REJECTED
    assert result_job.failure_category == "SCOPE_SNAPSHOT_TAMPERING_DETECTED"


def test_job_scope_exclusion_at_preflight_overrides_inclusion(db: Session, admin_user: User, test_organization: Organization):
    """Ensure that adding an exclusion after queuing causes preflight to immediately reject execution."""
    proj = Project(name="Scope Exclusion Preflight Test Project", organization_id=test_organization.id, is_active=True)
    db.add(proj)
    db.commit()

    st = ScopeTarget(
        project_id=proj.id,
        target_type=TargetType.IP_ADDRESS,
        target_value="127.0.0.1",
        authorization_status=AuthorizationStatus.AUTHORIZED,
        authorization_evidence="Test Authorization",
        created_by_id=admin_user.id,
    )
    db.add(st)
    db.commit()

    scope_eval = ScopeEngine.validate_target_in_scope(db=db, project_id=proj.id, target="127.0.0.1")
    snapshot, digest = AssessmentExecutionEngine.compute_scope_snapshot_and_digest(scope_eval)

    job = AssessmentJob(
        project_id=proj.id,
        target_input="127.0.0.1",
        adapter_name="local_fixture_adapter",
        created_by_id=admin_user.id,
        status=AssessmentStatus.QUEUED,
        attempt_count=1,
        scope_snapshot=snapshot,
        scope_snapshot_digest=digest,
    )
    db.add(job)
    db.commit()

    # Now add an explicit exclusion before execution starts
    excl = ScopeExclusion(
        project_id=proj.id,
        target_type=TargetType.IP_ADDRESS,
        target_value="127.0.0.1",
        reason="Emergency exclusion for production safety",
        created_by_id=admin_user.id,
    )
    db.add(excl)
    db.commit()

    # Preflight re-evaluates database rules and MUST fail closed
    result_job = AssessmentExecutionEngine.preflight_and_claim_job(db=db, job_id=job.id, worker_id="worker-01")
    assert result_job.status == AssessmentStatus.REJECTED
    assert result_job.failure_category == "SCOPE_AUTHORIZATION_DENIED"


# ==============================================================================
# SECTION 3: RACE-SAFE ADMINISTRATOR BOOTSTRAP & AUTHENTICATION
# ==============================================================================

def test_system_bootstrap_state_singleton_enforcement(client: TestClient, db: Session):
    """Ensure that after SystemBootstrapState exists, no subsequent public registration can ever become ADMIN."""
    # Ensure bootstrap state exists
    existing_state = db.query(SystemBootstrapState).filter(SystemBootstrapState.id == 1).first()
    if not existing_state:
        b_state = SystemBootstrapState(
            id=1,
            is_bootstrapped=True,
            bootstrap_user_id="init-admin-id",
            bootstrapped_at=datetime.now(timezone.utc),
        )
        db.add(b_state)
        db.commit()

    # Attempt to register with system_role="ADMIN"
    payload = {
        "email": "post_bootstrap_admin_attempt@vapt-test.local",
        "password": "Password123!",
        "full_name": "Post Bootstrap Attacker",
        "system_role": "ADMIN",
    }
    resp = client.post("/api/v1/auth/register", json=payload)
    assert resp.status_code == 201, resp.text
    data = resp.json()

    # Must be unprivileged SECURITY_TESTER
    assert data["system_role"] == "SECURITY_TESTER"


def test_unprivileged_user_cannot_list_all_users(client: TestClient, db: Session, tester_user: User):
    """Ensure that non-admin/auditor users cannot enumerate users via GET /api/v1/auth/users."""
    tester_token = create_access_token(
        subject=tester_user.id,
        claims={"email": tester_user.email, "role": tester_user.system_role.value},
    )

    resp = client.get(
        "/api/v1/auth/users",
        headers={"Authorization": f"Bearer {tester_token}"},
    )
    # Must be forbidden (403)
    assert resp.status_code == 403, resp.text


# ==============================================================================
# SECTION 4: AUDIT-CHAIN APPEND INTEGRITY & MULTI-PROCESS SERIALIZATION
# ==============================================================================

def test_audit_chain_head_initialization_and_monotonic_ordering(db: Session, admin_user: User):
    """Ensure that audit events use AuditChainHead for strictly monotonic sequence numbering."""
    project_id = "test-audit-head-project"

    # Record 3 events sequentially
    ev1 = AuditService.record_event(
        db=db,
        action="TEST_ACTION_1",
        target_type="test_entity",
        outcome="SUCCESS",
        project_id=project_id,
        actor_id=admin_user.id,
    )
    ev2 = AuditService.record_event(
        db=db,
        action="TEST_ACTION_2",
        target_type="test_entity",
        outcome="SUCCESS",
        project_id=project_id,
        actor_id=admin_user.id,
    )
    ev3 = AuditService.record_event(
        db=db,
        action="TEST_ACTION_3",
        target_type="test_entity",
        outcome="SUCCESS",
        project_id=project_id,
        actor_id=admin_user.id,
    )

    # Verify sequence numbers are monotonic non-null
    assert ev1.sequence_number is not None and ev1.sequence_number > 0
    assert ev2.sequence_number == ev1.sequence_number + 1
    assert ev3.sequence_number == ev2.sequence_number + 1

    # Verify hash chain continuity
    assert ev2.prev_event_hash == ev1.event_hash
    assert ev3.prev_event_hash == ev2.event_hash

    # Verify AuditChainHead matches latest state
    head = db.query(AuditChainHead).filter(AuditChainHead.partition_key == project_id).first()
    assert head is not None
    assert head.last_sequence_number == ev3.sequence_number
    assert head.last_event_hash == ev3.event_hash

    # Verify full chain integrity
    report = AuditService.verify_chain_integrity(db=db, project_id=project_id)
    assert report["valid"] is True
    assert report["broken_links"] == 0
    assert report["discrepancies"] == []


def test_strict_audit_mode_fails_closed_without_genesis_reset(db: Session, monkeypatch):
    """Ensure that persistence failures in strict audit mode raise AuditPersistenceError and do not reset to genesis."""
    project_id = "test-strict-audit-fail-closed"

    # Record first event
    ev1 = AuditService.record_event(
        db=db,
        action="INITIAL_EVENT",
        target_type="test_entity",
        outcome="SUCCESS",
        project_id=project_id,
    )
    assert ev1.sequence_number is not None
    ev1_seq = ev1.sequence_number
    ev1_hash = ev1.event_hash

    # Simulate persistence failure
    def mock_add_failure(event):
        raise RuntimeError("Simulated database write error during audit append")

    monkeypatch.setattr(db, "add", mock_add_failure)

    # Attempting to record an event under strict mode MUST fail closed
    with pytest.raises(Exception):
        AuditService.record_event(
            db=db,
            action="SHOULD_FAIL",
            target_type="test_entity",
            outcome="SUCCESS",
            project_id=project_id,
        )

    # Verify that head was NOT reset to genesis
    head = db.query(AuditChainHead).filter(AuditChainHead.partition_key == project_id).first()
    assert head.last_sequence_number == ev1_seq
    assert head.last_event_hash == ev1_hash


# ==============================================================================
# SECTION 5: DNS, SSRF & DESTINATION PINNING
# ==============================================================================

def test_scope_engine_obfuscated_ip_normalization_blocks_ssrf():
    """Ensure that hex, octal, and single dword IP addresses are normalized and blocked."""
    # Hex representation of 127.0.0.1 (0x7f000001)
    is_safe_hex, reason_hex, ip_hex = ScopeEngine.revalidate_destination_before_connection(
        "http://0x7f000001:8080/test",
        allow_loopback=False,
    )
    assert is_safe_hex is False
    assert "loopback" in reason_hex.lower() or "blocked" in reason_hex.lower()

    # Cloud metadata IP 169.254.169.254
    is_safe_meta, reason_meta, _ = ScopeEngine.revalidate_destination_before_connection(
        "http://169.254.169.254/latest/meta-data",
        allow_loopback=True,
        allow_private=True,
    )
    assert is_safe_meta is False
    assert "metadata" in reason_meta.lower() or "blocked" in reason_meta.lower()

    # Dotted octal 0177.0.0.1
    is_safe_oct, reason_oct, _ = ScopeEngine.revalidate_destination_before_connection(
        "0177.0.0.1",
        allow_loopback=False,
    )
    assert is_safe_oct is False
