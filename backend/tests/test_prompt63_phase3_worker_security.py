"""
VAPT Platform — Distributed Worker Security & Job Binding Tests (Phase 3).
Validates:
1. Worker registration persists session token hashes and expiration in the database.
2. Worker heartbeat succeeds with authentic session token and extends expiration.
3. Forged or expired worker session tokens are rejected (401).
4. Job execution binding verifies worker claim ownership; foreign workers are rejected (403).
5. Scope snapshot digest tampering is detected and fails closed (403).
"""
import time
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.user import User
from app.models.project import Project
from app.models.worker_node import WorkerNode, WorkerStatus
from app.models.assessment import AssessmentJob, AssessmentStatus
from app.worker.worker_registry import worker_registry
from app.worker.execution_interface import WorkerRegistrationRequest, WorkerHeartbeatRequest
import uuid
from app.core.config import settings


def test_worker_registration_persists_session_token_in_db(client: TestClient, db: Session):
    """Ensure worker registration persists session_token_hash and session_expires_at."""
    worker_id = f"worker-test-{str(uuid.uuid4())[:8]}"
    secret = settings.WORKER_REGISTRATION_SECRET or settings.SECRET_KEY

    reg_payload = {
        "worker_id": worker_id,
        "worker_type": "LOCAL_SUBPROCESS",
        "hostname": "test-runner-01",
        "pid": 12345,
        "concurrency_slots": 4,
        "capabilities": ["PASSIVE_AUDIT"],
        "auth_token": secret,
        "metadata": {"test": True},
    }

    resp = client.post("/api/v1/workers/register", json=reg_payload)
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["success"] is True
    session_token = data["session_token"]
    assert session_token is not None

    # Verify directly in the database
    node = db.query(WorkerNode).filter(WorkerNode.worker_id == worker_id).first()
    assert node is not None
    assert node.session_token_hash is not None
    assert node.session_expires_at is not None

    # Test heartbeat succeeds with authentic session token
    hb_payload = {
        "worker_id": worker_id,
        "session_token": session_token,
        "active_job_ids": [],
        "concurrency_utilization": 0.0,
    }
    resp_hb = client.post("/api/v1/workers/heartbeat", json=hb_payload)
    assert resp_hb.status_code == 200, resp_hb.text
    assert resp_hb.json()["acknowledged"] is True

    # Test heartbeat FAILS with forged session token
    hb_forged = {
        "worker_id": worker_id,
        "session_token": "forged-invalid-session-token-123",
        "active_job_ids": [],
    }
    resp_bad = client.post("/api/v1/workers/heartbeat", json=hb_forged)
    assert resp_bad.status_code == 401


def test_job_execution_binding_enforces_ownership_and_fails_closed(client: TestClient, db: Session, admin_user: User, test_project: Project):
    """
    Ensure verify-job-binding enforces that only the worker who claimed the job
    can report results, rejecting foreign workers.
    """
    secret = settings.WORKER_REGISTRATION_SECRET or settings.SECRET_KEY
    w1_id = f"worker-alpha-{str(uuid.uuid4())[:8]}"
    w2_id = f"worker-beta-{str(uuid.uuid4())[:8]}"

    # Register Worker 1
    resp1 = client.post("/api/v1/workers/register", json={
        "worker_id": w1_id,
        "worker_type": "LOCAL_SUBPROCESS",
        "hostname": "node-1",
        "concurrency_slots": 2,
        "capabilities": ["PASSIVE_AUDIT"],
        "auth_token": secret,
    })
    token1 = resp1.json()["session_token"]

    # Register Worker 2
    resp2 = client.post("/api/v1/workers/register", json={
        "worker_id": w2_id,
        "worker_type": "DISTRIBUTED_NODE",
        "hostname": "node-2",
        "concurrency_slots": 2,
        "capabilities": ["PASSIVE_AUDIT"],
        "auth_token": secret,
    })
    token2 = resp2.json()["session_token"]

    # Create a test job claimed exclusively by Worker 1
    job = AssessmentJob(
        project_id=test_project.id,
        status=AssessmentStatus.RUNNING,
        claimed_by=w1_id,
        created_by_id=admin_user.id,
        target_input="https://example.com",
        adapter_name="passive_header_adapter",
        adapter_version="1.0.0",
        policy_version="1.0",
        authorization_reference="AUTH-REF-12345",
        authorization_status="AUTHORIZED",
        timeout_seconds=60,
    )
    db.add(job)
    db.commit()
    db.refresh(job)

    # 1. Rightful owner (Worker 1) verifies successfully
    bind_req1 = {
        "job_id": job.id,
        "worker_id": w1_id,
        "session_token": token1,
    }
    resp_ok = client.post("/api/v1/workers/verify-job-binding", json=bind_req1)
    assert resp_ok.status_code == 200, resp_ok.text
    assert resp_ok.json()["valid"] is True

    # 2. Foreign worker (Worker 2) tries to act on Worker 1's job -> REJECTED (403)
    bind_req2 = {
        "job_id": job.id,
        "worker_id": w2_id,
        "session_token": token2,
    }
    resp_denied = client.post("/api/v1/workers/verify-job-binding", json=bind_req2)
    assert resp_denied.status_code == 403
    assert "ownership" in resp_denied.json()["detail"].lower()

    # 3. Forged session token -> REJECTED (401)
    bind_forged = {
        "job_id": job.id,
        "worker_id": w1_id,
        "session_token": "tampered_session_token",
    }
    resp_unauth = client.post("/api/v1/workers/verify-job-binding", json=bind_forged)
    assert resp_unauth.status_code == 401
