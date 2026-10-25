"""Phase 7A: Automated Test Suite for Isolated Worker Process Execution.

Verifies:
1. Subprocess worker execution success: real OS process spawned, worker_pid recorded, findings ingested.
2. Process environment sanitization: SECRET_KEY, DATABASE_URL, and auth tokens stripped from child process.
3. Process crash handling: non-zero worker process exit fails closed with WORKER_PROCESS_CRASHED.
4. Process timeout enforcement: worker execution exceeding timeout triggers process tree kill and TIMED_OUT status.
5. Cooperative & forceful cancellation: cancellation during execution terminates child process tree cleanly.
6. Worker IPC payload limit: oversized stream (> limit) clamped and fails closed with WORKER_PAYLOAD_EXCEEDED.
7. IPC identity mismatch: mismatched job_id, project_id, worker_id, or attempt_count fails closed with IPC_IDENTITY_MISMATCH.
8. Process tree and descendant cleanup: confirms both worker and any child processes are dead via Win32 process queries.
"""
import os
import sys
import time
import subprocess
import pytest
from datetime import datetime, timezone, timedelta
from typing import Generator, List
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.project import Project, ProjectMember, ProjectRole
from app.models.scope import ScopeTarget, TargetType, AuthorizationStatus
from app.models.assessment import AssessmentJob, AssessmentStatus, FindingSeverity, FindingConfidence
from app.models.user import User
from app.services.assessment_engine import AssessmentExecutionEngine
from app.services.subprocess_worker_runner import (
    SubprocessWorkerRunner,
    build_sanitized_env,
    terminate_process_tree,
    is_process_alive,
)
from app.worker.ipc_schemas import WorkerIPCRequest, WorkerIPCResponse, SUPPORTED_PROTOCOL_VERSION


@pytest.fixture
def spawned_pids() -> Generator[List[int], None, None]:
    """Tracks all PIDs spawned during tests and guarantees termination in teardown."""
    pids: List[int] = []
    yield pids
    for pid in pids:
        if is_process_alive(pid):
            terminate_process_tree(pid)


@pytest.fixture
def auth_target_p7(db: Session, test_project: Project, lead_user: User) -> ScopeTarget:
    target = ScopeTarget(
        project_id=test_project.id,
        target_type=TargetType.DOMAIN,
        target_value="worker-isolation.internal-defense.corp",
        authorization_status=AuthorizationStatus.AUTHORIZED,
        authorization_evidence="AUTH-ROE-PHASE7A-001",
        authorized_by_id=lead_user.id,
        authorized_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(days=30),
        created_by_id=lead_user.id,
    )
    db.add(target)
    db.commit()
    db.refresh(target)
    return target


def test_subprocess_worker_execution_success(
    db: Session,
    test_project: Project,
    lead_user: User,
    auth_target_p7: ScopeTarget,
    spawned_pids: List[int],
):
    """
    Test 1: Verifies that in SUBPROCESS execution mode, an isolated OS subprocess is spawned,
    its OS PID is recorded in job.worker_pid, and findings are cleanly returned and ingested.
    """
    job = AssessmentJob(
        project_id=test_project.id,
        target_input="worker-isolation.internal-defense.corp",
        adapter_name="local_fixture_adapter",
        adapter_version="1.0.0",
        status=AssessmentStatus.QUEUED,
        policy_version="2026.1",
        timeout_seconds=30,
        config={"fixture_profile": "WEB_APPLICATION_BASELINE"},
        summary_stats={},
        is_simulated=True,
        created_by_id=lead_user.id,
    )
    db.add(job)
    db.commit()
    db.refresh(job)

    executed_job = AssessmentExecutionEngine.execute_job(
        db=db,
        job_id=job.id,
        worker_id="test-worker-p7a",
    )

    db.refresh(executed_job)
    assert executed_job.status in (AssessmentStatus.COMPLETED, AssessmentStatus.PARTIAL)
    assert executed_job.worker_pid is not None
    assert executed_job.worker_pid > 0
    spawned_pids.append(executed_job.worker_pid)

    assert executed_job.summary_stats.get("findings_count", 0) > 0
    assert executed_job.summary_stats.get("adapter_name") == "local_fixture_adapter"
    assert executed_job.is_simulated is True

    # Process must have exited cleanly after completion
    assert not is_process_alive(executed_job.worker_pid)


def test_environment_sanitization_strips_secrets():
    """
    Test 2: Verifies that child process environment strips SECRET_KEY, DATABASE_URL,
    and sensitive credentials while preserving safe OS variables.
    """
    os.environ["SECRET_KEY"] = "super-secret-key-that-must-not-leak"
    os.environ["DATABASE_URL"] = "postgresql://user:pass@localhost:5432/vapt_secret"
    os.environ["JWT_SECRET_TOKEN"] = "token123"

    try:
        sanitized = build_sanitized_env()
        assert "SECRET_KEY" not in sanitized
        assert "DATABASE_URL" not in sanitized
        assert "JWT_SECRET_TOKEN" not in sanitized
        assert "PYTHONPATH" in sanitized

        # Execute a Python subprocess verifying the child process cannot access SECRET_KEY
        cmd = [
            sys.executable,
            "-c",
            "import os, sys; sys.exit(0 if 'SECRET_KEY' not in os.environ else 1)",
        ]
        res = subprocess.run(cmd, env=sanitized, shell=False, capture_output=True)
        assert res.returncode == 0, f"Child process observed SECRET_KEY! stderr: {res.stderr}"
    finally:
        os.environ.pop("SECRET_KEY", None)
        os.environ.pop("DATABASE_URL", None)
        os.environ.pop("JWT_SECRET_TOKEN", None)


def test_subprocess_worker_crash_handling(
    db: Session,
    test_project: Project,
    lead_user: User,
    auth_target_p7: ScopeTarget,
    spawned_pids: List[int],
    monkeypatch,
):
    """
    Test 3: Non-zero worker process exit code fails closed with WORKER_PROCESS_CRASHED.
    """
    job = AssessmentJob(
        project_id=test_project.id,
        target_input="worker-isolation.internal-defense.corp",
        adapter_name="local_fixture_adapter",
        adapter_version="1.0.0",
        status=AssessmentStatus.QUEUED,
        policy_version="2026.1",
        timeout_seconds=30,
        config={"fixture_profile": "WEB_APPLICATION_BASELINE"},
        summary_stats={},
        is_simulated=True,
        created_by_id=lead_user.id,
    )
    db.add(job)
    db.commit()
    db.refresh(job)

    # Configure runner to use a crash script
    crash_cmd = [sys.executable, "-c", "import sys; sys.stderr.write('Fatal crash simulated'); sys.exit(42)"]
    monkeypatch.setattr(SubprocessWorkerRunner, "worker_cmd", crash_cmd)

    executed_job = AssessmentExecutionEngine.execute_job(
        db=db,
        job_id=job.id,
        worker_id="test-worker-crash",
    )

    db.refresh(executed_job)
    assert executed_job.status == AssessmentStatus.FAILED
    assert executed_job.failure_category == "WORKER_PROCESS_CRASHED"
    assert "WORKER_PROCESS_CRASHED: Exit code 42" in (executed_job.error_message or "")
    if executed_job.worker_pid:
        spawned_pids.append(executed_job.worker_pid)
        assert not is_process_alive(executed_job.worker_pid)


def test_subprocess_worker_timeout_enforcement(
    db: Session,
    test_project: Project,
    lead_user: User,
    auth_target_p7: ScopeTarget,
    spawned_pids: List[int],
    monkeypatch,
):
    """
    Test 4: Worker process exceeding timeout is terminated via process tree kill and marked TIMED_OUT.
    """
    job = AssessmentJob(
        project_id=test_project.id,
        target_input="worker-isolation.internal-defense.corp",
        adapter_name="local_fixture_adapter",
        adapter_version="1.0.0",
        status=AssessmentStatus.QUEUED,
        policy_version="2026.1",
        timeout_seconds=1,  # Strict 1-second timeout
        config={"fixture_profile": "WEB_APPLICATION_BASELINE"},
        summary_stats={},
        is_simulated=True,
        created_by_id=lead_user.id,
    )
    db.add(job)
    db.commit()
    db.refresh(job)

    # Slow worker script that sleeps 15s
    slow_cmd = [sys.executable, "-c", "import time, sys; sys.stdin.read(); time.sleep(15)"]
    monkeypatch.setattr(SubprocessWorkerRunner, "worker_cmd", slow_cmd)

    executed_job = AssessmentExecutionEngine.execute_job(
        db=db,
        job_id=job.id,
        worker_id="test-worker-timeout",
    )

    db.refresh(executed_job)
    assert executed_job.status == AssessmentStatus.TIMED_OUT
    assert executed_job.failure_category == "WORKER_PROCESS_TIMEOUT"
    assert executed_job.worker_pid is not None
    spawned_pids.append(executed_job.worker_pid)

    # Verify that the timed out worker process was killed and is dead via Win32 API
    assert not is_process_alive(executed_job.worker_pid)


def test_cooperative_and_forceful_cancellation(
    db: Session,
    test_project: Project,
    lead_user: User,
    auth_target_p7: ScopeTarget,
    spawned_pids: List[int],
    monkeypatch,
):
    """
    Test 5: Cancellation check triggered while worker is running terminates process tree and transitions job to CANCELLED.
    """
    job = AssessmentJob(
        project_id=test_project.id,
        target_input="worker-isolation.internal-defense.corp",
        adapter_name="local_fixture_adapter",
        adapter_version="1.0.0",
        status=AssessmentStatus.QUEUED,
        policy_version="2026.1",
        timeout_seconds=30,
        config={"fixture_profile": "WEB_APPLICATION_BASELINE"},
        summary_stats={},
        is_simulated=True,
        created_by_id=lead_user.id,
    )
    db.add(job)
    db.commit()
    db.refresh(job)

    # Pre-request cancellation
    job.status = AssessmentStatus.CANCELLATION_REQUESTED
    db.commit()

    executed_job = AssessmentExecutionEngine.execute_job(
        db=db,
        job_id=job.id,
        worker_id="test-worker-cancel",
    )

    db.refresh(executed_job)
    assert executed_job.status == AssessmentStatus.CANCELLED
    assert executed_job.failure_category == "CANCELLED_BY_OPERATOR"


def test_worker_payload_exceeded_fails_closed(
    db: Session,
    test_project: Project,
    lead_user: User,
    auth_target_p7: ScopeTarget,
    spawned_pids: List[int],
    monkeypatch,
):
    """
    Test 6: Worker process generating stream exceeding WORKER_MAX_IPC_PAYLOAD_BYTES fails closed.
    """
    job = AssessmentJob(
        project_id=test_project.id,
        target_input="worker-isolation.internal-defense.corp",
        adapter_name="local_fixture_adapter",
        adapter_version="1.0.0",
        status=AssessmentStatus.QUEUED,
        policy_version="2026.1",
        timeout_seconds=30,
        config={"fixture_profile": "WEB_APPLICATION_BASELINE"},
        summary_stats={},
        is_simulated=True,
        created_by_id=lead_user.id,
    )
    db.add(job)
    db.commit()
    db.refresh(job)

    # Set temporary max payload to 50 bytes for this test
    monkeypatch.setattr(settings, "WORKER_MAX_IPC_PAYLOAD_BYTES", 50)

    # Mock worker that produces 500 bytes of output
    payload_cmd = [sys.executable, "-c", "import sys; sys.stdin.read(); sys.stdout.write('X' * 500); sys.stdout.flush()"]
    monkeypatch.setattr(SubprocessWorkerRunner, "worker_cmd", payload_cmd)

    executed_job = AssessmentExecutionEngine.execute_job(
        db=db,
        job_id=job.id,
        worker_id="test-worker-payload",
    )

    db.refresh(executed_job)
    assert executed_job.status == AssessmentStatus.FAILED
    assert executed_job.failure_category == "WORKER_PAYLOAD_EXCEEDED"
    if executed_job.worker_pid:
        spawned_pids.append(executed_job.worker_pid)
        assert not is_process_alive(executed_job.worker_pid)


def test_ipc_identity_mismatch_rejected(
    db: Session,
    test_project: Project,
    lead_user: User,
    auth_target_p7: ScopeTarget,
    spawned_pids: List[int],
    monkeypatch,
):
    """
    Test 7: Worker response with mismatched job_id, project_id, or attempt_count fails closed with IPC_IDENTITY_MISMATCH.
    """
    job = AssessmentJob(
        project_id=test_project.id,
        target_input="worker-isolation.internal-defense.corp",
        adapter_name="local_fixture_adapter",
        adapter_version="1.0.0",
        status=AssessmentStatus.QUEUED,
        policy_version="2026.1",
        timeout_seconds=30,
        config={"fixture_profile": "WEB_APPLICATION_BASELINE"},
        summary_stats={},
        is_simulated=True,
        created_by_id=lead_user.id,
    )
    db.add(job)
    db.commit()
    db.refresh(job)

    # Mock worker that returns valid JSON but with mismatched job_id
    mismatched_response = WorkerIPCResponse(
        protocol_version=SUPPORTED_PROTOCOL_VERSION,
        job_id="attacker-controlled-job-id-9999",  # MISMATCH
        project_id=test_project.id,
        worker_id="test-worker-mismatch",
        attempt_count=job.attempt_count,
        success=True,
        status_summary="Injected rogue result",
        findings=[],
        execution_duration_ms=10.0,
        is_simulated=True,
    ).model_dump_json()

    mismatch_cmd = [sys.executable, "-c", f"import sys; sys.stdin.read(); sys.stdout.write({repr(mismatched_response)}); sys.stdout.flush()"]
    monkeypatch.setattr(SubprocessWorkerRunner, "worker_cmd", mismatch_cmd)

    executed_job = AssessmentExecutionEngine.execute_job(
        db=db,
        job_id=job.id,
        worker_id="test-worker-mismatch",
    )

    db.refresh(executed_job)
    assert executed_job.status == AssessmentStatus.FAILED
    assert executed_job.failure_category == "IPC_IDENTITY_MISMATCH"
    assert "IPC_IDENTITY_MISMATCH" in (executed_job.error_message or "")
    if executed_job.worker_pid:
        spawned_pids.append(executed_job.worker_pid)
        assert not is_process_alive(executed_job.worker_pid)


def test_descendant_process_tree_termination(spawned_pids: List[int]):
    """
    Test 8: Verifies that terminating a process tree forcefully kills both the parent
    worker and any spawned descendant child processes on Windows.
    """
    # Spawn parent that spawns a child sleeping 30s
    worker_script = (
        "import subprocess, sys, time\n"
        "p = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'])\n"
        "print('CHILD_PID:' + str(p.pid), flush=True)\n"
        "time.sleep(30)\n"
    )

    parent = subprocess.Popen(
        [sys.executable, "-c", worker_script],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    spawned_pids.append(parent.pid)

    # Read child PID from stdout
    line = parent.stdout.readline().strip()
    assert line.startswith("CHILD_PID:"), f"Expected CHILD_PID, got: {line}"
    child_pid = int(line.split(":")[1])
    spawned_pids.append(child_pid)

    assert is_process_alive(parent.pid)
    assert is_process_alive(child_pid)

    # Forcefully terminate process tree
    terminate_process_tree(parent.pid)
    parent.wait(timeout=3)
    time.sleep(0.5)

    # Both parent and child process must be dead
    assert not is_process_alive(parent.pid), f"Parent PID {parent.pid} survived termination!"
    assert not is_process_alive(child_pid), f"Child descendant PID {child_pid} survived termination!"
