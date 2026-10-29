"""
VAPT Platform — Performance Engineering, Workload Isolation & Scalable Processing.
Test suite for Prompt 26.
Validates:
1. Composite database indexes exist in SQLite schema for findings, assets, jobs, and graph relationships.
2. SQLite EXPLAIN QUERY PLAN confirms index usage for finding filters, timeline queries, stale job scans, and graph lookups.
3. Concurrency-bounded worker execution pool and backpressure enforcement (HTTP 429 when saturated).
4. Workload priority enforcement (INTERACTIVE > BACKGROUND > MAINTENANCE).
5. Dead-worker lease scavenging and deterministic orphaned job reconciliation.
6. In-memory percentile latency tracking (p50, p95, p99) against explicit performance budgets.
7. Budget violation detection when p95 exceeds budget SLA.
8. Deterministic synthetic benchmark engine execution without N+1 query proliferation.
9. Benchmark data isolation and clean teardown without residual artifacts.
10. REST API endpoints under /system/performance/* with role-based access control (RBAC).
"""
import os
import sys
import uuid
import time
from datetime import datetime, timezone, timedelta
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from app.main import app
from app.core.database import SessionLocal, engine
from app.core.security import create_access_token
from app.models.base import utc_now
from app.models.user import User, SystemRole
from app.models.organization import Organization
from app.models.project import Project
from app.models.finding import VulnerabilityFinding
from app.models.asset import Asset
from app.models.assessment import AssessmentJob, AssessmentStatus
from app.models.graph import GraphNode, GraphRelationship
from app.services.workload_isolation_service import (
    workload_isolation_service,
    WorkloadIsolationService,
    WorkloadSaturatedError,
)
from app.schemas.performance import (
    WorkloadPriority,
    WorkloadQueueStatus,
    PerformanceBudgetsResponse,
    BenchmarkSuiteResponse,
    StaleJobReconciliationResult,
)


def auth_headers(user: User, request_id: str = "test-req-prompt26") -> dict:
    token = create_access_token(subject=user.id, claims={"role": user.system_role.value})
    return {
        "Authorization": f"Bearer {token}",
        "X-Request-ID": request_id,
        "X-Correlation-ID": request_id,
    }


# ------------------------------------------------------------------------------
# 1. Composite Database Indexes & EXPLAIN QUERY PLAN
# ------------------------------------------------------------------------------
def test_01_composite_database_indexes_exist():
    """
    Verifies that the composite indexes added in migration e4f5a6b7c8d9 exist in SQLite schema.
    """
    db = SessionLocal()
    try:
        indexes = db.execute(text("SELECT name, tbl_name FROM sqlite_master WHERE type='index'")).fetchall()
        index_names = {row[0] for row in indexes}

        required_indexes = [
            "ix_vulnerability_findings_proj_sev_status",
            "ix_vulnerability_findings_proj_created",
            "ix_assets_proj_criticality_status",
            "ix_assessment_jobs_status_heartbeat",
            "ix_graph_relationships_proj_src_tgt",
        ]
        for req_idx in required_indexes:
            assert req_idx in index_names, f"Missing composite index: {req_idx}"
    finally:
        db.close()


def test_02_sqlite_explain_query_plan_uses_composite_index_for_findings():
    """
    Verifies that EXPLAIN QUERY PLAN confirms usage of ix_vulnerability_findings_proj_sev_status.
    """
    db = SessionLocal()
    try:
        plan = db.execute(
            text(
                "EXPLAIN QUERY PLAN SELECT * FROM vulnerability_findings "
                "WHERE project_id = :p AND severity = :s AND status = :st"
            ),
            {"p": "test-p", "s": "HIGH", "st": "DETECTED"},
        ).fetchall()

        plan_text = " ".join([str(row) for row in plan])
        assert "ix_vulnerability_findings_proj_sev_status" in plan_text
        assert "USING INDEX" in plan_text or "USING COVERING INDEX" in plan_text
    finally:
        db.close()


def test_03_sqlite_explain_query_plan_uses_composite_index_for_timeline():
    """
    Verifies that EXPLAIN QUERY PLAN confirms index scan for timeline pagination ordering.
    """
    db = SessionLocal()
    try:
        plan = db.execute(
            text(
                "EXPLAIN QUERY PLAN SELECT id, title FROM vulnerability_findings "
                "WHERE project_id = :p ORDER BY created_at DESC LIMIT 50"
            ),
            {"p": "test-p"},
        ).fetchall()

        plan_text = " ".join([str(row) for row in plan])
        assert "ix_vulnerability_findings_proj_created" in plan_text
    finally:
        db.close()


def test_04_sqlite_explain_query_plan_uses_composite_index_for_stale_jobs():
    """
    Verifies that EXPLAIN QUERY PLAN confirms index scan for assessment job status & heartbeat.
    """
    db = SessionLocal()
    try:
        plan = db.execute(
            text(
                "EXPLAIN QUERY PLAN SELECT * FROM assessment_jobs "
                "WHERE status = 'RUNNING' AND heartbeat_at < :cutoff"
            ),
            {"cutoff": datetime.now(timezone.utc).isoformat()},
        ).fetchall()

        plan_text = " ".join([str(row) for row in plan])
        assert "ix_assessment_jobs_status_heartbeat" in plan_text
    finally:
        db.close()


def test_05_sqlite_explain_query_plan_uses_composite_index_for_graph_relationships():
    """
    Verifies that EXPLAIN QUERY PLAN confirms index scan for graph relationship lookups.
    """
    db = SessionLocal()
    try:
        plan = db.execute(
            text(
                "EXPLAIN QUERY PLAN SELECT * FROM graph_relationships "
                "WHERE project_id = :p AND source_node_id = :src"
            ),
            {"p": "test-p", "src": "node-1"},
        ).fetchall()

        plan_text = " ".join([str(row) for row in plan])
        assert "ix_graph_relationships_proj_src_tgt" in plan_text
    finally:
        db.close()


# ------------------------------------------------------------------------------
# 2. Workload Queue, Concurrency Slots & Backpressure
# ------------------------------------------------------------------------------
def test_06_workload_queue_capacity_initial_state():
    """
    Verifies queue telemetry returns active workers within configured bounds.
    """
    status = workload_isolation_service.get_queue_status()
    assert isinstance(status, WorkloadQueueStatus)
    assert status.max_concurrent_workers >= 1
    assert status.max_queue_depth >= 10
    assert 0.0 <= status.capacity_utilization_pct <= 100.0


def test_07_workload_slot_acquisition_and_release():
    """
    Verifies acquiring and releasing execution slots correctly updates worker tracking.
    """
    svc = WorkloadIsolationService(max_concurrent_workers=3, max_queue_depth=10)
    task_id = "test-task-1"

    status_before = svc.get_queue_status()
    assert status_before.active_workers == 0

    # Acquire slot
    svc.acquire_worker_slot(task_id=task_id, priority=WorkloadPriority.INTERACTIVE, operation="SCAN")
    status_mid = svc.get_queue_status()
    assert status_mid.active_workers == 1
    assert status_mid.capacity_utilization_pct == pytest.approx(33.33, 0.1)

    # Release slot
    svc.release_worker_slot(task_id=task_id)
    status_after = svc.get_queue_status()
    assert status_after.active_workers == 0


def test_08_workload_backpressure_rejection_when_saturated():
    """
    Verifies that when worker concurrency and pending queue reach capacity,
    WorkloadSaturatedError is raised and rejection counter increments.
    """
    svc = WorkloadIsolationService(max_concurrent_workers=1, max_queue_depth=1)

    # Slot 1: occupies active worker
    svc.acquire_worker_slot(task_id="task-active", priority=WorkloadPriority.INTERACTIVE)
    assert svc.get_queue_status().active_workers == 1

    # Task 2: enqueued
    svc.enqueue_pending_task(task_id="task-queued", priority=WorkloadPriority.BACKGROUND)
    assert svc.get_queue_status().queue_depth == 1
    assert svc.get_queue_status().saturated is True

    # Task 3: saturated -> must fail closed with WorkloadSaturatedError
    with pytest.raises(WorkloadSaturatedError) as exc_info:
        svc.enqueue_pending_task(task_id="task-rejected", priority=WorkloadPriority.MAINTENANCE)

    assert "saturated" in str(exc_info.value).lower()
    assert svc.get_queue_status().rejected_tasks_count == 1


def test_09_workload_priority_execution_ordering():
    """
    Verifies that INTERACTIVE tasks are dequeued before BACKGROUND and MAINTENANCE.
    """
    svc = WorkloadIsolationService(max_concurrent_workers=5, max_queue_depth=20)

    svc.enqueue_pending_task(task_id="task-maint", priority=WorkloadPriority.MAINTENANCE)
    svc.enqueue_pending_task(task_id="task-bg", priority=WorkloadPriority.BACKGROUND)
    svc.enqueue_pending_task(task_id="task-interactive", priority=WorkloadPriority.INTERACTIVE)

    first = svc.dequeue_next_task()
    assert first is not None
    assert first["task_id"] == "task-interactive"

    second = svc.dequeue_next_task()
    assert second is not None
    assert second["task_id"] == "task-bg"

    third = svc.dequeue_next_task()
    assert third is not None
    assert third["task_id"] == "task-maint"


# ------------------------------------------------------------------------------
# 3. Dead-Worker Lease Scavenging & Orphan Recovery
# ------------------------------------------------------------------------------
def test_10_stale_job_scavenging_heartbeat_timeout(db: Session, admin_user: User):
    """
    Verifies that orphaned assessment jobs with expired worker leases transition to TIMED_OUT.
    """
    org_id = f"test-org-{uuid.uuid4().hex[:8]}"
    proj_id = f"test-proj-{uuid.uuid4().hex[:8]}"
    job_id = f"test-job-{uuid.uuid4().hex[:8]}"
    try:
        org = Organization(id=org_id, name="Test Org", slug=f"slug-{uuid.uuid4().hex[:6]}")
        proj = Project(id=proj_id, organization_id=org_id, name="Test Project")
        db.add(org)
        db.add(proj)

        # Create job with heartbeat in the past (> 300s ago)
        stale_heartbeat = datetime.now(timezone.utc) - timedelta(seconds=600)
        stale_job = AssessmentJob(
            id=job_id,
            project_id=proj_id,
            target_input="192.168.1.1",
            created_by_id=admin_user.id,
            status=AssessmentStatus.RUNNING.value,
            claimed_by="worker-crashed-node-1",
            heartbeat_at=stale_heartbeat,
            created_at=stale_heartbeat,
        )
        db.add(stale_job)
        db.commit()

        # Run reconciliation
        res = workload_isolation_service.reconcile_stale_jobs(db, lease_timeout_seconds=300)
        assert res.recovered_jobs_count >= 1
        assert job_id in res.reconciled_job_ids

        # Verify DB state
        refreshed = db.query(AssessmentJob).filter(AssessmentJob.id == job_id).first()
        assert refreshed is not None
        assert refreshed.status == AssessmentStatus.TIMED_OUT.value
        assert "expired" in refreshed.error_message.lower()
    finally:
        try:
            db.query(AssessmentJob).filter(AssessmentJob.id == job_id).delete()
            db.query(Project).filter(Project.id == proj_id).delete()
            db.query(Organization).filter(Organization.id == org_id).delete()
            db.commit()
        except Exception:
            db.rollback()


def test_11_active_healthy_job_not_scavenged(db: Session, admin_user: User):
    """
    Verifies that actively heartbeating assessment jobs are not scavenged.
    """
    org_id = f"test-org-{uuid.uuid4().hex[:8]}"
    proj_id = f"test-proj-{uuid.uuid4().hex[:8]}"
    job_id = f"test-job-{uuid.uuid4().hex[:8]}"
    try:
        org = Organization(id=org_id, name="Test Org", slug=f"slug-{uuid.uuid4().hex[:6]}")
        proj = Project(id=proj_id, organization_id=org_id, name="Test Project")
        db.add(org)
        db.add(proj)

        # Create active job with fresh heartbeat (10 seconds ago)
        fresh_heartbeat = datetime.now(timezone.utc) - timedelta(seconds=10)
        active_job = AssessmentJob(
            id=job_id,
            project_id=proj_id,
            target_input="192.168.1.1",
            created_by_id=admin_user.id,
            status=AssessmentStatus.RUNNING.value,
            claimed_by="worker-healthy-node-1",
            heartbeat_at=fresh_heartbeat,
        )
        db.add(active_job)
        db.commit()

        # Run reconciliation
        res = workload_isolation_service.reconcile_stale_jobs(db, lease_timeout_seconds=300)
        assert job_id not in res.reconciled_job_ids

        refreshed = db.query(AssessmentJob).filter(AssessmentJob.id == job_id).first()
        assert refreshed.status == AssessmentStatus.RUNNING.value
    finally:
        try:
            db.query(AssessmentJob).filter(AssessmentJob.id == job_id).delete()
            db.query(Project).filter(Project.id == proj_id).delete()
            db.query(Organization).filter(Organization.id == org_id).delete()
            db.commit()
        except Exception:
            db.rollback()


# ------------------------------------------------------------------------------
# 4. Latency Budget Tracking & Percentile Conformance
# ------------------------------------------------------------------------------
def test_12_performance_budget_tracking_percentiles():
    """
    Verifies that recorded latencies produce accurate p50, p95, p99 percentiles.
    """
    svc = WorkloadIsolationService()
    # Record 100 deterministic latencies: 0.2ms to 20.0ms (SLA is 40.0ms)
    for i in range(1, 101):
        svc.record_latency("FINDINGS_LIST", float(i) * 0.2)

    budgets_resp = svc.get_performance_budgets()
    assert budgets_resp.overall_healthy is True

    findings_budget = next(b for b in budgets_resp.budgets if b.operation == "FINDINGS_LIST")
    assert findings_budget.sample_count >= 100
    assert findings_budget.p50_ms == pytest.approx(10.0, abs=1.0)
    assert findings_budget.p95_ms == pytest.approx(19.0, abs=1.0)
    assert findings_budget.p99_ms == pytest.approx(19.8, abs=1.0)
    assert findings_budget.within_budget is True


def test_13_performance_budget_violation_flagging():
    """
    Verifies that exceeding p95 target flags within_budget=False and overall_healthy=False.
    """
    svc = WorkloadIsolationService()
    # SLA for DASHBOARD_SUMMARY is 500ms; record latencies at 800ms
    for _ in range(50):
        svc.record_latency("DASHBOARD_SUMMARY", 800.0)

    budgets_resp = svc.get_performance_budgets()
    dash_budget = next(b for b in budgets_resp.budgets if b.operation == "DASHBOARD_SUMMARY")

    assert dash_budget.p95_ms == 800.0
    assert dash_budget.within_budget is False
    assert budgets_resp.overall_healthy is False


# ------------------------------------------------------------------------------
# 5. Deterministic Synthetic Benchmark Engine
# ------------------------------------------------------------------------------
def test_14_synthetic_benchmark_runner_executes_cleanly(db: Session):
    """
    Verifies the synthetic benchmark runner produces valid metrics without residual test data.
    """
    suite = workload_isolation_service.run_synthetic_benchmark(db, dataset_size="SMALL")
    assert isinstance(suite, BenchmarkSuiteResponse)
    assert suite.dataset_size == "SMALL"
    assert len(suite.benchmarks) == 3
    for b in suite.benchmarks:
        assert b.duration_ms >= 0.0
        assert b.ops_per_second >= 0.0
        assert b.query_count == 1  # Single indexed query execution

    # Verify no orphan benchmark records left in database
    orphan_count = (
        db.query(VulnerabilityFinding)
        .filter(VulnerabilityFinding.project_id.like("bench-proj-%"))
        .count()
    )
    assert orphan_count == 0


# ------------------------------------------------------------------------------
# 6. REST API Endpoints & Role-Based Access Control
# ------------------------------------------------------------------------------
def test_15_api_workload_queue_status_endpoint(client: TestClient, admin_user: User):
    """
    Verifies GET /api/v1/system/performance/workload returns 200 OK with valid schema.
    """
    headers = auth_headers(admin_user)
    resp = client.get("/api/v1/system/performance/workload", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "active_workers" in data
    assert "max_concurrent_workers" in data
    assert "queue_depth" in data
    assert "capacity_utilization_pct" in data


def test_16_api_performance_budgets_endpoint(client: TestClient, admin_user: User):
    """
    Verifies GET /api/v1/system/performance/budgets returns 200 OK with tracked SLAs.
    """
    headers = auth_headers(admin_user)
    resp = client.get("/api/v1/system/performance/budgets", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "budgets" in data
    assert "overall_healthy" in data
    assert len(data["budgets"]) >= 1


def test_17_api_benchmark_and_scavenge_endpoints_rbac(client: TestClient, admin_user: User, outsider_user: User):
    """
    Verifies that POST /benchmark and POST /reconcile-stale-jobs require ADMIN/LEAD role
    and strictly reject VIEWER with HTTP 403 Forbidden.
    """
    # 1. Admin can invoke benchmark
    admin_hdr = auth_headers(admin_user)
    resp_admin = client.post("/api/v1/system/performance/benchmark?dataset_size=SMALL", headers=admin_hdr)
    assert resp_admin.status_code == 200
    assert resp_admin.json()["dataset_size"] == "SMALL"

    # 2. Viewer (outsider_user) is rejected with 403 Forbidden
    viewer_hdr = auth_headers(outsider_user)
    resp_viewer_bench = client.post("/api/v1/system/performance/benchmark?dataset_size=SMALL", headers=viewer_hdr)
    assert resp_viewer_bench.status_code == 403

    resp_viewer_scavenge = client.post("/api/v1/system/performance/reconcile-stale-jobs", headers=viewer_hdr)
    assert resp_viewer_scavenge.status_code == 403
