import concurrent.futures
import json
import os
import sqlite3
import tempfile
import time
import uuid
import pytest
from fastapi import status
from sqlalchemy import text

from app.models.organization import Organization
from app.models.user import User, SystemRole
from app.models.project import Project, ProjectMember, ProjectRole
from app.models.finding import (
    VulnerabilityFinding,
    FindingLifecycleStatus,
)
from app.models.assessment import (
    FindingSeverity,
    FindingConfidence,
    AssessmentJob,
    AssessmentStatus,
    AssessmentFinding,
    FindingEvidence,
)
from app.core.security import create_access_token
from app.services.query_cache_service import (
    BoundedQueryCache,
    DatabaseOptimizationService,
    query_cache,
)


def auth_header_for_user(user: User) -> dict:
    token = create_access_token(
        subject=user.id,
        claims={"role": user.system_role.value, "email": user.email},
    )
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def perf_org(db):
    org = Organization(name="Perf Optimization Org", slug=f"perf-org-{uuid.uuid4().hex[:6]}")
    db.add(org)
    db.commit()
    db.refresh(org)
    return org


@pytest.fixture
def perf_project(db, perf_org):
    project = Project(
        name="Performance Optimization Project",
        description="Performance and database benchmarking",
        organization_id=perf_org.id,
    )
    db.add(project)
    db.commit()
    db.refresh(project)
    return project


@pytest.fixture
def perf_admin(db, perf_project):
    user = User(
        email=f"perf-admin-{uuid.uuid4().hex[:6]}@example.com",
        hashed_password="mock_hashed_pw",
        full_name="Perf Admin User",
        system_role=SystemRole.ADMIN,
        is_active=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    member = ProjectMember(
        project_id=perf_project.id,
        user_id=user.id,
        role=ProjectRole.LEAD,
    )
    db.add(member)
    db.commit()
    return user


def test_direct_sql_aggregation_matches_python_computation(db, perf_project):
    """Verify that direct SQL group-by aggregation produces identical totals to manual entity counting."""
    # Seed known findings
    findings = [
        VulnerabilityFinding(
            project_id=perf_project.id,
            title="SQLi Test",
            fingerprint=f"fp-{uuid.uuid4().hex}",
            target_value="10.0.0.1",
            status=FindingLifecycleStatus.DETECTED,
            severity=FindingSeverity.CRITICAL,
            vuln_id="CVE-2026-0001",
            has_contradictions=True,
        ),
        VulnerabilityFinding(
            project_id=perf_project.id,
            title="XSS Test",
            fingerprint=f"fp-{uuid.uuid4().hex}",
            target_value="10.0.0.2",
            status=FindingLifecycleStatus.CONFIRMED,
            severity=FindingSeverity.HIGH,
            vuln_id="CVE-2026-0002",
            has_contradictions=False,
        ),
        VulnerabilityFinding(
            project_id=perf_project.id,
            title="CSRF Test",
            fingerprint=f"fp-{uuid.uuid4().hex}",
            target_value="10.0.0.3",
            status=FindingLifecycleStatus.ACCEPTED_RISK,
            severity=FindingSeverity.MEDIUM,
            vuln_id="CVE-2026-0003",
            has_contradictions=False,
        ),
        VulnerabilityFinding(
            project_id=perf_project.id,
            title="Info Leak Test",
            fingerprint=f"fp-{uuid.uuid4().hex}",
            target_value="10.0.0.4",
            status=FindingLifecycleStatus.REOPENED,
            severity=FindingSeverity.LOW,
            vuln_id="CVE-2026-0004",
            has_contradictions=False,
        ),
    ]
    db.add_all(findings)
    db.commit()

    # Manual Python counting baseline
    all_findings = db.query(VulnerabilityFinding).filter(VulnerabilityFinding.project_id == perf_project.id).all()
    manual_total = len(all_findings)
    manual_by_status = {s.value: 0 for s in FindingLifecycleStatus}
    manual_by_severity = {s.value: 0 for s in FindingSeverity}
    for f in all_findings:
        s_val = f.status.value if hasattr(f.status, "value") else str(f.status)
        sev_val = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
        manual_by_status[s_val] = manual_by_status.get(s_val, 0) + 1
        manual_by_severity[sev_val] = manual_by_severity.get(sev_val, 0) + 1

    # Optimized SQL aggregation
    optimized_stats = DatabaseOptimizationService.get_finding_stats_optimized(
        db, perf_project.id, user_role="LEAD", use_cache=False
    )

    assert optimized_stats["total"] == manual_total
    assert optimized_stats["by_status"] == manual_by_status
    assert optimized_stats["by_severity"] == manual_by_severity
    assert optimized_stats["reopened_count"] == 1
    assert optimized_stats["accepted_risk_count"] == 1
    assert optimized_stats["contradiction_count"] == 1


def test_query_plan_uses_composite_indexes(db, perf_project):
    """Verify that EXPLAIN QUERY PLAN demonstrates composite index utilization."""
    conn = db.get_bind()
    result = conn.execute(
        text(
            "EXPLAIN QUERY PLAN "
            "SELECT id, title FROM vulnerability_findings "
            "WHERE project_id = :p AND status = :s AND severity = :sev "
            "ORDER BY last_observed_at DESC"
        ),
        {"p": perf_project.id, "s": "DETECTED", "sev": "CRITICAL"},
    ).fetchall()

    plan_str = " ".join([str(row) for row in result])
    # Verify that index usage is reported in the SQLite plan
    assert "ix_vf_proj_status_sev_lastobs" in plan_str or "USING INDEX" in plan_str.upper()


def test_bounded_cache_capacity_and_lru_eviction():
    """Verify bounded capacity and least-recently-used eviction order."""
    cache = BoundedQueryCache(max_capacity=3, default_ttl_seconds=60)

    cache.set("p1", "LEAD", "stats", "k1", "val1")
    cache.set("p1", "LEAD", "stats", "k2", "val2")
    cache.set("p1", "LEAD", "stats", "k3", "val3")

    assert cache.get_metrics()["total_cached_items"] == 3

    # Access k1 to make it most recently used; k2 is now oldest
    assert cache.get("p1", "LEAD", "stats", "k1") == "val1"

    # Insert k4 -> k2 should be evicted
    cache.set("p1", "LEAD", "stats", "k4", "val4")

    assert cache.get("p1", "LEAD", "stats", "k2") is None
    assert cache.get("p1", "LEAD", "stats", "k1") == "val1"
    assert cache.get("p1", "LEAD", "stats", "k3") == "val3"
    assert cache.get("p1", "LEAD", "stats", "k4") == "val4"
    assert cache.get_metrics()["evictions"] == 1


def test_bounded_cache_ttl_expiration():
    """Verify time-to-live expiration mechanics."""
    cache = BoundedQueryCache(max_capacity=10, default_ttl_seconds=1)
    cache.set("p1", "LEAD", "stats", "exp_key", "temp_val", ttl_seconds=0.1)

    assert cache.get("p1", "LEAD", "stats", "exp_key") == "temp_val"
    time.sleep(0.15)
    assert cache.get("p1", "LEAD", "stats", "exp_key") is None
    assert cache.get_metrics()["misses"] >= 1


def test_cache_multi_tenant_and_role_isolation():
    """Ensure cache keys strictly isolate tenants (projects) and user roles."""
    proj_a = "project-alpha"
    proj_b = "project-beta"

    key_admin_a = BoundedQueryCache.build_key(proj_a, "ADMIN", "stats", "summary")
    key_viewer_a = BoundedQueryCache.build_key(proj_a, "VIEWER", "stats", "summary")
    key_admin_b = BoundedQueryCache.build_key(proj_b, "ADMIN", "stats", "summary")

    # Verify keys are structurally distinct
    assert key_admin_a != key_viewer_a
    assert key_admin_a != key_admin_b
    assert "ADMIN" in key_admin_a
    assert "VIEWER" in key_viewer_a
    assert proj_a in key_admin_a
    assert proj_b in key_admin_b

    test_cache = BoundedQueryCache(max_capacity=10)
    test_cache.set(proj_a, "ADMIN", "stats", "summary", {"sensitive": "admin_only_data"})

    # Viewer or Project B cannot access Admin A data
    assert test_cache.get(proj_a, "VIEWER", "stats", "summary") is None
    assert test_cache.get(proj_b, "ADMIN", "stats", "summary") is None
    assert test_cache.get(proj_a, "ADMIN", "stats", "summary") == {"sensitive": "admin_only_data"}


def test_cache_invalidation_on_project_event():
    """Verify targeted cache invalidation by project_id."""
    test_cache = BoundedQueryCache(max_capacity=10)
    test_cache.set("proj-123", "LEAD", "stats", "k1", "data1")
    test_cache.set("proj-123", "VIEWER", "stats", "k2", "data2")
    test_cache.set("proj-456", "LEAD", "stats", "k3", "data3")

    # Invalidate proj-123
    removed = test_cache.invalidate_project("proj-123")
    assert removed == 2

    assert test_cache.get("proj-123", "LEAD", "stats", "k1") is None
    assert test_cache.get("proj-123", "VIEWER", "stats", "k2") is None
    assert test_cache.get("proj-456", "LEAD", "stats", "k3") == "data3"


def test_evidence_payload_deferral_mechanics(db, client, perf_project, perf_admin):
    """Verify that listing findings defers heavy evidence payloads unless requested."""
    # Create job, finding, and evidence
    job = AssessmentJob(
        project_id=perf_project.id,
        target_input="192.168.1.50",
        adapter_name="perf_scanner",
        adapter_version="1.0.0",
        status=AssessmentStatus.COMPLETED,
        timeout_seconds=300,
        retry_count=0,
        max_retries=3,
        progress_pct=100,
        is_simulated=True,
        created_by_id=perf_admin.id,
        config={},
        summary_stats={},
    )
    db.add(job)
    db.commit()

    finding = AssessmentFinding(
        project_id=perf_project.id,
        job_id=job.id,
        target_value="192.168.1.50",
        title="Heavy Evidence Finding",
        description="Payload deferral test",
        severity=FindingSeverity.HIGH,
        confidence=FindingConfidence.FIRM,
        is_simulated=True,
        reproduction_steps="Probe port 443",
    )
    db.add(finding)
    db.commit()

    heavy_payload = "PAYLOAD_" + ("A" * 10240)  # 10 KB string
    evidence = FindingEvidence(
        finding_id=finding.id,
        evidence_type="RAW_PACKET_DUMP",
        payload=heavy_payload,
        sha256_hash="mockhash123",
    )
    db.add(evidence)
    db.commit()

    headers = auth_header_for_user(perf_admin)

    # 1. List findings with default deferral (include_payloads=false)
    resp_deferred = client.get(
        f"/api/v1/projects/{perf_project.id}/assessments/{job.id}/findings?include_payloads=false",
        headers=headers,
    )
    assert resp_deferred.status_code == status.HTTP_200_OK
    data_deferred = resp_deferred.json()
    assert len(data_deferred) == 1
    ev_list = data_deferred[0].get("evidence_items", [])
    assert len(ev_list) == 1
    assert ev_list[0].get("payload") is None

    # 2. List findings with explicit payload retrieval (include_payloads=true)
    resp_full = client.get(
        f"/api/v1/projects/{perf_project.id}/assessments/{job.id}/findings?include_payloads=true",
        headers=headers,
    )
    assert resp_full.status_code == status.HTTP_200_OK
    data_full = resp_full.json()
    assert len(data_full) == 1
    assert data_full[0]["evidence_items"][0]["payload"] == heavy_payload


def test_sqlite_wal_concurrent_execution():
    """Verify SQLite WAL concurrency under simultaneous multi-threaded reads and writes using a standalone WAL db."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        tmp_db_path = tmp.name

    try:
        # Initialize SQLite database with WAL mode and table
        conn = sqlite3.connect(tmp_db_path)
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA busy_timeout=5000;")
        conn.execute(
            "CREATE TABLE perf_findings ("
            "id TEXT PRIMARY KEY, "
            "project_id TEXT, "
            "title TEXT, "
            "status TEXT"
            ");"
        )
        conn.commit()
        conn.close()

        def reader_task(worker_id):
            c = sqlite3.connect(tmp_db_path, timeout=5.0)
            c.execute("PRAGMA busy_timeout=5000;")
            try:
                for _ in range(15):
                    cur = c.cursor()
                    cur.execute("SELECT COUNT(*) FROM perf_findings")
                    _ = cur.fetchone()
                    time.sleep(0.005)
                return True
            finally:
                c.close()

        def writer_task(worker_id):
            c = sqlite3.connect(tmp_db_path, timeout=5.0)
            c.execute("PRAGMA busy_timeout=5000;")
            try:
                for j in range(5):
                    fid = str(uuid.uuid4())
                    c.execute(
                        "INSERT INTO perf_findings (id, project_id, title, status) VALUES (?, ?, ?, ?)",
                        (fid, "proj-test", f"Finding {worker_id}-{j}", "DETECTED"),
                    )
                    c.commit()
                    time.sleep(0.01)
                return True
            finally:
                c.close()

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            readers = [pool.submit(reader_task, i) for i in range(5)]
            writers = [pool.submit(writer_task, i) for i in range(3)]
            all_tasks = readers + writers
            concurrent.futures.wait(all_tasks)

            for t in all_tasks:
                assert t.result() is True
    finally:
        if os.path.exists(tmp_db_path):
            try:
                os.remove(tmp_db_path)
            except OSError:
                pass


def test_performance_endpoints_metrics_and_wal_status(client, perf_admin):
    """Test performance API endpoints for cache metrics, clearing, and WAL status."""
    headers = auth_header_for_user(perf_admin)

    # 1. Cache metrics
    resp_metrics = client.get("/api/v1/system/performance/cache-metrics", headers=headers)
    assert resp_metrics.status_code == status.HTTP_200_OK
    metrics = resp_metrics.json()
    assert "total_cached_items" in metrics
    assert "hits" in metrics
    assert "misses" in metrics
    assert "hit_ratio" in metrics

    # 2. SQLite WAL status
    resp_wal = client.get("/api/v1/system/performance/sqlite-wal", headers=headers)
    assert resp_wal.status_code == status.HTTP_200_OK
    wal_status = resp_wal.json()
    assert "journal_mode" in wal_status
    assert "wal_concurrency_enabled" in wal_status

    # 3. Cache clear
    resp_clear = client.post("/api/v1/system/performance/cache-clear", headers=headers)
    assert resp_clear.status_code == status.HTTP_200_OK
    clear_data = resp_clear.json()
    assert clear_data["cleared_scope"] == "GLOBAL"
