"""
Reproducible Benchmark and Evidence-Based Performance Verification (Prompt 41).
Measures query latencies, index efficiency, memory allocation differences,
bounded query cache hit ratios, and SQLite WAL lock contention under concurrency.
"""
import concurrent.futures
import json
import os
import sqlite3
import sys
import tempfile
import time
import uuid
from pathlib import Path

# Add backend directory to path
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "backend"))

from sqlalchemy import func
from app.core.database import SessionLocal, engine
from app.models.project import Project, ProjectMember, ProjectRole
from app.models.organization import Organization
from app.models.user import User, SystemRole
from app.models.asset import Asset, AssetType, AssetCriticality, AssetStatus
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
from app.services.query_cache_service import DatabaseOptimizationService, query_cache


def run_performance_benchmarks():
    print("=" * 80)
    print("   VAPT PLATFORM -- EVIDENCE-BASED PERFORMANCE BENCHMARK (PROMPT 41)")
    print("=" * 80)

    db = SessionLocal()
    results = {}

    try:
        # Create test organization and project
        org = Organization(name="Perf Benchmark Org", slug=f"perf-org-{uuid.uuid4().hex[:6]}")
        db.add(org)
        db.commit()

        project = Project(name="Perf Benchmark Project", organization_id=org.id)
        db.add(project)
        db.commit()

        test_user = User(
            email=f"perf-{uuid.uuid4().hex[:6]}@example.com",
            hashed_password="mock_hashed_pw",
            full_name="Perf Tester",
            system_role=SystemRole.SECURITY_TESTER,
            is_active=True,
        )
        db.add(test_user)
        db.commit()

        # ----------------------------------------------------------------------
        # Benchmark 1: Finding Stats Aggregation (Full Scan vs Direct SQL vs Cache)
        # ----------------------------------------------------------------------
        print("\n[*] Seed dataset: Creating 500 test findings...")
        findings_to_insert = []
        statuses = list(FindingLifecycleStatus)
        severities = list(FindingSeverity)

        for i in range(500):
            st = statuses[i % len(statuses)]
            sev = severities[i % len(severities)]
            findings_to_insert.append(
                VulnerabilityFinding(
                    project_id=project.id,
                    title=f"Benchmark Vulnerability Finding #{i}",
                    vuln_id=f"CVE-2026-{1000 + i}",
                    status=st,
                    severity=sev,
                    fingerprint=f"fp-perf-{i}-{uuid.uuid4().hex[:8]}",
                    target_value=f"10.0.{(i // 256)}.{(i % 256)}",
                    has_contradictions=(i % 10 == 0),
                )
            )
        db.bulk_save_objects(findings_to_insert)
        db.commit()

        # Baseline: Unoptimized Full-Table Python Scan (simulating pre-optimization code)
        t0 = time.perf_counter()
        raw_findings = db.query(VulnerabilityFinding).filter(VulnerabilityFinding.project_id == project.id).all()
        by_status_raw = {}
        for f in raw_findings:
            by_status_raw[f.status.value] = by_status_raw.get(f.status.value, 0) + 1
        t_raw_scan_ms = (time.perf_counter() - t0) * 1000.0

        # Optimized SQL Aggregation (Group By without cache)
        t0 = time.perf_counter()
        stats_sql = DatabaseOptimizationService.get_finding_stats_optimized(
            db, project.id, user_role="LEAD", use_cache=False
        )
        t_sql_agg_ms = (time.perf_counter() - t0) * 1000.0

        # Optimized with Bounded Cache (Warm Cache Hit)
        DatabaseOptimizationService.get_finding_stats_optimized(
            db, project.id, user_role="LEAD", use_cache=True
        )  # populate
        t0 = time.perf_counter()
        stats_cached = DatabaseOptimizationService.get_finding_stats_optimized(
            db, project.id, user_role="LEAD", use_cache=True
        )
        t_cached_ms = (time.perf_counter() - t0) * 1000.0

        print(f"    - Full Entity Python Scan Latency: {t_raw_scan_ms:.2f} ms")
        print(f"    - Optimized SQL Group-By Latency: {t_sql_agg_ms:.2f} ms")
        print(f"    - Bounded Cache Latency:          {t_cached_ms:.4f} ms")
        speedup = t_raw_scan_ms / max(t_cached_ms, 0.0001)
        print(f"    => Speedup Factor: {speedup:.1f}x faster via cache!")

        results["finding_stats_aggregation"] = {
            "records_tested": 500,
            "raw_python_scan_ms": round(t_raw_scan_ms, 2),
            "optimized_sql_agg_ms": round(t_sql_agg_ms, 2),
            "cached_query_ms": round(t_cached_ms, 4),
            "speedup_factor": round(speedup, 1),
        }

        # ----------------------------------------------------------------------
        # Benchmark 2: Evidence Payload Deferral (Metadata Projection vs Raw Load)
        # ----------------------------------------------------------------------
        print("\n[*] Seed dataset: Creating assessment findings with large evidence payloads...")
        job = AssessmentJob(
            project_id=project.id,
            target_input="10.0.1.1",
            adapter_name="network_port_scanner",
            adapter_version="1.0.0",
            status=AssessmentStatus.COMPLETED,
            timeout_seconds=300,
            retry_count=0,
            max_retries=3,
            progress_pct=100,
            is_simulated=True,
            created_by_id=test_user.id,
            config={},
            summary_stats={},
        )
        db.add(job)
        db.commit()

        # Create finding and 20 evidence items with 50KB payloads each (~1MB total)
        finding = AssessmentFinding(
            project_id=project.id,
            job_id=job.id,
            target_value="10.0.1.1",
            title="Large Evidence Benchmark Finding",
            description="Stress test for evidence payload loading",
            severity=FindingSeverity.HIGH,
            confidence=FindingConfidence.FIRM,
            is_simulated=True,
            reproduction_steps="Run scanner",
        )
        db.add(finding)
        db.commit()

        large_payload = "X" * (50 * 1024)  # 50 KB text per evidence item
        evidence_items = []
        for i in range(20):
            evidence_items.append(
                FindingEvidence(
                    finding_id=finding.id,
                    evidence_type="RAW_PACKET_STREAM",
                    payload=large_payload,
                    sha256_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                )
            )
        db.bulk_save_objects(evidence_items)
        db.commit()

        # Query 1: Full Load (including heavy payload)
        t0 = time.perf_counter()
        full_ev = db.query(FindingEvidence).filter(FindingEvidence.finding_id == finding.id).all()
        total_bytes_loaded = sum(len(e.payload) for e in full_ev)
        t_full_ev_ms = (time.perf_counter() - t0) * 1000.0

        # Query 2: Metadata-only projection (deferred payload)
        t0 = time.perf_counter()
        meta_ev = (
            db.query(FindingEvidence.id, FindingEvidence.evidence_type, FindingEvidence.sha256_hash, FindingEvidence.observed_at)
            .filter(FindingEvidence.finding_id == finding.id)
            .all()
        )
        t_meta_ev_ms = (time.perf_counter() - t0) * 1000.0

        print(f"    - Full Payload Load (20 x 50KB = {total_bytes_loaded/1024:.1f} KB): {t_full_ev_ms:.2f} ms")
        print(f"    - Metadata-Only Projection:                             {t_meta_ev_ms:.2f} ms")
        ev_speedup = t_full_ev_ms / max(t_meta_ev_ms, 0.0001)
        print(f"    => Payload Deferral Speedup: {ev_speedup:.1f}x faster, 0 KB payload materialized!")

        results["evidence_deferral"] = {
            "evidence_count": 20,
            "total_payload_kb": round(total_bytes_loaded / 1024, 1),
            "full_load_ms": round(t_full_ev_ms, 2),
            "metadata_projection_ms": round(t_meta_ev_ms, 2),
            "speedup_factor": round(ev_speedup, 1),
        }

        # ----------------------------------------------------------------------
        # Benchmark 3: SQLite WAL Mode Concurrency & Lock Contention Stress Test
        # ----------------------------------------------------------------------
        print("\n[*] Stress Testing SQLite WAL multi-threaded concurrency (10 parallel workers)...")

        target_project_id = str(project.id)
        target_org_id = str(org.id)

        def concurrent_reader(worker_id):
            session = SessionLocal()
            try:
                for _ in range(50):
                    _ = session.query(func.count(VulnerabilityFinding.id)).filter(VulnerabilityFinding.project_id == target_project_id).scalar()
                    time.sleep(0.001)
                return True
            finally:
                session.close()

        def concurrent_writer(worker_id):
            session = SessionLocal()
            try:
                for j in range(10):
                    a = Asset(
                        project_id=target_project_id,
                        organization_id=target_org_id,
                        name=f"worker-{worker_id}-asset-{j}.internal",
                        canonical_identifier=f"host:worker-{worker_id}-asset-{j}.internal",
                        asset_type=AssetType.HOST,
                        criticality=AssetCriticality.LOW,
                        status=AssetStatus.ACTIVE,
                        attributes={"is_scoped": False},
                    )
                    session.add(a)
                    session.commit()
                    time.sleep(0.002)
                return True
            finally:
                session.close()

        t0 = time.perf_counter()
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            readers = [executor.submit(concurrent_reader, i) for i in range(6)]
            writers = [executor.submit(concurrent_writer, i) for i in range(4)]
            all_futures = readers + writers
            concurrent.futures.wait(all_futures)

        concurrency_duration_s = time.perf_counter() - t0
        all_succeeded = all(f.result() is True for f in all_futures)
        print(f"    - 6 Readers (300 reads) + 4 Writers (40 commits) completed in {concurrency_duration_s:.2f}s")
        print(f"    - Concurrency Safety: {'VERIFIED (Zero Lock Errors)' if all_succeeded else 'FAILED'}")

        results["sqlite_wal_concurrency"] = {
            "concurrent_workers": 10,
            "readers": 6,
            "writers": 4,
            "total_reads": 300,
            "total_writes": 40,
            "duration_seconds": round(concurrency_duration_s, 2),
            "zero_lock_conflicts": all_succeeded,
        }

        # ----------------------------------------------------------------------
        # Benchmark 4: Cache Metrics Verification
        # ----------------------------------------------------------------------
        metrics = query_cache.get_metrics()
        print(f"\n[*] Query Cache Metrics: {json.dumps(metrics, indent=2)}")
        results["cache_metrics"] = metrics

        out_path = REPO_ROOT / "performance_benchmark_report.json"
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)

        print("\n" + "=" * 80)
        print(f"BENCHMARK COMPLETED: Report written to {out_path}")
        print("=" * 80)

    finally:
        db.close()


if __name__ == "__main__":
    run_performance_benchmarks()
