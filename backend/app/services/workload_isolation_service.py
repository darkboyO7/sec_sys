"""
VAPT Platform — Workload Isolation & Performance Engineering Service (Prompt 26).
Provides:
1. Concurrency-bounded worker execution pool and backpressure enforcement.
2. Dead-worker lease scavenging and deterministic orphaned job reconciliation.
3. In-memory percentile latency tracking against explicit performance budgets.
4. Synthetic performance benchmarking across indexed datasets.
"""
import os
import sys
import time
import uuid
import threading
from collections import defaultdict, deque
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional, Tuple

from sqlalchemy.orm import Session
from sqlalchemy import text, func

from app.core.config import settings
from app.models.base import utc_now
from app.models.organization import Organization
from app.models.project import Project
from app.models.assessment import AssessmentJob, AssessmentStatus
from app.models.finding import VulnerabilityFinding
from app.models.asset import Asset
from app.models.graph import GraphNode, GraphRelationship
from app.schemas.performance import (
    WorkloadPriority,
    WorkloadQueueStatus,
    PerformanceBudget,
    PerformanceBudgetsResponse,
    BenchmarkResult,
    BenchmarkSuiteResponse,
    StaleJobReconciliationResult,
)


class WorkloadSaturatedError(Exception):
    """Raised when worker pool and pending queue exceed configured capacity limits."""
    pass


# Default performance targets (milliseconds)
DEFAULT_PERFORMANCE_BUDGETS: Dict[str, float] = {
    "HEALTH_CHECK": 10.0,
    "DASHBOARD_SUMMARY": 50.0,
    "FINDINGS_LIST": 40.0,
    "JOB_SUBMISSION": 30.0,
    "GRAPH_TRAVERSAL": 100.0,
    "BENCHMARK": 250.0,
}


class WorkloadIsolationService:
    def __init__(
        self,
        max_concurrent_workers: int = 4,
        max_queue_depth: int = 20,
        lease_timeout_seconds: int = 300,
    ):
        self.max_concurrent_workers = max_concurrent_workers
        self.max_queue_depth = max_queue_depth
        self.lease_timeout_seconds = lease_timeout_seconds

        self._active_workers = 0
        self._queued_tasks: deque = deque()
        self._rejected_tasks_count = 0
        self._lock = threading.Lock()

        # Circular buffer for operation latencies (last 200 samples per operation)
        self._latency_samples: Dict[str, deque] = defaultdict(lambda: deque(maxlen=200))

    # --------------------------------------------------------------------------
    # 1. Workload Concurrency & Backpressure
    # --------------------------------------------------------------------------
    def acquire_slot(
        self,
        task_id: str,
        priority: WorkloadPriority = WorkloadPriority.BACKGROUND,
    ) -> bool:
        """
        Acquires an execution slot under configured concurrency bounds.
        Applies backpressure (WorkloadSaturatedError) when capacity is exhausted.
        """
        with self._lock:
            # Interactive tasks can use reserve headroom (+1)
            effective_max = self.max_concurrent_workers + (1 if priority == WorkloadPriority.INTERACTIVE else 0)

            if self._active_workers < effective_max:
                self._active_workers += 1
                return True

            # If capacity saturated, inspect queue depth
            if len(self._queued_tasks) >= self.max_queue_depth:
                self._rejected_tasks_count += 1
                raise WorkloadSaturatedError(
                    f"Workload saturated: {self._active_workers} active workers, "
                    f"{len(self._queued_tasks)} queued tasks. Maximum queue depth of "
                    f"{self.max_queue_depth} exceeded. Request deferred."
                )

            # Enqueue task
            priority_val = priority.value if hasattr(priority, "value") else str(priority)
            self._queued_tasks.append({
                "task_id": task_id,
                "priority": priority_val,
                "enqueued_at": time.time(),
            })
            return False

    def acquire_worker_slot(
        self,
        task_id: str,
        priority: WorkloadPriority = WorkloadPriority.BACKGROUND,
        operation: str = "DEFAULT",
    ) -> bool:
        """Alias for acquire_slot."""
        return self.acquire_slot(task_id, priority)

    def release_slot(self) -> None:
        """
        Releases an active worker slot and promotes the next eligible queued task.
        """
        with self._lock:
            if self._active_workers > 0:
                self._active_workers -= 1
            if self._queued_tasks and self._active_workers < self.max_concurrent_workers:
                next_task = self._pop_highest_priority_task_unlocked()
                if next_task:
                    self._active_workers += 1

    def release_worker_slot(self, task_id: Optional[str] = None) -> None:
        """Alias for release_slot."""
        self.release_slot()

    def enqueue_pending_task(
        self,
        task_id: str,
        priority: WorkloadPriority = WorkloadPriority.BACKGROUND,
    ) -> None:
        """
        Directly enqueues a pending background task or raises WorkloadSaturatedError if queue is full.
        """
        with self._lock:
            if len(self._queued_tasks) >= self.max_queue_depth:
                self._rejected_tasks_count += 1
                raise WorkloadSaturatedError(
                    f"Workload queue saturated: depth {len(self._queued_tasks)} >= max {self.max_queue_depth}."
                )
            priority_val = priority.value if hasattr(priority, "value") else str(priority)
            self._queued_tasks.append({
                "task_id": task_id,
                "priority": priority_val,
                "enqueued_at": time.time(),
            })

    def _pop_highest_priority_task_unlocked(self) -> Optional[Dict[str, Any]]:
        """Pops the task with highest priority (INTERACTIVE > BACKGROUND > MAINTENANCE)."""
        if not self._queued_tasks:
            return None
        rank_order = {"INTERACTIVE": 0, "BACKGROUND": 1, "MAINTENANCE": 2}
        best_idx = 0
        best_rank = 999
        for idx, task in enumerate(self._queued_tasks):
            p = task.get("priority", "BACKGROUND")
            rank = rank_order.get(p, 1)
            if rank < best_rank:
                best_rank = rank
                best_idx = idx
        task = self._queued_tasks[best_idx]
        del self._queued_tasks[best_idx]
        return task

    def dequeue_next_task(self) -> Optional[Dict[str, Any]]:
        """
        Dequeues the next pending task honoring priority tiers.
        """
        with self._lock:
            return self._pop_highest_priority_task_unlocked()

    def get_queue_status(self) -> WorkloadQueueStatus:
        """
        Returns real-time capacity and queue depth metrics.
        """
        with self._lock:
            active = self._active_workers
            queue_len = len(self._queued_tasks)
            utilization = round((active / self.max_concurrent_workers) * 100.0, 1) if self.max_concurrent_workers > 0 else 0.0
            saturated = (active >= self.max_concurrent_workers and queue_len >= self.max_queue_depth)

            return WorkloadQueueStatus(
                active_workers=active,
                max_concurrent_workers=self.max_concurrent_workers,
                queue_depth=queue_len,
                max_queue_depth=self.max_queue_depth,
                capacity_utilization_pct=utilization,
                saturated=saturated,
                rejected_tasks_count=self._rejected_tasks_count,
                active_tasks=list(self._queued_tasks),
            )

    # --------------------------------------------------------------------------
    # 2. Dead-Worker Lease Scavenging & Stale Job Recovery
    # --------------------------------------------------------------------------
    def reconcile_stale_jobs(
        self,
        db: Session,
        lease_timeout_seconds: Optional[int] = None,
    ) -> StaleJobReconciliationResult:
        """
        Reconciles orphaned background assessment jobs whose worker heartbeat has expired.
        Uses indexed (status, heartbeat_at) scan to update stale jobs to TIMED_OUT.
        """
        timeout = lease_timeout_seconds or self.lease_timeout_seconds
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=timeout)

        # Find active jobs that have missed heartbeats
        active_statuses = [
            AssessmentStatus.RUNNING.value if hasattr(AssessmentStatus.RUNNING, "value") else "RUNNING",
            AssessmentStatus.PREFLIGHT.value if hasattr(AssessmentStatus.PREFLIGHT, "value") else "PREFLIGHT",
            AssessmentStatus.QUEUED.value if hasattr(AssessmentStatus.QUEUED, "value") else "QUEUED",
        ]

        stale_jobs = (
            db.query(AssessmentJob)
            .filter(
                AssessmentJob.status.in_(active_statuses),
                (AssessmentJob.heartbeat_at < cutoff) | (AssessmentJob.heartbeat_at.is_(None) & (AssessmentJob.created_at < cutoff)),
            )
            .all()
        )

        reconciled_ids: List[str] = []
        details: List[str] = []

        now = utc_now()
        for job in stale_jobs:
            prior_status = job.status
            job.status = AssessmentStatus.TIMED_OUT.value if hasattr(AssessmentStatus.TIMED_OUT, "value") else "TIMED_OUT"
            job.completed_at = now
            job.error_message = f"Orphaned worker lease expired: no heartbeat received for > {timeout}s"
            reconciled_ids.append(job.id)
            details.append(f"Job {job.id} transitioned from {prior_status} to TIMED_OUT (worker: {job.claimed_by or 'none'})")

        if stale_jobs:
            db.commit()

        return StaleJobReconciliationResult(
            scanned_jobs=len(stale_jobs),
            recovered_jobs_count=len(reconciled_ids),
            reconciled_job_ids=reconciled_ids,
            details=details,
        )

    # --------------------------------------------------------------------------
    # 3. Performance Budget Tracking
    # --------------------------------------------------------------------------
    def record_latency(self, operation: str, duration_ms: float) -> None:
        """
        Thread-safe recording of an operation's execution duration in milliseconds.
        """
        with self._lock:
            self._latency_samples[operation].append(duration_ms)

    def get_performance_budgets(self) -> PerformanceBudgetsResponse:
        """
        Computes p50, p95, p99 percentiles for tracked operations and evaluates budget conformance.
        """
        with self._lock:
            budgets: List[PerformanceBudget] = []
            overall_healthy = True

            for op_name, target_ms in DEFAULT_PERFORMANCE_BUDGETS.items():
                samples = list(self._latency_samples.get(op_name, []))
                if samples:
                    sorted_samples = sorted(samples)
                    n = len(sorted_samples)
                    p50 = sorted_samples[int(n * 0.50)]
                    p95 = sorted_samples[min(int(n * 0.95), n - 1)]
                    p99 = sorted_samples[min(int(n * 0.99), n - 1)]
                    within_budget = (p95 <= target_ms)
                    if not within_budget:
                        overall_healthy = False
                else:
                    p50 = 0.0
                    p95 = 0.0
                    p99 = 0.0
                    within_budget = True

                budgets.append(
                    PerformanceBudget(
                        operation=op_name,
                        budget_ms=target_ms,
                        p50_ms=round(p50, 2),
                        p95_ms=round(p95, 2),
                        p99_ms=round(p99, 2),
                        sample_count=len(samples),
                        within_budget=within_budget,
                    )
                )

            return PerformanceBudgetsResponse(
                budgets=budgets,
                overall_healthy=overall_healthy,
            )

    # --------------------------------------------------------------------------
    # 4. Deterministic Synthetic Benchmark Engine
    # --------------------------------------------------------------------------
    def run_synthetic_benchmark(
        self,
        db: Session,
        dataset_size: str = "SMALL",
    ) -> BenchmarkSuiteResponse:
        """
        Executes a deterministic performance benchmark across indexed tables using synthetic datasets.
        Sizes:
          SMALL: 100 items
          MEDIUM: 1,000 items
          LARGE: 5,000 items
        """
        size_map = {"SMALL": 100, "MEDIUM": 1000, "LARGE": 5000}
        n_records = size_map.get(dataset_size.upper(), 100)
        bench_org_id = f"bench-org-{uuid.uuid4().hex[:8]}"
        benchmark_proj_id = f"bench-proj-{uuid.uuid4().hex[:8]}"

        benchmarks: List[BenchmarkResult] = []
        suite_start = time.perf_counter()

        # Step A: Seed synthetic benchmark organization, project, findings & assets
        bench_org = Organization(
            id=bench_org_id,
            name="Benchmark Org",
            slug=f"bench-org-{uuid.uuid4().hex[:8]}",
            is_active=True,
        )
        bench_proj = Project(
            id=benchmark_proj_id,
            organization_id=bench_org_id,
            name="Benchmark Project",
            is_active=True,
        )
        db.add(bench_org)
        db.add(bench_proj)
        db.commit()

        try:
            findings_to_insert = [
                VulnerabilityFinding(
                    project_id=benchmark_proj_id,
                    fingerprint=f"fp-bench-{i}-{uuid.uuid4().hex[:6]}",
                    target_value=f"10.0.0.{i % 254 + 1}",
                    title=f"Synthetic Vulnerability #{i}",
                    status="DETECTED" if i % 2 == 0 else "CONFIRMED",
                    severity="HIGH" if i % 3 == 0 else "MEDIUM",
                    vuln_id=f"CVE-2026-{1000 + i}",
                )
                for i in range(n_records)
            ]
            db.bulk_save_objects(findings_to_insert)
            db.commit()

            # Benchmark 1: Indexed Finding Filter (project_id, severity, status)
            t0 = time.perf_counter()
            f_count = (
                db.query(VulnerabilityFinding)
                .filter(
                    VulnerabilityFinding.project_id == benchmark_proj_id,
                    VulnerabilityFinding.severity == "HIGH",
                    VulnerabilityFinding.status == "DETECTED",
                )
                .count()
            )
            dur_1 = (time.perf_counter() - t0) * 1000.0
            ops_1 = round((n_records / (dur_1 / 1000.0)), 1) if dur_1 > 0 else 0.0
            self.record_latency("FINDINGS_LIST", dur_1)
            benchmarks.append(
                BenchmarkResult(
                    operation="Indexed Finding Filter (severity+status)",
                    dataset_size=dataset_size,
                    record_count=n_records,
                    duration_ms=round(dur_1, 2),
                    ops_per_second=ops_1,
                    query_count=1,
                )
            )

            # Benchmark 2: Timeline Ordering (project_id, created_at desc)
            t0 = time.perf_counter()
            ordered_findings = (
                db.query(VulnerabilityFinding.id, VulnerabilityFinding.title)
                .filter(VulnerabilityFinding.project_id == benchmark_proj_id)
                .order_by(VulnerabilityFinding.created_at.desc())
                .limit(50)
                .all()
            )
            dur_2 = (time.perf_counter() - t0) * 1000.0
            ops_2 = round((50.0 / (dur_2 / 1000.0)), 1) if dur_2 > 0 else 0.0
            benchmarks.append(
                BenchmarkResult(
                    operation="Indexed Finding Pagination & Timeline Ordering",
                    dataset_size=dataset_size,
                    record_count=len(ordered_findings),
                    duration_ms=round(dur_2, 2),
                    ops_per_second=ops_2,
                    query_count=1,
                )
            )

            # Benchmark 3: Dashboard Aggregation (group by severity)
            t0 = time.perf_counter()
            agg_stats = (
                db.query(VulnerabilityFinding.severity, func.count(VulnerabilityFinding.id))
                .filter(VulnerabilityFinding.project_id == benchmark_proj_id)
                .group_by(VulnerabilityFinding.severity)
                .all()
            )
            dur_3 = (time.perf_counter() - t0) * 1000.0
            ops_3 = round((n_records / (dur_3 / 1000.0)), 1) if dur_3 > 0 else 0.0
            self.record_latency("DASHBOARD_SUMMARY", dur_3)
            benchmarks.append(
                BenchmarkResult(
                    operation="Dashboard Finding KPI Aggregation",
                    dataset_size=dataset_size,
                    record_count=n_records,
                    duration_ms=round(dur_3, 2),
                    ops_per_second=ops_3,
                    query_count=1,
                )
            )
        finally:
            # Clean up synthetic benchmark data cleanly
            try:
                db.query(VulnerabilityFinding).filter(VulnerabilityFinding.project_id == benchmark_proj_id).delete()
                db.query(Project).filter(Project.id == benchmark_proj_id).delete()
                db.query(Organization).filter(Organization.id == bench_org_id).delete()
                db.commit()
            except Exception:
                db.rollback()

        total_dur = (time.perf_counter() - suite_start) * 1000.0
        self.record_latency("BENCHMARK", total_dur)

        summary = (
            f"Executed 3 core benchmarks on {n_records} synthetic records. "
            f"Indexed filter: {dur_1:.2f}ms ({ops_1} ops/s); "
            f"Timeline ordering: {dur_2:.2f}ms; "
            f"KPI aggregation: {dur_3:.2f}ms."
        )

        return BenchmarkSuiteResponse(
            environment={
                "python_version": sys.version.split()[0],
                "os": sys.platform,
                "db_dialect": db.bind.dialect.name if db.bind else "sqlite",
            },
            dataset_size=dataset_size,
            benchmarks=benchmarks,
            total_duration_ms=round(total_dur, 2),
            summary=summary,
        )


workload_isolation_service = WorkloadIsolationService()
