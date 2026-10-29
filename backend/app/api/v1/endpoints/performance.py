"""
VAPT Platform — Performance Engineering & Workload Isolation API (Prompt 26).
Provides endpoints for workload capacity monitoring, backpressure telemetry,
performance budget conformance, dead-worker lease scavenging, and deterministic benchmarks.
"""
from typing import Optional
from fastapi import APIRouter, Depends, Query, HTTPException, status
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.api.deps import get_current_user, require_system_roles
from app.models.user import User, SystemRole
from app.services.workload_isolation_service import workload_isolation_service
from app.services.query_cache_service import query_cache
from app.schemas.performance import (
    WorkloadQueueStatus,
    PerformanceBudgetsResponse,
    BenchmarkSuiteResponse,
    StaleJobReconciliationResult,
)

router = APIRouter()


@router.get("/workload", response_model=WorkloadQueueStatus)
def get_workload_queue_status(
    current_user: User = Depends(require_system_roles([SystemRole.ADMIN, SystemRole.SECURITY_LEAD, SystemRole.AUDITOR, SystemRole.SECURITY_TESTER])),
):
    """
    Returns real-time worker concurrency, queue depth, utilization, and backpressure metrics.
    """
    return workload_isolation_service.get_queue_status()


@router.get("/budgets", response_model=PerformanceBudgetsResponse)
def get_performance_budgets(
    current_user: User = Depends(require_system_roles([SystemRole.ADMIN, SystemRole.SECURITY_LEAD, SystemRole.AUDITOR, SystemRole.SECURITY_TESTER])),
):
    """
    Returns p50, p95, p99 operation latencies evaluated against explicit performance budgets.
    """
    return workload_isolation_service.get_performance_budgets()


@router.post("/benchmark", response_model=BenchmarkSuiteResponse)
def run_performance_benchmark(
    dataset_size: str = Query("SMALL", description="Synthetic benchmark size: SMALL (100), MEDIUM (1,000), LARGE (5,000)"),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_system_roles([SystemRole.ADMIN, SystemRole.SECURITY_LEAD])),
):
    """
    Executes an on-demand synthetic performance benchmark measuring query latencies across indexed tables.
    """
    return workload_isolation_service.run_synthetic_benchmark(db, dataset_size=dataset_size)


@router.post("/reconcile-stale-jobs", response_model=StaleJobReconciliationResult)
def reconcile_stale_jobs(
    timeout_seconds: int = Query(300, description="Worker heartbeat expiration threshold in seconds"),
    db: Session = Depends(get_db),
    current_user: User = Depends(require_system_roles([SystemRole.ADMIN, SystemRole.SECURITY_LEAD])),
):
    """
    Scavenges orphaned assessment worker leases and transitions dead jobs to TIMED_OUT.
    """
    return workload_isolation_service.reconcile_stale_jobs(db, lease_timeout_seconds=timeout_seconds)


@router.get("/cache-metrics")
def get_query_cache_metrics(
    current_user: User = Depends(require_system_roles([SystemRole.ADMIN, SystemRole.SECURITY_LEAD, SystemRole.AUDITOR])),
):
    """
    Returns real-time query cache statistics, hit ratios, evictions, and invalidations (Prompt 41).
    """
    return query_cache.get_metrics()


@router.post("/cache-clear")
def clear_query_cache(
    project_id: Optional[str] = Query(None, description="Optional project ID to selectively invalidate; omit to clear all"),
    current_user: User = Depends(require_system_roles([SystemRole.ADMIN, SystemRole.SECURITY_LEAD])),
):
    """
    Clears bounded query cache entries with optional tenant/project filtering (Prompt 41).
    """
    if project_id:
        count = query_cache.invalidate_project(project_id)
        return {"cleared_scope": f"project:{project_id}", "invalidated_count": count}
    query_cache.clear()
    return {"cleared_scope": "GLOBAL", "message": "All query cache partitions purged."}


@router.get("/sqlite-wal")
def get_sqlite_wal_status(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_system_roles([SystemRole.ADMIN, SystemRole.SECURITY_LEAD, SystemRole.AUDITOR])),
):
    """
    Inspects active SQLite pragma configuration: WAL journal mode, synchronous level, busy timeout, and cache size (Prompt 41).
    """
    from sqlalchemy import text
    journal_mode = db.execute(text("PRAGMA journal_mode;")).scalar()
    synchronous = db.execute(text("PRAGMA synchronous;")).scalar()
    busy_timeout = db.execute(text("PRAGMA busy_timeout;")).scalar()
    page_size = db.execute(text("PRAGMA page_size;")).scalar()
    cache_size = db.execute(text("PRAGMA cache_size;")).scalar()

    return {
        "journal_mode": str(journal_mode).upper(),
        "synchronous_level": synchronous,
        "busy_timeout_ms": busy_timeout,
        "page_size_bytes": page_size,
        "cache_size_pages": cache_size,
        "wal_concurrency_enabled": str(journal_mode).upper() == "WAL",
    }

