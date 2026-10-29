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
