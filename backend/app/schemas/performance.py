"""
VAPT Platform — Performance Engineering & Workload Isolation Schemas (Prompt 26).
Typed models for performance budgets, workload backpressure, concurrency monitoring,
dead-worker lease scavenging, and deterministic benchmark metrics.
"""
from typing import Optional, List, Dict, Any
from datetime import datetime, timezone
import enum
from pydantic import BaseModel, Field


class WorkloadPriority(str, enum.Enum):
    INTERACTIVE = "INTERACTIVE"
    BACKGROUND = "BACKGROUND"
    MAINTENANCE = "MAINTENANCE"


class WorkloadQueueStatus(BaseModel):
    active_workers: int
    max_concurrent_workers: int
    queue_depth: int
    max_queue_depth: int
    capacity_utilization_pct: float
    saturated: bool
    rejected_tasks_count: int
    active_tasks: List[Dict[str, Any]] = Field(default_factory=list)
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class PerformanceBudget(BaseModel):
    operation: str
    budget_ms: float
    p50_ms: float
    p95_ms: float
    p99_ms: float
    sample_count: int
    within_budget: bool


class PerformanceBudgetsResponse(BaseModel):
    budgets: List[PerformanceBudget]
    overall_healthy: bool
    measured_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class BenchmarkResult(BaseModel):
    operation: str
    dataset_size: str
    record_count: int
    duration_ms: float
    ops_per_second: float
    query_count: int


class BenchmarkSuiteResponse(BaseModel):
    environment: Dict[str, str]
    dataset_size: str
    benchmarks: List[BenchmarkResult]
    total_duration_ms: float
    summary: str
    executed_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class StaleJobReconciliationResult(BaseModel):
    scanned_jobs: int
    recovered_jobs_count: int
    reconciled_job_ids: List[str] = Field(default_factory=list)
    details: List[str] = Field(default_factory=list)
    reconciled_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
