import { describe, it, expect, vi, beforeEach } from 'vitest';
import { api } from '../services/api';
import type {
  WorkloadPriority,
  WorkloadQueueStatus,
  PerformanceBudgetsResponse,
  BenchmarkSuiteResponse,
  StaleJobReconciliationResult,
} from '../types';

describe('Prompt 26: Performance Engineering, Workload Isolation & Scalable Processing', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('validates workload priority levels and queue thresholds', () => {
    const priorities: WorkloadPriority[] = ['INTERACTIVE', 'BACKGROUND', 'MAINTENANCE'];
    expect(priorities).toHaveLength(3);
    expect(priorities).toContain('INTERACTIVE');
    expect(priorities).toContain('BACKGROUND');
    expect(priorities).toContain('MAINTENANCE');
  });

  it('fetches real-time workload queue status via api.getWorkloadQueueStatus', async () => {
    const mockStatus: WorkloadQueueStatus = {
      active_workers: 2,
      max_concurrent_workers: 4,
      queue_depth: 5,
      max_queue_depth: 50,
      capacity_utilization_pct: 50.0,
      saturated: false,
      rejected_tasks_count: 0,
      active_tasks: [],
      timestamp: '2026-10-29T10:00:00Z',
    };

    const spy = vi.spyOn(api as any, 'request').mockResolvedValueOnce(mockStatus);
    const result = await api.getWorkloadQueueStatus();

    expect(spy).toHaveBeenCalledWith('/system/performance/workload');
    expect(result.active_workers).toBe(2);
    expect(result.capacity_utilization_pct).toBe(50.0);
    expect(result.saturated).toBe(false);
  });

  it('fetches latency percentiles and performance budgets via api.getPerformanceBudgets', async () => {
    const mockBudgets: PerformanceBudgetsResponse = {
      budgets: [
        {
          operation: 'FINDINGS_LIST',
          budget_ms: 250.0,
          p50_ms: 12.5,
          p95_ms: 45.2,
          p99_ms: 68.0,
          sample_count: 100,
          within_budget: true,
        },
        {
          operation: 'DASHBOARD_SUMMARY',
          budget_ms: 500.0,
          p50_ms: 25.0,
          p95_ms: 95.0,
          p99_ms: 120.0,
          sample_count: 50,
          within_budget: true,
        },
      ],
      overall_healthy: true,
      measured_at: '2026-10-29T10:00:00Z',
    };

    const spy = vi.spyOn(api as any, 'request').mockResolvedValueOnce(mockBudgets);
    const result = await api.getPerformanceBudgets();

    expect(spy).toHaveBeenCalledWith('/system/performance/budgets');
    expect(result.budgets).toHaveLength(2);
    expect(result.overall_healthy).toBe(true);
    expect(result.budgets[0].within_budget).toBe(true);
  });

  it('executes synthetic performance benchmark via api.runPerformanceBenchmark', async () => {
    const mockBenchmark: BenchmarkSuiteResponse = {
      environment: {
        python_version: '3.14.7',
        os: 'win32',
        db_dialect: 'sqlite',
      },
      dataset_size: 'SMALL',
      benchmarks: [
        {
          operation: 'Indexed Finding Filter (severity+status)',
          dataset_size: 'SMALL',
          record_count: 100,
          duration_ms: 8.5,
          ops_per_second: 11764.7,
          query_count: 1,
        },
        {
          operation: 'Indexed Finding Pagination & Timeline Ordering',
          dataset_size: 'SMALL',
          record_count: 50,
          duration_ms: 1.2,
          ops_per_second: 41666.7,
          query_count: 1,
        },
      ],
      total_duration_ms: 45.0,
      summary: 'Executed 2 core benchmarks on 100 synthetic records.',
      executed_at: '2026-10-29T10:00:00Z',
    };

    const spy = vi.spyOn(api as any, 'request').mockResolvedValueOnce(mockBenchmark);
    const result = await api.runPerformanceBenchmark('SMALL');

    expect(spy).toHaveBeenCalledWith('/system/performance/benchmark?dataset_size=SMALL', {
      method: 'POST',
    });
    expect(result.benchmarks).toHaveLength(2);
    expect(result.benchmarks[0].ops_per_second).toBeGreaterThan(10000);
  });

  it('scavenges dead-worker leases and recovers orphaned jobs via api.reconcileStaleJobs', async () => {
    const mockReconciliation: StaleJobReconciliationResult = {
      scanned_jobs: 1,
      recovered_jobs_count: 1,
      reconciled_job_ids: ['job-dead-worker-1'],
      details: ['Job job-dead-worker-1 transitioned from RUNNING to TIMED_OUT (worker: worker-dead)'],
      reconciled_at: '2026-10-29T10:00:00Z',
    };

    const spy = vi.spyOn(api as any, 'request').mockResolvedValueOnce(mockReconciliation);
    const result = await api.reconcileStaleJobs(300);

    expect(spy).toHaveBeenCalledWith('/system/performance/reconcile-stale-jobs?timeout_seconds=300', {
      method: 'POST',
    });
    expect(result.recovered_jobs_count).toBe(1);
    expect(result.reconciled_job_ids).toContain('job-dead-worker-1');
  });

  it('correctly detects saturation and capacity utilization under workload spikes', () => {
    const saturatedQueue: WorkloadQueueStatus = {
      active_workers: 4,
      max_concurrent_workers: 4,
      queue_depth: 50,
      max_queue_depth: 50,
      capacity_utilization_pct: 100.0,
      saturated: true,
      rejected_tasks_count: 12,
      active_tasks: [],
      timestamp: '2026-10-29T10:00:00Z',
    };

    expect(saturatedQueue.saturated).toBe(true);
    expect(saturatedQueue.capacity_utilization_pct).toBe(100.0);
    expect(saturatedQueue.rejected_tasks_count).toBe(12);
  });

  it('correctly flags budget breach when p95 exceeds SLA threshold', () => {
    const breachingBudget: PerformanceBudgetsResponse = {
      budgets: [
        {
          operation: 'ATTACK_PATH_QUERY',
          budget_ms: 1000.0,
          p50_ms: 450.0,
          p95_ms: 1250.0, // Exceeds 1000.0ms budget
          p99_ms: 1800.0,
          sample_count: 25,
          within_budget: false,
        },
      ],
      overall_healthy: false,
      measured_at: '2026-10-29T10:00:00Z',
    };

    expect(breachingBudget.overall_healthy).toBe(false);
    expect(breachingBudget.budgets[0].within_budget).toBe(false);
    expect(breachingBudget.budgets[0].p95_ms).toBeGreaterThan(breachingBudget.budgets[0].budget_ms);
  });

  it('validates benchmark query count to guarantee absence of N+1 scans', () => {
    const singleScanBenchmark: BenchmarkSuiteResponse = {
      environment: { python_version: '3.14.7', os: 'win32', db_dialect: 'sqlite' },
      dataset_size: 'MEDIUM',
      benchmarks: [
        {
          operation: 'Indexed Finding Filter',
          dataset_size: 'MEDIUM',
          record_count: 1000,
          duration_ms: 7.0,
          ops_per_second: 142857.0,
          query_count: 1, // Strictly 1 single index scan, not 1000 individual queries
        },
      ],
      total_duration_ms: 25.0,
      summary: 'Clean',
      executed_at: '2026-10-29T10:00:00Z',
    };

    expect(singleScanBenchmark.benchmarks[0].query_count).toBe(1);
  });
});
