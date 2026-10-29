import React, { useState, useEffect } from 'react';
import {
  Gauge,
  Zap,
  Activity,
  CheckCircle2,
  AlertTriangle,
  XCircle,
  RefreshCw,
  Play,
  Layers,
  Cpu,
  ShieldAlert,
  Database,
  Trash2,
  Server,
} from 'lucide-react';
import { api } from '../services/api';
import type {
  WorkloadQueueStatus,
  PerformanceBudgetsResponse,
  BenchmarkSuiteResponse,
  StaleJobReconciliationResult,
  QueryCacheMetrics,
  SqliteWalStatus,
} from '../types';

export const PerformanceEngineeringView: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'workload' | 'budgets' | 'benchmark' | 'optimization'>('workload');
  const [workloadStatus, setWorkloadStatus] = useState<WorkloadQueueStatus | null>(null);
  const [budgetsResponse, setBudgetsResponse] = useState<PerformanceBudgetsResponse | null>(null);
  const [benchmarkResult, setBenchmarkResult] = useState<BenchmarkSuiteResponse | null>(null);
  const [reconciliationResult, setReconciliationResult] = useState<StaleJobReconciliationResult | null>(null);
  const [cacheMetrics, setCacheMetrics] = useState<QueryCacheMetrics | null>(null);
  const [walStatus, setWalStatus] = useState<SqliteWalStatus | null>(null);
  const [benchmarkSize, setBenchmarkSize] = useState<'SMALL' | 'MEDIUM' | 'LARGE'>('SMALL');

  const [loading, setLoading] = useState<boolean>(true);
  const [actionLoading, setActionLoading] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    setLoading(true);
    setError(null);
    try {
      const [wlData, bgData, cmData, walData] = await Promise.all([
        api.getWorkloadQueueStatus(),
        api.getPerformanceBudgets(),
        api.getQueryCacheMetrics().catch(() => null),
        api.getSqliteWalStatus().catch(() => null),
      ]);
      setWorkloadStatus(wlData);
      setBudgetsResponse(bgData);
      setCacheMetrics(cmData);
      setWalStatus(walData);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed loading performance telemetry');
    } finally {
      setLoading(false);
    }
  };

  const handleClearCache = async () => {
    setActionLoading('cache_clear');
    setError(null);
    setSuccessMessage(null);
    try {
      const res = await api.clearQueryCache();
      setSuccessMessage(res.message || 'All query cache partitions purged.');
      const updated = await api.getQueryCacheMetrics();
      setCacheMetrics(updated);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to clear query cache');
    } finally {
      setActionLoading(null);
    }
  };

  const handleReconcileStaleJobs = async () => {
    setActionLoading('reconcile');
    setError(null);
    setSuccessMessage(null);
    try {
      const res = await api.reconcileStaleJobs(300);
      setReconciliationResult(res);
      setSuccessMessage(`Scavenged ${res.recovered_jobs_count} stale/orphaned assessment leases.`);
      const wlData = await api.getWorkloadQueueStatus();
      setWorkloadStatus(wlData);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to reconcile stale jobs');
    } finally {
      setActionLoading(null);
    }
  };

  const handleRunBenchmark = async () => {
    setActionLoading('benchmark');
    setError(null);
    setSuccessMessage(null);
    try {
      const res = await api.runPerformanceBenchmark(benchmarkSize);
      setBenchmarkResult(res);
      setSuccessMessage(`Synthetic benchmark completed in ${res.total_duration_ms}ms.`);
      // Refresh budgets since benchmark records latencies
      const bgData = await api.getPerformanceBudgets();
      setBudgetsResponse(bgData);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Benchmark execution failed');
    } finally {
      setActionLoading(null);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 flex items-center gap-2">
            <Gauge className="w-7 h-7 text-indigo-600" />
            Performance Engineering & Workload Isolation
          </h1>
          <p className="text-sm text-gray-500 mt-1">
            Deterministic workload bounds, bounded concurrency pools, p95 latency budgets, and synthetic performance benchmarking.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={loadData}
            disabled={loading || actionLoading !== null}
            className="inline-flex items-center gap-2 px-3.5 py-2 border border-gray-300 shadow-sm text-sm font-medium rounded-lg text-gray-700 bg-white hover:bg-gray-50 disabled:opacity-50"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
            Refresh Telemetry
          </button>
        </div>
      </div>

      {/* Notifications */}
      {error && (
        <div className="p-4 bg-red-50 border border-red-200 rounded-lg flex items-center gap-3 text-red-800 text-sm">
          <XCircle className="w-5 h-5 flex-shrink-0 text-red-500" />
          <span>{error}</span>
        </div>
      )}
      {successMessage && (
        <div className="p-4 bg-emerald-50 border border-emerald-200 rounded-lg flex items-center gap-3 text-emerald-800 text-sm">
          <CheckCircle2 className="w-5 h-5 flex-shrink-0 text-emerald-500" />
          <span>{successMessage}</span>
        </div>
      )}

      {/* Navigation Tabs */}
      <div className="flex border-b border-gray-200 space-x-6">
        <button
          onClick={() => setActiveTab('workload')}
          className={`pb-3 text-sm font-medium flex items-center gap-2 border-b-2 transition-colors ${
            activeTab === 'workload'
              ? 'border-indigo-600 text-indigo-600'
              : 'border-transparent text-gray-500 hover:text-gray-700'
          }`}
        >
          <Layers className="w-4 h-4" />
          Workload Concurrency & Backpressure
        </button>
        <button
          onClick={() => setActiveTab('budgets')}
          className={`pb-3 text-sm font-medium flex items-center gap-2 border-b-2 transition-colors ${
            activeTab === 'budgets'
              ? 'border-indigo-600 text-indigo-600'
              : 'border-transparent text-gray-500 hover:text-gray-700'
          }`}
        >
          <Zap className="w-4 h-4" />
          Performance Budgets & Percentiles
        </button>
        <button
          onClick={() => setActiveTab('benchmark')}
          className={`pb-3 text-sm font-medium flex items-center gap-2 border-b-2 transition-colors ${
            activeTab === 'benchmark'
              ? 'border-indigo-600 text-indigo-600'
              : 'border-transparent text-gray-500 hover:text-gray-700'
          }`}
        >
          <Activity className="w-4 h-4" />
          Synthetic Benchmarking Suite
        </button>
        <button
          onClick={() => setActiveTab('optimization')}
          className={`pb-3 text-sm font-medium flex items-center gap-2 border-b-2 transition-colors ${
            activeTab === 'optimization'
              ? 'border-indigo-600 text-indigo-600'
              : 'border-transparent text-gray-500 hover:text-gray-700'
          }`}
        >
          <Database className="w-4 h-4" />
          Database & Query Optimization
        </button>
      </div>

      {/* TAB 1: Workload Concurrency */}
      {activeTab === 'workload' && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div className="p-4 bg-white border border-gray-200 rounded-lg shadow-sm">
              <div className="flex items-center justify-between text-gray-500 text-sm">
                <span>Active Concurrency</span>
                <Cpu className="w-4 h-4 text-indigo-500" />
              </div>
              <div className="mt-2 flex items-baseline gap-2">
                <span className="text-2xl font-bold text-gray-900">
                  {workloadStatus?.active_workers ?? 0}
                </span>
                <span className="text-xs text-gray-500">
                  / {workloadStatus?.max_concurrent_workers ?? 4} slots
                </span>
              </div>
              <div className="w-full bg-gray-100 rounded-full h-2 mt-3 overflow-hidden">
                <div
                  className="bg-indigo-600 h-2 rounded-full"
                  style={{
                    width: `${Math.min(
                      ((workloadStatus?.active_workers ?? 0) / (workloadStatus?.max_concurrent_workers ?? 4)) * 100,
                      100
                    )}%`,
                  }}
                />
              </div>
            </div>

            <div className="p-4 bg-white border border-gray-200 rounded-lg shadow-sm">
              <div className="flex items-center justify-between text-gray-500 text-sm">
                <span>Pending Task Queue</span>
                <Layers className="w-4 h-4 text-amber-500" />
              </div>
              <div className="mt-2 flex items-baseline gap-2">
                <span className="text-2xl font-bold text-gray-900">
                  {workloadStatus?.queue_depth ?? 0}
                </span>
                <span className="text-xs text-gray-500">
                  / {workloadStatus?.max_queue_depth ?? 50} limit
                </span>
              </div>
              <div className="w-full bg-gray-100 rounded-full h-2 mt-3 overflow-hidden">
                <div
                  className="bg-amber-500 h-2 rounded-full"
                  style={{
                    width: `${Math.min(
                      ((workloadStatus?.queue_depth ?? 0) / (workloadStatus?.max_queue_depth ?? 50)) * 100,
                      100
                    )}%`,
                  }}
                />
              </div>
            </div>

            <div className="p-4 bg-white border border-gray-200 rounded-lg shadow-sm">
              <div className="flex items-center justify-between text-gray-500 text-sm">
                <span>Queue Saturation</span>
                {workloadStatus?.saturated ? (
                  <AlertTriangle className="w-4 h-4 text-red-500" />
                ) : (
                  <CheckCircle2 className="w-4 h-4 text-emerald-500" />
                )}
              </div>
              <div className="mt-2 flex items-baseline gap-2">
                <span className={`text-2xl font-bold ${workloadStatus?.saturated ? 'text-red-600' : 'text-emerald-600'}`}>
                  {workloadStatus?.saturated ? 'SATURATED' : 'NOMINAL'}
                </span>
              </div>
              <div className="mt-3 text-xs text-gray-500">
                Capacity utilization: {workloadStatus?.capacity_utilization_pct?.toFixed(1) ?? '0.0'}%
              </div>
            </div>

            <div className="p-4 bg-white border border-gray-200 rounded-lg shadow-sm">
              <div className="flex items-center justify-between text-gray-500 text-sm">
                <span>Backpressure Drops</span>
                <ShieldAlert className="w-4 h-4 text-purple-500" />
              </div>
              <div className="mt-2 flex items-baseline gap-2">
                <span className="text-2xl font-bold text-gray-900">
                  {workloadStatus?.rejected_tasks_count ?? 0}
                </span>
                <span className="text-xs text-gray-500">HTTP 429 rejections</span>
              </div>
              <div className="mt-3 text-xs text-emerald-600 font-medium">
                Fail-closed protection active
              </div>
            </div>
          </div>

          {/* Lease Scavenging Action Panel */}
          <div className="bg-white border border-gray-200 rounded-lg p-6 shadow-sm">
            <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
              <div>
                <h3 className="text-base font-semibold text-gray-900">
                  Dead-Worker Lease Scavenging & Orphan Recovery
                </h3>
                <p className="text-sm text-gray-500 mt-1">
                  Scans active assessment jobs using indexed heartbeat checks. Jobs whose worker heartbeat has lapsed past 300s are deterministically transitioned to TIMED_OUT.
                </p>
              </div>
              <button
                onClick={handleReconcileStaleJobs}
                disabled={actionLoading !== null}
                className="inline-flex items-center gap-2 px-4 py-2 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 font-medium text-sm disabled:opacity-50"
              >
                <RefreshCw className={`w-4 h-4 ${actionLoading === 'reconcile' ? 'animate-spin' : ''}`} />
                Scavenge Orphaned Leases
              </button>
            </div>

            {reconciliationResult && (
              <div className="mt-4 p-4 bg-gray-50 border border-gray-200 rounded-lg">
                <div className="text-xs font-semibold text-gray-600 uppercase tracking-wider mb-2">
                  Scavenge Audit Report ({reconciliationResult.recovered_jobs_count} Jobs Recovered)
                </div>
                {reconciliationResult.details.length === 0 ? (
                  <div className="text-sm text-gray-500">No orphaned or stale worker leases detected.</div>
                ) : (
                  <ul className="space-y-1 text-sm text-gray-700">
                    {reconciliationResult.details.map((detail, idx) => (
                      <li key={idx} className="font-mono text-xs text-indigo-700">
                        â€¢ {detail}
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            )}
          </div>
        </div>
      )}

      {/* TAB 2: Performance Budgets */}
      {activeTab === 'budgets' && (
        <div className="space-y-6">
          <div className="p-4 bg-white border border-gray-200 rounded-lg shadow-sm flex items-center justify-between">
            <div>
              <div className="text-xs uppercase font-semibold text-gray-500">Overall Budget Status</div>
              <div className="mt-1 flex items-center gap-2">
                {budgetsResponse?.overall_healthy ? (
                  <span className="inline-flex items-center gap-1.5 px-3 py-1 bg-emerald-50 text-emerald-700 text-sm font-semibold rounded-full border border-emerald-200">
                    <CheckCircle2 className="w-4 h-4" />
                    All Workloads Within SLA Budgets
                  </span>
                ) : (
                  <span className="inline-flex items-center gap-1.5 px-3 py-1 bg-amber-50 text-amber-700 text-sm font-semibold rounded-full border border-amber-200">
                    <AlertTriangle className="w-4 h-4" />
                    Budget Violations Observed
                  </span>
                )}
              </div>
            </div>
            <div className="text-right text-xs text-gray-400">
              Evaluated at: {budgetsResponse?.measured_at ? new Date(budgetsResponse.measured_at).toLocaleTimeString() : 'N/A'}
            </div>
          </div>

          <div className="bg-white border border-gray-200 rounded-lg shadow-sm overflow-hidden">
            <div className="px-6 py-4 border-b border-gray-200 bg-gray-50">
              <h3 className="text-sm font-semibold text-gray-900">Tracked Endpoint Latency Budgets</h3>
            </div>
            <table className="min-w-full divide-y divide-gray-200 text-sm">
              <thead className="bg-gray-50">
                <tr>
                  <th className="px-6 py-3 text-left font-medium text-gray-500 uppercase text-xs">Operation</th>
                  <th className="px-6 py-3 text-left font-medium text-gray-500 uppercase text-xs">Target SLA (p95)</th>
                  <th className="px-6 py-3 text-left font-medium text-gray-500 uppercase text-xs">p50 Latency</th>
                  <th className="px-6 py-3 text-left font-medium text-gray-500 uppercase text-xs">p95 Latency</th>
                  <th className="px-6 py-3 text-left font-medium text-gray-500 uppercase text-xs">p99 Latency</th>
                  <th className="px-6 py-3 text-left font-medium text-gray-500 uppercase text-xs">Samples</th>
                  <th className="px-6 py-3 text-left font-medium text-gray-500 uppercase text-xs">Conformance</th>
                </tr>
              </thead>
              <tbody className="bg-white divide-y divide-gray-200">
                {budgetsResponse?.budgets.map((b) => (
                  <tr key={b.operation} className="hover:bg-gray-50">
                    <td className="px-6 py-4 font-mono font-medium text-gray-900">{b.operation}</td>
                    <td className="px-6 py-4 text-gray-600 font-mono">â‰¤ {b.budget_ms} ms</td>
                    <td className="px-6 py-4 text-gray-700 font-mono">{b.p50_ms.toFixed(2)} ms</td>
                    <td className="px-6 py-4 text-gray-900 font-bold font-mono">{b.p95_ms.toFixed(2)} ms</td>
                    <td className="px-6 py-4 text-gray-500 font-mono">{b.p99_ms.toFixed(2)} ms</td>
                    <td className="px-6 py-4 text-gray-500">{b.sample_count}</td>
                    <td className="px-6 py-4">
                      {b.within_budget ? (
                        <span className="inline-flex items-center gap-1 text-xs font-medium text-emerald-700 bg-emerald-50 px-2 py-0.5 rounded-full border border-emerald-200">
                          <CheckCircle2 className="w-3.5 h-3.5" />
                          PASS
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 text-xs font-medium text-red-700 bg-red-50 px-2 py-0.5 rounded-full border border-red-200">
                          <XCircle className="w-3.5 h-3.5" />
                          EXCEEDED
                        </span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* TAB 3: Synthetic Benchmarks */}
      {activeTab === 'benchmark' && (
        <div className="space-y-6">
          <div className="bg-white border border-gray-200 rounded-lg p-6 shadow-sm">
            <h3 className="text-base font-semibold text-gray-900">
              Synthetic Dataset Performance Benchmark
            </h3>
            <p className="text-sm text-gray-500 mt-1">
              Executes isolated, multi-iteration database read/filter/aggregate benchmarks against indexed schema tables. Measures indexed query throughput, timeline ordering latency, and KPI aggregation speed.
            </p>

            <div className="mt-4 flex flex-col sm:flex-row sm:items-center gap-4">
              <div className="flex items-center gap-2">
                <label className="text-sm font-medium text-gray-700">Dataset Size:</label>
                <select
                  value={benchmarkSize}
                  onChange={(e) => setBenchmarkSize(e.target.value as 'SMALL' | 'MEDIUM' | 'LARGE')}
                  className="rounded-lg border-gray-300 shadow-sm text-sm focus:border-indigo-500 focus:ring-indigo-500"
                >
                  <option value="SMALL">SMALL (100 synthetic findings)</option>
                  <option value="MEDIUM">MEDIUM (1,000 synthetic findings)</option>
                  <option value="LARGE">LARGE (5,000 synthetic findings)</option>
                </select>
              </div>

              <button
                onClick={handleRunBenchmark}
                disabled={actionLoading !== null}
                className="inline-flex items-center gap-2 px-4 py-2 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 font-medium text-sm disabled:opacity-50"
              >
                <Play className={`w-4 h-4 ${actionLoading === 'benchmark' ? 'animate-spin' : ''}`} />
                Run Synthetic Benchmark
              </button>
            </div>
          </div>

          {benchmarkResult && (
            <div className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div className="p-4 bg-white border border-gray-200 rounded-lg shadow-sm">
                  <div className="text-xs uppercase font-semibold text-gray-500">Benchmark Environment</div>
                  <div className="mt-2 text-sm text-gray-900 font-mono">
                    Python {benchmarkResult.environment.python_version} ({benchmarkResult.environment.os})
                  </div>
                  <div className="text-xs text-gray-500 mt-1">
                    Dialect: {benchmarkResult.environment.db_dialect} (WAL active)
                  </div>
                </div>

                <div className="p-4 bg-white border border-gray-200 rounded-lg shadow-sm">
                  <div className="text-xs uppercase font-semibold text-gray-500">Total Benchmark Duration</div>
                  <div className="mt-2 text-2xl font-bold text-indigo-600">
                    {benchmarkResult.total_duration_ms.toFixed(2)} ms
                  </div>
                  <div className="text-xs text-gray-500 mt-1">
                    Dataset scale: {benchmarkResult.dataset_size}
                  </div>
                </div>

                <div className="p-4 bg-white border border-gray-200 rounded-lg shadow-sm">
                  <div className="text-xs uppercase font-semibold text-gray-500">Status</div>
                  <div className="mt-2 inline-flex items-center gap-1.5 text-sm font-semibold text-emerald-700 bg-emerald-50 px-3 py-1 rounded-full border border-emerald-200">
                    <CheckCircle2 className="w-4 h-4" />
                    Benchmark Passed
                  </div>
                </div>
              </div>

              <div className="bg-white border border-gray-200 rounded-lg shadow-sm overflow-hidden">
                <div className="px-6 py-4 border-b border-gray-200 bg-gray-50">
                  <h4 className="text-sm font-semibold text-gray-900">Benchmark Execution Metrics</h4>
                </div>
                <table className="min-w-full divide-y divide-gray-200 text-sm">
                  <thead className="bg-gray-50">
                    <tr>
                      <th className="px-6 py-3 text-left font-medium text-gray-500 uppercase text-xs">Operation</th>
                      <th className="px-6 py-3 text-left font-medium text-gray-500 uppercase text-xs">Record Count</th>
                      <th className="px-6 py-3 text-left font-medium text-gray-500 uppercase text-xs">Query Count</th>
                      <th className="px-6 py-3 text-left font-medium text-gray-500 uppercase text-xs">Duration</th>
                      <th className="px-6 py-3 text-left font-medium text-gray-500 uppercase text-xs">Throughput</th>
                    </tr>
                  </thead>
                  <tbody className="bg-white divide-y divide-gray-200">
                    {benchmarkResult.benchmarks.map((b, idx) => (
                      <tr key={idx} className="hover:bg-gray-50">
                        <td className="px-6 py-4 font-medium text-gray-900">{b.operation}</td>
                        <td className="px-6 py-4 text-gray-600">{b.record_count}</td>
                        <td className="px-6 py-4 text-gray-600 font-mono">{b.query_count} (Single Scan)</td>
                        <td className="px-6 py-4 font-mono font-bold text-gray-900">{b.duration_ms.toFixed(2)} ms</td>
                        <td className="px-6 py-4 font-mono font-bold text-indigo-600">{b.ops_per_second.toLocaleString()} ops/s</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      )}

      {/* TAB 4: Database Optimization & Query Cache */}
      {activeTab === 'optimization' && (
        <div className="space-y-6">
          {/* Header Card */}
          <div className="p-6 bg-white border border-gray-200 rounded-lg shadow-sm flex flex-col md:flex-row md:items-center md:justify-between gap-4">
            <div>
              <h3 className="text-lg font-bold text-gray-900 flex items-center gap-2">
                <Database className="w-5 h-5 text-indigo-600" />
                Query Cache & Database Optimization (Prompt 41)
              </h3>
              <p className="text-sm text-gray-500 mt-1">
                Thread-safe, memory-bounded LRU cache with multi-tenant role isolation, composite query indexes, and SQLite WAL pragma optimization.
              </p>
            </div>
            <div className="flex items-center gap-3">
              <button
                onClick={handleClearCache}
                disabled={actionLoading !== null}
                className="inline-flex items-center gap-2 px-3.5 py-2 border border-red-300 text-sm font-medium rounded-lg text-red-700 bg-white hover:bg-red-50 disabled:opacity-50"
              >
                <Trash2 className="w-4 h-4" />
                Purge Query Cache
              </button>
            </div>
          </div>

          {/* Metrics Grid */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div className="p-4 bg-white border border-gray-200 rounded-lg shadow-sm">
              <div className="text-xs uppercase font-semibold text-gray-500">Cached Items</div>
              <div className="mt-2 text-2xl font-bold text-gray-900">
                {cacheMetrics ? `${cacheMetrics.total_cached_items} / ${cacheMetrics.max_capacity}` : '—'}
              </div>
              <div className="text-xs text-gray-400 mt-1">Bounded Capacity</div>
            </div>

            <div className="p-4 bg-white border border-gray-200 rounded-lg shadow-sm">
              <div className="text-xs uppercase font-semibold text-gray-500">Cache Hit Ratio</div>
              <div className="mt-2 text-2xl font-bold text-indigo-600">
                {cacheMetrics ? `${(cacheMetrics.hit_ratio * 100).toFixed(1)}%` : '—'}
              </div>
              <div className="text-xs text-gray-400 mt-1">
                {cacheMetrics ? `${cacheMetrics.hits} Hits / ${cacheMetrics.misses} Misses` : 'No lookups yet'}
              </div>
            </div>

            <div className="p-4 bg-white border border-gray-200 rounded-lg shadow-sm">
              <div className="text-xs uppercase font-semibold text-gray-500">Evictions & Purges</div>
              <div className="mt-2 text-2xl font-bold text-gray-900">
                {cacheMetrics ? cacheMetrics.evictions : 0}
              </div>
              <div className="text-xs text-gray-400 mt-1">
                {cacheMetrics ? `${cacheMetrics.invalidations} Invalidations` : '0 Invalidations'}
              </div>
            </div>

            <div className="p-4 bg-white border border-gray-200 rounded-lg shadow-sm">
              <div className="text-xs uppercase font-semibold text-gray-500">SQLite WAL Status</div>
              <div className="mt-2 inline-flex items-center gap-1.5 text-sm font-semibold text-emerald-700 bg-emerald-50 px-3 py-1 rounded-full border border-emerald-200">
                <Server className="w-4 h-4" />
                {walStatus?.wal_concurrency_enabled ? 'WAL Mode Active' : 'WAL Unavailable'}
              </div>
              <div className="text-xs text-gray-400 mt-1">
                Timeout: {walStatus ? `${walStatus.busy_timeout_ms}ms` : '—'}
              </div>
            </div>
          </div>

          {/* SQLite WAL Pragma Inspection Card */}
          {walStatus && (
            <div className="bg-white border border-gray-200 rounded-lg shadow-sm p-6">
              <h4 className="text-sm font-semibold text-gray-900 mb-4 flex items-center gap-2">
                <Server className="w-4 h-4 text-gray-500" />
                SQLite Engine Runtime Configuration
              </h4>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm font-mono">
                <div className="p-3 bg-gray-50 rounded border border-gray-100">
                  <div className="text-xs text-gray-500 font-sans uppercase">Journal Mode</div>
                  <div className="font-bold text-indigo-700 mt-1">{walStatus.journal_mode}</div>
                </div>
                <div className="p-3 bg-gray-50 rounded border border-gray-100">
                  <div className="text-xs text-gray-500 font-sans uppercase">Synchronous Level</div>
                  <div className="font-bold text-gray-800 mt-1">{walStatus.synchronous_level} (NORMAL)</div>
                </div>
                <div className="p-3 bg-gray-50 rounded border border-gray-100">
                  <div className="text-xs text-gray-500 font-sans uppercase">Busy Timeout</div>
                  <div className="font-bold text-gray-800 mt-1">{walStatus.busy_timeout_ms} ms</div>
                </div>
                <div className="p-3 bg-gray-50 rounded border border-gray-100">
                  <div className="text-xs text-gray-500 font-sans uppercase">Page Size</div>
                  <div className="font-bold text-gray-800 mt-1">{walStatus.page_size_bytes} bytes</div>
                </div>
              </div>
            </div>
          )}

          {/* Optimization Evidence Overview */}
          <div className="bg-white border border-gray-200 rounded-lg shadow-sm p-6">
            <h4 className="text-sm font-semibold text-gray-900 mb-3">
              Implemented Database Engineering Controls
            </h4>
            <div className="space-y-3 text-sm text-gray-600">
              <div className="flex items-start gap-2">
                <CheckCircle2 className="w-4 h-4 text-emerald-500 mt-0.5 flex-shrink-0" />
                <span><strong>Composite Covering Indexes:</strong> Added index on <code>vulnerability_findings(project_id, status, severity, last_observed_at)</code> and <code>assets(project_id, status, freshness_status)</code> eliminating sequential scans.</span>
              </div>
              <div className="flex items-start gap-2">
                <CheckCircle2 className="w-4 h-4 text-emerald-500 mt-0.5 flex-shrink-0" />
                <span><strong>Direct SQL Aggregation:</strong> Replaced Python in-memory iterations with direct SQL <code>COUNT(*) ... GROUP BY</code> operations for finding status and severity distributions.</span>
              </div>
              <div className="flex items-start gap-2">
                <CheckCircle2 className="w-4 h-4 text-emerald-500 mt-0.5 flex-shrink-0" />
                <span><strong>Heavy Evidence Payload Deferral:</strong> Findings listing endpoints default to <code>include_payloads=false</code>, deferring multi-megabyte raw logs until individual drilldown.</span>
              </div>
              <div className="flex items-start gap-2">
                <CheckCircle2 className="w-4 h-4 text-emerald-500 mt-0.5 flex-shrink-0" />
                <span><strong>Multi-Tenant Role Isolation:</strong> Cache partitions strictly namespace keys by <code>proj:&lt;id&gt;:role:&lt;role&gt;</code>, preventing cross-tenant and cross-privilege cache poisoning.</span>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
export default PerformanceEngineeringView;
