import React, { useState, useEffect } from 'react';
import type {
  AssessmentQueueItem,
  SchedulerCapacity,
  SchedulerDecision,
  SchedulerPolicy,
  QueueItemPreviewResponse,
  QueueItemStatus,
  PriorityBand,
  Project,
} from '../types';
import { api } from '../services/api';

interface IntelligentSchedulingViewProps {
  currentProjectId?: string;
}

export const IntelligentSchedulingView: React.FC<IntelligentSchedulingViewProps> = ({ currentProjectId }) => {
  const [projects, setProjects] = useState<Project[]>([]);
  const [selectedProjectId, setSelectedProjectId] = useState<string>(currentProjectId || '');
  const [activeTab, setActiveTab] = useState<'queue' | 'capacity' | 'preview' | 'decisions' | 'policy'>('queue');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);

  // Data states
  const [queueItems, setQueueItems] = useState<AssessmentQueueItem[]>([]);
  const [capacity, setCapacity] = useState<SchedulerCapacity | null>(null);
  const [decisions, setDecisions] = useState<SchedulerDecision[]>([]);
  const [policy, setPolicy] = useState<SchedulerPolicy | null>(null);
  const [statusFilter, setStatusFilter] = useState<string>('');

  // Enqueue Modal
  const [showEnqueueModal, setShowEnqueueModal] = useState(false);
  const [newTarget, setNewTarget] = useState('');
  const [newAdapter, setNewAdapter] = useState('local_fixture_adapter');
  const [newScheduleName, setNewScheduleName] = useState('Ad-Hoc Assessment');

  // Preview form
  const [previewTarget, setPreviewTarget] = useState('');
  const [previewAdapter, setPreviewAdapter] = useState('local_fixture_adapter');
  const [previewResult, setPreviewResult] = useState<QueueItemPreviewResponse | null>(null);
  const [previewLoading, setPreviewLoading] = useState(false);

  // Policy Edit Form
  const [policyForm, setPolicyForm] = useState<{
    max_concurrent_assessments: number;
    max_per_target_concurrency: number;
    max_per_adapter_concurrency: number;
    max_queued_jobs: number;
    aging_factor_per_hour: number;
    stale_lease_timeout_sec: number;
    cooldown_period_sec: number;
  }>({
    max_concurrent_assessments: 5,
    max_per_target_concurrency: 1,
    max_per_adapter_concurrency: 2,
    max_queued_jobs: 100,
    aging_factor_per_hour: 2.0,
    stale_lease_timeout_sec: 120,
    cooldown_period_sec: 3600,
  });

  // Load projects
  useEffect(() => {
    api.listProjects()
      .then(projs => {
        setProjects(projs);
        if (!selectedProjectId && projs.length > 0) {
          setSelectedProjectId(projs[0].id);
        }
      })
      .catch(err => setError(`Failed to load projects: ${err.message}`));
  }, []);

  // Load scheduler data when project changes
  useEffect(() => {
    if (!selectedProjectId) return;
    refreshData();
  }, [selectedProjectId, activeTab, statusFilter]);

  const refreshData = async () => {
    if (!selectedProjectId) return;
    setLoading(true);
    setError(null);
    try {
      const [capRes, polRes] = await Promise.all([
        api.getSchedulerCapacity(selectedProjectId),
        api.getSchedulerPolicy(selectedProjectId),
      ]);
      setCapacity(capRes);
      setPolicy(polRes);
      setPolicyForm({
        max_concurrent_assessments: polRes.max_concurrent_assessments,
        max_per_target_concurrency: polRes.max_per_target_concurrency,
        max_per_adapter_concurrency: polRes.max_per_adapter_concurrency,
        max_queued_jobs: polRes.max_queued_jobs,
        aging_factor_per_hour: polRes.aging_factor_per_hour,
        stale_lease_timeout_sec: polRes.stale_lease_timeout_sec,
        cooldown_period_sec: polRes.cooldown_period_sec,
      });

      if (activeTab === 'queue') {
        const items = await api.listQueueItems(selectedProjectId, {
          status: statusFilter || undefined,
        });
        setQueueItems(items);
      } else if (activeTab === 'decisions') {
        const decs = await api.listSchedulerDecisions(selectedProjectId);
        setDecisions(decs);
      }
    } catch (err: any) {
      setError(`Failed to fetch scheduler data: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  const handleEnqueue = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedProjectId || !newTarget.trim()) return;
    setError(null);
    try {
      await api.enqueueAssessment(selectedProjectId, {
        target_input: newTarget.trim(),
        adapter_name: newAdapter,
        schedule_name: newScheduleName,
      });
      setSuccessMessage(`Assessment enqueued for target '${newTarget}'`);
      setShowEnqueueModal(false);
      setNewTarget('');
      refreshData();
    } catch (err: any) {
      setError(`Failed to enqueue assessment: ${err.message}`);
    }
  };

  const handlePreview = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedProjectId || !previewTarget.trim()) return;
    setPreviewLoading(true);
    setError(null);
    try {
      const res = await api.previewScheduling(selectedProjectId, {
        target_input: previewTarget.trim(),
        adapter_name: previewAdapter,
      });
      setPreviewResult(res);
    } catch (err: any) {
      setError(`Failed to preview priority: ${err.message}`);
    } finally {
      setPreviewLoading(false);
    }
  };

  const handleDispatchNext = async () => {
    if (!selectedProjectId) return;
    setError(null);
    try {
      const res = await api.dispatchNextJob(selectedProjectId);
      if (res.dispatched) {
        setSuccessMessage(`Job dispatched successfully! (Job ID: ${res.job_id})`);
      } else {
        setSuccessMessage(`Dispatch status: ${res.message}`);
      }
      refreshData();
    } catch (err: any) {
      setError(`Failed to dispatch next job: ${err.message}`);
    }
  };

  const handleRecoverStale = async () => {
    if (!selectedProjectId) return;
    setError(null);
    try {
      const res = await api.recoverStaleLeases(selectedProjectId);
      setSuccessMessage(`Recovered ${res.recovered_count} expired lease(s); Dead-lettered ${res.dead_letter_count} item(s).`);
      refreshData();
    } catch (err: any) {
      setError(`Failed to recover stale leases: ${err.message}`);
    }
  };

  const handleCancelItem = async (queueId: string) => {
    if (!selectedProjectId) return;
    setError(null);
    try {
      await api.cancelQueueItem(selectedProjectId, queueId, 'User requested cancellation from dashboard');
      setSuccessMessage(`Queue item ${queueId} cancelled.`);
      refreshData();
    } catch (err: any) {
      setError(`Failed to cancel item: ${err.message}`);
    }
  };

  const handleSavePolicy = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedProjectId) return;
    setError(null);
    try {
      const updated = await api.updateSchedulerPolicy(selectedProjectId, policyForm);
      setPolicy(updated);
      setSuccessMessage('Scheduling policy updated successfully.');
    } catch (err: any) {
      setError(`Failed to update policy: ${err.message}`);
    }
  };

  const getPriorityBadgeClass = (band: PriorityBand) => {
    switch (band) {
      case 'CRITICAL':
        return 'bg-red-900/60 text-red-300 border-red-700';
      case 'HIGH':
        return 'bg-orange-900/60 text-orange-300 border-orange-700';
      case 'MEDIUM':
        return 'bg-yellow-900/60 text-yellow-300 border-yellow-700';
      case 'LOW':
        return 'bg-blue-900/60 text-blue-300 border-blue-700';
      default:
        return 'bg-zinc-800 text-zinc-300 border-zinc-700';
    }
  };

  const getStatusBadgeClass = (status: QueueItemStatus) => {
    switch (status) {
      case 'SCHEDULED':
        return 'bg-sky-900/60 text-sky-300 border-sky-700';
      case 'DISPATCHED':
        return 'bg-indigo-900/60 text-indigo-300 border-indigo-700 animate-pulse';
      case 'COMPLETED':
        return 'bg-emerald-900/60 text-emerald-300 border-emerald-700';
      case 'FAILED':
        return 'bg-red-900/60 text-red-300 border-red-700';
      case 'CANCELLED':
        return 'bg-zinc-800 text-zinc-400 border-zinc-700';
      default:
        return 'bg-zinc-800 text-zinc-300 border-zinc-700';
    }
  };

  return (
    <div className="p-6 space-y-6 max-w-7xl mx-auto text-zinc-100">
      {/* Header & Controls */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-zinc-800">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
            <span className="text-cyan-400">⚡</span> Intelligent Assessment Scheduling & Orchestration
          </h1>
          <p className="text-sm text-zinc-400 mt-1">
            Deterministic risk-based prioritization, fail-closed eligibility, worker lease recovery, and anti-starvation aging.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <select
            value={selectedProjectId}
            onChange={(e) => setSelectedProjectId(e.target.value)}
            className="bg-zinc-900 border border-zinc-700 rounded px-3 py-1.5 text-sm text-zinc-200 focus:outline-none focus:border-cyan-500"
          >
            {projects.map(p => (
              <option key={p.id} value={p.id}>{p.name}</option>
            ))}
          </select>
          <button
            onClick={refreshData}
            disabled={loading}
            className="px-3 py-1.5 bg-zinc-800 hover:bg-zinc-700 border border-zinc-700 rounded text-sm font-medium transition"
          >
            {loading ? 'Refreshing...' : 'Refresh'}
          </button>
        </div>
      </div>

      {/* Notifications */}
      {error && (
        <div className="p-3 bg-red-950/60 border border-red-800 rounded text-sm text-red-200">
          {error}
        </div>
      )}
      {successMessage && (
        <div className="p-3 bg-emerald-950/60 border border-emerald-800 rounded text-sm text-emerald-200">
          {successMessage}
        </div>
      )}

      {/* Capacity KPI Bar */}
      {capacity && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="bg-zinc-900/80 border border-zinc-800 rounded p-4">
            <div className="text-xs text-zinc-400 uppercase tracking-wider">Active Concurrency</div>
            <div className="text-2xl font-bold text-cyan-400 mt-1">
              {capacity.current_running_assessments} <span className="text-sm font-normal text-zinc-400">/ {capacity.max_concurrent_assessments} slots</span>
            </div>
            <div className="text-xs text-zinc-500 mt-1">{capacity.available_capacity} slots available</div>
          </div>
          <div className="bg-zinc-900/80 border border-zinc-800 rounded p-4">
            <div className="text-xs text-zinc-400 uppercase tracking-wider">Queue Depth</div>
            <div className="text-2xl font-bold text-sky-400 mt-1">{capacity.total_queued_items}</div>
            <div className="text-xs text-zinc-500 mt-1">{capacity.queue_utilization_pct}% capacity utilized</div>
          </div>
          <div className="bg-zinc-900/80 border border-zinc-800 rounded p-4">
            <div className="text-xs text-zinc-400 uppercase tracking-wider">Stale / Unclaimed Leases</div>
            <div className={`text-2xl font-bold mt-1 ${capacity.stale_unclaimed_leases > 0 ? 'text-amber-400' : 'text-zinc-300'}`}>
              {capacity.stale_unclaimed_leases}
            </div>
            <div className="text-xs text-zinc-500 mt-1">Worker timeout: {policy?.stale_lease_timeout_sec}s</div>
          </div>
          <div className="bg-zinc-900/80 border border-zinc-800 rounded p-4 flex flex-col justify-center gap-2">
            <button
              onClick={handleDispatchNext}
              className="w-full py-1.5 px-3 bg-cyan-600 hover:bg-cyan-500 rounded text-xs font-semibold text-white transition"
            >
              Dispatch Next Job
            </button>
            <button
              onClick={handleRecoverStale}
              className="w-full py-1.5 px-3 bg-zinc-800 hover:bg-zinc-700 border border-zinc-700 rounded text-xs font-semibold text-zinc-200 transition"
            >
              Recover Stale Leases
            </button>
          </div>
        </div>
      )}

      {/* Tabs */}
      <div className="flex border-b border-zinc-800 gap-2">
        <button
          onClick={() => setActiveTab('queue')}
          className={`px-4 py-2 text-sm font-medium border-b-2 transition ${
            activeTab === 'queue' ? 'border-cyan-500 text-cyan-400' : 'border-transparent text-zinc-400 hover:text-zinc-200'
          }`}
        >
          Queue & Orchestration
        </button>
        <button
          onClick={() => setActiveTab('capacity')}
          className={`px-4 py-2 text-sm font-medium border-b-2 transition ${
            activeTab === 'capacity' ? 'border-cyan-500 text-cyan-400' : 'border-transparent text-zinc-400 hover:text-zinc-200'
          }`}
        >
          Capacity & Worker Slots
        </button>
        <button
          onClick={() => setActiveTab('preview')}
          className={`px-4 py-2 text-sm font-medium border-b-2 transition ${
            activeTab === 'preview' ? 'border-cyan-500 text-cyan-400' : 'border-transparent text-zinc-400 hover:text-zinc-200'
          }`}
        >
          Priority Calculator & Sandbox
        </button>
        <button
          onClick={() => setActiveTab('decisions')}
          className={`px-4 py-2 text-sm font-medium border-b-2 transition ${
            activeTab === 'decisions' ? 'border-cyan-500 text-cyan-400' : 'border-transparent text-zinc-400 hover:text-zinc-200'
          }`}
        >
          Decision Audit Ledger
        </button>
        <button
          onClick={() => setActiveTab('policy')}
          className={`px-4 py-2 text-sm font-medium border-b-2 transition ${
            activeTab === 'policy' ? 'border-cyan-500 text-cyan-400' : 'border-transparent text-zinc-400 hover:text-zinc-200'
          }`}
        >
          Policy Governance
        </button>
      </div>

      {/* Tab 1: Queue & Orchestration */}
      {activeTab === 'queue' && (
        <div className="space-y-4">
          <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
            <div className="flex items-center gap-2">
              <span className="text-xs text-zinc-400 uppercase tracking-wider">Filter Status:</span>
              <select
                value={statusFilter}
                onChange={(e) => setStatusFilter(e.target.value)}
                className="bg-zinc-900 border border-zinc-700 rounded px-2.5 py-1 text-xs text-zinc-200"
              >
                <option value="">All Statuses</option>
                <option value="SCHEDULED">SCHEDULED</option>
                <option value="DISPATCHED">DISPATCHED</option>
                <option value="COMPLETED">COMPLETED</option>
                <option value="FAILED">FAILED</option>
                <option value="CANCELLED">CANCELLED</option>
              </select>
            </div>
            <button
              onClick={() => setShowEnqueueModal(true)}
              className="px-3 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-white rounded text-sm font-medium transition"
            >
              + Enqueue Assessment
            </button>
          </div>

          <div className="bg-zinc-900/60 border border-zinc-800 rounded-lg overflow-hidden">
            <table className="w-full text-left text-sm">
              <thead className="bg-zinc-900/90 text-xs text-zinc-400 uppercase border-b border-zinc-800">
                <tr>
                  <th className="px-4 py-3">Priority</th>
                  <th className="px-4 py-3">Schedule / Target</th>
                  <th className="px-4 py-3">Adapter</th>
                  <th className="px-4 py-3">Status</th>
                  <th className="px-4 py-3">Worker Lease</th>
                  <th className="px-4 py-3">Retries</th>
                  <th className="px-4 py-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-zinc-800">
                {queueItems.length === 0 ? (
                  <tr>
                    <td colSpan={7} className="px-4 py-8 text-center text-zinc-500">
                      No assessment items in queue for the selected filter.
                    </td>
                  </tr>
                ) : (
                  queueItems.map((item) => (
                    <tr key={item.id} className="hover:bg-zinc-800/40 transition">
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-2">
                          <span className={`px-2 py-0.5 rounded text-xs font-bold border ${getPriorityBadgeClass(item.priority_band)}`}>
                            {item.priority_score.toFixed(1)}
                          </span>
                          <span className="text-xs text-zinc-400">{item.priority_band}</span>
                        </div>
                      </td>
                      <td className="px-4 py-3">
                        <div className="font-medium text-white">{item.schedule_name}</div>
                        <div className="text-xs text-zinc-400 font-mono mt-0.5">{item.target_input}</div>
                        <div className="text-xs text-zinc-500 mt-1 line-clamp-1">{item.priority_explanation}</div>
                      </td>
                      <td className="px-4 py-3">
                        <span className="font-mono text-xs text-zinc-300">{item.adapter_name}</span>
                      </td>
                      <td className="px-4 py-3">
                        <span className={`px-2 py-0.5 rounded text-xs font-semibold border ${getStatusBadgeClass(item.status)}`}>
                          {item.status}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-xs text-zinc-400 font-mono">
                        {item.worker_claim_id ? (
                          <div>
                            <div className="text-cyan-400">{item.worker_claim_id}</div>
                            {item.lease_expires_at && (
                              <div className="text-zinc-500 text-[10px]">
                                Exp: {new Date(item.lease_expires_at).toLocaleTimeString()}
                              </div>
                            )}
                          </div>
                        ) : (
                          <span className="text-zinc-500">Unclaimed</span>
                        )}
                      </td>
                      <td className="px-4 py-3 text-xs text-zinc-400">
                        {item.retry_count} / {item.max_retries}
                      </td>
                      <td className="px-4 py-3 text-right">
                        {['SCHEDULED', 'DISPATCHED', 'PENDING'].includes(item.status) && (
                          <button
                            onClick={() => handleCancelItem(item.id)}
                            className="px-2.5 py-1 bg-red-950 hover:bg-red-900 border border-red-800 text-red-300 rounded text-xs font-medium transition"
                          >
                            Cancel
                          </button>
                        )}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Tab 2: Capacity & Worker Slots */}
      {activeTab === 'capacity' && capacity && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div className="bg-zinc-900/60 border border-zinc-800 rounded-lg p-5 space-y-4">
            <h3 className="text-base font-semibold text-white">Active Concurrency by Target</h3>
            <p className="text-xs text-zinc-400">
              Enforces per-target concurrency throttles (max {policy?.max_per_target_concurrency} per host) to prevent target exhaustion.
            </p>
            {Object.keys(capacity.active_by_target).length === 0 ? (
              <div className="text-xs text-zinc-500 italic">No targets currently running assessments.</div>
            ) : (
              <div className="space-y-2">
                {Object.entries(capacity.active_by_target).map(([target, count]) => (
                  <div key={target} className="flex items-center justify-between p-2 bg-zinc-800/40 rounded border border-zinc-800">
                    <span className="font-mono text-xs text-zinc-300">{target}</span>
                    <span className="text-xs font-bold text-cyan-400">{count} active</span>
                  </div>
                ))}
              </div>
            )}
          </div>

          <div className="bg-zinc-900/60 border border-zinc-800 rounded-lg p-5 space-y-4">
            <h3 className="text-base font-semibold text-white">Active Concurrency by Adapter</h3>
            <p className="text-xs text-zinc-400">
              Enforces per-adapter limits (max {policy?.max_per_adapter_concurrency} per adapter) to isolate resource-heavy tooling.
            </p>
            {Object.keys(capacity.active_by_adapter).length === 0 ? (
              <div className="text-xs text-zinc-500 italic">No adapters currently running assessments.</div>
            ) : (
              <div className="space-y-2">
                {Object.entries(capacity.active_by_adapter).map(([adapter, count]) => (
                  <div key={adapter} className="flex items-center justify-between p-2 bg-zinc-800/40 rounded border border-zinc-800">
                    <span className="font-mono text-xs text-zinc-300">{adapter}</span>
                    <span className="text-xs font-bold text-indigo-400">{count} active</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* Tab 3: Priority Calculator & Sandbox */}
      {activeTab === 'preview' && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div className="bg-zinc-900/60 border border-zinc-800 rounded-lg p-5 space-y-4 lg:col-span-1">
            <h3 className="text-base font-semibold text-white">Priority Calculation Preview</h3>
            <p className="text-xs text-zinc-400">
              Inspect how the evidence-backed priority engine scores a candidate target without enqueuing or allocating resources.
            </p>
            <form onSubmit={handlePreview} className="space-y-3">
              <div>
                <label className="block text-xs font-medium text-zinc-300 mb-1">Target Host / URL</label>
                <input
                  type="text"
                  value={previewTarget}
                  onChange={(e) => setPreviewTarget(e.target.value)}
                  placeholder="e.g. https://app.example.com"
                  className="w-full bg-zinc-800 border border-zinc-700 rounded px-3 py-1.5 text-sm text-zinc-100 font-mono"
                  required
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-zinc-300 mb-1">Assessment Adapter</label>
                <select
                  value={previewAdapter}
                  onChange={(e) => setPreviewAdapter(e.target.value)}
                  className="w-full bg-zinc-800 border border-zinc-700 rounded px-3 py-1.5 text-sm text-zinc-100"
                >
                  <option value="local_fixture_adapter">local_fixture_adapter</option>
                  <option value="ssl_tls_analyzer">ssl_tls_analyzer</option>
                  <option value="http_header_inspector">http_header_inspector</option>
                  <option value="port_service_scanner">port_service_scanner</option>
                  <option value="compliance_evaluator">compliance_evaluator</option>
                </select>
              </div>
              <button
                type="submit"
                disabled={previewLoading}
                className="w-full py-2 bg-cyan-600 hover:bg-cyan-500 rounded text-sm font-semibold text-white transition"
              >
                {previewLoading ? 'Calculating...' : 'Preview Priority & Eligibility'}
              </button>
            </form>
          </div>

          <div className="bg-zinc-900/60 border border-zinc-800 rounded-lg p-5 lg:col-span-2">
            <h3 className="text-base font-semibold text-white mb-3">Engine Assessment Results</h3>
            {previewResult ? (
              <div className="space-y-4">
                <div className="flex items-center justify-between p-4 bg-zinc-800/40 rounded border border-zinc-700">
                  <div>
                    <div className="text-xs text-zinc-400 uppercase">Computed Score</div>
                    <div className="text-3xl font-bold text-white flex items-center gap-2 mt-1">
                      {previewResult.computed_priority.toFixed(1)}
                      <span className={`text-xs px-2 py-0.5 rounded border ${getPriorityBadgeClass(previewResult.priority_band)}`}>
                        {previewResult.priority_band}
                      </span>
                    </div>
                  </div>
                  <div className="text-right">
                    <div className="text-xs text-zinc-400 uppercase">Pre-flight Eligibility</div>
                    <div className={`text-sm font-bold mt-1 ${previewResult.is_eligible ? 'text-emerald-400' : 'text-red-400'}`}>
                      {previewResult.eligibility_status}
                    </div>
                  </div>
                </div>

                <div className="p-3 bg-zinc-800/30 rounded border border-zinc-800 text-xs text-zinc-300">
                  <span className="font-semibold text-cyan-400">Explanation: </span>
                  {previewResult.priority_explanation}
                </div>

                <div>
                  <h4 className="text-xs font-semibold text-zinc-400 uppercase tracking-wider mb-2">Signal Contribution Breakdown</h4>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs">
                    {Object.entries(previewResult.priority_factors).map(([signal, details]: [string, any]) => (
                      <div key={signal} className="p-2.5 bg-zinc-800/50 rounded border border-zinc-800">
                        <div className="flex justify-between font-medium">
                          <span className="text-zinc-300 capitalize">{signal.replace(/_/g, ' ')}</span>
                          <span className="text-cyan-400 font-mono">+{details.contribution || 0}</span>
                        </div>
                        <div className="text-[11px] text-zinc-500 mt-0.5 font-mono truncate">
                          {details.source || details.raw_value}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                {!previewResult.is_eligible && (
                  <div className="p-3 bg-red-950/40 border border-red-800 rounded text-xs text-red-300">
                    <div className="font-semibold">Eligibility Blockers:</div>
                    <ul className="list-disc list-inside mt-1">
                      {previewResult.eligibility_reasons.map((r, i) => (
                        <li key={i}>{r}</li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            ) : (
              <div className="h-48 flex items-center justify-center text-zinc-500 text-sm">
                Enter a target and click 'Preview Priority & Eligibility' to view evidence-backed factors.
              </div>
            )}
          </div>
        </div>
      )}

      {/* Tab 4: Decision Audit Ledger */}
      {activeTab === 'decisions' && (
        <div className="bg-zinc-900/60 border border-zinc-800 rounded-lg overflow-hidden">
          <table className="w-full text-left text-sm">
            <thead className="bg-zinc-900/90 text-xs text-zinc-400 uppercase border-b border-zinc-800">
              <tr>
                <th className="px-4 py-3">Timestamp</th>
                <th className="px-4 py-3">Decision</th>
                <th className="px-4 py-3">Trigger Source</th>
                <th className="px-4 py-3">Target</th>
                <th className="px-4 py-3">Score</th>
                <th className="px-4 py-3">Rationale</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-zinc-800 text-xs">
              {decisions.length === 0 ? (
                <tr>
                  <td colSpan={6} className="px-4 py-8 text-center text-zinc-500">
                    No decisions recorded yet.
                  </td>
                </tr>
              ) : (
                decisions.map((dec) => (
                  <tr key={dec.id} className="hover:bg-zinc-800/40 transition">
                    <td className="px-4 py-3 text-zinc-400 whitespace-nowrap">
                      {new Date(dec.created_at).toLocaleTimeString()}
                    </td>
                    <td className="px-4 py-3 font-semibold text-white">
                      <span className="px-2 py-0.5 rounded bg-zinc-800 border border-zinc-700">
                        {dec.decision_type}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-zinc-300 font-mono">{dec.trigger_source}</td>
                    <td className="px-4 py-3 text-zinc-200 font-mono truncate max-w-xs">{dec.target_input}</td>
                    <td className="px-4 py-3 text-cyan-400 font-mono">{dec.priority_score.toFixed(1)}</td>
                    <td className="px-4 py-3 text-zinc-400 max-w-md">{dec.decision_rationale}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      )}

      {/* Tab 5: Policy Governance */}
      {activeTab === 'policy' && policy && (
        <div className="bg-zinc-900/60 border border-zinc-800 rounded-lg p-5 max-w-2xl space-y-4">
          <h3 className="text-base font-semibold text-white">Orchestration & Resource Limits Policy</h3>
          <p className="text-xs text-zinc-400">
            Configure concurrency ceilings, per-target rate limiting, and starvation prevention factors.
          </p>
          <form onSubmit={handleSavePolicy} className="space-y-4 text-xs">
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="block text-zinc-300 font-medium mb-1">Max Concurrent Scans</label>
                <input
                  type="number"
                  min="1"
                  max="20"
                  value={policyForm.max_concurrent_assessments}
                  onChange={(e) => setPolicyForm({ ...policyForm, max_concurrent_assessments: parseInt(e.target.value) || 1 })}
                  className="w-full bg-zinc-800 border border-zinc-700 rounded px-3 py-1.5 text-zinc-100"
                />
              </div>
              <div>
                <label className="block text-zinc-300 font-medium mb-1">Max Per-Target Concurrency</label>
                <input
                  type="number"
                  min="1"
                  max="5"
                  value={policyForm.max_per_target_concurrency}
                  onChange={(e) => setPolicyForm({ ...policyForm, max_per_target_concurrency: parseInt(e.target.value) || 1 })}
                  className="w-full bg-zinc-800 border border-zinc-700 rounded px-3 py-1.5 text-zinc-100"
                />
              </div>
              <div>
                <label className="block text-zinc-300 font-medium mb-1">Max Per-Adapter Concurrency</label>
                <input
                  type="number"
                  min="1"
                  max="10"
                  value={policyForm.max_per_adapter_concurrency}
                  onChange={(e) => setPolicyForm({ ...policyForm, max_per_adapter_concurrency: parseInt(e.target.value) || 1 })}
                  className="w-full bg-zinc-800 border border-zinc-700 rounded px-3 py-1.5 text-zinc-100"
                />
              </div>
              <div>
                <label className="block text-zinc-300 font-medium mb-1">Max Queued Jobs</label>
                <input
                  type="number"
                  min="5"
                  max="500"
                  value={policyForm.max_queued_jobs}
                  onChange={(e) => setPolicyForm({ ...policyForm, max_queued_jobs: parseInt(e.target.value) || 10 })}
                  className="w-full bg-zinc-800 border border-zinc-700 rounded px-3 py-1.5 text-zinc-100"
                />
              </div>
              <div>
                <label className="block text-zinc-300 font-medium mb-1">Aging Factor (/hour)</label>
                <input
                  type="number"
                  step="0.5"
                  min="0"
                  max="20"
                  value={policyForm.aging_factor_per_hour}
                  onChange={(e) => setPolicyForm({ ...policyForm, aging_factor_per_hour: parseFloat(e.target.value) || 0 })}
                  className="w-full bg-zinc-800 border border-zinc-700 rounded px-3 py-1.5 text-zinc-100"
                />
              </div>
              <div>
                <label className="block text-zinc-300 font-medium mb-1">Stale Lease Timeout (sec)</label>
                <input
                  type="number"
                  min="30"
                  max="1800"
                  value={policyForm.stale_lease_timeout_sec}
                  onChange={(e) => setPolicyForm({ ...policyForm, stale_lease_timeout_sec: parseInt(e.target.value) || 30 })}
                  className="w-full bg-zinc-800 border border-zinc-700 rounded px-3 py-1.5 text-zinc-100"
                />
              </div>
            </div>

            <button
              type="submit"
              className="py-2 px-4 bg-cyan-600 hover:bg-cyan-500 rounded text-sm font-semibold text-white transition"
            >
              Save Policy Parameters
            </button>
          </form>
        </div>
      )}

      {/* Enqueue Modal */}
      {showEnqueueModal && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center p-4 z-50">
          <div className="bg-zinc-900 border border-zinc-800 rounded-lg max-w-md w-full p-6 space-y-4">
            <h3 className="text-base font-semibold text-white">Enqueue Authorized Assessment</h3>
            <form onSubmit={handleEnqueue} className="space-y-3 text-xs">
              <div>
                <label className="block text-zinc-300 font-medium mb-1">Schedule Name</label>
                <input
                  type="text"
                  value={newScheduleName}
                  onChange={(e) => setNewScheduleName(e.target.value)}
                  className="w-full bg-zinc-800 border border-zinc-700 rounded px-3 py-1.5 text-zinc-100"
                  required
                />
              </div>
              <div>
                <label className="block text-zinc-300 font-medium mb-1">Target Host / URL</label>
                <input
                  type="text"
                  value={newTarget}
                  onChange={(e) => setNewTarget(e.target.value)}
                  placeholder="https://app.example.com"
                  className="w-full bg-zinc-800 border border-zinc-700 rounded px-3 py-1.5 text-zinc-100 font-mono"
                  required
                />
              </div>
              <div>
                <label className="block text-zinc-300 font-medium mb-1">Adapter</label>
                <select
                  value={newAdapter}
                  onChange={(e) => setNewAdapter(e.target.value)}
                  className="w-full bg-zinc-800 border border-zinc-700 rounded px-3 py-1.5 text-zinc-100"
                >
                  <option value="local_fixture_adapter">local_fixture_adapter</option>
                  <option value="ssl_tls_analyzer">ssl_tls_analyzer</option>
                  <option value="http_header_inspector">http_header_inspector</option>
                  <option value="port_service_scanner">port_service_scanner</option>
                  <option value="compliance_evaluator">compliance_evaluator</option>
                </select>
              </div>

              <div className="flex justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setShowEnqueueModal(false)}
                  className="px-3 py-1.5 bg-zinc-800 hover:bg-zinc-700 text-zinc-300 rounded text-xs transition"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-3 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-white rounded text-xs font-semibold transition"
                >
                  Enqueue Workload
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
