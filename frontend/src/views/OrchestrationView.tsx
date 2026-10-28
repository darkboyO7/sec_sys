import React, { useState, useEffect } from 'react';
import {
  Layers,
  Play,
  CheckCircle,
  XCircle,
  AlertTriangle,
  RefreshCw,
  TrendingUp,
} from 'lucide-react';
import { api } from '../services/api';
import type {
  Project,
  OrchestrationDashboard,
  AdaptiveOptimization,
} from '../types';

interface OrchestrationViewProps {
  currentProject: Project;
}

export const OrchestrationView: React.FC<OrchestrationViewProps> = ({ currentProject }) => {
  const [dashboard, setDashboard] = useState<OrchestrationDashboard | null>(null);
  const [optimizations, setOptimizations] = useState<AdaptiveOptimization[]>([]);
  const [loading, setLoading] = useState(false);
  const [actionLoading, setActionLoading] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  // New Event Form State
  const [newEventType, setNewEventType] = useState('CONFIG_CHANGED');
  const [newTarget, setNewTarget] = useState('');
  const [submittingEvent, setSubmittingEvent] = useState(false);

  const fetchOrchestrationData = async () => {
    setLoading(true);
    setError(null);
    try {
      const [dashRes, optRes] = await Promise.all([
        api.getOrchestrationDashboard(currentProject.id),
        api.getAdaptiveOptimizations(currentProject.id),
      ]);
      setDashboard(dashRes);
      setOptimizations(optRes || []);
    } catch (err: any) {
      setError(err?.message || 'Failed to load orchestration control plane.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchOrchestrationData();
  }, [currentProject.id]);

  const handleApprove = async (workflowId: string) => {
    setActionLoading(workflowId);
    try {
      await api.approveOrchestrationWorkflow(currentProject.id, workflowId, 'Approved via Operator Console');
      await fetchOrchestrationData();
    } catch (err: any) {
      setError(err?.message || 'Failed to approve workflow.');
    } finally {
      setActionLoading(null);
    }
  };

  const handleReject = async (workflowId: string) => {
    setActionLoading(workflowId);
    try {
      await api.rejectOrchestrationWorkflow(currentProject.id, workflowId, 'Rejected via Operator Console');
      await fetchOrchestrationData();
    } catch (err: any) {
      setError(err?.message || 'Failed to reject workflow.');
    } finally {
      setActionLoading(null);
    }
  };

  const handleSuspend = async (workflowId: string) => {
    setActionLoading(workflowId);
    try {
      await api.suspendOrchestrationWorkflow(currentProject.id, workflowId, 'Suspended by operator');
      await fetchOrchestrationData();
    } catch (err: any) {
      setError(err?.message || 'Failed to suspend workflow.');
    } finally {
      setActionLoading(null);
    }
  };

  const handleResume = async (workflowId: string) => {
    setActionLoading(workflowId);
    try {
      await api.resumeOrchestrationWorkflow(currentProject.id, workflowId);
      await fetchOrchestrationData();
    } catch (err: any) {
      setError(err?.message || 'Failed to resume workflow.');
    } finally {
      setActionLoading(null);
    }
  };

  const handleRetry = async (workflowId: string) => {
    setActionLoading(workflowId);
    try {
      await api.retryOrchestrationWorkflow(currentProject.id, workflowId);
      await fetchOrchestrationData();
    } catch (err: any) {
      setError(err?.message || 'Failed to retry workflow.');
    } finally {
      setActionLoading(null);
    }
  };

  const handleTriggerEvent = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newTarget.trim()) return;

    setSubmittingEvent(true);
    setError(null);
    try {
      await api.ingestOrchestrationEvent(currentProject.id, newEventType, newTarget.trim(), {
        triggered_by: 'operator_ui',
      });
      setNewTarget('');
      await fetchOrchestrationData();
    } catch (err: any) {
      setError(err?.message || 'Failed to trigger event.');
    } finally {
      setSubmittingEvent(false);
    }
  };

  const getStateBadgeClass = (state: string) => {
    switch (state) {
      case 'COMPLETED':
        return 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20';
      case 'AWAITING_APPROVAL':
        return 'bg-amber-500/10 text-amber-400 border-amber-500/20 animate-pulse';
      case 'ACTION_RUNNING':
        return 'bg-cyan-500/10 text-cyan-400 border-cyan-500/20';
      case 'SUSPENDED':
        return 'bg-yellow-500/10 text-yellow-400 border-yellow-500/20';
      case 'FAILED':
        return 'bg-rose-500/10 text-rose-400 border-rose-500/20';
      default:
        return 'bg-slate-500/10 text-slate-400 border-slate-500/20';
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="bg-cyber-850 border border-cyber-750 rounded-xl p-5 shadow-lg flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <Layers className="w-5 h-5 text-accent-cyan" />
            <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono">
              Autonomous Security Orchestrator & Control Plane
            </h3>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Closed-loop security orchestration: Ingestion → Deduplication → Evidence Planner → Approval Gates → Verification → Measurable Improvement.
          </p>
        </div>

        <button
          onClick={fetchOrchestrationData}
          disabled={loading}
          className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-cyber-800 hover:bg-cyber-750 text-slate-300 hover:text-white text-xs font-semibold transition-colors shrink-0"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin text-accent-cyan' : ''}`} />
          Refresh Workflows
        </button>
      </div>

      {error && (
        <div className="p-4 bg-rose-500/10 border border-rose-500/20 rounded-xl text-rose-400 text-xs flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Summary KPI Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-4">
        <div className="bg-cyber-850/60 border border-cyber-750 p-4 rounded-xl">
          <span className="text-[11px] font-mono uppercase text-slate-400">Total Workflows</span>
          <p className="text-xl font-bold font-mono text-white mt-1">
            {dashboard?.summary?.total_workflows ?? 0}
          </p>
        </div>
        <div className="bg-cyber-850/60 border border-cyber-750 p-4 rounded-xl">
          <span className="text-[11px] font-mono uppercase text-cyan-400">Active / Queued</span>
          <p className="text-xl font-bold font-mono text-cyan-400 mt-1">
            {dashboard?.summary?.active_workflows ?? 0}
          </p>
        </div>
        <div className="bg-cyber-850/60 border border-cyber-750 p-4 rounded-xl">
          <span className="text-[11px] font-mono uppercase text-amber-400">Pending Approvals</span>
          <p className="text-xl font-bold font-mono text-amber-400 mt-1">
            {dashboard?.summary?.pending_approvals ?? 0}
          </p>
        </div>
        <div className="bg-cyber-850/60 border border-cyber-750 p-4 rounded-xl">
          <span className="text-[11px] font-mono uppercase text-emerald-400">Completed</span>
          <p className="text-xl font-bold font-mono text-emerald-400 mt-1">
            {dashboard?.summary?.completed_workflows ?? 0}
          </p>
        </div>
        <div className="bg-cyber-850/60 border border-cyber-750 p-4 rounded-xl">
          <span className="text-[11px] font-mono uppercase text-yellow-400">Suspended</span>
          <p className="text-xl font-bold font-mono text-yellow-400 mt-1">
            {dashboard?.summary?.suspended_workflows ?? 0}
          </p>
        </div>
        <div className="bg-cyber-850/60 border border-cyber-750 p-4 rounded-xl">
          <span className="text-[11px] font-mono uppercase text-rose-400">Failed</span>
          <p className="text-xl font-bold font-mono text-rose-400 mt-1">
            {dashboard?.summary?.failed_workflows ?? 0}
          </p>
        </div>
      </div>

      {/* Pending Approvals Section */}
      {(dashboard?.pending_approvals?.length ?? 0) > 0 && (
        <div className="bg-cyber-850 border border-amber-500/30 rounded-xl p-5 shadow-lg space-y-4">
          <div className="flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-amber-400" />
            <h4 className="text-xs font-bold text-white uppercase tracking-wider font-mono">
              Action Approval Requests ({dashboard?.pending_approvals.length})
            </h4>
          </div>
          <div className="space-y-3">
            {dashboard?.pending_approvals.map((wf) => (
              <div
                key={wf.id}
                className="bg-cyber-900/60 border border-cyber-750 p-4 rounded-lg flex flex-col md:flex-row md:items-center justify-between gap-4"
              >
                <div>
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-bold text-white font-mono">{wf.recommended_action}</span>
                    <span className="text-[10px] px-2 py-0.5 rounded border font-mono bg-amber-500/10 text-amber-400 border-amber-500/20">
                      Req: {wf.required_approval_role || 'LEAD'}
                    </span>
                  </div>
                  <p className="text-xs text-slate-300 mt-1">{wf.action_rationale}</p>
                  <p className="text-[11px] text-slate-500 mt-0.5 font-mono">
                    Target: <span className="text-slate-300">{wf.target_resource}</span> | Confidence: {(wf.confidence * 100).toFixed(0)}%
                  </p>
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  <button
                    onClick={() => handleApprove(wf.id)}
                    disabled={actionLoading === wf.id}
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg text-xs font-semibold transition-colors disabled:opacity-50"
                  >
                    <CheckCircle className="w-3.5 h-3.5" />
                    Approve Action
                  </button>
                  <button
                    onClick={() => handleReject(wf.id)}
                    disabled={actionLoading === wf.id}
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-rose-600/80 hover:bg-rose-600 text-white rounded-lg text-xs font-semibold transition-colors disabled:opacity-50"
                  >
                    <XCircle className="w-3.5 h-3.5" />
                    Reject
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Manual Ingestion Form */}
      <div className="bg-cyber-850 border border-cyber-750 rounded-xl p-5 shadow-lg">
        <h4 className="text-xs font-bold text-white uppercase tracking-wider font-mono mb-3">
          Ingest Operational Event (Trigger Orchestration Cycle)
        </h4>
        <form onSubmit={handleTriggerEvent} className="flex flex-col sm:flex-row items-center gap-3">
          <select
            value={newEventType}
            onChange={(e) => setNewEventType(e.target.value)}
            className="bg-cyber-900 border border-cyber-700 text-slate-200 text-xs rounded-lg px-3 py-2 w-full sm:w-auto font-mono focus:outline-none focus:border-accent-cyan"
          >
            <option value="CONFIG_CHANGED">CONFIG_CHANGED</option>
            <option value="ASSET_DISCOVERED">ASSET_DISCOVERED</option>
            <option value="FINDING_DETECTED">FINDING_DETECTED</option>
            <option value="REMEDIATION_APPLIED">REMEDIATION_APPLIED</option>
            <option value="SCAN_COMPLETED">SCAN_COMPLETED</option>
            <option value="MANUAL_TRIGGER">MANUAL_TRIGGER</option>
            <option value="DIAGNOSTIC_FAILURE">DIAGNOSTIC_FAILURE</option>
            <option value="INTEGRITY_ALERT">INTEGRITY_ALERT</option>
          </select>

          <input
            type="text"
            placeholder="Target Resource (e.g. 192.168.1.100 or app.internal)"
            value={newTarget}
            onChange={(e) => setNewTarget(e.target.value)}
            className="bg-cyber-900 border border-cyber-700 text-slate-200 text-xs rounded-lg px-3 py-2 flex-1 w-full font-mono focus:outline-none focus:border-accent-cyan"
          />

          <button
            type="submit"
            disabled={submittingEvent || !newTarget.trim()}
            className="inline-flex items-center gap-1.5 px-4 py-2 bg-accent-cyan hover:bg-accent-cyan/80 text-cyber-950 font-bold rounded-lg text-xs transition-colors disabled:opacity-50 w-full sm:w-auto justify-center"
          >
            <Play className="w-3.5 h-3.5 fill-current" />
            Ingest & Run Cycle
          </button>
        </form>
      </div>

      {/* Active Workflows Table */}
      <div className="bg-cyber-850 border border-cyber-750 rounded-xl overflow-hidden shadow-lg">
        <div className="p-4 border-b border-cyber-750 flex items-center justify-between">
          <h4 className="text-xs font-bold text-white uppercase tracking-wider font-mono">
            Orchestration Workflows ({dashboard?.active_workflows?.length ?? 0})
          </h4>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-cyber-900/60 text-slate-400 border-b border-cyber-750">
              <tr>
                <th className="p-3">Workflow ID</th>
                <th className="p-3">Target</th>
                <th className="p-3">State</th>
                <th className="p-3">Recommended Action</th>
                <th className="p-3">Outcome</th>
                <th className="p-3">Attempts</th>
                <th className="p-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-cyber-800 text-slate-300">
              {(dashboard?.active_workflows?.length ?? 0) === 0 ? (
                <tr>
                  <td colSpan={7} className="p-6 text-center text-slate-500 font-sans text-xs">
                    No active workflows recorded. Ingest an event above to start a cycle.
                  </td>
                </tr>
              ) : (
                dashboard?.active_workflows.map((wf) => (
                  <tr key={wf.id} className="hover:bg-cyber-800/40 transition-colors">
                    <td className="p-3 font-mono text-slate-400">{wf.id.substring(0, 8)}</td>
                    <td className="p-3 font-semibold text-white">{wf.target_resource}</td>
                    <td className="p-3">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${getStateBadgeClass(wf.state)}`}>
                        {wf.state}
                      </span>
                    </td>
                    <td className="p-3 text-slate-300">{wf.recommended_action || '—'}</td>
                    <td className="p-3">
                      {wf.outcome_status ? (
                        <span className="text-emerald-400 text-[11px]">{wf.outcome_status}</span>
                      ) : (
                        <span className="text-slate-500 text-[11px]">In Progress</span>
                      )}
                    </td>
                    <td className="p-3">{wf.attempt_count} / {wf.max_retries}</td>
                    <td className="p-3 text-right space-x-1">
                      {wf.state === 'ACTION_RUNNING' && (
                        <button
                          onClick={() => handleSuspend(wf.id)}
                          className="px-2 py-1 bg-yellow-500/10 hover:bg-yellow-500/20 text-yellow-400 rounded text-[10px]"
                        >
                          Suspend
                        </button>
                      )}
                      {wf.state === 'SUSPENDED' && (
                        <button
                          onClick={() => handleResume(wf.id)}
                          className="px-2 py-1 bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-400 rounded text-[10px]"
                        >
                          Resume
                        </button>
                      )}
                      {wf.state === 'FAILED' && (
                        <button
                          onClick={() => handleRetry(wf.id)}
                          className="px-2 py-1 bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-400 rounded text-[10px]"
                        >
                          Retry
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

      {/* Adaptive Optimizations */}
      {optimizations.length > 0 && (
        <div className="bg-cyber-850 border border-cyber-750 rounded-xl p-5 shadow-lg">
          <div className="flex items-center gap-2 mb-3">
            <TrendingUp className="w-4 h-4 text-emerald-400" />
            <h4 className="text-xs font-bold text-white uppercase tracking-wider font-mono">
              Controlled Adaptive Optimizations ({optimizations.length})
            </h4>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {optimizations.map((opt) => (
              <div key={opt.id} className="bg-cyber-900/60 border border-cyber-750 p-3 rounded-lg text-xs space-y-1">
                <div className="flex items-center justify-between">
                  <span className="font-bold text-white font-mono">{opt.optimization_name}</span>
                  <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${opt.is_accepted ? 'bg-emerald-500/10 text-emerald-400' : 'bg-rose-500/10 text-rose-400'}`}>
                    {opt.is_accepted ? 'ACCEPTED' : 'REJECTED'}
                  </span>
                </div>
                <p className="text-slate-400 text-[11px]">{opt.objective}</p>
                <div className="flex items-center gap-3 text-slate-500 font-mono text-[10px] pt-1">
                  <span>Baseline: {opt.baseline_value}</span>
                  <span>Evaluated: {opt.evaluated_value}</span>
                  <span>Threshold: {opt.threshold_value}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};
