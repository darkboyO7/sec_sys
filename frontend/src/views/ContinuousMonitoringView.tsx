import React, { useState, useEffect, useCallback } from 'react';
import {
  Clock,
  Play,
  Pause,
  RefreshCw,
  Plus,
  AlertTriangle,
  CheckCircle2,
  Calendar,
} from 'lucide-react';
import { api } from '../services/api';
import type { Project, ScopeTarget } from '../types';

interface Props {
  currentProject: Project;
  authorizedTargets?: ScopeTarget[];
}

export const ContinuousMonitoringView: React.FC<Props> = ({ currentProject, authorizedTargets = [] }) => {
  const [schedules, setSchedules] = useState<any[]>([]);
  const [runs, setRuns] = useState<any[]>([]);
  const [overview, setOverview] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [actionLoading, setActionLoading] = useState<string | null>(null);
  const [statusMessage, setStatusMessage] = useState<string | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  // Modal state
  const [isCreateOpen, setIsCreateOpen] = useState(false);
  const [newScheduleName, setNewScheduleName] = useState('');
  const [selectedTarget, setSelectedTarget] = useState('');
  const [frequency, setFrequency] = useState('DAILY');
  const [adapterName, setAdapterName] = useState('live_network_auditor_adapter');

  const loadData = useCallback(async () => {
    setLoading(true);
    setErrorMessage(null);
    try {
      const [schedsData, runsData, overviewData] = await Promise.all([
        api.listMonitoringSchedules(currentProject.id),
        api.listMonitoringRuns(currentProject.id),
        api.getMonitoringOverview(currentProject.id),
      ]);
      setSchedules(schedsData || []);
      setRuns(runsData || []);
      setOverview(overviewData || null);
    } catch (err: any) {
      setErrorMessage(err.message || 'Failed to load monitoring data');
    } finally {
      setLoading(false);
    }
  }, [currentProject.id]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedTarget) {
      setErrorMessage('Please select an authorized scope target.');
      return;
    }
    setLoading(true);
    try {
      await api.createMonitoringSchedule(currentProject.id, {
        name: newScheduleName.trim() || `Daily Monitor - ${selectedTarget}`,
        target_input: selectedTarget,
        adapter_name: adapterName,
        fixture_profile: 'LIVE_WEB_SECURITY_AUDIT',
        frequency,
        interval_seconds: frequency === 'HOURLY' ? 3600 : frequency === 'WEEKLY' ? 604800 : 86400,
      });
      setIsCreateOpen(false);
      setNewScheduleName('');
      setSelectedTarget('');
      setStatusMessage('Continuous monitoring schedule activated successfully.');
      loadData();
    } catch (err: any) {
      setErrorMessage(err.message || 'Failed to create monitoring schedule');
    } finally {
      setLoading(false);
    }
  };

  const handleRunNow = async (schedId: string) => {
    setActionLoading(schedId);
    setErrorMessage(null);
    try {
      const run = await api.triggerMonitoringScheduleRun(currentProject.id, schedId);
      setStatusMessage(`On-demand run completed: ${run.status}. Changes: ${run.new_findings_count} new, ${run.recurring_findings_count} recurring.`);
      loadData();
    } catch (err: any) {
      setErrorMessage(err.message || 'Failed to execute monitoring run');
    } finally {
      setActionLoading(null);
    }
  };

  const handleTogglePause = async (sched: any) => {
    setActionLoading(sched.id);
    try {
      if (sched.status === 'ACTIVE') {
        await api.pauseMonitoringSchedule(currentProject.id, sched.id);
        setStatusMessage(`Schedule '${sched.name}' paused.`);
      } else {
        await api.resumeMonitoringSchedule(currentProject.id, sched.id);
        setStatusMessage(`Schedule '${sched.name}' resumed.`);
      }
      loadData();
    } catch (err: any) {
      setErrorMessage(err.message || 'Failed to toggle schedule state');
    } finally {
      setActionLoading(null);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex justify-between items-center bg-cyber-850 p-6 rounded-xl border border-cyber-700">
        <div>
          <h2 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <Clock className="w-6 h-6 text-accent-cyan" />
            Continuous Security Monitoring & Change Detection
          </h2>
          <p className="text-sm text-slate-400 mt-1">
            Automates recurring assessments for authorized targets, detects drift and recurring vulnerabilities, and tracks resolution deltas.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={() => setIsCreateOpen(true)}
            className="px-4 py-2 bg-accent-cyan hover:bg-cyan-400 text-cyber-900 font-semibold text-xs rounded-lg flex items-center gap-2 transition"
          >
            <Plus className="w-4 h-4" />
            New Schedule
          </button>
          <button
            onClick={loadData}
            disabled={loading}
            className="px-3.5 py-2 bg-cyber-750 hover:bg-cyber-700 text-slate-200 text-xs rounded-lg flex items-center gap-2 border border-cyber-600 transition"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </button>
        </div>
      </div>

      {statusMessage && (
        <div className="p-4 bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 rounded-lg text-sm flex items-center justify-between">
          <span className="flex items-center gap-2"><CheckCircle2 className="w-4 h-4" /> {statusMessage}</span>
          <button onClick={() => setStatusMessage(null)} className="text-xs hover:underline">Dismiss</button>
        </div>
      )}

      {errorMessage && (
        <div className="p-4 bg-red-500/10 border border-red-500/30 text-red-300 rounded-lg text-sm flex items-center justify-between">
          <span className="flex items-center gap-2"><AlertTriangle className="w-4 h-4" /> {errorMessage}</span>
          <button onClick={() => setErrorMessage(null)} className="text-xs hover:underline">Dismiss</button>
        </div>
      )}

      {/* Metrics Row */}
      {overview && (
        <div className="grid grid-cols-4 gap-4">
          <div className="bg-cyber-850 p-4 rounded-xl border border-cyber-700">
            <div className="text-xs text-slate-400 font-medium">Active Schedules</div>
            <div className="text-2xl font-bold text-emerald-400 mt-1">{overview.active_schedules}</div>
            <div className="text-xs text-slate-500 mt-0.5">Total configured: {overview.total_schedules}</div>
          </div>
          <div className="bg-cyber-850 p-4 rounded-xl border border-cyber-700">
            <div className="text-xs text-slate-400 font-medium">Paused / Expired</div>
            <div className="text-2xl font-bold text-amber-400 mt-1">{overview.paused_schedules + overview.expired_schedules}</div>
            <div className="text-xs text-slate-500 mt-0.5">Expired: {overview.expired_schedules}</div>
          </div>
          <div className="bg-cyber-850 p-4 rounded-xl border border-cyber-700">
            <div className="text-xs text-slate-400 font-medium">Total Runs Executed</div>
            <div className="text-2xl font-bold text-accent-cyan mt-1">{overview.total_runs_executed}</div>
            <div className="text-xs text-slate-500 mt-0.5">Historical verification cycles</div>
          </div>
          <div className="bg-cyber-850 p-4 rounded-xl border border-cyber-700">
            <div className="text-xs text-slate-400 font-medium">Engine Mode</div>
            <div className="text-2xl font-bold text-slate-100 mt-1">Autonomous</div>
            <div className="text-xs text-slate-500 mt-0.5">Worker queue integrated</div>
          </div>
        </div>
      )}

      {/* Configured Schedules List */}
      <div className="bg-cyber-850 rounded-xl border border-cyber-700 overflow-hidden">
        <div className="px-6 py-4 border-b border-cyber-750 font-semibold text-sm text-slate-200 flex justify-between items-center">
          <span>Configured Recurring Monitoring Schedules</span>
          <span className="text-xs text-slate-400">{schedules.length} Schedules</span>
        </div>
        <div className="divide-y divide-cyber-750">
          {schedules.length === 0 ? (
            <div className="p-8 text-center text-slate-400 text-sm">
              No continuous monitoring schedules created yet. Click "New Schedule" to configure recurring automated scans on authorized targets.
            </div>
          ) : (
            schedules.map((s) => (
              <div key={s.id} className="p-6 hover:bg-cyber-800/40 transition flex items-center justify-between">
                <div className="space-y-1">
                  <div className="flex items-center gap-3">
                    <h3 className="font-semibold text-slate-100 text-sm">{s.name}</h3>
                    <span className={`px-2 py-0.5 text-xs rounded-full font-mono ${
                      s.status === 'ACTIVE' ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30' :
                      s.status === 'PAUSED' ? 'bg-amber-500/20 text-amber-300 border border-amber-500/30' :
                      'bg-red-500/20 text-red-300 border border-red-500/30'
                    }`}>
                      {s.status}
                    </span>
                    <span className="px-2 py-0.5 text-xs rounded bg-cyber-750 text-slate-300 font-mono">
                      {s.frequency}
                    </span>
                  </div>
                  <div className="text-xs text-slate-400 flex items-center gap-4">
                    <span>Target: <strong className="text-slate-200 font-mono">{s.target_input}</strong></span>
                    <span>Runs: <strong className="text-slate-200">{s.run_count}</strong></span>
                    <span>Last Run: {s.last_run_at ? new Date(s.last_run_at).toLocaleString() : 'Never'}</span>
                    <span>Next Due: {s.next_run_at ? new Date(s.next_run_at).toLocaleString() : 'N/A'}</span>
                  </div>
                  {s.last_error && (
                    <div className="text-xs text-red-400 flex items-center gap-1 mt-1">
                      <AlertTriangle className="w-3.5 h-3.5" />
                      {s.last_error}
                    </div>
                  )}
                </div>

                <div className="flex items-center gap-2">
                  <button
                    onClick={() => handleRunNow(s.id)}
                    disabled={actionLoading === s.id}
                    className="px-3 py-1.5 bg-accent-cyan/20 hover:bg-accent-cyan/30 text-accent-cyan border border-accent-cyan/40 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition disabled:opacity-50"
                  >
                    <Play className="w-3.5 h-3.5" />
                    Run Now
                  </button>
                  <button
                    onClick={() => handleTogglePause(s)}
                    disabled={actionLoading === s.id}
                    className="px-3 py-1.5 bg-cyber-750 hover:bg-cyber-700 text-slate-200 border border-cyber-600 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition disabled:opacity-50"
                  >
                    {s.status === 'ACTIVE' ? <Pause className="w-3.5 h-3.5" /> : <Play className="w-3.5 h-3.5" />}
                    {s.status === 'ACTIVE' ? 'Pause' : 'Resume'}
                  </button>
                </div>
              </div>
            ))
          )}
        </div>
      </div>

      {/* Historical Execution Runs */}
      <div className="bg-cyber-850 rounded-xl border border-cyber-700 overflow-hidden">
        <div className="px-6 py-4 border-b border-cyber-750 font-semibold text-sm text-slate-200 flex justify-between items-center">
          <span>Recent Scheduled Assessment Runs & Delta Reports</span>
          <span className="text-xs text-slate-400">{runs.length} Runs</span>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-cyber-900/60 text-slate-400 border-b border-cyber-750">
              <tr>
                <th className="px-6 py-3">Executed At</th>
                <th className="px-6 py-3">Status</th>
                <th className="px-6 py-3">New Findings</th>
                <th className="px-6 py-3">Recurring</th>
                <th className="px-6 py-3">Resolved</th>
                <th className="px-6 py-3">Delta Notes</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-cyber-750">
              {runs.length === 0 ? (
                <tr>
                  <td colSpan={6} className="px-6 py-8 text-center text-slate-400">
                    No execution run records recorded yet.
                  </td>
                </tr>
              ) : (
                runs.slice(0, 15).map((r) => (
                  <tr key={r.id} className="hover:bg-cyber-800/30 transition">
                    <td className="px-6 py-3 text-slate-300 font-mono">
                      {new Date(r.executed_at).toLocaleString()}
                    </td>
                    <td className="px-6 py-3">
                      <span className={`px-2 py-0.5 rounded text-xs font-mono ${
                        r.status === 'SUCCESS' ? 'bg-emerald-500/20 text-emerald-300' :
                        r.status === 'SKIPPED_DUPLICATE' ? 'bg-amber-500/20 text-amber-300' :
                        'bg-red-500/20 text-red-300'
                      }`}>
                        {r.status}
                      </span>
                    </td>
                    <td className="px-6 py-3 font-semibold text-red-400">+{r.new_findings_count}</td>
                    <td className="px-6 py-3 font-semibold text-amber-400">{r.recurring_findings_count}</td>
                    <td className="px-6 py-3 font-semibold text-emerald-400">{r.resolved_findings_count}</td>
                    <td className="px-6 py-3 text-slate-400 max-w-xs truncate" title={r.summary_notes}>
                      {r.summary_notes || 'Run completed normally.'}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Create Schedule Modal */}
      {isCreateOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
          <div className="bg-cyber-850 border border-cyber-700 rounded-xl max-w-md w-full p-6 space-y-4 shadow-2xl">
            <h3 className="text-base font-bold text-slate-100 flex items-center gap-2">
              <Calendar className="w-5 h-5 text-accent-cyan" />
              Configure Continuous Monitoring Schedule
            </h3>
            <p className="text-xs text-slate-400">
              Schedules recurring assessments on authorized scope targets with strict boundary re-validation before every execution.
            </p>

            <form onSubmit={handleCreate} className="space-y-4 pt-2">
              <div>
                <label className="text-xs font-semibold text-slate-300 block mb-1">Schedule Name</label>
                <input
                  type="text"
                  value={newScheduleName}
                  onChange={(e) => setNewScheduleName(e.target.value)}
                  placeholder="e.g. Daily Core Web Audit"
                  className="w-full bg-cyber-900 border border-cyber-700 rounded-lg px-3 py-2 text-xs text-slate-100 focus:outline-none focus:border-accent-cyan"
                  required
                />
              </div>

              <div>
                <label className="text-xs font-semibold text-slate-300 block mb-1">Authorized Target</label>
                <select
                  value={selectedTarget}
                  onChange={(e) => setSelectedTarget(e.target.value)}
                  className="w-full bg-cyber-900 border border-cyber-700 rounded-lg px-3 py-2 text-xs text-slate-100 focus:outline-none focus:border-accent-cyan"
                  required
                >
                  <option value="">Select an authorized scope target...</option>
                  {authorizedTargets.map((t) => (
                    <option key={t.id} value={t.target_value}>
                      {t.target_value} ({t.target_type})
                    </option>
                  ))}
                </select>
                {authorizedTargets.length === 0 && (
                  <p className="text-xs text-amber-400 mt-1">No authorized scope targets registered for this project.</p>
                )}
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-xs font-semibold text-slate-300 block mb-1">Frequency</label>
                  <select
                    value={frequency}
                    onChange={(e) => setFrequency(e.target.value)}
                    className="w-full bg-cyber-900 border border-cyber-700 rounded-lg px-3 py-2 text-xs text-slate-100 focus:outline-none focus:border-accent-cyan"
                  >
                    <option value="HOURLY">Hourly (3600s)</option>
                    <option value="DAILY">Daily (24h)</option>
                    <option value="WEEKLY">Weekly (7d)</option>
                  </select>
                </div>
                <div>
                  <label className="text-xs font-semibold text-slate-300 block mb-1">Assessment Engine</label>
                  <select
                    value={adapterName}
                    onChange={(e) => setAdapterName(e.target.value)}
                    className="w-full bg-cyber-900 border border-cyber-700 rounded-lg px-3 py-2 text-xs text-slate-100 focus:outline-none focus:border-accent-cyan"
                  >
                    <option value="live_network_auditor_adapter">Live Network Auditor</option>
                    <option value="local_fixture_adapter">Local Fixture Simulator</option>
                  </select>
                </div>
              </div>

              <div className="flex justify-end gap-3 pt-3 border-t border-cyber-750">
                <button
                  type="button"
                  onClick={() => setIsCreateOpen(false)}
                  className="px-4 py-2 bg-cyber-750 hover:bg-cyber-700 text-slate-300 text-xs rounded-lg transition"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={loading || !selectedTarget}
                  className="px-4 py-2 bg-accent-cyan text-cyber-900 font-semibold text-xs rounded-lg hover:bg-cyan-400 transition disabled:opacity-50"
                >
                  Create & Activate
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
