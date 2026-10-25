import React, { useState } from 'react';
import {
  PlayCircle,
  CheckCircle2,
  AlertTriangle,
  Clock,
  Ban,
  RefreshCw,
  Plus,
  X,
  FileCode,
  Hash,
  Info,
} from 'lucide-react';
import type { Project, AssessmentJob, AssessmentFinding, ScopeTarget, FindingSeverity } from '../types';
import { api } from '../services/api';
import { EmptyState } from '../components/EmptyState';

interface AssessmentJobsViewProps {
  project: Project;
  authorizedTargets: ScopeTarget[];
  jobs: AssessmentJob[];
  onRefresh: () => void;
  loading: boolean;
}

export const AssessmentJobsView: React.FC<AssessmentJobsViewProps> = ({
  project,
  authorizedTargets,
  jobs,
  onRefresh,
  loading,
}) => {
  const [isLaunchModalOpen, setIsLaunchModalOpen] = useState(false);
  const [selectedJob, setSelectedJob] = useState<AssessmentJob | null>(null);
  const [jobFindings, setJobFindings] = useState<AssessmentFinding[]>([]);
  const [loadingFindings, setLoadingFindings] = useState(false);
  const [selectedFinding, setSelectedFinding] = useState<AssessmentFinding | null>(null);

  // Form state
  const [targetInput, setTargetInput] = useState('');
  const [fixtureProfile, setFixtureProfile] = useState('WEB_APPLICATION_BASELINE');
  const [timeoutSeconds, setTimeoutSeconds] = useState(300);
  const [idempotencyKey, setIdempotencyKey] = useState('');
  const [launching, setLaunching] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleLaunch = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!targetInput.trim()) return;

    setLaunching(true);
    setError(null);

    try {
      await api.createAssessment(project.id, {
        target_input: targetInput.trim(),
        adapter_name: 'local_fixture_adapter',
        fixture_profile: fixtureProfile,
        timeout_seconds: Number(timeoutSeconds),
        idempotency_key: idempotencyKey.trim() || undefined,
      });
      setIsLaunchModalOpen(false);
      setTargetInput('');
      setIdempotencyKey('');
      onRefresh();
    } catch (err: any) {
      setError(err.message || 'Failed to dispatch assessment');
    } finally {
      setLaunching(false);
    }
  };

  const handleSelectJob = async (job: AssessmentJob) => {
    setSelectedJob(job);
    setSelectedFinding(null);
    setLoadingFindings(true);
    try {
      const findings = await api.listAssessmentFindings(project.id, job.id);
      setJobFindings(findings);
    } catch (err) {
      console.error('Failed to load findings:', err);
      setJobFindings([]);
    } finally {
      setLoadingFindings(false);
    }
  };

  const handleCancelJob = async (jobId: string) => {
    if (!window.confirm('Are you sure you want to request cancellation for this assessment?')) return;
    try {
      await api.cancelAssessment(project.id, jobId);
      onRefresh();
      if (selectedJob && selectedJob.id === jobId) {
        const updated = await api.getAssessment(project.id, jobId);
        setSelectedJob(updated);
      }
    } catch (err: any) {
      alert(err.message || 'Failed to cancel assessment');
    }
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'COMPLETED':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
            <CheckCircle2 className="w-3 h-3" /> COMPLETED
          </span>
        );
      case 'READY':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-cyan-500/10 text-cyan-400 border border-cyan-500/30">
            <CheckCircle2 className="w-3 h-3" /> READY
          </span>
        );
      case 'PREFLIGHT':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-purple-500/10 text-purple-400 border border-purple-500/30 animate-pulse">
            <RefreshCw className="w-3 h-3 animate-spin" /> PREFLIGHT
          </span>
        );
      case 'RUNNING':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-accent-blue/10 text-accent-blue border border-accent-blue/30 animate-pulse">
            <RefreshCw className="w-3 h-3 animate-spin" /> RUNNING
          </span>
        );
      case 'CANCELLATION_REQUESTED':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-amber-500/10 text-amber-300 border border-amber-500/30 animate-pulse">
            <Clock className="w-3 h-3 animate-spin" /> CANCEL REQ
          </span>
        );
      case 'QUEUED':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-amber-500/10 text-amber-400 border border-amber-500/30">
            <Clock className="w-3 h-3" /> QUEUED
          </span>
        );
      case 'PARTIAL':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-amber-500/15 text-amber-300 border border-amber-500/30">
            <AlertTriangle className="w-3 h-3" /> PARTIAL
          </span>
        );
      case 'FAILED':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-rose-500/10 text-rose-400 border border-rose-500/30">
            <Ban className="w-3 h-3" /> FAILED
          </span>
        );
      case 'REJECTED':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-rose-500/10 text-rose-400 border border-rose-500/30">
            <Ban className="w-3 h-3" /> REJECTED
          </span>
        );
      case 'CANCELLED':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-500/10 text-slate-400 border border-slate-500/30">
            <Ban className="w-3 h-3" /> CANCELLED
          </span>
        );
      case 'TIMED_OUT':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-rose-500/10 text-rose-300 border border-rose-500/30">
            <Clock className="w-3 h-3" /> TIMED OUT
          </span>
        );
      default:
        return null;
    }
  };

  const getSeverityBadge = (sev: FindingSeverity) => {
    switch (sev) {
      case 'CRITICAL':
        return (
          <span className="px-2 py-0.5 rounded text-[10px] font-bold font-mono bg-rose-500/20 text-rose-400 border border-rose-500/40">
            CRITICAL
          </span>
        );
      case 'HIGH':
        return (
          <span className="px-2 py-0.5 rounded text-[10px] font-bold font-mono bg-orange-500/20 text-orange-400 border border-orange-500/40">
            HIGH
          </span>
        );
      case 'MEDIUM':
        return (
          <span className="px-2 py-0.5 rounded text-[10px] font-bold font-mono bg-amber-500/20 text-amber-400 border border-amber-500/40">
            MEDIUM
          </span>
        );
      case 'LOW':
        return (
          <span className="px-2 py-0.5 rounded text-[10px] font-bold font-mono bg-blue-500/20 text-blue-400 border border-blue-500/40">
            LOW
          </span>
        );
      case 'INFO':
        return (
          <span className="px-2 py-0.5 rounded text-[10px] font-bold font-mono bg-slate-500/20 text-slate-300 border border-slate-500/40">
            INFO
          </span>
        );
    }
  };

  return (
    <div className="space-y-6">
      {/* Policy Notice & Header */}
      <div className="bg-cyber-850 border border-cyber-750 rounded-xl p-5 shadow-lg flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <PlayCircle className="w-5 h-5 text-accent-cyan" />
            <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono">
              Controlled Assessment Orchestration
            </h3>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyber-800 text-amber-400 border border-cyber-750">
              Deterministic Fixture Mode
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1 max-w-2xl">
            Execute governed assessment jobs against authorized targets. All observations are generated through
            reproducible, validated local fixtures. Live network socket scanning remains strictly disabled by policy.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={onRefresh}
            disabled={loading}
            className="p-2 rounded-lg bg-cyber-800 hover:bg-cyber-750 text-slate-400 hover:text-white transition-colors"
            title="Refresh Assessments"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin text-accent-cyan' : ''}`} />
          </button>
          <button
            onClick={() => {
              setError(null);
              setIsLaunchModalOpen(true);
            }}
            className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-accent-blue hover:bg-accent-blue/90 text-white text-xs font-semibold transition-colors shrink-0 shadow-sm"
          >
            <Plus className="w-3.5 h-3.5" />
            Launch Assessment Job
          </button>
        </div>
      </div>

      {/* Main Grid: Jobs List & Job Details Drawer */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left: Assessment Jobs Table */}
        <div className="lg:col-span-2 bg-cyber-850 border border-cyber-750 rounded-xl overflow-hidden shadow-lg">
          <div className="p-4 border-b border-cyber-750 bg-cyber-900/60 flex items-center justify-between">
            <span className="text-xs font-bold text-white uppercase font-mono tracking-wider">
              Execution Job History ({jobs.length})
            </span>
          </div>

          {jobs.length === 0 ? (
            <div className="p-8">
              <EmptyState
                icon={PlayCircle}
                title="No Assessments Dispatched Yet"
                description="No assessment jobs have been executed for this project. Launch an assessment against an authorized target to test the execution pipeline."
                actionLabel="Launch Assessment"
                onAction={() => setIsLaunchModalOpen(true)}
              />
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse text-xs font-mono">
                <thead>
                  <tr className="border-b border-cyber-750 bg-cyber-900/40 text-slate-400 text-[11px]">
                    <th className="py-3 px-4">Target Input</th>
                    <th className="py-3 px-4">Adapter</th>
                    <th className="py-3 px-4">Status</th>
                    <th className="py-3 px-4">Findings</th>
                    <th className="py-3 px-4">Queued</th>
                    <th className="py-3 px-4 text-right">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-cyber-800">
                  {jobs.map((j) => {
                    const isSelected = selectedJob?.id === j.id;
                    return (
                      <tr
                        key={j.id}
                        onClick={() => handleSelectJob(j)}
                        className={`cursor-pointer transition-colors ${
                          isSelected ? 'bg-cyber-800 text-white' : 'hover:bg-cyber-800/40 text-slate-300'
                        }`}
                      >
                        <td className="py-3 px-4 font-semibold text-slate-200">
                          <div>{j.target_input}</div>
                          {j.is_simulated && (
                            <span className="text-[9px] text-amber-400 font-normal">SIMULATED FIXTURE</span>
                          )}
                        </td>
                        <td className="py-3 px-4 text-slate-400">
                          <div>{j.adapter_name}</div>
                          <div className="text-[10px] text-slate-500">v{j.adapter_version}</div>
                        </td>
                        <td className="py-3 px-4">{getStatusBadge(j.status)}</td>
                        <td className="py-3 px-4 text-slate-300 font-bold">
                          {j.summary_stats?.findings_count ?? 0}
                        </td>
                        <td className="py-3 px-4 text-slate-400 text-[11px]">
                          {new Date(j.queued_at).toLocaleTimeString()}
                        </td>
                        <td className="py-3 px-4 text-right">
                          {['QUEUED', 'PREFLIGHT', 'READY', 'RUNNING'].includes(j.status) && (
                            <button
                              onClick={(e) => {
                                e.stopPropagation();
                                handleCancelJob(j.id);
                              }}
                              className="px-2 py-1 bg-rose-500/10 hover:bg-rose-500/20 text-rose-400 border border-rose-500/30 rounded text-[10px] font-semibold transition-colors"
                            >
                              Cancel
                            </button>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* Right: Job Details & Findings Drawer */}
        <div className="bg-cyber-850 border border-cyber-750 rounded-xl p-5 shadow-lg flex flex-col min-h-[450px]">
          {selectedJob ? (
            <div className="space-y-4 flex-1">
              <div className="flex items-center justify-between pb-3 border-b border-cyber-750">
                <div>
                  <h4 className="text-xs font-bold text-white uppercase font-mono">Job Details</h4>
                  <div className="text-[10px] font-mono text-slate-500">ID: {selectedJob.id}</div>
                </div>
                <div>{getStatusBadge(selectedJob.status)}</div>
              </div>

              {/* Stats overview */}
              <div className="grid grid-cols-2 gap-2 text-xs font-mono">
                <div className="p-2.5 bg-cyber-900 rounded border border-cyber-800">
                  <div className="text-[10px] text-slate-500">Target</div>
                  <div className="font-semibold text-slate-200 truncate">{selectedJob.target_input}</div>
                </div>
                <div className="p-2.5 bg-cyber-900 rounded border border-cyber-800">
                  <div className="text-[10px] text-slate-500">Duration</div>
                  <div className="font-semibold text-slate-200">
                    {selectedJob.summary_stats?.duration_ms
                      ? `${selectedJob.summary_stats.duration_ms.toFixed(1)} ms`
                      : 'N/A'}
                  </div>
                </div>
              </div>

              {/* Phase 6A Governance Contract Details */}
              <div className="p-2.5 bg-cyber-900 rounded border border-cyber-800 text-[11px] font-mono space-y-1">
                <div className="flex justify-between">
                  <span className="text-slate-500">Policy:</span>
                  <span className="text-accent-cyan font-bold">{selectedJob.policy_version || '2026.1'}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-500">Auth Status:</span>
                  <span className="text-emerald-400 font-bold">{selectedJob.authorization_status || 'AUTHORIZED'}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-500">Scope Digest:</span>
                  <span className="text-slate-300 truncate max-w-[140px]" title={selectedJob.scope_snapshot_digest || ''}>
                    {selectedJob.scope_snapshot_digest ? `${selectedJob.scope_snapshot_digest.substring(0, 12)}...` : 'N/A'}
                  </span>
                </div>
                {selectedJob.failure_category && (
                  <div className="flex justify-between pt-1 border-t border-cyber-800">
                    <span className="text-rose-400 font-bold">Failure Category:</span>
                    <span className="text-rose-300 font-bold">{selectedJob.failure_category}</span>
                  </div>
                )}
              </div>

              {selectedJob.error_message && (
                <div className="p-3 bg-rose-500/10 border border-rose-500/20 rounded-lg text-xs text-rose-300 font-mono">
                  {selectedJob.error_message}
                </div>
              )}

              {/* Findings section */}
              <div>
                <div className="flex items-center justify-between mb-2">
                  <h5 className="text-xs font-bold text-white uppercase font-mono">
                    Observed Findings ({jobFindings.length})
                  </h5>
                </div>

                {loadingFindings ? (
                  <div className="text-center py-6 text-xs text-slate-500">
                    <RefreshCw className="w-4 h-4 animate-spin mx-auto mb-1 text-accent-cyan" />
                    Loading findings...
                  </div>
                ) : jobFindings.length === 0 ? (
                  <div className="text-center py-6 text-xs text-slate-500 bg-cyber-900 rounded border border-cyber-800 p-4">
                    {selectedJob.status === 'COMPLETED'
                      ? 'No vulnerabilities detected by this fixture profile.'
                      : 'No findings recorded for this execution.'}
                  </div>
                ) : (
                  <div className="space-y-2 max-h-[320px] overflow-y-auto">
                    {jobFindings.map((f) => (
                      <div
                        key={f.id}
                        onClick={() => setSelectedFinding(f)}
                        className="p-3 bg-cyber-900 hover:bg-cyber-800 border border-cyber-750 rounded-lg cursor-pointer transition-colors"
                      >
                        <div className="flex items-center justify-between mb-1">
                          {getSeverityBadge(f.severity)}
                          <span className="text-[10px] text-slate-500 font-mono">
                            {f.vuln_id || 'GENERAL_FINDING'}
                          </span>
                        </div>
                        <div className="text-xs font-semibold text-slate-200 mb-1">{f.title}</div>
                        <p className="text-[11px] text-slate-400 line-clamp-2">{f.description}</p>
                        <div className="mt-2 text-[10px] text-accent-cyan hover:underline flex items-center gap-1 font-mono">
                          <Hash className="w-3 h-3" /> Inspect Evidence Provenance ({f.evidence_items?.length || 0})
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          ) : (
            <div className="flex-1 flex flex-col items-center justify-center text-center p-6 text-slate-500">
              <PlayCircle className="w-10 h-10 mb-2 text-cyber-700" />
              <div className="text-xs font-semibold text-slate-400">No Job Selected</div>
              <p className="text-[11px] max-w-xs mt-1">
                Select an assessment job from the history table to view findings, safe error reports, and cryptographic
                evidence provenance.
              </p>
            </div>
          )}
        </div>
      </div>

      {/* Modal: Launch Assessment */}
      {isLaunchModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm">
          <div className="w-full max-w-lg bg-cyber-850 border border-cyber-700 rounded-xl shadow-2xl p-5">
            <div className="flex items-center justify-between pb-3 border-b border-cyber-750">
              <div className="flex items-center gap-2">
                <PlayCircle className="w-5 h-5 text-accent-cyan" />
                <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono">
                  Dispatch Controlled Assessment
                </h3>
              </div>
              <button
                onClick={() => setIsLaunchModalOpen(false)}
                className="text-slate-400 hover:text-white p-1 rounded hover:bg-cyber-750"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="my-3 p-3 bg-amber-500/10 border border-amber-500/20 rounded-lg text-xs text-amber-300 font-mono flex items-start gap-2">
              <Info className="w-4 h-4 shrink-0 mt-0.5" />
              <span>
                Safety Control: In accordance with Phase 2 requirements, executions operate deterministically using safe
                local fixtures. Real network socket scans are disabled.
              </span>
            </div>

            {error && (
              <div className="p-2.5 bg-rose-500/10 border border-rose-500/20 rounded text-xs text-rose-300 mb-3 font-mono">
                {error}
              </div>
            )}

            <form onSubmit={handleLaunch} className="space-y-4">
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">Target Assessment Scope *</label>
                {authorizedTargets.length > 0 ? (
                  <select
                    value={targetInput}
                    onChange={(e) => setTargetInput(e.target.value)}
                    required
                    className="w-full bg-cyber-900 border border-cyber-700 rounded-lg px-3 py-2 text-xs font-mono text-white focus:outline-none focus:border-accent-cyan"
                  >
                    <option value="">Select from authorized targets...</option>
                    {authorizedTargets.map((t) => (
                      <option key={t.id} value={t.target_value}>
                        {t.target_value} ({t.target_type})
                      </option>
                    ))}
                  </select>
                ) : (
                  <input
                    type="text"
                    required
                    value={targetInput}
                    onChange={(e) => setTargetInput(e.target.value)}
                    placeholder="e.g. api.target.corp, 192.168.1.50"
                    className="w-full bg-cyber-900 border border-cyber-700 rounded-lg px-3 py-2 text-xs font-mono text-white placeholder-slate-500 focus:outline-none focus:border-accent-cyan"
                  />
                )}
                <p className="text-[10px] text-slate-500 mt-1">
                  Target will be verified against active Rules of Engagement and exclusions before execution.
                </p>
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">Local Fixture Test Profile</label>
                <select
                  value={fixtureProfile}
                  onChange={(e) => setFixtureProfile(e.target.value)}
                  className="w-full bg-cyber-900 border border-cyber-700 rounded-lg px-3 py-2 text-xs font-mono text-white focus:outline-none focus:border-accent-cyan"
                >
                  <option value="WEB_APPLICATION_BASELINE">
                    WEB_APPLICATION_BASELINE — CSP, Clickjacking & Security Headers
                  </option>
                  <option value="TLS_CONFIGURATION_CHECK">
                    TLS_CONFIGURATION_CHECK — Legacy Protocol & Cipher Weakness
                  </option>
                  <option value="HARDENED_HOST_BASELINE">
                    HARDENED_HOST_BASELINE — Clean Host Benchmark (0 Findings)
                  </option>
                  <option value="SIMULATED_CRITICAL_EXPOSURE">
                    SIMULATED_CRITICAL_EXPOSURE — Unauthenticated SQLi Demonstration
                  </option>
                  <option value="PARTIAL_FAILURE_PROFILE">
                    PARTIAL_FAILURE_PROFILE — Simulated Partial Module Timeout
                  </option>
                </select>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-medium text-slate-300 mb-1">Timeout (Seconds)</label>
                  <input
                    type="number"
                    min={10}
                    max={3600}
                    value={timeoutSeconds}
                    onChange={(e) => setTimeoutSeconds(Number(e.target.value))}
                    className="w-full bg-cyber-900 border border-cyber-700 rounded-lg px-3 py-2 text-xs font-mono text-white focus:outline-none focus:border-accent-cyan"
                  />
                </div>
                <div>
                  <label className="block text-xs font-medium text-slate-300 mb-1">Idempotency Key (Optional)</label>
                  <input
                    type="text"
                    value={idempotencyKey}
                    onChange={(e) => setIdempotencyKey(e.target.value)}
                    placeholder="e.g. sched-2026-10-25"
                    className="w-full bg-cyber-900 border border-cyber-700 rounded-lg px-3 py-2 text-xs font-mono text-white placeholder-slate-500 focus:outline-none focus:border-accent-cyan"
                  />
                </div>
              </div>

              <div className="flex justify-end gap-2 pt-2 border-t border-cyber-750">
                <button
                  type="button"
                  onClick={() => setIsLaunchModalOpen(false)}
                  className="px-3 py-1.5 text-xs text-slate-400 hover:text-white"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={launching || !targetInput.trim()}
                  className="px-4 py-2 bg-accent-blue hover:bg-accent-blue/90 disabled:bg-cyber-750 text-white rounded-lg text-xs font-semibold"
                >
                  {launching ? 'Executing Pipeline...' : 'Dispatch Assessment'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Modal: Evidence Provenance Inspection */}
      {selectedFinding && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm">
          <div className="w-full max-w-2xl bg-cyber-850 border border-cyber-700 rounded-xl shadow-2xl p-5 font-mono text-xs">
            <div className="flex items-center justify-between pb-3 border-b border-cyber-750">
              <div className="flex items-center gap-2">
                <FileCode className="w-5 h-5 text-accent-cyan" />
                <h4 className="font-bold text-white uppercase truncate max-w-md">{selectedFinding.title}</h4>
              </div>
              <button
                onClick={() => setSelectedFinding(null)}
                className="text-slate-400 hover:text-white p-1 rounded hover:bg-cyber-750"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="mt-4 space-y-4 max-h-[500px] overflow-y-auto">
              <div className="grid grid-cols-3 gap-2">
                <div>
                  <span className="text-slate-500">Severity: </span>
                  {getSeverityBadge(selectedFinding.severity)}
                </div>
                <div>
                  <span className="text-slate-500">Confidence: </span>
                  <span className="text-slate-200 font-bold">{selectedFinding.confidence}</span>
                </div>
                <div>
                  <span className="text-slate-500">Vuln ID: </span>
                  <span className="text-accent-cyan">{selectedFinding.vuln_id || 'N/A'}</span>
                </div>
              </div>

              {selectedFinding.reproduction_steps && (
                <div>
                  <div className="text-slate-500 font-semibold mb-1">Reproduction Method:</div>
                  <div className="p-2.5 bg-cyber-900 border border-cyber-800 rounded text-slate-300 font-sans text-xs">
                    {selectedFinding.reproduction_steps}
                  </div>
                </div>
              )}

              <div>
                <div className="text-slate-500 font-semibold mb-2">Cryptographic Evidence Artifacts:</div>
                {selectedFinding.evidence_items && selectedFinding.evidence_items.length > 0 ? (
                  <div className="space-y-3">
                    {selectedFinding.evidence_items.map((ev, idx) => (
                      <div key={ev.id || idx} className="p-3 bg-cyber-900 border border-cyber-800 rounded-lg space-y-2">
                        <div className="flex items-center justify-between text-[11px]">
                          <span className="text-accent-cyan font-bold">{ev.evidence_type}</span>
                          <span className="text-slate-500">Observed: {new Date(ev.observed_at).toISOString()}</span>
                        </div>
                        <div>
                          <div className="text-[10px] text-slate-500">SHA-256 Digest:</div>
                          <div className="text-[10px] text-emerald-400 break-all">{ev.sha256_hash}</div>
                        </div>
                        <div>
                          <div className="text-[10px] text-slate-500 mb-1">Raw Evidence Transcript:</div>
                          <pre className="p-2.5 bg-cyber-950 border border-cyber-800/80 rounded text-[11px] text-slate-300 overflow-x-auto whitespace-pre-wrap">
                            {ev.payload}
                          </pre>
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="p-3 bg-cyber-900 border border-cyber-800 rounded text-slate-500">
                    No raw evidence payloads attached to this finding.
                  </div>
                )}
              </div>
            </div>

            <div className="mt-5 flex justify-end">
              <button
                onClick={() => setSelectedFinding(null)}
                className="px-3.5 py-1.5 rounded bg-cyber-750 hover:bg-cyber-700 text-white text-xs font-semibold"
              >
                Close Provenance Inspector
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
