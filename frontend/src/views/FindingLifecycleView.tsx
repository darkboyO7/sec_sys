import React, { useState, useEffect } from 'react';
import {
  ShieldAlert,
  Search,
  Filter,
  RefreshCw,
  AlertTriangle,
  CheckCircle2,
  Clock,
  ArrowRight,
  Eye,
  FileCheck,
  XCircle,
  HelpCircle,
  Activity,
  History,
  Info,
} from 'lucide-react';
import { api } from '../services/api';
import type {
  Project,
  VulnerabilityFinding,
  VulnerabilityFindingDetail,
  FindingStatsResponse,
  FindingLifecycleStatus,
  FindingSeverity,
} from '../types';

interface FindingLifecycleViewProps {
  currentProject: Project | null;
}

const STATUS_CONFIG: Record<
  FindingLifecycleStatus,
  { label: string; bg: string; text: string; border: string }
> = {
  DETECTED: { label: 'Detected', bg: 'bg-blue-500/10', text: 'text-blue-400', border: 'border-blue-500/30' },
  NEEDS_VALIDATION: { label: 'Needs Validation', bg: 'bg-amber-500/10', text: 'text-amber-400', border: 'border-amber-500/30' },
  CONFIRMED: { label: 'Confirmed', bg: 'bg-emerald-500/10', text: 'text-emerald-400', border: 'border-emerald-500/30' },
  FALSE_POSITIVE: { label: 'False Positive', bg: 'bg-zinc-500/10', text: 'text-zinc-400', border: 'border-zinc-500/30' },
  INCONCLUSIVE: { label: 'Inconclusive', bg: 'bg-purple-500/10', text: 'text-purple-400', border: 'border-purple-500/30' },
  REMEDIATION_PROPOSED: { label: 'Remediation Proposed', bg: 'bg-indigo-500/10', text: 'text-indigo-400', border: 'border-indigo-500/30' },
  REMEDIATION_APPROVED: { label: 'Remediation Approved', bg: 'bg-cyan-500/10', text: 'text-cyan-400', border: 'border-cyan-500/30' },
  REMEDIATION_ATTEMPTED: { label: 'Remediation Attempted', bg: 'bg-teal-500/10', text: 'text-teal-400', border: 'border-teal-500/30' },
  REMEDIATED_PENDING_VERIFICATION: { label: 'Pending Verification', bg: 'bg-yellow-500/10', text: 'text-yellow-400', border: 'border-yellow-500/30' },
  VERIFIED_CLOSED: { label: 'Verified Closed', bg: 'bg-emerald-500/20', text: 'text-emerald-300', border: 'border-emerald-500/40' },
  REOPENED: { label: 'Reopened', bg: 'bg-rose-500/20', text: 'text-rose-400', border: 'border-rose-500/40' },
  ACCEPTED_RISK: { label: 'Accepted Risk', bg: 'bg-violet-500/10', text: 'text-violet-400', border: 'border-violet-500/30' },
  EXPIRED: { label: 'Expired Acceptance', bg: 'bg-red-500/10', text: 'text-red-400', border: 'border-red-500/30' },
};

const SEVERITY_CONFIG: Record<
  FindingSeverity,
  { label: string; bg: string; text: string; border: string }
> = {
  CRITICAL: { label: 'Critical', bg: 'bg-red-500/10', text: 'text-red-400', border: 'border-red-500/30' },
  HIGH: { label: 'High', bg: 'bg-orange-500/10', text: 'text-orange-400', border: 'border-orange-500/30' },
  MEDIUM: { label: 'Medium', bg: 'bg-yellow-500/10', text: 'text-yellow-400', border: 'border-yellow-500/30' },
  LOW: { label: 'Low', bg: 'bg-blue-500/10', text: 'text-blue-400', border: 'border-blue-500/30' },
  INFO: { label: 'Info', bg: 'bg-zinc-500/10', text: 'text-zinc-400', border: 'border-zinc-500/30' },
};

export const FindingLifecycleView: React.FC<FindingLifecycleViewProps> = ({ currentProject }) => {
  const [findings, setFindings] = useState<VulnerabilityFinding[]>([]);
  const [stats, setStats] = useState<FindingStatsResponse | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [actionLoading, setActionLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  // Filters
  const [search, setSearch] = useState<string>('');
  const [statusFilter, setStatusFilter] = useState<string>('ALL');
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [onlyContradictions, setOnlyContradictions] = useState<boolean>(false);

  // Detail & Transition Modals
  const [selectedFindingId, setSelectedFindingId] = useState<string | null>(null);
  const [findingDetail, setFindingDetail] = useState<VulnerabilityFindingDetail | null>(null);
  const [isDetailLoading, setIsDetailLoading] = useState<boolean>(false);

  // Transition form state
  const [targetStatus, setTargetStatus] = useState<FindingLifecycleStatus | ''>('');
  const [transitionReason, setTransitionReason] = useState<string>('');
  const [expiresAt, setExpiresAt] = useState<string>('');
  const [compensatingControls, setCompensatingControls] = useState<string>('');
  const [verificationNotes, setVerificationNotes] = useState<string>('');
  const [remediationNotes, setRemediationNotes] = useState<string>('');

  const loadFindingsAndStats = async () => {
    if (!currentProject) return;
    try {
      setLoading(true);
      setError(null);

      const [statsData, findingsData] = await Promise.all([
        api.getFindingStats(currentProject.id),
        api.listFindings(currentProject.id, {
          status: statusFilter !== 'ALL' ? (statusFilter as FindingLifecycleStatus) : undefined,
          severity: severityFilter !== 'ALL' ? (severityFilter as FindingSeverity) : undefined,
          has_contradictions: onlyContradictions ? true : undefined,
          search: search.trim() || undefined,
        }),
      ]);

      setStats(statsData);
      setFindings(findingsData);
    } catch (err: any) {
      setError(err.message || 'Failed to load vulnerability findings');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadFindingsAndStats();
  }, [currentProject, statusFilter, severityFilter, onlyContradictions]);

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    loadFindingsAndStats();
  };

  const handleOpenDetail = async (findingId: string) => {
    if (!currentProject) return;
    try {
      setSelectedFindingId(findingId);
      setIsDetailLoading(true);
      const detail = await api.getFindingDetail(currentProject.id, findingId);
      setFindingDetail(detail);
      // Reset transition inputs
      setTargetStatus('');
      setTransitionReason('');
      setExpiresAt('');
      setCompensatingControls('');
      setVerificationNotes('');
      setRemediationNotes('');
    } catch (err: any) {
      alert(`Error loading finding detail: ${err.message}`);
    } finally {
      setIsDetailLoading(false);
    }
  };

  const handleCloseDetail = () => {
    setSelectedFindingId(null);
    setFindingDetail(null);
  };

  const handleExecuteTransition = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!currentProject || !findingDetail || !targetStatus) return;

    try {
      setActionLoading(true);
      const updated = await api.transitionFinding(currentProject.id, findingDetail.id, {
        to_status: targetStatus as FindingLifecycleStatus,
        reason: transitionReason,
        expires_at: expiresAt ? new Date(expiresAt).toISOString() : undefined,
        compensating_controls: compensatingControls || undefined,
        verification_notes: verificationNotes || undefined,
        remediation_notes: remediationNotes || undefined,
      });

      setFindingDetail(updated);
      await loadFindingsAndStats();
      alert(`Finding successfully transitioned to ${targetStatus}!`);
      // Reset form
      setTargetStatus('');
      setTransitionReason('');
    } catch (err: any) {
      alert(`Transition failed: ${err.message}`);
    } finally {
      setActionLoading(false);
    }
  };

  const handleSweepExpiredRisks = async () => {
    if (!currentProject) return;
    try {
      setActionLoading(true);
      const res = await api.sweepExpiredRisks(currentProject.id);
      alert(
        res.expired_count > 0
          ? `Swept and transitioned ${res.expired_count} overdue accepted risk(s) to EXPIRED.`
          : 'No overdue accepted risks found. All accepted risks are within their authorized grace period.'
      );
      await loadFindingsAndStats();
    } catch (err: any) {
      alert(`Failed to sweep expired risks: ${err.message}`);
    } finally {
      setActionLoading(false);
    }
  };

  if (!currentProject) {
    return (
      <div className="flex flex-col items-center justify-center p-12 text-center text-zinc-400">
        <ShieldAlert className="w-12 h-12 text-zinc-600 mb-4" />
        <h3 className="text-lg font-medium text-zinc-200">No Active Project Selected</h3>
        <p className="mt-1 text-sm">Select or create a project to inspect and manage vulnerability lifecycles.</p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* View Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-zinc-800 pb-5">
        <div>
          <div className="flex items-center space-x-2">
            <h1 className="text-2xl font-bold text-zinc-100">Finding Lifecycle & Deduplication</h1>
            <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
              Phase 3 Verified
            </span>
          </div>
          <p className="text-sm text-zinc-400 mt-1">
            Deterministic 13-state vulnerability governance, correlation engine, and non-destructive contradiction tracking.
          </p>
        </div>

        <div className="flex items-center space-x-3">
          <button
            onClick={handleSweepExpiredRisks}
            disabled={actionLoading}
            className="flex items-center space-x-2 px-3 py-1.5 text-xs font-medium rounded-lg bg-zinc-800 hover:bg-zinc-700 text-zinc-300 border border-zinc-700 transition"
            title="Automatically transition overdue accepted risks to EXPIRED"
          >
            <Clock className="w-3.5 h-3.5 text-violet-400" />
            <span>Sweep Expired Risks</span>
          </button>

          <button
            onClick={loadFindingsAndStats}
            disabled={loading}
            className="flex items-center space-x-2 px-3.5 py-1.5 text-xs font-medium rounded-lg bg-emerald-600/20 text-emerald-300 border border-emerald-500/30 hover:bg-emerald-600/30 transition"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {/* KPI Stats Banner */}
      {stats && (
        <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
          <div className="p-4 rounded-xl bg-zinc-900 border border-zinc-800">
            <div className="flex items-center justify-between text-zinc-400 text-xs">
              <span>Tracked Vulnerabilities</span>
              <Activity className="w-4 h-4 text-cyan-400" />
            </div>
            <div className="text-2xl font-bold text-zinc-100 mt-2">{stats.total}</div>
            <div className="text-xs text-zinc-500 mt-1">Deduplicated canonical items</div>
          </div>

          <div className="p-4 rounded-xl bg-zinc-900 border border-zinc-800">
            <div className="flex items-center justify-between text-zinc-400 text-xs">
              <span>Unresolved Attention</span>
              <ShieldAlert className="w-4 h-4 text-amber-400" />
            </div>
            <div className="text-2xl font-bold text-amber-400 mt-2">{stats.unresolved_count}</div>
            <div className="text-xs text-zinc-500 mt-1">Detected, Triaged, or In Work</div>
          </div>

          <div className="p-4 rounded-xl bg-zinc-900 border border-zinc-800">
            <div className="flex items-center justify-between text-zinc-400 text-xs">
              <span>Accepted Risk</span>
              <FileCheck className="w-4 h-4 text-violet-400" />
            </div>
            <div className="text-2xl font-bold text-violet-400 mt-2">{stats.accepted_risk_count}</div>
            <div className="text-xs text-zinc-500 mt-1">With authorized compensating controls</div>
          </div>

          <div className="p-4 rounded-xl bg-zinc-900 border border-zinc-800">
            <div className="flex items-center justify-between text-zinc-400 text-xs">
              <span>Contradiction Warnings</span>
              <AlertTriangle className="w-4 h-4 text-orange-400" />
            </div>
            <div className="text-2xl font-bold text-orange-400 mt-2">{stats.contradiction_count}</div>
            <div className="text-xs text-zinc-500 mt-1">Divergent scanner observations</div>
          </div>

          <div className="p-4 rounded-xl bg-zinc-900 border border-zinc-800">
            <div className="flex items-center justify-between text-zinc-400 text-xs">
              <span>Reopened Findings</span>
              <RefreshCw className="w-4 h-4 text-rose-400" />
            </div>
            <div className="text-2xl font-bold text-rose-400 mt-2">{stats.reopened_count}</div>
            <div className="text-xs text-zinc-500 mt-1">Observed after closure</div>
          </div>
        </div>
      )}

      {/* Filter and Search Bar */}
      <div className="p-4 rounded-xl bg-zinc-900 border border-zinc-800 flex flex-col md:flex-row items-center justify-between gap-4">
        <form onSubmit={handleSearchSubmit} className="flex-1 w-full flex items-center gap-2">
          <div className="relative flex-1">
            <Search className="w-4 h-4 absolute left-3 top-2.5 text-zinc-400" />
            <input
              type="text"
              placeholder="Search by title, vulnerability ID (CVE/CWE), or target..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full pl-9 pr-3 py-1.5 text-sm bg-zinc-950 border border-zinc-800 rounded-lg text-zinc-200 placeholder-zinc-500 focus:outline-none focus:border-cyan-500"
            />
          </div>
          <button
            type="submit"
            className="px-3.5 py-1.5 text-xs font-medium rounded-lg bg-zinc-800 hover:bg-zinc-700 text-zinc-200 border border-zinc-700"
          >
            Search
          </button>
        </form>

        <div className="flex flex-wrap items-center gap-3 w-full md:w-auto">
          {/* Status Filter */}
          <div className="flex items-center space-x-1.5">
            <Filter className="w-3.5 h-3.5 text-zinc-400" />
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="text-xs bg-zinc-950 border border-zinc-800 rounded-lg px-2.5 py-1.5 text-zinc-300 focus:outline-none focus:border-cyan-500"
            >
              <option value="ALL">All Statuses (13)</option>
              {Object.keys(STATUS_CONFIG).map((s) => (
                <option key={s} value={s}>
                  {STATUS_CONFIG[s as FindingLifecycleStatus].label}
                </option>
              ))}
            </select>
          </div>

          {/* Severity Filter */}
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="text-xs bg-zinc-950 border border-zinc-800 rounded-lg px-2.5 py-1.5 text-zinc-300 focus:outline-none focus:border-cyan-500"
          >
            <option value="ALL">All Severities</option>
            {Object.keys(SEVERITY_CONFIG).map((sev) => (
              <option key={sev} value={sev}>
                {SEVERITY_CONFIG[sev as FindingSeverity].label}
              </option>
            ))}
          </select>

          {/* Contradiction Toggle */}
          <label className="flex items-center space-x-2 text-xs text-zinc-300 cursor-pointer select-none">
            <input
              type="checkbox"
              checked={onlyContradictions}
              onChange={(e) => setOnlyContradictions(e.target.checked)}
              className="rounded bg-zinc-950 border-zinc-700 text-cyan-600 focus:ring-0"
            />
            <span className="flex items-center space-x-1">
              <AlertTriangle className="w-3.5 h-3.5 text-orange-400" />
              <span>Contradictions only</span>
            </span>
          </label>
        </div>
      </div>

      {/* Findings Table */}
      {error && (
        <div className="p-4 rounded-xl bg-red-500/10 border border-red-500/20 text-sm text-red-400 flex items-center space-x-2">
          <XCircle className="w-4 h-4 flex-shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {loading ? (
        <div className="p-12 text-center text-zinc-500 text-sm">
          <RefreshCw className="w-6 h-6 animate-spin mx-auto mb-2 text-zinc-400" />
          Loading correlated vulnerability findings...
        </div>
      ) : findings.length === 0 ? (
        <div className="p-12 text-center rounded-xl bg-zinc-900 border border-zinc-800 text-zinc-400">
          <HelpCircle className="w-10 h-10 mx-auto text-zinc-600 mb-2" />
          <p className="font-medium text-zinc-300">No findings match the current criteria</p>
          <p className="text-xs text-zinc-500 mt-1">
            Run an authorized assessment in the Assessment Console to discover vulnerabilities and populate the lifecycle engine.
          </p>
        </div>
      ) : (
        <div className="rounded-xl bg-zinc-900 border border-zinc-800 overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead className="bg-zinc-950/60 border-b border-zinc-800 text-xs text-zinc-400 uppercase tracking-wider">
                <tr>
                  <th className="py-3 px-4">Severity</th>
                  <th className="py-3 px-4">Vulnerability & Identifier</th>
                  <th className="py-3 px-4">Target Asset</th>
                  <th className="py-3 px-4">Lifecycle State</th>
                  <th className="py-3 px-4">Observations</th>
                  <th className="py-3 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-zinc-800/60">
                {findings.map((f) => {
                  const statusMeta = STATUS_CONFIG[f.status] || {
                    label: f.status,
                    bg: 'bg-zinc-500/10',
                    text: 'text-zinc-400',
                    border: 'border-zinc-500/30',
                  };
                  const sevMeta = SEVERITY_CONFIG[f.severity] || {
                    label: f.severity,
                    bg: 'bg-zinc-500/10',
                    text: 'text-zinc-400',
                    border: 'border-zinc-500/30',
                  };

                  return (
                    <tr key={f.id} className="hover:bg-zinc-800/30 transition">
                      {/* Severity */}
                      <td className="py-3.5 px-4 whitespace-nowrap">
                        <span
                          className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold border ${sevMeta.bg} ${sevMeta.text} ${sevMeta.border}`}
                        >
                          {sevMeta.label}
                          {f.cvss_score && <span className="ml-1 opacity-70">({f.cvss_score.toFixed(1)})</span>}
                        </span>
                      </td>

                      {/* Title & Identifiers */}
                      <td className="py-3.5 px-4">
                        <div className="font-medium text-zinc-200 flex items-center gap-2">
                          <span>{f.title}</span>
                          {f.has_contradictions && (
                            <span
                              className="px-1.5 py-0.5 text-[10px] font-semibold bg-orange-500/10 text-orange-400 border border-orange-500/30 rounded inline-flex items-center gap-1"
                              title="Contradictory evidence or confidence divergence observed across scans"
                            >
                              <AlertTriangle className="w-2.5 h-2.5" />
                              Contradiction
                            </span>
                          )}
                          {f.is_simulated && (
                            <span className="px-1.5 py-0.5 text-[10px] font-semibold bg-zinc-800 text-zinc-400 rounded">
                              Simulated
                            </span>
                          )}
                        </div>
                        {f.vuln_id && (
                          <div className="text-xs text-cyan-400 font-mono mt-0.5">{f.vuln_id}</div>
                        )}
                      </td>

                      {/* Target */}
                      <td className="py-3.5 px-4 whitespace-nowrap font-mono text-xs text-zinc-300">
                        {f.target_value}
                      </td>

                      {/* Status */}
                      <td className="py-3.5 px-4 whitespace-nowrap">
                        <span
                          className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold border ${statusMeta.bg} ${statusMeta.text} ${statusMeta.border}`}
                        >
                          {statusMeta.label}
                        </span>
                      </td>

                      {/* Observations Counter */}
                      <td className="py-3.5 px-4 whitespace-nowrap text-xs text-zinc-400">
                        <span className="font-semibold text-zinc-200">{f.occurrence_count}x</span>
                        <div className="text-[11px] text-zinc-500">
                          Last: {new Date(f.last_observed_at).toLocaleDateString()}
                        </div>
                      </td>

                      {/* Actions */}
                      <td className="py-3.5 px-4 whitespace-nowrap text-right">
                        <button
                          onClick={() => handleOpenDetail(f.id)}
                          className="inline-flex items-center space-x-1 px-3 py-1 text-xs font-medium rounded-lg bg-zinc-800 hover:bg-zinc-700 text-zinc-200 border border-zinc-700 transition"
                        >
                          <Eye className="w-3.5 h-3.5 text-cyan-400" />
                          <span>Inspect / Transition</span>
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Finding Detail & State Machine Transition Drawer / Modal */}
      {selectedFindingId && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm overflow-y-auto">
          <div className="relative w-full max-w-4xl max-h-[90vh] overflow-y-auto rounded-2xl bg-zinc-900 border border-zinc-800 p-6 shadow-2xl text-zinc-200 space-y-6">
            {/* Modal Header */}
            <div className="flex items-start justify-between border-b border-zinc-800 pb-4">
              <div>
                <div className="flex items-center space-x-2">
                  <h2 className="text-xl font-bold text-zinc-100">
                    {findingDetail ? findingDetail.title : 'Loading finding details...'}
                  </h2>
                </div>
                {findingDetail && (
                  <div className="flex items-center gap-2 mt-1 text-xs text-zinc-400 font-mono">
                    <span>Target: {findingDetail.target_value}</span>
                    <span>•</span>
                    <span>Vuln ID: {findingDetail.vuln_id || 'N/A'}</span>
                    <span>•</span>
                    <span>Fingerprint: {findingDetail.fingerprint.substring(0, 12)}...</span>
                  </div>
                )}
              </div>
              <button
                onClick={handleCloseDetail}
                className="text-zinc-400 hover:text-zinc-100 text-sm font-semibold px-2 py-1 rounded-lg bg-zinc-800 hover:bg-zinc-700"
              >
                ✕ Close
              </button>
            </div>

            {isDetailLoading || !findingDetail ? (
              <div className="p-8 text-center text-zinc-500">
                <RefreshCw className="w-6 h-6 animate-spin mx-auto mb-2 text-zinc-400" />
                Retrieving finding provenance & transition history...
              </div>
            ) : (
              <div className="space-y-6">
                {/* Status Badges & Quick Stats */}
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 p-4 rounded-xl bg-zinc-950/60 border border-zinc-800/80">
                  <div>
                    <span className="text-[11px] text-zinc-500 uppercase tracking-wider block">Current Status</span>
                    <span
                      className={`inline-block mt-1 px-2.5 py-0.5 rounded-full text-xs font-semibold border ${
                        STATUS_CONFIG[findingDetail.status]?.bg
                      } ${STATUS_CONFIG[findingDetail.status]?.text} ${
                        STATUS_CONFIG[findingDetail.status]?.border
                      }`}
                    >
                      {STATUS_CONFIG[findingDetail.status]?.label}
                    </span>
                  </div>

                  <div>
                    <span className="text-[11px] text-zinc-500 uppercase tracking-wider block">Severity</span>
                    <span
                      className={`inline-block mt-1 px-2.5 py-0.5 rounded-full text-xs font-semibold border ${
                        SEVERITY_CONFIG[findingDetail.severity]?.bg
                      } ${SEVERITY_CONFIG[findingDetail.severity]?.text} ${
                        SEVERITY_CONFIG[findingDetail.severity]?.border
                      }`}
                    >
                      {SEVERITY_CONFIG[findingDetail.severity]?.label}
                    </span>
                  </div>

                  <div>
                    <span className="text-[11px] text-zinc-500 uppercase tracking-wider block">Confidence</span>
                    <span className="text-sm font-medium text-zinc-200 mt-1 block">
                      {findingDetail.confidence}
                    </span>
                  </div>

                  <div>
                    <span className="text-[11px] text-zinc-500 uppercase tracking-wider block">Total Observations</span>
                    <span className="text-sm font-medium text-cyan-400 mt-1 block">
                      {findingDetail.occurrence_count} scan(s)
                    </span>
                  </div>
                </div>

                {/* Contradictory Evidence Banner (if present) */}
                {findingDetail.has_contradictions && (
                  <div className="p-4 rounded-xl bg-orange-500/10 border border-orange-500/30 text-xs text-orange-300 space-y-2">
                    <div className="flex items-center space-x-2 font-semibold text-orange-200 text-sm">
                      <AlertTriangle className="w-4 h-4 text-orange-400" />
                      <span>Contradictory or Divergent Evidence Recorded</span>
                    </div>
                    <p>
                      Subsequent assessment jobs reported contradictory severity or confidence observations. In accordance
                      with Phase 3 requirements, all contradictory signals are preserved without silent overwrite:
                    </p>
                    <ul className="list-disc pl-5 space-y-1">
                      {findingDetail.contradiction_notes.map((c, i) => (
                        <li key={i}>
                          Job <span className="font-mono text-zinc-200">{c.job_id}</span> observed{' '}
                          <span className="font-semibold text-zinc-200">
                            {c.observed_severity} / {c.observed_confidence}
                          </span>{' '}
                          at {new Date(c.observed_at).toLocaleDateString()}: {c.note}
                        </li>
                      ))}
                    </ul>
                  </div>
                )}

                {/* Accepted Risk Metadata (if applicable) */}
                {findingDetail.status === 'ACCEPTED_RISK' && (
                  <div className="p-4 rounded-xl bg-violet-500/10 border border-violet-500/30 text-xs text-violet-300 space-y-2">
                    <div className="flex items-center space-x-2 font-semibold text-violet-200 text-sm">
                      <FileCheck className="w-4 h-4 text-violet-400" />
                      <span>Authorized Risk Acceptance Record</span>
                    </div>
                    <div className="grid grid-cols-2 gap-2 text-zinc-300">
                      <div>
                        <span className="text-zinc-500">Authorized Expiration:</span>{' '}
                        {findingDetail.risk_accepted_expires_at
                          ? new Date(findingDetail.risk_accepted_expires_at).toLocaleDateString()
                          : 'None'}
                      </div>
                      <div>
                        <span className="text-zinc-500">Approver ID:</span>{' '}
                        {findingDetail.risk_accepted_by_id || 'System Admin'}
                      </div>
                    </div>
                    <div>
                      <span className="text-zinc-500">Business Justification:</span>{' '}
                      <span className="text-zinc-200">{findingDetail.risk_accepted_reason}</span>
                    </div>
                    <div>
                      <span className="text-zinc-500">Compensating Controls:</span>{' '}
                      <span className="text-zinc-200">{findingDetail.compensating_controls}</span>
                    </div>
                  </div>
                )}

                {/* False Positive Metadata (if applicable) */}
                {findingDetail.status === 'FALSE_POSITIVE' && (
                  <div className="p-4 rounded-xl bg-zinc-800/80 border border-zinc-700 text-xs text-zinc-300 space-y-1">
                    <div className="font-semibold text-zinc-200 flex items-center space-x-1.5">
                      <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                      <span>False Positive Review Sign-off</span>
                    </div>
                    <div>
                      <span className="text-zinc-500">Reviewer Justification:</span>{' '}
                      <span className="text-zinc-200">{findingDetail.false_positive_reason}</span>
                    </div>
                  </div>
                )}

                {/* Description & Reproduction Steps */}
                <div className="space-y-3">
                  <div>
                    <h4 className="text-xs font-semibold uppercase tracking-wider text-zinc-400">Description</h4>
                    <p className="text-sm text-zinc-300 mt-1 whitespace-pre-wrap bg-zinc-950 p-3 rounded-lg border border-zinc-800">
                      {findingDetail.description || 'No description provided.'}
                    </p>
                  </div>

                  {findingDetail.reproduction_steps && (
                    <div>
                      <h4 className="text-xs font-semibold uppercase tracking-wider text-zinc-400">
                        Reproduction & Verification Steps
                      </h4>
                      <p className="text-xs font-mono text-zinc-300 mt-1 whitespace-pre-wrap bg-zinc-950 p-3 rounded-lg border border-zinc-800">
                        {findingDetail.reproduction_steps}
                      </p>
                    </div>
                  )}
                </div>

                {/* State Machine Transition Form */}
                <div className="p-4 rounded-xl bg-zinc-950 border border-zinc-800 space-y-4">
                  <div className="flex items-center space-x-2">
                    <ArrowRight className="w-4 h-4 text-cyan-400" />
                    <h3 className="text-sm font-semibold text-zinc-100">Advance Finding Lifecycle State</h3>
                  </div>

                  <form onSubmit={handleExecuteTransition} className="space-y-4 text-xs">
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                      <div>
                        <label className="block text-zinc-400 mb-1 font-medium">Target Status</label>
                        <select
                          value={targetStatus}
                          onChange={(e) => setTargetStatus(e.target.value as FindingLifecycleStatus)}
                          required
                          className="w-full bg-zinc-900 border border-zinc-800 rounded-lg px-3 py-2 text-zinc-200 focus:outline-none focus:border-cyan-500 text-xs"
                        >
                          <option value="">Select Next Legal State...</option>
                          {Object.keys(STATUS_CONFIG)
                            .filter((s) => s !== findingDetail.status)
                            .map((s) => (
                              <option key={s} value={s}>
                                {STATUS_CONFIG[s as FindingLifecycleStatus].label}
                              </option>
                            ))}
                        </select>
                      </div>

                      <div>
                        <label className="block text-zinc-400 mb-1 font-medium">
                          Transition Rationale / Reason (min 5 chars)
                        </label>
                        <input
                          type="text"
                          required
                          placeholder="e.g., Confirmed exploitability in lab; or approved PR #42"
                          value={transitionReason}
                          onChange={(e) => setTransitionReason(e.target.value)}
                          className="w-full bg-zinc-900 border border-zinc-800 rounded-lg px-3 py-2 text-zinc-200 focus:outline-none focus:border-cyan-500 text-xs"
                        />
                      </div>
                    </div>

                    {/* Specific fields for ACCEPTED_RISK */}
                    {targetStatus === 'ACCEPTED_RISK' && (
                      <div className="p-3 rounded-lg bg-violet-500/10 border border-violet-500/20 space-y-3">
                        <div className="flex items-center space-x-1.5 text-violet-300 font-semibold">
                          <Info className="w-3.5 h-3.5" />
                          <span>Required for Risk Acceptance: Expiration & Compensating Controls</span>
                        </div>
                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                          <div>
                            <label className="block text-zinc-400 mb-1">
                              Mandatory Expiration Date (must be in future)
                            </label>
                            <input
                              type="date"
                              required
                              value={expiresAt}
                              onChange={(e) => setExpiresAt(e.target.value)}
                              className="w-full bg-zinc-900 border border-zinc-800 rounded-lg px-3 py-1.5 text-zinc-200 text-xs"
                            />
                          </div>
                          <div>
                            <label className="block text-zinc-400 mb-1">Compensating Controls</label>
                            <input
                              type="text"
                              required
                              placeholder="e.g., WAF rule #9021, VPN boundary"
                              value={compensatingControls}
                              onChange={(e) => setCompensatingControls(e.target.value)}
                              className="w-full bg-zinc-900 border border-zinc-800 rounded-lg px-3 py-1.5 text-zinc-200 text-xs"
                            />
                          </div>
                        </div>
                      </div>
                    )}

                    {/* Specific fields for VERIFIED_CLOSED */}
                    {targetStatus === 'VERIFIED_CLOSED' && (
                      <div className="p-3 rounded-lg bg-emerald-500/10 border border-emerald-500/20 space-y-2">
                        <label className="block text-emerald-300 font-medium">
                          Verification Evidence / Verification Notes (min 10 chars)
                        </label>
                        <textarea
                          required
                          rows={2}
                          placeholder="Document the re-assessment scan results or verification evidence proving remediation..."
                          value={verificationNotes}
                          onChange={(e) => setVerificationNotes(e.target.value)}
                          className="w-full bg-zinc-900 border border-zinc-800 rounded-lg px-3 py-1.5 text-zinc-200 text-xs"
                        />
                      </div>
                    )}

                    {/* Specific fields for REMEDIATION_PROPOSED */}
                    {targetStatus === 'REMEDIATION_PROPOSED' && (
                      <div className="p-3 rounded-lg bg-indigo-500/10 border border-indigo-500/20 space-y-2">
                        <label className="block text-indigo-300 font-medium">Proposed Remediation Plan</label>
                        <textarea
                          required
                          rows={2}
                          placeholder="Outline the patch or mitigation steps to be taken..."
                          value={remediationNotes}
                          onChange={(e) => setRemediationNotes(e.target.value)}
                          className="w-full bg-zinc-900 border border-zinc-800 rounded-lg px-3 py-1.5 text-zinc-200 text-xs"
                        />
                      </div>
                    )}

                    <button
                      type="submit"
                      disabled={actionLoading || !targetStatus}
                      className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-zinc-100 font-medium transition disabled:opacity-50"
                    >
                      {actionLoading ? 'Executing transition...' : 'Commit State Transition'}
                    </button>
                  </form>
                </div>

                {/* State Transition Provenance Timeline */}
                <div className="space-y-3">
                  <div className="flex items-center space-x-2">
                    <History className="w-4 h-4 text-zinc-400" />
                    <h3 className="text-sm font-semibold text-zinc-200">
                      State Transition Provenance & Audit History
                    </h3>
                  </div>

                  {findingDetail.transitions.length === 0 ? (
                    <p className="text-xs text-zinc-500">No prior transitions recorded.</p>
                  ) : (
                    <div className="space-y-2">
                      {findingDetail.transitions.map((t) => (
                        <div
                          key={t.id}
                          className="p-3 rounded-lg bg-zinc-950 border border-zinc-800/80 text-xs space-y-1"
                        >
                          <div className="flex items-center justify-between">
                            <div className="flex items-center space-x-2">
                              <span className="font-medium text-zinc-400">{t.from_status}</span>
                              <ArrowRight className="w-3 h-3 text-cyan-400" />
                              <span className="font-semibold text-cyan-300">{t.to_status}</span>
                            </div>
                            <span className="text-[11px] text-zinc-500">
                              {new Date(t.created_at).toLocaleString()}
                            </span>
                          </div>
                          <p className="text-zinc-300 pt-0.5">
                            <span className="text-zinc-500">Reason:</span> {t.reason}
                          </p>
                          {t.metadata_snapshot?.actor_email && (
                            <p className="text-[11px] text-zinc-500">
                              Actor: {t.metadata_snapshot.actor_email} ({t.metadata_snapshot.actor_role || 'ADMIN'})
                            </p>
                          )}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
