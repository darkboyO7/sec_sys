import React, { useState, useEffect } from 'react';
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  RefreshCw,
  AlertCircle,
  PlayCircle,
  XCircle,
  Search,
} from 'lucide-react';
import { api } from '../services/api';
import type {
  Project,
  ExposureDriftRecord,
  ReassessmentProposal,
  ProjectDriftOverview,
  Asset,
} from '../types';

interface AssetExposureDriftViewProps {
  currentProject: Project | null;
}

export const AssetExposureDriftView: React.FC<AssetExposureDriftViewProps> = ({ currentProject }) => {
  const [activeTab, setActiveTab] = useState<'timeline' | 'proposals' | 'freshness' | 'aliases'>('timeline');
  const [overview, setOverview] = useState<ProjectDriftOverview | null>(null);
  const [driftRecords, setDriftRecords] = useState<ExposureDriftRecord[]>([]);
  const [proposals, setProposals] = useState<ReassessmentProposal[]>([]);
  const [assets, setAssets] = useState<Asset[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // Filters
  const [materialityFilter, setMaterialityFilter] = useState<string>('ALL');
  const [proposalStatusFilter, setProposalStatusFilter] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');

  // Rejection modal state
  const [rejectingProposalId, setRejectingProposalId] = useState<string | null>(null);
  const [rejectionReason, setRejectionReason] = useState<string>('');
  const [actionLoading, setActionLoading] = useState<boolean>(false);
  const [actionSuccess, setActionSuccess] = useState<string | null>(null);

  const loadData = async () => {
    if (!currentProject) return;
    try {
      setLoading(true);
      setError(null);
      const [overviewData, driftsData, propsData, assetsData] = await Promise.all([
        api.getDriftOverview(currentProject.id),
        api.listDriftRecords(currentProject.id, {
          materiality: materialityFilter !== 'ALL' ? materialityFilter : undefined,
          limit: 100,
        }),
        api.listReassessmentProposals(
          currentProject.id,
          proposalStatusFilter !== 'ALL' ? proposalStatusFilter : undefined
        ),
        api.listAssets(currentProject.id, { limit: 100 }),
      ]);
      setOverview(overviewData);
      setDriftRecords(driftsData);
      setProposals(propsData);
      setAssets(assetsData);
    } catch (err: any) {
      setError(err.message || 'Failed to load exposure drift intelligence');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, [currentProject?.id, materialityFilter, proposalStatusFilter]);

  const handleApproveProposal = async (proposalId: string) => {
    if (!currentProject) return;
    try {
      setActionLoading(true);
      setActionSuccess(null);
      await api.approveReassessmentProposal(currentProject.id, proposalId);
      setActionSuccess('Reassessment job queued successfully with execution-boundary scope verification.');
      await loadData();
    } catch (err: any) {
      setError(err.message || 'Failed to approve proposal');
    } finally {
      setActionLoading(false);
    }
  };

  const handleRejectProposal = async () => {
    if (!currentProject || !rejectingProposalId || !rejectionReason.trim()) return;
    try {
      setActionLoading(true);
      setActionSuccess(null);
      await api.rejectReassessmentProposal(currentProject.id, rejectingProposalId, rejectionReason);
      setActionSuccess('Reassessment proposal rejected.');
      setRejectingProposalId(null);
      setRejectionReason('');
      await loadData();
    } catch (err: any) {
      setError(err.message || 'Failed to reject proposal');
    } finally {
      setActionLoading(false);
    }
  };

  const filteredDrifts = driftRecords.filter((d) =>
    searchQuery ? d.target_resource.toLowerCase().includes(searchQuery.toLowerCase()) || d.title.toLowerCase().includes(searchQuery.toLowerCase()) : true
  );

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold font-mono tracking-tight text-slate-100 flex items-center gap-2">
            <Activity className="h-5 w-5 text-cyan-400" />
            ASSET IDENTITY, EXPOSURE DRIFT & CONTINUOUS CHANGE INTELLIGENCE
          </h1>
          <p className="text-xs text-slate-400 font-mono mt-1">
            Prompt 20: Track asset identity, exposure drift, stale findings, and policy-constrained reassessments.
          </p>
        </div>
        <button
          onClick={loadData}
          disabled={loading}
          className="px-3 py-1.5 bg-cyber-800 hover:bg-cyber-700 text-slate-200 border border-cyber-700 rounded text-xs font-mono flex items-center gap-2 transition"
        >
          <RefreshCw className={`h-3.5 w-3.5 ${loading ? 'animate-spin' : ''}`} />
          Refresh Baseline
        </button>
      </div>

      {/* Notifications / Errors */}
      {error && (
        <div className="bg-red-500/10 border border-red-500/30 text-red-400 p-3 rounded text-xs font-mono flex items-center gap-2">
          <AlertTriangle className="h-4 w-4 shrink-0" />
          <span>{error}</span>
        </div>
      )}
      {actionSuccess && (
        <div className="bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 p-3 rounded text-xs font-mono flex items-center gap-2">
          <CheckCircle2 className="h-4 w-4 shrink-0" />
          <span>{actionSuccess}</span>
        </div>
      )}

      {/* Overview Metrics Cards */}
      {overview && (
        <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
          <div className="bg-cyber-900 border border-cyber-750 p-3 rounded">
            <div className="text-[10px] font-mono text-slate-400 uppercase">Fresh Assets</div>
            <div className="text-lg font-bold font-mono text-emerald-400 mt-1">
              {overview.freshness_distribution['FRESH'] || 0}
            </div>
            <div className="text-[10px] text-slate-500 font-mono mt-0.5">Observed &lt; 24h</div>
          </div>

          <div className="bg-cyber-900 border border-cyber-750 p-3 rounded">
            <div className="text-[10px] font-mono text-slate-400 uppercase">Stale / Expired</div>
            <div className="text-lg font-bold font-mono text-amber-400 mt-1">
              {(overview.freshness_distribution['STALE'] || 0) + (overview.freshness_distribution['EXPIRED'] || 0)}
            </div>
            <div className="text-[10px] text-slate-500 font-mono mt-0.5">Needs Re-probing</div>
          </div>

          <div className="bg-cyber-900 border border-cyber-750 p-3 rounded">
            <div className="text-[10px] font-mono text-slate-400 uppercase">Material Drifts</div>
            <div className="text-lg font-bold font-mono text-cyan-400 mt-1">
              {overview.drift_materiality_distribution['MATERIAL'] || 0}
            </div>
            <div className="text-[10px] text-slate-500 font-mono mt-0.5">Security relevant</div>
          </div>

          <div className="bg-cyber-900 border border-cyber-750 p-3 rounded">
            <div className="text-[10px] font-mono text-slate-400 uppercase">Pending Reassessments</div>
            <div className="text-lg font-bold font-mono text-purple-400 mt-1">
              {overview.reassessment_proposals_distribution['PROPOSED'] || 0}
            </div>
            <div className="text-[10px] text-slate-500 font-mono mt-0.5">Awaiting queue</div>
          </div>

          <div className="bg-cyber-900 border border-cyber-750 p-3 rounded">
            <div className="text-[10px] font-mono text-slate-400 uppercase">Avg Completeness</div>
            <div className="text-lg font-bold font-mono text-slate-200 mt-1">
              {(overview.average_collection_completeness * 100).toFixed(1)}%
            </div>
            <div className="text-[10px] text-slate-500 font-mono mt-0.5">Collection health</div>
          </div>
        </div>
      )}

      {/* Governance Warnings */}
      {overview && overview.governance_warnings.length > 0 && (
        <div className="bg-amber-500/10 border border-amber-500/30 rounded p-3 text-xs font-mono text-amber-300 space-y-1">
          <div className="flex items-center gap-2 font-bold text-amber-400">
            <AlertCircle className="h-4 w-4" />
            OPERATIONAL DATA GAP WARNINGS
          </div>
          {overview.governance_warnings.map((w, idx) => (
            <div key={idx} className="pl-6 text-[11px] text-amber-200/80">
              • {w}
            </div>
          ))}
        </div>
      )}

      {/* Tab Navigation */}
      <div className="flex border-b border-cyber-750 text-xs font-mono">
        <button
          onClick={() => setActiveTab('timeline')}
          className={`px-4 py-2 font-semibold border-b-2 transition ${
            activeTab === 'timeline'
              ? 'border-cyan-400 text-cyan-400 bg-cyber-800/40'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          Exposure Drift Timeline ({driftRecords.length})
        </button>
        <button
          onClick={() => setActiveTab('proposals')}
          className={`px-4 py-2 font-semibold border-b-2 transition ${
            activeTab === 'proposals'
              ? 'border-purple-400 text-purple-400 bg-cyber-800/40'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          Reassessment Proposals ({proposals.length})
        </button>
        <button
          onClick={() => setActiveTab('freshness')}
          className={`px-4 py-2 font-semibold border-b-2 transition ${
            activeTab === 'freshness'
              ? 'border-emerald-400 text-emerald-400 bg-cyber-800/40'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          Asset Freshness & Collection Gaps ({assets.length})
        </button>
      </div>

      {/* Tab Content: Exposure Drift Timeline */}
      {activeTab === 'timeline' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between gap-3">
            <div className="flex items-center gap-2">
              <span className="text-xs font-mono text-slate-400">Materiality:</span>
              {(['ALL', 'MATERIAL', 'IMMATERIAL', 'INCONCLUSIVE'] as const).map((m) => (
                <button
                  key={m}
                  onClick={() => setMaterialityFilter(m)}
                  className={`px-2.5 py-1 text-[11px] font-mono rounded border transition ${
                    materialityFilter === m
                      ? 'bg-cyan-500/20 text-cyan-400 border-cyan-500/40 font-bold'
                      : 'bg-cyber-900 text-slate-400 border-cyber-750 hover:bg-cyber-800'
                  }`}
                >
                  {m}
                </button>
              ))}
            </div>

            <div className="relative">
              <Search className="h-3.5 w-3.5 text-slate-500 absolute left-2.5 top-2.5" />
              <input
                type="text"
                placeholder="Search target or title..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="pl-8 pr-3 py-1 bg-cyber-900 border border-cyber-750 rounded text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500 w-64"
              />
            </div>
          </div>

          {filteredDrifts.length === 0 ? (
            <div className="bg-cyber-900 border border-cyber-750 rounded p-8 text-center text-xs font-mono text-slate-500">
              No exposure drift records matched the current filter.
            </div>
          ) : (
            <div className="space-y-3">
              {filteredDrifts.map((d) => (
                <div key={d.id} className="bg-cyber-900 border border-cyber-750 rounded p-4 space-y-2">
                  <div className="flex items-start justify-between">
                    <div className="space-y-1">
                      <div className="flex items-center gap-2">
                        <span
                          className={`px-2 py-0.5 text-[10px] font-mono rounded border font-bold ${
                            d.materiality === 'MATERIAL'
                              ? 'bg-red-500/10 text-red-400 border-red-500/30'
                              : d.materiality === 'INCONCLUSIVE'
                              ? 'bg-amber-500/10 text-amber-400 border-amber-500/30'
                              : 'bg-slate-500/10 text-slate-400 border-slate-500/30'
                          }`}
                        >
                          {d.materiality}
                        </span>
                        <span className="text-xs font-mono font-bold text-slate-200">{d.title}</span>
                      </div>
                      <div className="text-[11px] font-mono text-slate-400">
                        Target: <span className="text-cyan-400">{d.target_resource}</span> • Type: {d.drift_type}
                      </div>
                    </div>
                    <div className="text-right text-[10px] font-mono text-slate-500">
                      <div>{new Date(d.detected_at).toLocaleString()}</div>
                      {d.reassessment_recommended && (
                        <span className="text-purple-400 font-bold mt-1 inline-block">Reassessment Recommended</span>
                      )}
                    </div>
                  </div>

                  <p className="text-xs text-slate-300 font-mono">{d.materiality_reason}</p>
                  {d.security_impact_summary && (
                    <div className="text-[11px] font-mono text-slate-400 bg-cyber-850 p-2 rounded border border-cyber-750">
                      <span className="text-slate-300 font-bold">Security Impact:</span> {d.security_impact_summary}
                    </div>
                  )}

                  {/* Diff details */}
                  <div className="grid grid-cols-2 gap-2 text-[10px] font-mono bg-cyber-950 p-2 rounded">
                    <div>
                      <span className="text-slate-500 uppercase">Previous State:</span>
                      <pre className="text-slate-400 overflow-x-auto mt-0.5">
                        {JSON.stringify(d.previous_state, null, 2)}
                      </pre>
                    </div>
                    <div>
                      <span className="text-slate-500 uppercase">New State:</span>
                      <pre className="text-cyan-300 overflow-x-auto mt-0.5">
                        {JSON.stringify(d.new_state, null, 2)}
                      </pre>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Tab Content: Reassessment Proposals */}
      {activeTab === 'proposals' && (
        <div className="space-y-4">
          <div className="flex items-center gap-2">
            <span className="text-xs font-mono text-slate-400">Status Filter:</span>
            {(['ALL', 'PROPOSED', 'QUEUED', 'DEFERRED', 'REJECTED'] as const).map((s) => (
              <button
                key={s}
                onClick={() => setProposalStatusFilter(s)}
                className={`px-2.5 py-1 text-[11px] font-mono rounded border transition ${
                  proposalStatusFilter === s
                    ? 'bg-purple-500/20 text-purple-400 border-purple-500/40 font-bold'
                    : 'bg-cyber-900 text-slate-400 border-cyber-750 hover:bg-cyber-800'
                }`}
              >
                {s}
              </button>
            ))}
          </div>

          {proposals.length === 0 ? (
            <div className="bg-cyber-900 border border-cyber-750 rounded p-8 text-center text-xs font-mono text-slate-500">
              No reassessment proposals currently match filter.
            </div>
          ) : (
            <div className="bg-cyber-900 border border-cyber-750 rounded overflow-hidden">
              <table className="w-full text-left text-xs font-mono">
                <thead className="bg-cyber-850 text-slate-400 text-[10px] uppercase border-b border-cyber-750">
                  <tr>
                    <th className="p-3">Priority</th>
                    <th className="p-3">Target</th>
                    <th className="p-3">Status</th>
                    <th className="p-3">Rationale & Scope</th>
                    <th className="p-3 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-cyber-750 text-slate-300">
                  {proposals.map((p) => (
                    <tr key={p.id} className="hover:bg-cyber-800/40">
                      <td className="p-3">
                        <span
                          className={`px-2 py-0.5 text-[10px] rounded border font-bold ${
                            p.priority === 'CRITICAL'
                              ? 'bg-red-500/10 text-red-400 border-red-500/30'
                              : p.priority === 'HIGH'
                              ? 'bg-orange-500/10 text-orange-400 border-orange-500/30'
                              : 'bg-blue-500/10 text-blue-400 border-blue-500/30'
                          }`}
                        >
                          {p.priority}
                        </span>
                      </td>
                      <td className="p-3 font-semibold text-cyan-400">{p.target_input}</td>
                      <td className="p-3">
                        <span
                          className={`px-2 py-0.5 text-[10px] rounded border ${
                            p.status === 'QUEUED'
                              ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                              : p.status === 'REJECTED'
                              ? 'bg-red-500/10 text-red-400 border-red-500/30'
                              : p.status === 'DEFERRED'
                              ? 'bg-amber-500/10 text-amber-400 border-amber-500/30'
                              : 'bg-purple-500/10 text-purple-400 border-purple-500/30 font-bold'
                          }`}
                        >
                          {p.status}
                        </span>
                      </td>
                      <td className="p-3 max-w-md">
                        <div>{p.rationale}</div>
                        <div className="text-[10px] text-slate-500 mt-1">
                          Scope: {p.scope_authorized ? 'Authorized' : 'Unauthorized'} • Approval:{' '}
                          {p.requires_human_approval ? 'Required' : 'Standard'}
                        </div>
                      </td>
                      <td className="p-3 text-right space-x-2">
                        {p.status === 'PROPOSED' && (
                          <>
                            <button
                              onClick={() => handleApproveProposal(p.id)}
                              disabled={actionLoading}
                              className="px-2.5 py-1 bg-emerald-600/20 hover:bg-emerald-600/30 text-emerald-400 border border-emerald-500/40 rounded text-[11px] font-bold transition inline-flex items-center gap-1"
                            >
                              <PlayCircle className="h-3 w-3" /> Approve
                            </button>
                            <button
                              onClick={() => setRejectingProposalId(p.id)}
                              disabled={actionLoading}
                              className="px-2.5 py-1 bg-red-600/20 hover:bg-red-600/30 text-red-400 border border-red-500/40 rounded text-[11px] font-bold transition inline-flex items-center gap-1"
                            >
                              <XCircle className="h-3 w-3" /> Reject
                            </button>
                          </>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {/* Rejection Modal */}
          {rejectingProposalId && (
            <div className="fixed inset-0 bg-black/70 flex items-center justify-center p-4 z-50">
              <div className="bg-cyber-900 border border-cyber-700 rounded-lg p-5 max-w-md w-full space-y-4">
                <h3 className="text-sm font-bold font-mono text-slate-100 flex items-center gap-2">
                  <XCircle className="h-4 w-4 text-red-400" />
                  Reject Reassessment Proposal
                </h3>
                <p className="text-xs font-mono text-slate-400">
                  Provide a mandatory operational justification for rejecting this reassessment.
                </p>
                <textarea
                  rows={3}
                  value={rejectionReason}
                  onChange={(e) => setRejectionReason(e.target.value)}
                  placeholder="e.g. Known expected maintenance window; target undergoing approved migration."
                  className="w-full bg-cyber-950 border border-cyber-750 rounded p-2 text-xs font-mono text-slate-200 focus:outline-none focus:border-red-500"
                />
                <div className="flex justify-end gap-2 text-xs font-mono">
                  <button
                    onClick={() => {
                      setRejectingProposalId(null);
                      setRejectionReason('');
                    }}
                    className="px-3 py-1.5 bg-cyber-800 text-slate-400 rounded hover:bg-cyber-700"
                  >
                    Cancel
                  </button>
                  <button
                    onClick={handleRejectProposal}
                    disabled={actionLoading || rejectionReason.trim().length < 5}
                    className="px-3 py-1.5 bg-red-600 text-white font-bold rounded hover:bg-red-500 disabled:opacity-50"
                  >
                    Confirm Rejection
                  </button>
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Tab Content: Asset Freshness & Collection Gaps */}
      {activeTab === 'freshness' && (
        <div className="bg-cyber-900 border border-cyber-750 rounded overflow-hidden">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-cyber-850 text-slate-400 text-[10px] uppercase border-b border-cyber-750">
              <tr>
                <th className="p-3">Asset</th>
                <th className="p-3">Type</th>
                <th className="p-3">Freshness</th>
                <th className="p-3">Last Observation</th>
                <th className="p-3">Completeness</th>
                <th className="p-3">Absence Counter</th>
                <th className="p-3">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-cyber-750 text-slate-300">
              {assets.map((a) => (
                <tr key={a.id} className="hover:bg-cyber-800/40">
                  <td className="p-3 font-semibold text-cyan-400">{a.canonical_identifier}</td>
                  <td className="p-3 text-[11px] text-slate-400">{a.asset_type}</td>
                  <td className="p-3">
                    <span
                      className={`px-2 py-0.5 text-[10px] rounded border font-bold ${
                        a.freshness_status === 'FRESH'
                          ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                          : a.freshness_status === 'AGING'
                          ? 'bg-blue-500/10 text-blue-400 border-blue-500/30'
                          : a.freshness_status === 'STALE'
                          ? 'bg-amber-500/10 text-amber-400 border-amber-500/30'
                          : 'bg-red-500/10 text-red-400 border-red-500/30'
                      }`}
                    >
                      {a.freshness_status || 'UNOBSERVED'}
                    </span>
                  </td>
                  <td className="p-3 text-slate-400 text-[11px]">
                    {a.last_successful_observation_at
                      ? new Date(a.last_successful_observation_at).toLocaleString()
                      : 'Never'}
                  </td>
                  <td className="p-3">
                    <div className="flex items-center gap-1.5">
                      <div className="w-16 bg-cyber-800 rounded-full h-1.5 overflow-hidden">
                        <div
                          className="bg-cyan-400 h-1.5"
                          style={{ width: `${Math.round((a.completeness_score || 1.0) * 100)}%` }}
                        />
                      </div>
                      <span className="text-[10px] text-slate-400">
                        {Math.round((a.completeness_score || 1.0) * 100)}%
                      </span>
                    </div>
                  </td>
                  <td className="p-3 text-slate-400 text-[11px]">
                    {a.consecutive_absences || 0} / 3
                  </td>
                  <td className="p-3">
                    {a.confirmed_absent ? (
                      <span className="text-red-400 text-[10px] font-bold">CONFIRMED ABSENT</span>
                    ) : (
                      <span className="text-emerald-400 text-[10px]">{a.status}</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};
