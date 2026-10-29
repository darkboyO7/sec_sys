import React, { useState, useEffect } from 'react';
import type {
  ResolutionResult,
  DeduplicationProposal,
  DataQualityIssue,
  DryRunImpact,
} from '../types';
import { api } from '../services/api';

interface Props {
  projectId: string;
}

export const CanonicalAssetIdentityView: React.FC<Props> = ({ projectId }) => {
  const [activeTab, setActiveTab] = useState<'resolver' | 'proposals' | 'quality' | 'invariants'>('resolver');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);

  // Tab 1: Resolver State
  const [candidateTarget, setCandidateTarget] = useState('');
  const [cloudArn, setCloudArn] = useState('');
  const [resolutionResult, setResolutionResult] = useState<ResolutionResult | null>(null);

  // Tab 2: Proposals State
  const [proposals, setProposals] = useState<DeduplicationProposal[]>([]);
  const [dryRunImpact, setDryRunImpact] = useState<DryRunImpact | null>(null);
  const [sourceAssetId, setSourceAssetId] = useState('');
  const [targetAssetId, setTargetAssetId] = useState('');
  const [proposalRationale, setProposalRationale] = useState('');
  const [reviewComments, setReviewComments] = useState('');

  // Tab 3: Data Quality State
  const [qualityIssues, setQualityIssues] = useState<DataQualityIssue[]>([]);
  const [auditRunning, setAuditRunning] = useState(false);

  useEffect(() => {
    if (activeTab === 'proposals') {
      loadProposals();
    } else if (activeTab === 'quality') {
      loadQualityIssues();
    }
  }, [activeTab, projectId]);

  const loadProposals = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await api.listDeduplicationProposals(projectId);
      setProposals(data);
    } catch (err: any) {
      setError(err.message || 'Failed to load deduplication proposals');
    } finally {
      setLoading(false);
    }
  };

  const loadQualityIssues = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await api.listDataQualityIssues(projectId);
      setQualityIssues(data);
    } catch (err: any) {
      setError(err.message || 'Failed to load data quality issues');
    } finally {
      setLoading(false);
    }
  };

  const handleResolve = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!candidateTarget.trim()) return;
    setLoading(true);
    setError(null);
    try {
      const attrs = cloudArn.trim() ? { cloud_resource_id: cloudArn.trim() } : undefined;
      const res = await api.resolveAssetEntity(projectId, candidateTarget.trim(), attrs);
      setResolutionResult(res);
    } catch (err: any) {
      setError(err.message || 'Entity resolution failed');
    } finally {
      setLoading(false);
    }
  };

  const handleDryRun = async () => {
    if (!sourceAssetId.trim() || !targetAssetId.trim()) return;
    setLoading(true);
    setError(null);
    try {
      const impact = await api.evaluateDeduplicationDryRun(projectId, sourceAssetId.trim(), targetAssetId.trim());
      setDryRunImpact(impact);
    } catch (err: any) {
      setError(err.message || 'Dry run evaluation failed');
    } finally {
      setLoading(false);
    }
  };

  const handlePropose = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!sourceAssetId.trim() || !targetAssetId.trim() || !proposalRationale.trim()) return;
    setLoading(true);
    setError(null);
    try {
      await api.proposeAssetDeduplication(projectId, {
        source_asset_id: sourceAssetId.trim(),
        target_asset_id: targetAssetId.trim(),
        rationale: proposalRationale.trim(),
      });
      setSuccessMessage('Deduplication proposal submitted for review.');
      setSourceAssetId('');
      setTargetAssetId('');
      setProposalRationale('');
      setDryRunImpact(null);
      await loadProposals();
    } catch (err: any) {
      setError(err.message || 'Failed to submit proposal');
    } finally {
      setLoading(false);
    }
  };

  const handleApprove = async (proposalId: string) => {
    setLoading(true);
    setError(null);
    try {
      await api.approveDeduplicationProposal(projectId, proposalId, reviewComments.trim() || undefined);
      setSuccessMessage('Deduplication merge approved and executed.');
      setReviewComments('');
      await loadProposals();
    } catch (err: any) {
      setError(err.message || 'Approval failed');
    } finally {
      setLoading(false);
    }
  };

  const handleReject = async (proposalId: string) => {
    setLoading(true);
    setError(null);
    try {
      await api.rejectDeduplicationProposal(projectId, proposalId, reviewComments.trim() || undefined);
      setSuccessMessage('Deduplication merge rejected.');
      setReviewComments('');
      await loadProposals();
    } catch (err: any) {
      setError(err.message || 'Rejection failed');
    } finally {
      setLoading(false);
    }
  };

  const handleRevert = async (proposalId: string) => {
    setLoading(true);
    setError(null);
    try {
      await api.revertDeduplicationProposal(projectId, proposalId, reviewComments.trim() || undefined);
      setSuccessMessage('Deduplication merge reverted. Original assets and findings restored.');
      setReviewComments('');
      await loadProposals();
    } catch (err: any) {
      setError(err.message || 'Reversal failed');
    } finally {
      setLoading(false);
    }
  };

  const handleRunAudit = async () => {
    setAuditRunning(true);
    setError(null);
    try {
      const data = await api.runDataQualityAudit(projectId);
      setQualityIssues(data);
      setSuccessMessage(`Data quality audit complete. ${data.length} issues identified.`);
    } catch (err: any) {
      setError(err.message || 'Data quality audit failed');
    } finally {
      setAuditRunning(false);
    }
  };

  const handleResolveIssue = async (issueId: string, newStatus: 'RESOLVED' | 'IGNORED') => {
    setLoading(true);
    setError(null);
    try {
      await api.updateDataQualityIssueStatus(projectId, issueId, newStatus);
      await loadQualityIssues();
    } catch (err: any) {
      setError(err.message || 'Failed to update issue status');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row justify-between items-start md:items-center pb-4 border-b border-gray-700">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-wide">
            Asset Identity Resolution & Canonical Governance
          </h1>
          <p className="text-sm text-gray-400 mt-1">
            Prompt 37: Confidence-aware entity resolution, address reuse defense, reviewable deduplication, and data quality audits.
          </p>
        </div>
      </div>

      {/* Global Alerts */}
      {error && (
        <div className="bg-red-900/40 border border-red-500/50 p-4 rounded-lg text-red-200 text-sm flex justify-between items-center">
          <span>{error}</span>
          <button onClick={() => setError(null)} className="text-red-400 hover:text-white">&times;</button>
        </div>
      )}
      {successMessage && (
        <div className="bg-emerald-900/40 border border-emerald-500/50 p-4 rounded-lg text-emerald-200 text-sm flex justify-between items-center">
          <span>{successMessage}</span>
          <button onClick={() => setSuccessMessage(null)} className="text-emerald-400 hover:text-white">&times;</button>
        </div>
      )}

      {/* Tab Navigation */}
      <div className="flex space-x-2 border-b border-gray-700 pb-2">
        <button
          onClick={() => setActiveTab('resolver')}
          className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
            activeTab === 'resolver'
              ? 'bg-blue-600 text-white'
              : 'text-gray-400 hover:text-white hover:bg-gray-800'
          }`}
        >
          Entity Resolution & Uncertainty Inspector
        </button>
        <button
          onClick={() => setActiveTab('proposals')}
          className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
            activeTab === 'proposals'
              ? 'bg-blue-600 text-white'
              : 'text-gray-400 hover:text-white hover:bg-gray-800'
          }`}
        >
          Deduplication Review & Merge Plans
        </button>
        <button
          onClick={() => setActiveTab('quality')}
          className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
            activeTab === 'quality'
              ? 'bg-blue-600 text-white'
              : 'text-gray-400 hover:text-white hover:bg-gray-800'
          }`}
        >
          Data Quality Anomalies ({qualityIssues.filter((q) => q.status === 'OPEN').length})
        </button>
        <button
          onClick={() => setActiveTab('invariants')}
          className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
            activeTab === 'invariants'
              ? 'bg-blue-600 text-white'
              : 'text-gray-400 hover:text-white hover:bg-gray-800'
          }`}
        >
          Grounding Invariants
        </button>
      </div>

      {/* TAB 1: ENTITY RESOLUTION */}
      {activeTab === 'resolver' && (
        <div className="space-y-6">
          <div className="bg-gray-800/60 border border-gray-700 p-6 rounded-xl">
            <h2 className="text-lg font-semibold text-white mb-2">Live Candidate Entity Resolution</h2>
            <p className="text-sm text-gray-400 mb-4">
              Evaluates candidates against project assets using canonical key normalizers, strong fingerprints, and time-bounded observation horizons.
            </p>

            <form onSubmit={handleResolve} className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs font-semibold text-gray-300 uppercase mb-1">
                    Candidate Target String (URL, Domain, Hostname, IP, Service)
                  </label>
                  <input
                    type="text"
                    value={candidateTarget}
                    onChange={(e) => setCandidateTarget(e.target.value)}
                    placeholder="e.g. https://api.corp.internal or 198.51.100.42"
                    className="w-full bg-gray-900 border border-gray-700 rounded-lg px-3 py-2 text-white text-sm focus:border-blue-500 focus:outline-none"
                    required
                  />
                </div>
                <div>
                  <label className="block text-xs font-semibold text-gray-300 uppercase mb-1">
                    Optional Strong Fingerprint (Cloud ARN / TLS Serial)
                  </label>
                  <input
                    type="text"
                    value={cloudArn}
                    onChange={(e) => setCloudArn(e.target.value)}
                    placeholder="e.g. arn:aws:ec2:... or cert serial"
                    className="w-full bg-gray-900 border border-gray-700 rounded-lg px-3 py-2 text-white text-sm focus:border-blue-500 focus:outline-none"
                  />
                </div>
              </div>

              <button
                type="submit"
                disabled={loading}
                className="bg-blue-600 hover:bg-blue-500 text-white font-medium px-4 py-2 rounded-lg text-sm transition-colors disabled:opacity-50"
              >
                {loading ? 'Resolving...' : 'Resolve Entity'}
              </button>
            </form>
          </div>

          {resolutionResult && (
            <div className="bg-gray-800/80 border border-gray-700 p-6 rounded-xl space-y-4">
              <div className="flex items-center justify-between">
                <h3 className="text-md font-semibold text-white">Resolution Outcome</h3>
                <span
                  className={`px-3 py-1 rounded-full text-xs font-bold ${
                    resolutionResult.outcome === 'EXACT_MATCH'
                      ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                      : resolutionResult.outcome === 'STRONG_CORRELATION'
                      ? 'bg-blue-500/20 text-blue-400 border border-blue-500/30'
                      : resolutionResult.outcome === 'AMBIGUOUS_CONFLICT'
                      ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                      : 'bg-gray-500/20 text-gray-300 border border-gray-500/30'
                  }`}
                >
                  {resolutionResult.outcome} ({Math.round(resolutionResult.confidence * 100)}% Confidence)
                </span>
              </div>

              {resolutionResult.matched_asset_id && (
                <div className="bg-gray-900/70 p-3 rounded-lg border border-gray-800 text-sm">
                  <div className="text-gray-400 text-xs uppercase font-medium">Matched Canonical Asset</div>
                  <div className="text-white font-mono mt-1">{resolutionResult.matched_canonical_identifier}</div>
                  <div className="text-gray-500 text-xs font-mono mt-0.5">Asset ID: {resolutionResult.matched_asset_id}</div>
                </div>
              )}

              {resolutionResult.match_reasons.length > 0 && (
                <div>
                  <div className="text-xs uppercase font-semibold text-gray-400 mb-1">Explainable Match Vectors</div>
                  <ul className="list-disc list-inside text-sm text-gray-300 space-y-1">
                    {resolutionResult.match_reasons.map((r, i) => (
                      <li key={i}>{r}</li>
                    ))}
                  </ul>
                </div>
              )}

              {resolutionResult.conflicts_detected.length > 0 && (
                <div className="bg-amber-950/30 border border-amber-500/40 p-3 rounded-lg">
                  <div className="text-xs uppercase font-semibold text-amber-400 mb-1">Conflicts & Uncertainty Flags</div>
                  <ul className="list-disc list-inside text-sm text-amber-200 space-y-1">
                    {resolutionResult.conflicts_detected.map((c, i) => (
                      <li key={i}>{c}</li>
                    ))}
                  </ul>
                  <div className="text-xs text-amber-300/80 mt-2">
                    Auto-merge is prevented. Requires explicit human review and dry-run evaluation.
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* TAB 2: PROPOSALS & MERGE PLANS */}
      {activeTab === 'proposals' && (
        <div className="space-y-6">
          {/* Create Proposal Card */}
          <div className="bg-gray-800/60 border border-gray-700 p-6 rounded-xl">
            <h2 className="text-lg font-semibold text-white mb-2">Propose Deduplication Merge</h2>
            <p className="text-sm text-gray-400 mb-4">
              All asset merges are reviewable, require Lead approval, and preserve complete rollback state.
            </p>

            <form onSubmit={handlePropose} className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs font-semibold text-gray-300 uppercase mb-1">Source Asset ID</label>
                  <input
                    type="text"
                    value={sourceAssetId}
                    onChange={(e) => setSourceAssetId(e.target.value)}
                    placeholder="Asset to be decommissioned and merged from"
                    className="w-full bg-gray-900 border border-gray-700 rounded-lg px-3 py-2 text-white text-sm focus:border-blue-500 focus:outline-none"
                    required
                  />
                </div>
                <div>
                  <label className="block text-xs font-semibold text-gray-300 uppercase mb-1">Target Canonical Asset ID</label>
                  <input
                    type="text"
                    value={targetAssetId}
                    onChange={(e) => setTargetAssetId(e.target.value)}
                    placeholder="Authoritative asset to merge into"
                    className="w-full bg-gray-900 border border-gray-700 rounded-lg px-3 py-2 text-white text-sm focus:border-blue-500 focus:outline-none"
                    required
                  />
                </div>
              </div>

              <div>
                <label className="block text-xs font-semibold text-gray-300 uppercase mb-1">Merge Justification / Rationale</label>
                <input
                  type="text"
                  value={proposalRationale}
                  onChange={(e) => setProposalRationale(e.target.value)}
                  placeholder="e.g. Verified identical host deployment across DNS alias and IP observation"
                  className="w-full bg-gray-900 border border-gray-700 rounded-lg px-3 py-2 text-white text-sm focus:border-blue-500 focus:outline-none"
                  required
                />
              </div>

              <div className="flex space-x-3">
                <button
                  type="button"
                  onClick={handleDryRun}
                  disabled={loading || !sourceAssetId || !targetAssetId}
                  className="bg-gray-700 hover:bg-gray-600 text-white font-medium px-4 py-2 rounded-lg text-sm transition-colors disabled:opacity-50"
                >
                  Dry-Run Impact
                </button>
                <button
                  type="submit"
                  disabled={loading}
                  className="bg-blue-600 hover:bg-blue-500 text-white font-medium px-4 py-2 rounded-lg text-sm transition-colors disabled:opacity-50"
                >
                  Submit Merge Proposal
                </button>
              </div>
            </form>

            {dryRunImpact && (
              <div className="mt-4 bg-gray-900/80 p-4 rounded-lg border border-gray-800 text-sm space-y-2">
                <div className="font-semibold text-white">Dry-Run Impact Summary:</div>
                <div className="grid grid-cols-3 gap-2 text-xs">
                  <div className="bg-gray-800 p-2 rounded">
                    <span className="text-gray-400">Findings to Repoint:</span>{' '}
                    <span className="text-white font-bold">{dryRunImpact.findings_to_repoint}</span>
                  </div>
                  <div className="bg-gray-800 p-2 rounded">
                    <span className="text-gray-400">Aliases to Transfer:</span>{' '}
                    <span className="text-white font-bold">{dryRunImpact.aliases_to_transfer}</span>
                  </div>
                  <div className="bg-gray-800 p-2 rounded">
                    <span className="text-gray-400">Observations to Repoint:</span>{' '}
                    <span className="text-white font-bold">{dryRunImpact.observations_to_repoint}</span>
                  </div>
                </div>
                {dryRunImpact.conflicts_detected.length > 0 && (
                  <div className="text-amber-400 text-xs">
                    Conflicts: {dryRunImpact.conflicts_detected.join('; ')}
                  </div>
                )}
              </div>
            )}
          </div>

          {/* Proposals Ledger */}
          <div className="bg-gray-800/60 border border-gray-700 p-6 rounded-xl space-y-4">
            <h2 className="text-lg font-semibold text-white">Deduplication Proposals</h2>
            {proposals.length === 0 ? (
              <div className="text-sm text-gray-400 py-4">No deduplication proposals recorded for this project.</div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-sm text-gray-300">
                  <thead className="bg-gray-900/80 text-xs uppercase text-gray-400 border-b border-gray-700">
                    <tr>
                      <th className="p-3">Proposal ID</th>
                      <th className="p-3">Source & Target</th>
                      <th className="p-3">Confidence</th>
                      <th className="p-3">Status</th>
                      <th className="p-3">Created</th>
                      <th className="p-3">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-700/50">
                    {proposals.map((p) => (
                      <tr key={p.id} className="hover:bg-gray-750">
                        <td className="p-3 font-mono text-xs">{p.id.substring(0, 8)}...</td>
                        <td className="p-3 text-xs">
                          <div>From: <span className="font-mono text-gray-400">{p.source_asset_id.substring(0, 8)}</span></div>
                          <div>To: <span className="font-mono text-blue-400">{p.target_asset_id.substring(0, 8)}</span></div>
                        </td>
                        <td className="p-3 text-xs font-bold">{Math.round(p.confidence_score * 100)}%</td>
                        <td className="p-3">
                          <span
                            className={`px-2 py-0.5 rounded text-xs font-semibold ${
                              p.status === 'APPROVED'
                                ? 'bg-emerald-500/20 text-emerald-400'
                                : p.status === 'PROPOSED'
                                ? 'bg-amber-500/20 text-amber-400'
                                : p.status === 'REVERTED'
                                ? 'bg-purple-500/20 text-purple-400'
                                : 'bg-red-500/20 text-red-400'
                            }`}
                          >
                            {p.status}
                          </span>
                        </td>
                        <td className="p-3 text-xs text-gray-400">
                          {new Date(p.created_at).toLocaleDateString()}
                        </td>
                        <td className="p-3 space-x-2">
                          {p.status === 'PROPOSED' && (
                            <>
                              <button
                                onClick={() => handleApprove(p.id)}
                                className="bg-emerald-600 hover:bg-emerald-500 text-white text-xs px-2.5 py-1 rounded transition-colors"
                              >
                                Approve
                              </button>
                              <button
                                onClick={() => handleReject(p.id)}
                                className="bg-red-600 hover:bg-red-500 text-white text-xs px-2.5 py-1 rounded transition-colors"
                              >
                                Reject
                              </button>
                            </>
                          )}
                          {p.status === 'APPROVED' && (
                            <button
                              onClick={() => handleRevert(p.id)}
                              className="bg-purple-600 hover:bg-purple-500 text-white text-xs px-2.5 py-1 rounded transition-colors"
                            >
                              Revert / Split
                            </button>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      )}

      {/* TAB 3: DATA QUALITY ANOMALIES */}
      {activeTab === 'quality' && (
        <div className="space-y-6">
          <div className="bg-gray-800/60 border border-gray-700 p-6 rounded-xl flex items-center justify-between">
            <div>
              <h2 className="text-lg font-semibold text-white">Inventory Data Quality Audits</h2>
              <p className="text-sm text-gray-400 mt-1">
                Audits orphaned findings, missing asset references, duplicate identifiers, inconsistent timestamps, and stale observations.
              </p>
            </div>
            <button
              onClick={handleRunAudit}
              disabled={auditRunning}
              className="bg-blue-600 hover:bg-blue-500 text-white font-medium px-4 py-2 rounded-lg text-sm transition-colors disabled:opacity-50"
            >
              {auditRunning ? 'Running Audit...' : 'Run Data Quality Audit'}
            </button>
          </div>

          <div className="bg-gray-800/60 border border-gray-700 p-6 rounded-xl">
            <h3 className="text-md font-semibold text-white mb-4">Identified Quality Issues</h3>
            {qualityIssues.length === 0 ? (
              <div className="text-sm text-gray-400 py-4">No data quality anomalies identified in this project.</div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-sm text-gray-300">
                  <thead className="bg-gray-900/80 text-xs uppercase text-gray-400 border-b border-gray-700">
                    <tr>
                      <th className="p-3">Issue Type</th>
                      <th className="p-3">Severity</th>
                      <th className="p-3">Resource</th>
                      <th className="p-3">Details</th>
                      <th className="p-3">Status</th>
                      <th className="p-3">Action</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-700/50">
                    {qualityIssues.map((iss) => (
                      <tr key={iss.id} className="hover:bg-gray-750">
                        <td className="p-3 font-semibold text-xs text-white">{iss.issue_type}</td>
                        <td className="p-3">
                          <span
                            className={`px-2 py-0.5 rounded text-xs font-bold ${
                              iss.severity === 'CRITICAL' || iss.severity === 'HIGH'
                                ? 'bg-red-500/20 text-red-400'
                                : 'bg-amber-500/20 text-amber-400'
                            }`}
                          >
                            {iss.severity}
                          </span>
                        </td>
                        <td className="p-3 text-xs font-mono">{iss.affected_resource_type}: {iss.affected_resource_id.substring(0, 8)}</td>
                        <td className="p-3 text-xs text-gray-400 max-w-xs truncate">
                          {iss.details.reason || JSON.stringify(iss.details)}
                        </td>
                        <td className="p-3">
                          <span
                            className={`px-2 py-0.5 rounded text-xs font-semibold ${
                              iss.status === 'RESOLVED'
                                ? 'bg-emerald-500/20 text-emerald-400'
                                : iss.status === 'OPEN'
                                ? 'bg-red-500/20 text-red-400'
                                : 'bg-gray-500/20 text-gray-400'
                            }`}
                          >
                            {iss.status}
                          </span>
                        </td>
                        <td className="p-3 space-x-2">
                          {iss.status === 'OPEN' && (
                            <>
                              <button
                                onClick={() => handleResolveIssue(iss.id, 'RESOLVED')}
                                className="bg-emerald-600 hover:bg-emerald-500 text-white text-xs px-2 py-1 rounded"
                              >
                                Resolve
                              </button>
                              <button
                                onClick={() => handleResolveIssue(iss.id, 'IGNORED')}
                                className="bg-gray-700 hover:bg-gray-600 text-white text-xs px-2 py-1 rounded"
                              >
                                Ignore
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
          </div>
        </div>
      )}

      {/* TAB 4: GROUNDING INVARIANTS */}
      {activeTab === 'invariants' && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div className="bg-gray-800/60 border border-gray-700 p-6 rounded-xl space-y-2">
            <h3 className="text-white font-semibold flex items-center">
              <span className="w-2.5 h-2.5 rounded-full bg-emerald-400 mr-2"></span>
              Never Merge on IP Alone
            </h3>
            <p className="text-sm text-gray-300">
              IP addresses are ephemeral, shared across multi-tenant gateways, and subject to DHCP reallocation. Assets must never be merged solely because they share an observed IP address.
            </p>
          </div>

          <div className="bg-gray-800/60 border border-gray-700 p-6 rounded-xl space-y-2">
            <h3 className="text-white font-semibold flex items-center">
              <span className="w-2.5 h-2.5 rounded-full bg-blue-400 mr-2"></span>
              Zero Evidence Deletion
            </h3>
            <p className="text-sm text-gray-300">
              Historical observations, scan findings, and cryptographic evidence hashes are never purged to clean up inventory representations. Merges repoint relationships while preserving provenance.
            </p>
          </div>

          <div className="bg-gray-800/60 border border-gray-700 p-6 rounded-xl space-y-2">
            <h3 className="text-white font-semibold flex items-center">
              <span className="w-2.5 h-2.5 rounded-full bg-amber-400 mr-2"></span>
              7-Day Observation Horizon
            </h3>
            <p className="text-sm text-gray-300">
              Correlations on ephemeral identifiers separated by more than 7 days trigger temporal conflict warnings to defend against address reuse and cloud tenant churn.
            </p>
          </div>

          <div className="bg-gray-800/60 border border-gray-700 p-6 rounded-xl space-y-2">
            <h3 className="text-white font-semibold flex items-center">
              <span className="w-2.5 h-2.5 rounded-full bg-purple-400 mr-2"></span>
              Reversible Split Workflows
            </h3>
            <p className="text-sm text-gray-300">
              Every approved merge records source attribute snapshots and finding IDs. Operators can safely revert merges, restoring source assets to ACTIVE and moving findings back.
            </p>
          </div>
        </div>
      )}
    </div>
  );
};
