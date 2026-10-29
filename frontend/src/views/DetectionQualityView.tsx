import React, { useState, useEffect } from 'react';
import { api } from '../services/api';
import type {
  QualityOverviewResponse,
  FixtureBenchmarksResponse,
  FindingValidationStatus,
} from '../types';

interface DetectionQualityViewProps {
  projectId: string;
}

export const DetectionQualityView: React.FC<DetectionQualityViewProps> = ({ projectId }) => {
  const [overview, setOverview] = useState<QualityOverviewResponse | null>(null);
  const [fixtures, setFixtures] = useState<FixtureBenchmarksResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [benchmarking, setBenchmarking] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<'overview' | 'fixtures' | 'provenance'>('overview');

  // Manual provenance search
  const [searchFindingId, setSearchFindingId] = useState('');
  const [provenanceResult, setProvenanceResult] = useState<any | null>(null);
  const [provenanceLoading, setProvenanceLoading] = useState(false);

  // Transition form
  const [targetStatus, setTargetStatus] = useState<FindingValidationStatus>('CONFIRMED_TRUE_POSITIVE');
  const [transitionReason, setTransitionReason] = useState('');
  const [transitionEvidenceRef, setTransitionEvidenceRef] = useState('');
  const [transitionMsg, setTransitionMsg] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  const loadOverview = async () => {
    try {
      setLoading(true);
      setError(null);
      const data = await api.getQualityOverview(projectId);
      setOverview(data);
    } catch (err: any) {
      setError(err.message || 'Failed to load detection quality overview');
    } finally {
      setLoading(false);
    }
  };

  const runBenchmarks = async () => {
    try {
      setBenchmarking(true);
      setError(null);
      const data = await api.getFixtureBenchmarks(projectId);
      setFixtures(data);
    } catch (err: any) {
      setError(err.message || 'Failed to execute fixture benchmarks');
    } finally {
      setBenchmarking(false);
    }
  };

  const lookupProvenance = async () => {
    if (!searchFindingId.trim()) return;
    try {
      setProvenanceLoading(true);
      setTransitionMsg(null);
      const res = await api.getFindingProvenance(projectId, searchFindingId.trim());
      setProvenanceResult(res);
    } catch (err: any) {
      setProvenanceResult(null);
      setTransitionMsg({ type: 'error', text: err.message || 'Finding not found or error loading provenance' });
    } finally {
      setProvenanceLoading(false);
    }
  };

  const executeTransition = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!provenanceResult?.finding_id) return;
    try {
      setTransitionMsg(null);
      await api.transitionFindingValidation(projectId, provenanceResult.finding_id, {
        to_status: targetStatus,
        reason: transitionReason,
        evidence_ref: transitionEvidenceRef || undefined,
        validation_method: 'MANUAL_OPERATOR_REVIEW',
      });
      setTransitionMsg({ type: 'success', text: `Successfully transitioned finding to ${targetStatus}` });
      setTransitionReason('');
      setTransitionEvidenceRef('');
      await lookupProvenance();
      await loadOverview();
    } catch (err: any) {
      setTransitionMsg({ type: 'error', text: err.message || 'Validation transition failed' });
    }
  };

  useEffect(() => {
    loadOverview();
  }, [projectId]);

  const formatPercent = (val?: number) => {
    if (val === undefined || val === null) return '0.0%';
    return `${(val * 100).toFixed(1)}%`;
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-gray-700 pb-4">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight">Detection Quality & Intelligence Validation</h1>
          <p className="text-sm text-gray-400 mt-1">
            Epistemic proof lifecycle, deterministic fixture benchmarks, and mathematically honest quality metrics.
          </p>
        </div>
        <div className="flex items-center space-x-3">
          <button
            onClick={loadOverview}
            disabled={loading}
            className="px-3 py-1.5 bg-gray-800 hover:bg-gray-700 text-gray-200 text-sm font-medium rounded-md border border-gray-600 transition"
          >
            {loading ? 'Refreshing...' : 'Refresh'}
          </button>
          <button
            onClick={runBenchmarks}
            disabled={benchmarking}
            className="px-3 py-1.5 bg-blue-600 hover:bg-blue-500 text-white text-sm font-medium rounded-md transition flex items-center space-x-1.5"
          >
            <span>{benchmarking ? 'Running Benchmarks...' : 'Run Fixture Benchmarks'}</span>
          </button>
        </div>
      </div>

      {error && (
        <div className="p-4 bg-red-900/50 border border-red-700 rounded-lg text-red-200 text-sm">
          {error}
        </div>
      )}

      {/* Tabs */}
      <div className="flex border-b border-gray-700 space-x-4">
        <button
          onClick={() => setActiveTab('overview')}
          className={`pb-2 text-sm font-medium transition ${
            activeTab === 'overview'
              ? 'border-b-2 border-blue-500 text-blue-400'
              : 'text-gray-400 hover:text-gray-200'
          }`}
        >
          Quality Metrics Overview
        </button>
        <button
          onClick={() => {
            setActiveTab('fixtures');
            if (!fixtures) runBenchmarks();
          }}
          className={`pb-2 text-sm font-medium transition ${
            activeTab === 'fixtures'
              ? 'border-b-2 border-blue-500 text-blue-400'
              : 'text-gray-400 hover:text-gray-200'
          }`}
        >
          Deterministic Fixture Benchmarks
        </button>
        <button
          onClick={() => setActiveTab('provenance')}
          className={`pb-2 text-sm font-medium transition ${
            activeTab === 'provenance'
              ? 'border-b-2 border-blue-500 text-blue-400'
              : 'text-gray-400 hover:text-gray-200'
          }`}
        >
          Finding Provenance & Epistemic FSM
        </button>
      </div>

      {/* TAB 1: OVERVIEW */}
      {activeTab === 'overview' && overview && (
        <div className="space-y-6">
          {/* Quality Warnings */}
          {overview.quality_warnings && overview.quality_warnings.length > 0 && (
            <div className="p-4 bg-amber-950/40 border border-amber-700 rounded-lg space-y-2">
              <h4 className="text-amber-400 font-semibold text-sm flex items-center gap-2">
                <span>⚠</span> Quality Health Warnings
              </h4>
              <ul className="list-disc list-inside text-xs text-amber-200/90 space-y-1">
                {overview.quality_warnings.map((w, i) => (
                  <li key={i}>{w}</li>
                ))}
              </ul>
            </div>
          )}

          {/* Metric Cards Grid */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            <div className="bg-gray-800 border border-gray-700 rounded-lg p-4">
              <span className="text-xs text-gray-400 uppercase font-semibold">Evidence Completeness</span>
              <div className="text-2xl font-bold text-white mt-1">
                {formatPercent(overview.metrics.evidence_completeness_rate)}
              </div>
              <p className="text-xs text-gray-400 mt-2">
                Verified: <span className="text-gray-200 font-mono">{overview.disclosed_denominators.evidence_completeness}</span>
              </p>
            </div>

            <div className="bg-gray-800 border border-gray-700 rounded-lg p-4">
              <span className="text-xs text-gray-400 uppercase font-semibold">Independent Reproduction</span>
              <div className="text-2xl font-bold text-white mt-1">
                {formatPercent(overview.metrics.independent_reproduction_rate)}
              </div>
              <p className="text-xs text-gray-400 mt-2">
                Corroborated: <span className="text-gray-200 font-mono">{overview.disclosed_denominators.reproduction_rate}</span>
              </p>
            </div>

            <div className="bg-gray-800 border border-gray-700 rounded-lg p-4">
              <span className="text-xs text-gray-400 uppercase font-semibold">Confirmed False Positive</span>
              <div className="text-2xl font-bold text-white mt-1">
                {formatPercent(overview.metrics.confirmed_false_positive_rate)}
              </div>
              <p className="text-xs text-gray-400 mt-2">
                Reviewed denominator: <span className="text-gray-200 font-mono">{overview.disclosed_denominators.confirmed_false_positive_rate}</span>
              </p>
            </div>

            <div className="bg-gray-800 border border-gray-700 rounded-lg p-4">
              <span className="text-xs text-gray-400 uppercase font-semibold">Retest Recurrence Rate</span>
              <div className="text-2xl font-bold text-white mt-1">
                {formatPercent(overview.metrics.retest_recurrence_rate)}
              </div>
              <p className="text-xs text-gray-400 mt-2">
                Reopened: <span className="text-gray-200 font-mono">{overview.disclosed_denominators.retest_recurrence_rate}</span>
              </p>
            </div>
          </div>

          {/* Validation Status Distribution */}
          <div className="bg-gray-800 border border-gray-700 rounded-lg p-5">
            <h3 className="text-md font-semibold text-white mb-4">Epistemic Validation State Distribution (9 States)</h3>
            <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3">
              {Object.entries(overview.validation_status_distribution).map(([state, count]) => {
                let badgeColor = 'bg-gray-700 text-gray-300';
                if (state === 'CONFIRMED_TRUE_POSITIVE') badgeColor = 'bg-red-950 text-red-300 border-red-800';
                else if (state === 'CONFIRMED_FALSE_POSITIVE') badgeColor = 'bg-blue-950 text-blue-300 border-blue-800';
                else if (state === 'RESOLVED_AFTER_RETEST') badgeColor = 'bg-green-950 text-green-300 border-green-800';
                else if (state === 'INDEPENDENTLY_REPRODUCED') badgeColor = 'bg-purple-950 text-purple-300 border-purple-800';
                else if (state === 'INCONCLUSIVE' || state === 'UNABLE_TO_VERIFY') badgeColor = 'bg-amber-950 text-amber-300 border-amber-800';

                return (
                  <div key={state} className={`p-3 rounded border ${badgeColor}`}>
                    <div className="text-xs font-semibold truncate" title={state}>{state}</div>
                    <div className="text-xl font-bold mt-1">{count}</div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Sample Size Disclosures */}
          <div className="bg-gray-800 border border-gray-700 rounded-lg p-5 text-sm text-gray-300">
            <h4 className="font-semibold text-white mb-2">Sample Size & Data Integrity Disclosures</h4>
            <div className="grid grid-cols-2 sm:grid-cols-3 gap-4 text-xs font-mono">
              <div>Total Canonical: <span className="text-white font-bold">{overview.sample_sizes.total_canonical_findings}</span></div>
              <div>Raw Observations: <span className="text-white font-bold">{overview.sample_sizes.total_raw_observations}</span></div>
              <div>Reviewed Findings: <span className="text-white font-bold">{overview.sample_sizes.reviewed_findings}</span></div>
              <div>Remediated Findings: <span className="text-white font-bold">{overview.sample_sizes.remediated_findings}</span></div>
              <div>Evidence Supported: <span className="text-white font-bold">{overview.sample_sizes.evidence_supported_findings}</span></div>
              <div>Duplication Rate: <span className="text-white font-bold">{formatPercent(overview.metrics.duplicate_observation_rate)}</span></div>
            </div>
          </div>
        </div>
      )}

      {/* TAB 2: DETERMINISTIC FIXTURES */}
      {activeTab === 'fixtures' && (
        <div className="space-y-6">
          <div className="flex justify-between items-center">
            <p className="text-sm text-gray-400">
              Evaluates detection performance against controlled ephemeral loopback HTTP fixtures with known ground truth.
            </p>
            {fixtures && (
              <span className="text-xs font-mono text-gray-400">Framework v{fixtures.framework_version}</span>
            )}
          </div>

          {fixtures ? (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {Object.entries(fixtures.benchmark_scenarios).map(([name, res]) => (
                <div key={name} className="bg-gray-800 border border-gray-700 rounded-lg p-5 space-y-3">
                  <div className="flex items-center justify-between">
                    <h3 className="font-bold text-white capitalize">{name.replace('_', ' ')} Fixture</h3>
                    <span className="text-xs px-2 py-0.5 rounded bg-gray-700 text-gray-300 font-mono">
                      {res.ground_truth_status}
                    </span>
                  </div>

                  {res.precision !== undefined && (
                    <div className="grid grid-cols-2 gap-2 text-xs">
                      <div className="bg-gray-900/50 p-2 rounded">
                        <span className="text-gray-400">Precision:</span>{' '}
                        <span className="font-bold text-white font-mono">{formatPercent(res.precision)}</span>
                      </div>
                      <div className="bg-gray-900/50 p-2 rounded">
                        <span className="text-gray-400">Recall:</span>{' '}
                        <span className="font-bold text-white font-mono">{formatPercent(res.recall)}</span>
                      </div>
                      <div className="bg-gray-900/50 p-2 rounded">
                        <span className="text-gray-400">False Positive Rate:</span>{' '}
                        <span className="font-bold text-white font-mono">{formatPercent(res.false_positive_rate)}</span>
                      </div>
                      <div className="bg-gray-900/50 p-2 rounded">
                        <span className="text-gray-400">Sample Size:</span>{' '}
                        <span className="font-bold text-white font-mono">{res.sample_size ?? 0}</span>
                      </div>
                    </div>
                  )}

                  {res.reported_validation_status && (
                    <div className="text-xs bg-gray-900/50 p-2 rounded text-gray-300">
                      Reported Status: <span className="font-mono text-blue-400 font-semibold">{res.reported_validation_status}</span>
                      {res.valid_failure_handling !== undefined && (
                        <span className="ml-2 text-green-400">✓ Valid Failure Handling</span>
                      )}
                      {res.valid_ambiguity_handling !== undefined && (
                        <span className="ml-2 text-purple-400">✓ Valid Ambiguity Handling</span>
                      )}
                    </div>
                  )}

                  {res.notes && (
                    <p className="text-xs text-gray-400 italic">{res.notes}</p>
                  )}
                </div>
              ))}
            </div>
          ) : (
            <div className="p-8 text-center bg-gray-800 border border-gray-700 rounded-lg text-gray-400 text-sm">
              Click &quot;Run Fixture Benchmarks&quot; to execute real deterministic loopback evaluations.
            </div>
          )}
        </div>
      )}

      {/* TAB 3: PROVENANCE & FSM */}
      {activeTab === 'provenance' && (
        <div className="space-y-6">
          {/* Search Bar */}
          <div className="bg-gray-800 border border-gray-700 rounded-lg p-4 flex flex-col sm:flex-row gap-3">
            <input
              type="text"
              placeholder="Enter Finding ID for cryptographic provenance inspection..."
              value={searchFindingId}
              onChange={(e) => setSearchFindingId(e.target.value)}
              className="flex-1 bg-gray-900 border border-gray-700 rounded px-3 py-2 text-sm text-gray-200 focus:outline-none focus:border-blue-500 font-mono"
            />
            <button
              onClick={lookupProvenance}
              disabled={provenanceLoading || !searchFindingId.trim()}
              className="px-4 py-2 bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white text-sm font-medium rounded transition"
            >
              {provenanceLoading ? 'Verifying...' : 'Inspect Provenance'}
            </button>
          </div>

          {transitionMsg && (
            <div
              className={`p-3 rounded text-sm ${
                transitionMsg.type === 'success'
                  ? 'bg-green-950/60 border border-green-800 text-green-200'
                  : 'bg-red-950/60 border border-red-800 text-red-200'
              }`}
            >
              {transitionMsg.text}
            </div>
          )}

          {provenanceResult && (
            <div className="space-y-6">
              {/* Finding Summary */}
              <div className="bg-gray-800 border border-gray-700 rounded-lg p-5 space-y-4">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-gray-700 pb-3">
                  <div>
                    <h3 className="text-lg font-bold text-white">{provenanceResult.title}</h3>
                    <p className="text-xs text-gray-400 font-mono mt-0.5">Fingerprint: {provenanceResult.fingerprint}</p>
                  </div>
                  <div className="flex items-center space-x-2">
                    <span className="text-xs px-2 py-0.5 rounded bg-blue-950 text-blue-300 font-mono">
                      Validation: {provenanceResult.validation_status || 'DETECTED'}
                    </span>
                    <span
                      className={`text-xs px-2 py-0.5 rounded font-mono ${
                        provenanceResult.cryptographic_integrity_verified
                          ? 'bg-green-950 text-green-300 border border-green-800'
                          : 'bg-red-950 text-red-300 border border-red-800'
                      }`}
                    >
                      {provenanceResult.cryptographic_integrity_verified ? 'SHA-256 Verified' : 'Integrity Mismatch'}
                    </span>
                  </div>
                </div>

                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
                  <div>Severity: <span className="font-semibold text-white">{provenanceResult.severity}</span></div>
                  <div>Confidence: <span className="font-semibold text-white">{provenanceResult.confidence}</span></div>
                  <div>Operational Status: <span className="font-semibold text-white">{provenanceResult.operational_status}</span></div>
                  <div>Evidence Quality: <span className="font-semibold text-white">{provenanceResult.evidence_quality_score}</span></div>
                </div>
              </div>

              {/* State Transition Form */}
              <div className="bg-gray-800 border border-gray-700 rounded-lg p-5">
                <h4 className="font-semibold text-white mb-3">Execute Governed Validation Transition</h4>
                <form onSubmit={executeTransition} className="space-y-4">
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                    <div>
                      <label className="block text-xs font-medium text-gray-400 mb-1">Target Validation Status</label>
                      <select
                        value={targetStatus}
                        onChange={(e) => setTargetStatus(e.target.value as FindingValidationStatus)}
                        className="w-full bg-gray-900 border border-gray-700 rounded px-3 py-2 text-sm text-gray-200"
                      >
                        <option value="CONFIRMED_TRUE_POSITIVE">CONFIRMED_TRUE_POSITIVE</option>
                        <option value="CONFIRMED_FALSE_POSITIVE">CONFIRMED_FALSE_POSITIVE</option>
                        <option value="EVIDENCE_SUPPORTED">EVIDENCE_SUPPORTED</option>
                        <option value="INDEPENDENTLY_REPRODUCED">INDEPENDENTLY_REPRODUCED</option>
                        <option value="INCONCLUSIVE">INCONCLUSIVE</option>
                        <option value="UNABLE_TO_VERIFY">UNABLE_TO_VERIFY</option>
                        <option value="RESOLVED_AFTER_RETEST">RESOLVED_AFTER_RETEST</option>
                      </select>
                    </div>

                    <div>
                      <label className="block text-xs font-medium text-gray-400 mb-1">Evidence Reference / Job ID</label>
                      <input
                        type="text"
                        placeholder="e.g. job-abc-123 or manual verification log"
                        value={transitionEvidenceRef}
                        onChange={(e) => setTransitionEvidenceRef(e.target.value)}
                        className="w-full bg-gray-900 border border-gray-700 rounded px-3 py-2 text-sm text-gray-200 font-mono"
                      />
                    </div>
                  </div>

                  <div>
                    <label className="block text-xs font-medium text-gray-400 mb-1">
                      Technical Justification (min 5 chars; min 10 for false positives)
                    </label>
                    <textarea
                      required
                      rows={2}
                      placeholder="Detailed rationale for this epistemic transition..."
                      value={transitionReason}
                      onChange={(e) => setTransitionReason(e.target.value)}
                      className="w-full bg-gray-900 border border-gray-700 rounded px-3 py-2 text-sm text-gray-200"
                    />
                  </div>

                  <div className="flex justify-end">
                    <button
                      type="submit"
                      className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white text-sm font-medium rounded transition"
                    >
                      Record Validation Transition
                    </button>
                  </div>
                </form>
              </div>

              {/* Validation History */}
              {provenanceResult.validation_history && provenanceResult.validation_history.length > 0 && (
                <div className="bg-gray-800 border border-gray-700 rounded-lg p-5">
                  <h4 className="font-semibold text-white mb-3">Immutable Transition Audit Trail</h4>
                  <div className="space-y-3">
                    {provenanceResult.validation_history.map((tr: any, idx: number) => (
                      <div key={idx} className="p-3 bg-gray-900/60 border border-gray-700 rounded text-xs space-y-1">
                        <div className="flex justify-between items-center">
                          <span className="font-mono text-blue-400 font-semibold">
                            {tr.from_status} → {tr.to_status}
                          </span>
                          <span className="text-gray-400">{tr.created_at ? new Date(tr.created_at).toLocaleString() : ''}</span>
                        </div>
                        <p className="text-gray-300">{tr.reason}</p>
                        <div className="text-gray-500 font-mono">
                          Method: {tr.validation_method} | Actor: {tr.actor_id}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
};
