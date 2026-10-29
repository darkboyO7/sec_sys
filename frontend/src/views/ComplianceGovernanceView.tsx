import React, { useState, useEffect } from 'react';
import { api } from '../services/api';
import type {
  Project,
  ComplianceControl,
  BaselineProfile,
  ComplianceEvaluationRun,
  ComplianceDriftEvent,
  ComplianceException,
  ComplianceEvaluationStatus,
} from '../types';

export const ComplianceGovernanceView: React.FC = () => {
  const [projects, setProjects] = useState<Project[]>([]);
  const [selectedProjectId, setSelectedProjectId] = useState<string>('');
  const [activeTab, setActiveTab] = useState<'posture' | 'catalog' | 'baselines' | 'drift' | 'exceptions'>('posture');

  const [controls, setControls] = useState<ComplianceControl[]>([]);
  const [profiles, setProfiles] = useState<BaselineProfile[]>([]);
  const [selectedProfileId, setSelectedProfileId] = useState<string>('');
  const [latestRun, setLatestRun] = useState<ComplianceEvaluationRun | null>(null);
  const [evalRuns, setEvalRuns] = useState<ComplianceEvaluationRun[]>([]);
  const [driftEvents, setDriftEvents] = useState<ComplianceDriftEvent[]>([]);
  const [exceptions, setExceptions] = useState<ComplianceException[]>([]);

  const [loading, setLoading] = useState<boolean>(false);
  const [evaluating, setEvaluating] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [actionSuccess, setActionSuccess] = useState<string | null>(null);

  // Exception request form state
  const [showExceptionModal, setShowExceptionModal] = useState<boolean>(false);
  const [excControlId, setExcControlId] = useState<string>('');
  const [excJustification, setExcJustification] = useState<string>('');
  const [excRiskAssessment, setExcRiskAssessment] = useState<string>('');
  const [excCompensatingControls, setExcCompensatingControls] = useState<string>('');
  const [excDays, setExcDays] = useState<number>(30);

  useEffect(() => {
    loadProjects();
    loadControls();
  }, []);

  useEffect(() => {
    if (selectedProjectId) {
      loadProjectData(selectedProjectId);
    }
  }, [selectedProjectId]);

  const loadProjects = async () => {
    try {
      setLoading(true);
      const projs = await api.listProjects();
      setProjects(projs);
      if (projs.length > 0 && !selectedProjectId) {
        setSelectedProjectId(projs[0].id);
      }
    } catch (err: any) {
      setError(err?.message || 'Failed to load projects');
    } finally {
      setLoading(false);
    }
  };

  const loadControls = async () => {
    try {
      const data = await api.getComplianceControls();
      setControls(data);
    } catch (err: any) {
      console.error('Failed to load controls', err);
    }
  };

  const loadProjectData = async (projectId: string) => {
    try {
      setLoading(true);
      setError(null);
      const [profs, runs, drifts, excs] = await Promise.all([
        api.getProjectBaselineProfiles(projectId),
        api.getComplianceEvaluations(projectId),
        api.getComplianceDriftEvents(projectId),
        api.getComplianceExceptions(projectId),
      ]);
      setProfiles(profs);
      if (profs.length > 0 && !selectedProfileId) {
        setSelectedProfileId(profs[0].id);
      }
      setEvalRuns(runs);
      if (runs.length > 0) {
        setLatestRun(runs[0]);
      } else {
        setLatestRun(null);
      }
      setDriftEvents(drifts);
      setExceptions(excs);
    } catch (err: any) {
      setError(err?.message || 'Failed to load project compliance data');
    } finally {
      setLoading(false);
    }
  };

  const handleEvaluate = async () => {
    if (!selectedProjectId || !selectedProfileId) return;
    try {
      setEvaluating(true);
      setError(null);
      setActionSuccess(null);
      const run = await api.evaluateComplianceBaseline(selectedProjectId, {
        baseline_profile_id: selectedProfileId,
      });
      setLatestRun(run);
      setActionSuccess(`Evaluation complete! Provenance Digest: ${run.provenance_digest.substring(0, 16)}...`);
      // Reload runs & drift
      loadProjectData(selectedProjectId);
    } catch (err: any) {
      setError(err?.message || 'Baseline evaluation failed');
    } finally {
      setEvaluating(false);
    }
  };

  const handleRequestException = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedProjectId || !excControlId) return;
    try {
      setLoading(true);
      setError(null);
      const expiresAt = new Date(Date.now() + excDays * 24 * 60 * 60 * 1000).toISOString();
      await api.requestComplianceException(selectedProjectId, {
        control_id: excControlId,
        justification: excJustification,
        risk_assessment: excRiskAssessment,
        compensating_controls: excCompensatingControls,
        expires_at: expiresAt,
      });
      setShowExceptionModal(false);
      setExcJustification('');
      setExcRiskAssessment('');
      setExcCompensatingControls('');
      setActionSuccess('Exception requested successfully. Pending independent review.');
      loadProjectData(selectedProjectId);
    } catch (err: any) {
      setError(err?.message || 'Failed to request exception');
    } finally {
      setLoading(false);
    }
  };

  const handleReviewException = async (exceptionId: string, approved: boolean) => {
    if (!selectedProjectId) return;
    try {
      setLoading(true);
      setError(null);
      await api.reviewComplianceException(selectedProjectId, exceptionId, {
        approved,
        review_notes: approved ? 'Approved by authorized reviewer' : 'Rejected after risk assessment',
      });
      setActionSuccess(`Exception ${approved ? 'approved' : 'rejected'} successfully.`);
      loadProjectData(selectedProjectId);
    } catch (err: any) {
      setError(err?.message || 'Failed to review exception (Separation of duties may apply)');
    } finally {
      setLoading(false);
    }
  };

  const getStatusBadge = (status: ComplianceEvaluationStatus) => {
    switch (status) {
      case 'PASS':
        return <span className="px-2 py-0.5 text-xs font-semibold rounded bg-emerald-900/60 text-emerald-300 border border-emerald-700">PASS</span>;
      case 'FAIL':
        return <span className="px-2 py-0.5 text-xs font-semibold rounded bg-rose-900/60 text-rose-300 border border-rose-700">FAIL</span>;
      case 'PARTIAL':
        return <span className="px-2 py-0.5 text-xs font-semibold rounded bg-amber-900/60 text-amber-300 border border-amber-700">PARTIAL</span>;
      case 'UNKNOWN':
        return <span className="px-2 py-0.5 text-xs font-semibold rounded bg-indigo-900/60 text-indigo-300 border border-indigo-700">UNKNOWN</span>;
      case 'NOT_APPLICABLE':
        return <span className="px-2 py-0.5 text-xs font-semibold rounded bg-slate-800 text-slate-400 border border-slate-700">N/A</span>;
      case 'ERROR':
        return <span className="px-2 py-0.5 text-xs font-semibold rounded bg-red-950 text-red-400 border border-red-800">ERROR</span>;
      default:
        return <span className="px-2 py-0.5 text-xs font-semibold rounded bg-slate-800 text-slate-300">{status}</span>;
    }
  };

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6 text-slate-100">
      {/* Header & Project Selector */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-5">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
            <span className="p-2 bg-blue-600/20 text-blue-400 rounded-lg border border-blue-500/30">
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
              </svg>
            </span>
            Continuous Compliance & Baseline Governance
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Deterministic evidence-grounded security control evaluation, baseline profiles, and configuration drift intelligence.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <label className="text-xs font-medium text-slate-400">Project Workspace:</label>
          <select
            value={selectedProjectId}
            onChange={(e) => setSelectedProjectId(e.target.value)}
            className="bg-slate-900 border border-slate-700 text-slate-200 text-sm rounded-lg px-3 py-2 focus:ring-blue-500 focus:border-blue-500"
          >
            {projects.map((p) => (
              <option key={p.id} value={p.id}>{p.name}</option>
            ))}
          </select>
        </div>
      </div>

      {/* Notifications */}
      {error && (
        <div className="p-4 bg-rose-950/60 border border-rose-800 text-rose-200 rounded-lg flex items-center gap-3 text-sm">
          <svg className="w-5 h-5 shrink-0 text-rose-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
          <span>{error}</span>
        </div>
      )}
      {actionSuccess && (
        <div className="p-4 bg-emerald-950/60 border border-emerald-800 text-emerald-200 rounded-lg flex items-center gap-3 text-sm">
          <svg className="w-5 h-5 shrink-0 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
          </svg>
          <span>{actionSuccess}</span>
        </div>
      )}

      {/* Tab Navigation */}
      <div className="flex border-b border-slate-800 gap-1 overflow-x-auto">
        <button
          onClick={() => setActiveTab('posture')}
          className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors whitespace-nowrap ${
            activeTab === 'posture'
              ? 'border-blue-500 text-blue-400 bg-slate-900/50'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          Baseline Posture & Evaluation
        </button>
        <button
          onClick={() => setActiveTab('catalog')}
          className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors whitespace-nowrap ${
            activeTab === 'catalog'
              ? 'border-blue-500 text-blue-400 bg-slate-900/50'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          Controls Catalog ({controls.length})
        </button>
        <button
          onClick={() => setActiveTab('baselines')}
          className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors whitespace-nowrap ${
            activeTab === 'baselines'
              ? 'border-blue-500 text-blue-400 bg-slate-900/50'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          Baseline Profiles ({profiles.length})
        </button>
        <button
          onClick={() => setActiveTab('drift')}
          className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors whitespace-nowrap ${
            activeTab === 'drift'
              ? 'border-blue-500 text-blue-400 bg-slate-900/50'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          Configuration Drift ({driftEvents.length})
        </button>
        <button
          onClick={() => setActiveTab('exceptions')}
          className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors whitespace-nowrap ${
            activeTab === 'exceptions'
              ? 'border-blue-500 text-blue-400 bg-slate-900/50'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          Exceptions & SoD ({exceptions.length})
        </button>
      </div>

      {/* Tab 1: Posture & Evaluation */}
      {activeTab === 'posture' && (
        <div className="space-y-6">
          {/* Action Bar */}
          <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-4 flex flex-col md:flex-row items-center justify-between gap-4">
            <div className="flex items-center gap-3 w-full md:w-auto">
              <label className="text-xs text-slate-400 whitespace-nowrap">Active Baseline Profile:</label>
              <select
                value={selectedProfileId}
                onChange={(e) => setSelectedProfileId(e.target.value)}
                className="bg-slate-950 border border-slate-700 text-sm rounded-lg px-3 py-1.5 text-slate-200"
              >
                {profiles.map((p) => (
                  <option key={p.id} value={p.id}>{p.name} (v{p.version})</option>
                ))}
              </select>
            </div>

            <button
              onClick={handleEvaluate}
              disabled={evaluating || !selectedProfileId}
              className="w-full md:w-auto px-4 py-2 bg-blue-600 hover:bg-blue-500 disabled:bg-slate-800 text-white text-sm font-medium rounded-lg shadow transition flex items-center justify-center gap-2"
            >
              {evaluating ? (
                <>
                  <svg className="animate-spin h-4 w-4 text-white" fill="none" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                  </svg>
                  Evaluating Evidence...
                </>
              ) : (
                <>
                  <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z" />
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                  </svg>
                  Evaluate Baseline
                </>
              )}
            </button>
          </div>

          {/* KPI Tiles */}
          {latestRun ? (
            <div className="space-y-6">
              <div className="grid grid-cols-2 md:grid-cols-6 gap-3">
                <div className="bg-slate-900/80 border border-emerald-900/40 rounded-xl p-4">
                  <div className="text-xs font-medium text-emerald-400">PASS</div>
                  <div className="text-2xl font-bold text-emerald-200 mt-1">{latestRun.pass_count}</div>
                  <div className="text-xs text-slate-500 mt-1">Sufficient proof</div>
                </div>
                <div className="bg-slate-900/80 border border-rose-900/40 rounded-xl p-4">
                  <div className="text-xs font-medium text-rose-400">FAIL</div>
                  <div className="text-2xl font-bold text-rose-200 mt-1">{latestRun.fail_count}</div>
                  <div className="text-xs text-slate-500 mt-1">Violations detected</div>
                </div>
                <div className="bg-slate-900/80 border border-amber-900/40 rounded-xl p-4">
                  <div className="text-xs font-medium text-amber-400">PARTIAL</div>
                  <div className="text-2xl font-bold text-amber-200 mt-1">{latestRun.partial_count}</div>
                  <div className="text-xs text-slate-500 mt-1">Incomplete proof</div>
                </div>
                <div className="bg-slate-900/80 border border-indigo-900/40 rounded-xl p-4">
                  <div className="text-xs font-medium text-indigo-400">UNKNOWN</div>
                  <div className="text-2xl font-bold text-indigo-200 mt-1">{latestRun.unknown_count}</div>
                  <div className="text-xs text-slate-500 mt-1">Missing evidence</div>
                </div>
                <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-4">
                  <div className="text-xs font-medium text-slate-400">N/A</div>
                  <div className="text-2xl font-bold text-slate-300 mt-1">{latestRun.not_applicable_count}</div>
                  <div className="text-xs text-slate-500 mt-1">Out of scope</div>
                </div>
                <div className="bg-slate-900/80 border border-red-950 rounded-xl p-4">
                  <div className="text-xs font-medium text-red-400">ERROR</div>
                  <div className="text-2xl font-bold text-red-300 mt-1">{latestRun.error_count}</div>
                  <div className="text-xs text-slate-500 mt-1">Catalog errors</div>
                </div>
              </div>

              {/* Integrity & Grounding Notice */}
              <div className="p-3 bg-blue-950/30 border border-blue-900/50 rounded-lg text-xs text-blue-300 flex items-center justify-between">
                <span>
                  <strong>Truthful Evaluation Principle:</strong> Insufficient or missing evidence produces{' '}
                  <code className="text-indigo-300 font-mono">UNKNOWN</code>, never <code className="text-emerald-300 font-mono">PASS</code>.
                  Evaluated at {new Date(latestRun.evaluated_at).toLocaleString()}.
                </span>
                <span className="font-mono text-slate-400">Provenance: {latestRun.provenance_digest.substring(0, 12)}</span>
              </div>

              {/* Detailed Results Table */}
              <div className="bg-slate-900/50 border border-slate-800 rounded-xl overflow-hidden">
                <div className="px-5 py-4 border-b border-slate-800 font-medium text-sm text-slate-200">
                  Control Evaluation Outcomes ({latestRun.control_results.length})
                </div>
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-sm">
                    <thead className="bg-slate-950 text-xs uppercase text-slate-400 border-b border-slate-800">
                      <tr>
                        <th className="px-5 py-3">Control ID</th>
                        <th className="px-5 py-3">Status</th>
                        <th className="px-5 py-3">Evidence-Grounded Reasoning</th>
                        <th className="px-5 py-3">Evidence Digests</th>
                        <th className="px-5 py-3">Missing Requirements</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/60 font-normal">
                      {latestRun.control_results.map((res) => (
                        <tr key={res.id} className="hover:bg-slate-800/30">
                          <td className="px-5 py-3.5 font-mono text-xs font-semibold text-slate-200 whitespace-nowrap">
                            {res.control_id}
                            <span className="text-slate-500 ml-1">v{res.control_version}</span>
                          </td>
                          <td className="px-5 py-3.5 whitespace-nowrap">
                            {getStatusBadge(res.status)}
                            {res.has_exception && (
                              <span className="ml-2 px-1.5 py-0.5 text-xs bg-amber-950/80 text-amber-300 border border-amber-800 rounded">
                                Exception
                              </span>
                            )}
                          </td>
                          <td className="px-5 py-3.5 text-slate-300 max-w-md">
                            {res.reasoning}
                          </td>
                          <td className="px-5 py-3.5 font-mono text-xs text-slate-400 whitespace-nowrap">
                            {res.evidence_digests.length > 0 ? (
                              <span title={res.evidence_digests.join(', ')}>
                                {res.evidence_digests.length} digest(s) ({res.evidence_digests[0].substring(0, 8)}...)
                              </span>
                            ) : (
                              <span className="text-slate-600">None</span>
                            )}
                          </td>
                          <td className="px-5 py-3.5 text-xs">
                            {res.missing_evidence_types.length > 0 ? (
                              <div className="flex flex-wrap gap-1">
                                {res.missing_evidence_types.map((m, idx) => (
                                  <span key={idx} className="px-1.5 py-0.5 bg-indigo-950 text-indigo-300 rounded border border-indigo-900 text-xs">
                                    {m}
                                  </span>
                                ))}
                              </div>
                            ) : (
                              <span className="text-emerald-500 text-xs">Complete</span>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>

              {/* Historical Evaluation Runs */}
              {evalRuns.length > 1 && (
                <div className="bg-slate-900/40 border border-slate-800 rounded-xl p-4">
                  <div className="text-xs font-semibold text-slate-300 mb-2 uppercase tracking-wider">
                    Historical Evaluation Runs ({evalRuns.length})
                  </div>
                  <div className="space-y-2">
                    {evalRuns.map((r) => (
                      <div
                        key={r.id}
                        onClick={() => setLatestRun(r)}
                        className={`p-3 rounded-lg border text-xs flex items-center justify-between cursor-pointer transition ${
                          latestRun.id === r.id
                            ? 'bg-blue-950/40 border-blue-700 text-blue-200'
                            : 'bg-slate-950/40 border-slate-800/80 text-slate-300 hover:bg-slate-800/40'
                        }`}
                      >
                        <div className="flex items-center gap-3">
                          <span className="font-mono text-slate-400">Digest: {r.provenance_digest.substring(0, 10)}...</span>
                          <span className="text-slate-500">|</span>
                          <span className="text-emerald-400 font-semibold">{r.pass_count} PASS</span>
                          <span className="text-rose-400 font-semibold">{r.fail_count} FAIL</span>
                          <span className="text-indigo-400 font-semibold">{r.unknown_count} UNKNOWN</span>
                        </div>
                        <div className="text-slate-500">
                          {new Date(r.evaluated_at).toLocaleString()}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          ) : (
            <div className="p-12 text-center bg-slate-900/30 border border-dashed border-slate-800 rounded-xl">
              <p className="text-slate-400 text-sm">No baseline evaluations run yet for this workspace.</p>
              <button
                onClick={handleEvaluate}
                disabled={evaluating || !selectedProfileId}
                className="mt-4 px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white text-sm font-medium rounded-lg"
              >
                Run First Evaluation
              </button>
            </div>
          )}
        </div>
      )}

      {/* Tab 2: Controls Catalog */}
      {activeTab === 'catalog' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-lg font-semibold text-white">Versioned Security Requirements Catalog</h2>
            <span className="text-xs text-slate-400">Total Controls: {controls.length}</span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {controls.map((ctrl) => (
              <div key={ctrl.id} className="bg-slate-900/70 border border-slate-800 rounded-xl p-5 space-y-3">
                <div className="flex items-start justify-between">
                  <div>
                    <span className="font-mono text-xs font-bold text-blue-400">{ctrl.control_id}</span>
                    <span className="text-xs text-slate-500 ml-2">v{ctrl.version}</span>
                    <h3 className="font-medium text-white text-base mt-0.5">{ctrl.title}</h3>
                  </div>
                  <span className={`px-2 py-0.5 text-xs rounded font-semibold ${
                    ctrl.severity === 'CRITICAL' ? 'bg-red-950 text-red-300 border border-red-800' :
                    ctrl.severity === 'HIGH' ? 'bg-orange-950 text-orange-300 border border-orange-800' :
                    'bg-slate-800 text-slate-300 border border-slate-700'
                  }`}>
                    {ctrl.severity}
                  </span>
                </div>

                <p className="text-xs text-slate-300 leading-relaxed">{ctrl.requirement_statement}</p>

                <div className="pt-2 border-t border-slate-800/80 flex flex-wrap items-center gap-x-4 gap-y-2 text-xs text-slate-400">
                  <div>
                    <span className="text-slate-500">Framework:</span> {ctrl.framework} {ctrl.framework_reference}
                  </div>
                  <div>
                    <span className="text-slate-500">Category:</span> {ctrl.category}
                  </div>
                  <div>
                    <span className="text-slate-500">Rule:</span> <code className="text-slate-300 font-mono">{ctrl.evaluation_rule}</code>
                  </div>
                </div>

                <div className="text-xs text-slate-400">
                  <span className="text-slate-500">Required Evidence:</span>{' '}
                  {ctrl.required_evidence_types.map((ev, i) => (
                    <span key={i} className="inline-block px-1.5 py-0.5 bg-slate-800 text-slate-300 rounded text-xs mr-1">
                      {ev}
                    </span>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Tab 3: Baseline Profiles */}
      {activeTab === 'baselines' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-lg font-semibold text-white">Configured Security Baseline Profiles</h2>
            <span className="text-xs text-slate-400">Total Profiles: {profiles.length}</span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {profiles.map((p) => (
              <div key={p.id} className="bg-slate-900/70 border border-slate-800 rounded-xl p-5 space-y-3">
                <div className="flex items-start justify-between">
                  <div>
                    <span className="font-mono text-xs font-bold text-emerald-400">{p.profile_key}</span>
                    <span className="text-xs text-slate-500 ml-2">v{p.version}</span>
                    <h3 className="font-medium text-white text-base mt-0.5">{p.name}</h3>
                  </div>
                  <span className="px-2 py-0.5 text-xs rounded bg-emerald-950 text-emerald-300 border border-emerald-800 font-medium">
                    ACTIVE
                  </span>
                </div>

                <p className="text-xs text-slate-300">{p.description}</p>

                <div className="pt-2 border-t border-slate-800 text-xs">
                  <div className="text-slate-400 mb-1">Included Controls ({p.control_ids.length}):</div>
                  <div className="flex flex-wrap gap-1.5">
                    {p.control_ids.map((cid) => (
                      <span key={cid} className="px-2 py-0.5 bg-slate-800 text-slate-200 font-mono text-xs rounded border border-slate-700">
                        {cid}
                      </span>
                    ))}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Tab 4: Configuration Drift */}
      {activeTab === 'drift' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-lg font-semibold text-white">Configuration & Evidence Drift Timeline</h2>
              <p className="text-xs text-slate-400">Idempotently tracked state transitions and evidence regressions.</p>
            </div>
          </div>

          {driftEvents.length > 0 ? (
            <div className="space-y-3">
              {driftEvents.map((d) => (
                <div key={d.id} className="bg-slate-900/70 border border-slate-800 rounded-xl p-4 flex flex-col md:flex-row md:items-center justify-between gap-3">
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <span className={`px-2 py-0.5 text-xs font-bold rounded ${
                        d.drift_type === 'REGRESSION_FAIL' ? 'bg-rose-950 text-rose-300 border border-rose-800' :
                        d.drift_type === 'EVIDENCE_DISAPPEARED_UNKNOWN' ? 'bg-indigo-950 text-indigo-300 border border-indigo-800' :
                        'bg-emerald-950 text-emerald-300 border border-emerald-800'
                      }`}>
                        {d.drift_type}
                      </span>
                      <span className="font-mono text-xs font-semibold text-white">{d.control_id}</span>
                      <span className="text-xs text-slate-500">
                        {d.previous_status} &rarr; {d.new_status}
                      </span>
                    </div>
                    <p className="text-xs text-slate-300">{d.reason}</p>
                  </div>
                  <div className="text-right text-xs text-slate-500 whitespace-nowrap">
                    <div>{new Date(d.detected_at).toLocaleString()}</div>
                    <div className="font-mono text-[10px] text-slate-600 mt-0.5">Hash: {d.deduplication_hash.substring(0, 12)}...</div>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="p-8 text-center bg-slate-900/30 border border-slate-800 rounded-xl text-slate-400 text-xs">
              No configuration or evidence drift events detected yet.
            </div>
          )}
        </div>
      )}

      {/* Tab 5: Exceptions & Separation of Duties */}
      {activeTab === 'exceptions' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-lg font-semibold text-white">Controlled Baseline Exceptions</h2>
              <p className="text-xs text-slate-400">Time-bounded security exceptions governed with Separation of Duties.</p>
            </div>
            <button
              onClick={() => setShowExceptionModal(true)}
              className="px-3 py-1.5 bg-blue-600 hover:bg-blue-500 text-white text-xs font-medium rounded-lg shadow"
            >
              + Request Exception
            </button>
          </div>

          {exceptions.length > 0 ? (
            <div className="space-y-3">
              {exceptions.map((exc) => (
                <div key={exc.id} className="bg-slate-900/70 border border-slate-800 rounded-xl p-5 space-y-3">
                  <div className="flex items-start justify-between">
                    <div>
                      <span className="font-mono text-xs font-bold text-blue-400">{exc.control_id}</span>
                      <span className={`ml-2 px-2 py-0.5 text-xs font-bold rounded ${
                        exc.status === 'APPROVED' ? 'bg-emerald-950 text-emerald-300 border border-emerald-800' :
                        exc.status === 'REQUESTED' ? 'bg-amber-950 text-amber-300 border border-amber-800' :
                        exc.status === 'EXPIRED' ? 'bg-slate-800 text-slate-400 border border-slate-700' :
                        'bg-rose-950 text-rose-300 border border-rose-800'
                      }`}>
                        {exc.status}
                      </span>
                    </div>

                    <div className="text-xs text-slate-400">
                      Expires: {new Date(exc.expires_at).toLocaleDateString()}
                    </div>
                  </div>

                  <div className="text-xs space-y-1.5">
                    <div><span className="text-slate-500">Justification:</span> <span className="text-slate-300">{exc.justification}</span></div>
                    <div><span className="text-slate-500">Risk Assessment:</span> <span className="text-slate-300">{exc.risk_assessment}</span></div>
                    <div><span className="text-slate-500">Compensating Controls:</span> <span className="text-slate-300">{exc.compensating_controls}</span></div>
                  </div>

                  {exc.status === 'REQUESTED' && (
                    <div className="pt-3 border-t border-slate-800 flex items-center justify-between">
                      <span className="text-xs text-amber-400/80">
                        * Separation of duties enforced: Requester cannot approve their own request.
                      </span>
                      <div className="flex gap-2">
                        <button
                          onClick={() => handleReviewException(exc.id, false)}
                          className="px-2.5 py-1 text-xs bg-rose-900/60 hover:bg-rose-900 text-rose-300 rounded border border-rose-800"
                        >
                          Reject
                        </button>
                        <button
                          onClick={() => handleReviewException(exc.id, true)}
                          className="px-2.5 py-1 text-xs bg-emerald-900/60 hover:bg-emerald-900 text-emerald-300 rounded border border-emerald-800"
                        >
                          Approve Exception
                        </button>
                      </div>
                    </div>
                  )}
                </div>
              ))}
            </div>
          ) : (
            <div className="p-8 text-center bg-slate-900/30 border border-slate-800 rounded-xl text-slate-400 text-xs">
              No active or historical exceptions requested.
            </div>
          )}

          {/* Modal Form */}
          {showExceptionModal && (
            <div className="fixed inset-0 bg-black/70 flex items-center justify-center p-4 z-50">
              <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 max-w-lg w-full space-y-4">
                <h3 className="text-lg font-semibold text-white">Request Time-Bounded Exception</h3>
                <form onSubmit={handleRequestException} className="space-y-3">
                  <div>
                    <label className="text-xs text-slate-400 block mb-1">Target Control:</label>
                    <select
                      value={excControlId}
                      onChange={(e) => setExcControlId(e.target.value)}
                      required
                      className="w-full bg-slate-950 border border-slate-700 text-sm rounded-lg px-3 py-2 text-slate-200"
                    >
                      <option value="">Select a control...</option>
                      {controls.map((c) => (
                        <option key={c.control_id} value={c.control_id}>{c.control_id} - {c.title}</option>
                      ))}
                    </select>
                  </div>
                  <div>
                    <label className="text-xs text-slate-400 block mb-1">Business Justification:</label>
                    <textarea
                      value={excJustification}
                      onChange={(e) => setExcJustification(e.target.value)}
                      required
                      rows={2}
                      className="w-full bg-slate-950 border border-slate-700 text-sm rounded-lg px-3 py-2 text-slate-200"
                      placeholder="Why cannot this control be immediately satisfied?"
                    />
                  </div>
                  <div>
                    <label className="text-xs text-slate-400 block mb-1">Risk Assessment:</label>
                    <textarea
                      value={excRiskAssessment}
                      onChange={(e) => setExcRiskAssessment(e.target.value)}
                      required
                      rows={2}
                      className="w-full bg-slate-950 border border-slate-700 text-sm rounded-lg px-3 py-2 text-slate-200"
                      placeholder="Evaluated risk during exception window"
                    />
                  </div>
                  <div>
                    <label className="text-xs text-slate-400 block mb-1">Compensating Controls:</label>
                    <textarea
                      value={excCompensatingControls}
                      onChange={(e) => setExcCompensatingControls(e.target.value)}
                      required
                      rows={2}
                      className="w-full bg-slate-950 border border-slate-700 text-sm rounded-lg px-3 py-2 text-slate-200"
                      placeholder="Active mitigations, e.g. WAF, IP restrictions, mTLS"
                    />
                  </div>
                  <div>
                    <label className="text-xs text-slate-400 block mb-1">Duration (Days):</label>
                    <input
                      type="number"
                      min={1}
                      max={90}
                      value={excDays}
                      onChange={(e) => setExcDays(parseInt(e.target.value) || 30)}
                      className="w-full bg-slate-950 border border-slate-700 text-sm rounded-lg px-3 py-2 text-slate-200"
                    />
                  </div>
                  <div className="pt-2 flex justify-end gap-2">
                    <button
                      type="button"
                      onClick={() => setShowExceptionModal(false)}
                      className="px-4 py-2 bg-slate-800 text-slate-300 text-sm rounded-lg"
                    >
                      Cancel
                    </button>
                    <button
                      type="submit"
                      disabled={loading}
                      className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white text-sm font-medium rounded-lg"
                    >
                      Submit Request
                    </button>
                  </div>
                </form>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
