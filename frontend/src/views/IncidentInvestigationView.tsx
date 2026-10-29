import React, { useState, useEffect } from 'react';
import { api } from '../services/api';
import type {
  IncidentCaseSummary,
  IncidentCaseDetail,
  CorrelationExplanation,
  TimelineEvent,
  CaseSeverity,
  CaseStatus,
} from '../types';

interface IncidentInvestigationViewProps {
  projectId: string;
}

export const IncidentInvestigationView: React.FC<IncidentInvestigationViewProps> = ({ projectId }) => {
  const [cases, setCases] = useState<IncidentCaseSummary[]>([]);
  const [selectedCaseId, setSelectedCaseId] = useState<string | null>(null);
  const [caseDetail, setCaseDetail] = useState<IncidentCaseDetail | null>(null);
  const [correlations, setCorrelations] = useState<CorrelationExplanation | null>(null);
  const [timeline, setTimeline] = useState<TimelineEvent[]>([]);

  const [activeTab, setActiveTab] = useState<'correlations' | 'artifacts' | 'evidence' | 'timeline'>('correlations');
  const [statusFilter, setStatusFilter] = useState<string>('');

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  // New Case Modal State
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [newTitle, setNewTitle] = useState('');
  const [newDescription, setNewDescription] = useState('');
  const [newSeverity, setNewSeverity] = useState<CaseSeverity>('HIGH');
  const [newTeam, setNewTeam] = useState('SOC-Tier2');

  // Status Transition Modal State
  const [showTransitionModal, setShowTransitionModal] = useState(false);
  const [targetStatus, setTargetStatus] = useState<CaseStatus>('TRIAGED');
  const [transitionReason, setTransitionReason] = useState('');
  const [closureSummary, setClosureSummary] = useState('');
  const [reopeningRationale, setReopeningRationale] = useState('');

  // Add Note State
  const [noteContent, setNoteContent] = useState('');
  const [isAlternativeHypothesis, setIsAlternativeHypothesis] = useState(false);

  const loadCases = async () => {
    try {
      setLoading(true);
      setError(null);
      const data = await api.listIncidentCases(projectId, statusFilter || undefined);
      setCases(data);
      if (data.length > 0 && !selectedCaseId) {
        setSelectedCaseId(data[0].id);
      }
    } catch (err: any) {
      setError(err.message || 'Failed to load incident cases');
    } finally {
      setLoading(false);
    }
  };

  const loadCaseDetail = async (caseId: string) => {
    try {
      setLoading(true);
      setError(null);
      const [detail, corr, time] = await Promise.all([
        api.getIncidentCase(projectId, caseId),
        api.getCaseCorrelations(projectId, caseId).catch(() => null),
        api.getCaseTimeline(projectId, caseId).catch(() => []),
      ]);
      setCaseDetail(detail);
      setCorrelations(corr);
      setTimeline(time);
    } catch (err: any) {
      setError(err.message || 'Failed to load case detail');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadCases();
  }, [projectId, statusFilter]);

  useEffect(() => {
    if (selectedCaseId) {
      loadCaseDetail(selectedCaseId);
    }
  }, [selectedCaseId]);

  const handleCreateCase = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      setLoading(true);
      setError(null);
      const created = await api.createIncidentCase(projectId, {
        title: newTitle,
        description: newDescription,
        severity: newSeverity,
        assigned_team: newTeam,
      });
      setSuccess(`Incident Case ${created.case_number} created successfully.`);
      setShowCreateModal(false);
      setNewTitle('');
      setNewDescription('');
      setSelectedCaseId(created.id);
      await loadCases();
    } catch (err: any) {
      setError(err.message || 'Failed to create case');
    } finally {
      setLoading(false);
    }
  };

  const handleTransitionSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!caseDetail) return;
    try {
      setLoading(true);
      setError(null);
      await api.transitionCaseStatus(projectId, caseDetail.id, {
        to_status: targetStatus,
        reason: transitionReason,
        closure_summary: targetStatus === 'CLOSED' ? closureSummary : undefined,
        reopening_rationale: targetStatus === 'REOPENED' ? reopeningRationale : undefined,
      });
      setSuccess(`Case transitioned to ${targetStatus}.`);
      setShowTransitionModal(false);
      setTransitionReason('');
      setClosureSummary('');
      setReopeningRationale('');
      await loadCaseDetail(caseDetail.id);
      await loadCases();
    } catch (err: any) {
      setError(err.message || 'Transition failed');
    } finally {
      setLoading(false);
    }
  };

  const handleAddNote = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!caseDetail || !noteContent.trim()) return;
    try {
      setLoading(true);
      setError(null);
      await api.addCaseNote(projectId, caseDetail.id, {
        content: noteContent.trim(),
        note_type: isAlternativeHypothesis ? 'ALTERNATIVE_HYPOTHESIS' : 'ANALYST_OBSERVATION',
        is_alternative_hypothesis: isAlternativeHypothesis,
      });
      setSuccess('Investigation note recorded.');
      setNoteContent('');
      setIsAlternativeHypothesis(false);
      await loadCaseDetail(caseDetail.id);
    } catch (err: any) {
      setError(err.message || 'Failed to add note');
    } finally {
      setLoading(false);
    }
  };

  const getSeverityBadge = (sev: CaseSeverity) => {
    switch (sev) {
      case 'CRITICAL':
        return 'bg-red-900/60 text-red-300 border-red-700/60';
      case 'HIGH':
        return 'bg-orange-900/60 text-orange-300 border-orange-700/60';
      case 'MEDIUM':
        return 'bg-amber-900/60 text-amber-300 border-amber-700/60';
      case 'LOW':
        return 'bg-blue-900/60 text-blue-300 border-blue-700/60';
      default:
        return 'bg-slate-800 text-slate-300 border-slate-700';
    }
  };

  const getStatusBadge = (st: CaseStatus) => {
    switch (st) {
      case 'OPEN':
        return 'bg-emerald-900/60 text-emerald-300';
      case 'TRIAGED':
        return 'bg-blue-900/60 text-blue-300';
      case 'INVESTIGATING':
        return 'bg-purple-900/60 text-purple-300';
      case 'CONTAINED':
        return 'bg-teal-900/60 text-teal-300';
      case 'CLOSED':
        return 'bg-slate-800 text-slate-400';
      case 'REOPENED':
        return 'bg-rose-900/60 text-rose-300';
      default:
        return 'bg-slate-800 text-slate-300';
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="bg-slate-900 border border-slate-800 rounded-lg p-6 shadow-sm">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <h1 className="text-2xl font-bold text-white tracking-tight flex items-center gap-2">
              <span className="text-rose-400">🛡️</span> Security Incident Investigation & Case Management
            </h1>
            <p className="text-sm text-slate-400 mt-1">
              Evidence-preserving case cockpit connecting observations into reviewable cases without confusing correlation with confirmed causation.
            </p>
          </div>
          <div className="flex items-center gap-3">
            <button
              onClick={() => setShowCreateModal(true)}
              className="px-4 py-2 bg-rose-600 hover:bg-rose-500 text-white text-xs font-semibold rounded-md shadow transition"
            >
              + New Incident Case
            </button>
            <button
              onClick={() => {
                loadCases();
                if (selectedCaseId) loadCaseDetail(selectedCaseId);
              }}
              disabled={loading}
              className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold rounded-md border border-slate-700 transition"
            >
              {loading ? 'Refreshing...' : '↻ Refresh'}
            </button>
          </div>
        </div>

        {/* Notifications */}
        {error && (
          <div className="mt-4 p-3 bg-red-900/40 border border-red-700/60 rounded text-red-200 text-xs">
            {error}
          </div>
        )}
        {success && (
          <div className="mt-4 p-3 bg-emerald-900/40 border border-emerald-700/60 rounded text-emerald-200 text-xs">
            {success}
          </div>
        )}
      </div>

      {/* Main Workspace Layout */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Column: Cases List */}
        <div className="lg:col-span-1 space-y-4">
          <div className="bg-slate-900 border border-slate-800 rounded-lg p-4 shadow-sm">
            <div className="flex items-center justify-between mb-3">
              <h2 className="text-sm font-semibold text-white">Active Cases ({cases.length})</h2>
              <select
                value={statusFilter}
                onChange={(e) => setStatusFilter(e.target.value)}
                className="bg-slate-950 border border-slate-800 rounded px-2 py-1 text-xs text-slate-300"
              >
                <option value="">All Statuses</option>
                <option value="OPEN">OPEN</option>
                <option value="TRIAGED">TRIAGED</option>
                <option value="INVESTIGATING">INVESTIGATING</option>
                <option value="CONTAINED">CONTAINED</option>
                <option value="CLOSED">CLOSED</option>
                <option value="REOPENED">REOPENED</option>
              </select>
            </div>

            {cases.length === 0 ? (
              <p className="text-xs text-slate-500 italic py-8 text-center">No incident cases found.</p>
            ) : (
              <div className="space-y-2 max-h-[680px] overflow-y-auto pr-1">
                {cases.map((c) => (
                  <div
                    key={c.id}
                    onClick={() => setSelectedCaseId(c.id)}
                    className={`p-3 rounded-lg border cursor-pointer transition ${
                      selectedCaseId === c.id
                        ? 'bg-slate-800/80 border-rose-500/80 shadow'
                        : 'bg-slate-950 border-slate-800 hover:border-slate-700'
                    }`}
                  >
                    <div className="flex items-center justify-between mb-1">
                      <span className="font-mono text-xs font-bold text-white">{c.case_number}</span>
                      <span className={`text-[10px] px-2 py-0.5 rounded font-bold ${getStatusBadge(c.status)}`}>
                        {c.status}
                      </span>
                    </div>
                    <div className="text-xs font-medium text-slate-200 truncate">{c.title}</div>
                    <div className="flex items-center justify-between mt-2 text-[10px]">
                      <span className={`px-1.5 py-0.5 rounded border font-semibold ${getSeverityBadge(c.severity)}`}>
                        {c.severity}
                      </span>
                      <span className="text-slate-500">{new Date(c.opened_at).toLocaleDateString()}</span>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Right Columns: Case Investigation Cockpit */}
        <div className="lg:col-span-2 space-y-4">
          {caseDetail ? (
            <div className="bg-slate-900 border border-slate-800 rounded-lg p-6 shadow-sm space-y-6">
              {/* Case Header & Quick Actions */}
              <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4 pb-4 border-b border-slate-800">
                <div>
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-sm font-bold text-rose-400">{caseDetail.case_number}</span>
                    <span className={`text-xs px-2 py-0.5 rounded font-bold ${getStatusBadge(caseDetail.status)}`}>
                      {caseDetail.status}
                    </span>
                    <span className={`text-xs px-2 py-0.5 rounded border font-semibold ${getSeverityBadge(caseDetail.severity)}`}>
                      {caseDetail.severity}
                    </span>
                  </div>
                  <h2 className="text-lg font-bold text-white mt-1">{caseDetail.title}</h2>
                  <p className="text-xs text-slate-400 mt-1">{caseDetail.description || 'No description provided.'}</p>
                </div>
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => {
                      setTargetStatus(caseDetail.status === 'CLOSED' ? 'REOPENED' : 'CLOSED');
                      setShowTransitionModal(true);
                    }}
                    className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-white text-xs font-medium rounded border border-slate-700 transition"
                  >
                    Transition Status
                  </button>
                </div>
              </div>

              {/* Sub-Tabs */}
              <div className="flex flex-wrap gap-2 border-b border-slate-800 pb-2">
                <button
                  onClick={() => setActiveTab('correlations')}
                  className={`px-3 py-1.5 rounded text-xs font-medium transition ${
                    activeTab === 'correlations' ? 'bg-rose-600 text-white shadow' : 'bg-slate-800/60 text-slate-400 hover:text-white'
                  }`}
                >
                  Correlation & Causation Inspector
                </button>
                <button
                  onClick={() => setActiveTab('artifacts')}
                  className={`px-3 py-1.5 rounded text-xs font-medium transition ${
                    activeTab === 'artifacts' ? 'bg-rose-600 text-white shadow' : 'bg-slate-800/60 text-slate-400 hover:text-white'
                  }`}
                >
                  Linked Assets ({caseDetail.linked_assets.length}) & Findings ({caseDetail.linked_findings.length})
                </button>
                <button
                  onClick={() => setActiveTab('evidence')}
                  className={`px-3 py-1.5 rounded text-xs font-medium transition ${
                    activeTab === 'evidence' ? 'bg-rose-600 text-white shadow' : 'bg-slate-800/60 text-slate-400 hover:text-white'
                  }`}
                >
                  Evidence Vault ({caseDetail.linked_evidence.length}) & Notes ({caseDetail.notes.length})
                </button>
                <button
                  onClick={() => setActiveTab('timeline')}
                  className={`px-3 py-1.5 rounded text-xs font-medium transition ${
                    activeTab === 'timeline' ? 'bg-rose-600 text-white shadow' : 'bg-slate-800/60 text-slate-400 hover:text-white'
                  }`}
                >
                  Investigation Timeline ({timeline.length})
                </button>
              </div>

              {/* Sub-Tab 1: Correlation & Causation Inspector */}
              {activeTab === 'correlations' && (
                <div className="space-y-4">
                  {correlations ? (
                    <div className="space-y-4">
                      <div className="p-3 bg-slate-950 border border-slate-800 rounded text-xs text-slate-300">
                        <span className="font-semibold text-white">Epistemic Rule (Prompt 39 Req 4, 5):</span> {correlations.correlation_summary}
                      </div>

                      {/* Confirmed Causation */}
                      <div className="bg-slate-950 border border-emerald-900/40 rounded-lg p-4">
                        <h3 className="text-xs font-bold text-emerald-400 mb-2 flex items-center gap-1.5">
                          <span>✓</span> Confirmed Causation ({correlations.confirmed_causation.length})
                        </h3>
                        {correlations.confirmed_causation.length === 0 ? (
                          <p className="text-xs text-slate-500 italic">No confirmed causal links identified yet.</p>
                        ) : (
                          <div className="space-y-2">
                            {correlations.confirmed_causation.map((c, i) => (
                              <div key={i} className="p-2.5 bg-slate-900 border border-slate-800 rounded text-xs">
                                <div className="font-semibold text-white">{c.title}</div>
                                <div className="text-slate-400 mt-1">{c.rationale}</div>
                                <div className="text-[10px] text-emerald-400 mt-1 font-mono">Confidence: {(c.confidence * 100).toFixed(0)}%</div>
                              </div>
                            ))}
                          </div>
                        )}
                      </div>

                      {/* Temporal Coincidence (Not Causation) */}
                      <div className="bg-slate-950 border border-amber-900/40 rounded-lg p-4">
                        <h3 className="text-xs font-bold text-amber-400 mb-2 flex items-center gap-1.5">
                          <span>⏱️</span> Temporal Coincidences ({correlations.temporal_coincidences.length})
                        </h3>
                        <p className="text-[11px] text-slate-400 mb-2">
                          Events observed in the same time window but lacking confirmed telemetry or direct causal overlap.
                        </p>
                        {correlations.temporal_coincidences.length === 0 ? (
                          <p className="text-xs text-slate-500 italic">No unconfirmed temporal coincidences.</p>
                        ) : (
                          <div className="space-y-2">
                            {correlations.temporal_coincidences.map((c, i) => (
                              <div key={i} className="p-2.5 bg-slate-900 border border-slate-800 rounded text-xs">
                                <div className="font-semibold text-white">{c.title}</div>
                                <div className="text-slate-400 mt-1">{c.rationale}</div>
                                <div className="text-[10px] text-amber-400 mt-1 font-mono">Correlation Confidence: {(c.confidence * 100).toFixed(0)}%</div>
                              </div>
                            ))}
                          </div>
                        )}
                      </div>

                      {/* Contradictory Evidence & Alternative Hypotheses */}
                      <div className="bg-slate-950 border border-rose-900/40 rounded-lg p-4">
                        <h3 className="text-xs font-bold text-rose-400 mb-2 flex items-center gap-1.5">
                          <span>⚡</span> Contradictory Evidence & Alternative Hypotheses ({correlations.alternative_hypotheses_count})
                        </h3>
                        {caseDetail.alternative_explanations.length === 0 ? (
                          <p className="text-xs text-slate-500 italic">No alternative explanations recorded.</p>
                        ) : (
                          <div className="space-y-2">
                            {caseDetail.alternative_explanations.map((alt, i) => (
                              <div key={i} className="p-2.5 bg-slate-900 border border-slate-800 rounded text-xs">
                                <div className="text-slate-200">{alt.hypothesis}</div>
                                <div className="text-[10px] text-slate-500 mt-1 font-mono">Recorded: {new Date(alt.recorded_at).toLocaleString()}</div>
                              </div>
                            ))}
                          </div>
                        )}
                      </div>
                    </div>
                  ) : (
                    <p className="text-xs text-slate-500 italic py-6 text-center">Loading correlation intelligence...</p>
                  )}
                </div>
              )}

              {/* Sub-Tab 2: Linked Assets & Findings */}
              {activeTab === 'artifacts' && (
                <div className="space-y-6">
                  <div>
                    <h3 className="text-xs font-bold text-white mb-2">Linked Assets ({caseDetail.linked_assets.length})</h3>
                    {caseDetail.linked_assets.length === 0 ? (
                      <p className="text-xs text-slate-500 italic">No assets linked to this case yet.</p>
                    ) : (
                      <table className="w-full text-left text-xs border-collapse">
                        <thead>
                          <tr className="border-b border-slate-800 text-slate-400">
                            <th className="py-2">Relationship Type</th>
                            <th className="py-2">Confidence</th>
                            <th className="py-2">Contradictory</th>
                            <th className="py-2">Notes</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-800/60">
                          {caseDetail.linked_assets.map((a) => (
                            <tr key={a.id}>
                              <td className="py-2.5 font-medium text-white">{a.relationship_type}</td>
                              <td className="py-2.5 font-mono text-slate-300">{(a.confidence * 100).toFixed(0)}%</td>
                              <td className="py-2.5">
                                {a.is_contradictory ? (
                                  <span className="px-1.5 py-0.5 bg-rose-900/60 text-rose-300 text-[10px] rounded font-bold">YES</span>
                                ) : (
                                  <span className="text-slate-500 text-[10px]">NO</span>
                                )}
                              </td>
                              <td className="py-2.5 text-slate-400">{a.notes || '—'}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    )}
                  </div>

                  <div>
                    <h3 className="text-xs font-bold text-white mb-2">Linked Findings ({caseDetail.linked_findings.length})</h3>
                    {caseDetail.linked_findings.length === 0 ? (
                      <p className="text-xs text-slate-500 italic">No findings linked to this case yet.</p>
                    ) : (
                      <table className="w-full text-left text-xs border-collapse">
                        <thead>
                          <tr className="border-b border-slate-800 text-slate-400">
                            <th className="py-2">Correlation Type</th>
                            <th className="py-2">Confidence</th>
                            <th className="py-2">Rationale</th>
                          </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-800/60">
                          {caseDetail.linked_findings.map((f) => (
                            <tr key={f.id}>
                              <td className="py-2.5 font-medium text-white">{f.correlation_type}</td>
                              <td className="py-2.5 font-mono text-slate-300">{(f.confidence * 100).toFixed(0)}%</td>
                              <td className="py-2.5 text-slate-400">{f.rationale || '—'}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    )}
                  </div>
                </div>
              )}

              {/* Sub-Tab 3: Evidence Vault & Notes */}
              {activeTab === 'evidence' && (
                <div className="space-y-6">
                  <div>
                    <h3 className="text-xs font-bold text-white mb-2">Immutable Evidence Snapshots ({caseDetail.linked_evidence.length})</h3>
                    {caseDetail.linked_evidence.length === 0 ? (
                      <p className="text-xs text-slate-500 italic">No evidence snapshots attached yet.</p>
                    ) : (
                      <div className="space-y-2">
                        {caseDetail.linked_evidence.map((ev) => (
                          <div key={ev.id} className="p-3 bg-slate-950 border border-slate-800 rounded text-xs space-y-1">
                            <div className="flex items-center justify-between">
                              <span className="font-semibold text-white">{ev.evidence_summary}</span>
                              {ev.is_contradictory && (
                                <span className="px-2 py-0.5 bg-rose-900/60 text-rose-300 rounded text-[10px] font-bold">
                                  CONTRADICTORY EVIDENCE
                                </span>
                              )}
                            </div>
                            <div className="font-mono text-[10px] text-slate-500 truncate">SHA256: {ev.evidence_digest}</div>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>

                  {/* Add Analyst Note Form */}
                  <div className="p-4 bg-slate-950 border border-slate-800 rounded-lg space-y-3">
                    <h3 className="text-xs font-bold text-white">Record Analyst Note or Alternative Hypothesis</h3>
                    <form onSubmit={handleAddNote} className="space-y-3">
                      <textarea
                        value={noteContent}
                        onChange={(e) => setNoteContent(e.target.value)}
                        placeholder="Document observations, working hypotheses, or task logs..."
                        className="w-full bg-slate-900 border border-slate-800 rounded px-3 py-2 text-xs text-white"
                        rows={3}
                        required
                      />
                      <div className="flex items-center justify-between">
                        <label className="flex items-center gap-2 text-xs text-slate-400">
                          <input
                            type="checkbox"
                            checked={isAlternativeHypothesis}
                            onChange={(e) => setIsAlternativeHypothesis(e.target.checked)}
                            className="rounded bg-slate-900 border-slate-800 text-rose-600 focus:ring-0"
                          />
                          Mark as Alternative Hypothesis / Contradictory Explanation
                        </label>
                        <button
                          type="submit"
                          disabled={loading || !noteContent.trim()}
                          className="px-3 py-1.5 bg-rose-600 hover:bg-rose-500 text-white text-xs font-semibold rounded transition"
                        >
                          Record Note
                        </button>
                      </div>
                    </form>
                  </div>
                </div>
              )}

              {/* Sub-Tab 4: Timeline */}
              {activeTab === 'timeline' && (
                <div className="space-y-3">
                  <h3 className="text-xs font-bold text-white mb-2">Investigation Timeline with Provenance</h3>
                  {timeline.length === 0 ? (
                    <p className="text-xs text-slate-500 italic py-6 text-center">No timeline events recorded.</p>
                  ) : (
                    <div className="space-y-3 pl-4 border-l-2 border-slate-800">
                      {timeline.map((t, idx) => (
                        <div key={idx} className="relative group">
                          <div className="absolute -left-[21px] top-1.5 w-2.5 h-2.5 rounded-full bg-rose-500"></div>
                          <div className="text-[11px] text-slate-400 font-mono">{new Date(t.timestamp).toLocaleString()}</div>
                          <div className="text-xs font-semibold text-white mt-0.5">{t.summary}</div>
                          {t.details?.reason && (
                            <div className="text-xs text-slate-400 mt-1 italic">Reason: {t.details.reason}</div>
                          )}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </div>
          ) : (
            <div className="bg-slate-900 border border-slate-800 rounded-lg p-12 text-center text-xs text-slate-500 italic">
              Select an incident case on the left to inspect correlation intelligence and evidence.
            </div>
          )}
        </div>
      </div>

      {/* New Case Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center p-4 z-50">
          <div className="bg-slate-900 border border-slate-800 rounded-lg p-6 max-w-md w-full space-y-4">
            <h3 className="text-base font-bold text-white">Create New Security Incident Case</h3>
            <form onSubmit={handleCreateCase} className="space-y-4">
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">Title</label>
                <input
                  type="text"
                  value={newTitle}
                  onChange={(e) => setNewTitle(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-xs text-white"
                  placeholder="e.g. Exploited SQL Injection on External Auth API"
                  required
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">Severity</label>
                <select
                  value={newSeverity}
                  onChange={(e) => setNewSeverity(e.target.value as CaseSeverity)}
                  className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-xs text-white"
                >
                  <option value="CRITICAL">CRITICAL</option>
                  <option value="HIGH">HIGH</option>
                  <option value="MEDIUM">MEDIUM</option>
                  <option value="LOW">LOW</option>
                  <option value="INFORMATIONAL">INFORMATIONAL</option>
                </select>
              </div>
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">Assigned Team</label>
                <input
                  type="text"
                  value={newTeam}
                  onChange={(e) => setNewTeam(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-xs text-white"
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">Description</label>
                <textarea
                  value={newDescription}
                  onChange={(e) => setNewDescription(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-xs text-white"
                  rows={3}
                />
              </div>
              <div className="flex justify-end gap-2">
                <button
                  type="button"
                  onClick={() => setShowCreateModal(false)}
                  className="px-3 py-1.5 bg-slate-800 text-slate-300 text-xs rounded hover:bg-slate-700"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={loading}
                  className="px-3 py-1.5 bg-rose-600 text-white text-xs rounded hover:bg-rose-500 font-semibold"
                >
                  Initialize Case
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Status Transition Modal */}
      {showTransitionModal && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center p-4 z-50">
          <div className="bg-slate-900 border border-slate-800 rounded-lg p-6 max-w-md w-full space-y-4">
            <h3 className="text-base font-bold text-white">Transition Case Status</h3>
            <form onSubmit={handleTransitionSubmit} className="space-y-4">
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">Target Status</label>
                <select
                  value={targetStatus}
                  onChange={(e) => setTargetStatus(e.target.value as CaseStatus)}
                  className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-xs text-white"
                >
                  <option value="TRIAGED">TRIAGED</option>
                  <option value="INVESTIGATING">INVESTIGATING</option>
                  <option value="CONTAINED">CONTAINED</option>
                  <option value="CLOSED">CLOSED</option>
                  <option value="REOPENED">REOPENED</option>
                </select>
              </div>
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">Transition Reason</label>
                <textarea
                  value={transitionReason}
                  onChange={(e) => setTransitionReason(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-xs text-white"
                  rows={2}
                  required
                />
              </div>
              {targetStatus === 'CLOSED' && (
                <div>
                  <label className="block text-xs font-medium text-slate-300 mb-1">Closure Summary (Mandatory)</label>
                  <textarea
                    value={closureSummary}
                    onChange={(e) => setClosureSummary(e.target.value)}
                    placeholder="Document root cause resolution, patch verification, and containment proof..."
                    className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-xs text-white"
                    rows={3}
                    required
                  />
                  <p className="text-[10px] text-amber-400 mt-1">
                    * Separation of Duties: Lead investigator cannot approve their own case closure.
                  </p>
                </div>
              )}
              {targetStatus === 'REOPENED' && (
                <div>
                  <label className="block text-xs font-medium text-slate-300 mb-1">Reopening Justification (Mandatory)</label>
                  <textarea
                    value={reopeningRationale}
                    onChange={(e) => setReopeningRationale(e.target.value)}
                    placeholder="State justification for reopening closed investigation..."
                    className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-xs text-white"
                    rows={3}
                    required
                  />
                </div>
              )}
              <div className="flex justify-end gap-2">
                <button
                  type="button"
                  onClick={() => setShowTransitionModal(false)}
                  className="px-3 py-1.5 bg-slate-800 text-slate-300 text-xs rounded hover:bg-slate-700"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={loading}
                  className="px-3 py-1.5 bg-rose-600 text-white text-xs rounded hover:bg-rose-500 font-semibold"
                >
                  Confirm Transition
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
