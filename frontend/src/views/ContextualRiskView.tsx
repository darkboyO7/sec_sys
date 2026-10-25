import React, { useState, useEffect } from 'react';
import {
  ShieldAlert,
  Flame,
  GitFork,
  AlertTriangle,
  RefreshCw,
  Eye,
  FileCheck2,
  X,
  Info,
} from 'lucide-react';
import { api } from '../services/api';
import type {
  Project,
  RiskAssessment,
  RiskSummary,
  RiskPriority,
  AttackPathAnalysisResponse,
  RemediationRecommendation,
  RecommendationStatus,
} from '../types';

interface ContextualRiskViewProps {
  currentProject: Project | null;
  currentUserRole?: string | null;
}

const PRIORITY_CONFIG: Record<
  RiskPriority,
  { label: string; bg: string; text: string; border: string; barColor: string }
> = {
  CRITICAL: { label: 'Critical', bg: 'bg-red-500/10', text: 'text-red-400', border: 'border-red-500/30', barColor: 'bg-red-500' },
  HIGH: { label: 'High', bg: 'bg-orange-500/10', text: 'text-orange-400', border: 'border-orange-500/30', barColor: 'bg-orange-500' },
  MEDIUM: { label: 'Medium', bg: 'bg-yellow-500/10', text: 'text-yellow-400', border: 'border-yellow-500/30', barColor: 'bg-yellow-500' },
  LOW: { label: 'Low', bg: 'bg-blue-500/10', text: 'text-blue-400', border: 'border-blue-500/30', barColor: 'bg-blue-500' },
  INFORMATIONAL: { label: 'Info', bg: 'bg-zinc-500/10', text: 'text-zinc-400', border: 'border-zinc-500/30', barColor: 'bg-zinc-500' },
};

const ACTION_TYPE_CONFIG: Record<string, { label: string; bg: string; text: string; border: string }> = {
  CODE_REFACTOR: { label: 'Code Refactor', bg: 'bg-cyan-500/10', text: 'text-cyan-400', border: 'border-cyan-500/30' },
  CONFIG_HARDENING: { label: 'Config Hardening', bg: 'bg-emerald-500/10', text: 'text-emerald-400', border: 'border-emerald-500/30' },
  PATCH_UPDATE: { label: 'Patch Update', bg: 'bg-purple-500/10', text: 'text-purple-400', border: 'border-purple-500/30' },
  INPUT_OUTPUT_SANITIZATION: { label: 'Sanitization', bg: 'bg-amber-500/10', text: 'text-amber-400', border: 'border-amber-500/30' },
  MANUAL_ANALYST_REVIEW: { label: 'Analyst Review', bg: 'bg-rose-500/10', text: 'text-rose-400', border: 'border-rose-500/30' },
};

export const ContextualRiskView: React.FC<ContextualRiskViewProps> = ({
  currentProject,
  currentUserRole,
}) => {
  const [activeTab, setActiveTab] = useState<'assessments' | 'paths' | 'remediations'>('assessments');

  // Summary State
  const [summary, setSummary] = useState<RiskSummary | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [recalculatingAll, setRecalculatingAll] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  // Risk Assessments Tab State
  const [assessments, setAssessments] = useState<RiskAssessment[]>([]);
  const [priorityFilter, setPriorityFilter] = useState<string>('ALL');
  const [selectedAssessment, setSelectedAssessment] = useState<RiskAssessment | null>(null);
  const [recalculatingId, setRecalculatingId] = useState<string | null>(null);

  // Attack Path Tab State
  const [pathDepth, setPathDepth] = useState<number>(3);
  const [pathResults, setPathResults] = useState<AttackPathAnalysisResponse | null>(null);
  const [pathLoading, setPathLoading] = useState<boolean>(false);

  // Remediation Tab State
  const [remediations, setRemediations] = useState<RemediationRecommendation[]>([]);
  const [remediationFilter, setRemediationFilter] = useState<string>('ALL');
  const [selectedRemediation, setSelectedRemediation] = useState<RemediationRecommendation | null>(null);
  const [reviewModalOpen, setReviewModalOpen] = useState<boolean>(false);
  const [reviewAction, setReviewAction] = useState<RecommendationStatus>('APPROVED');
  const [reviewNotes, setReviewNotes] = useState<string>('');
  const [reviewSubmitting, setReviewSubmitting] = useState<boolean>(false);
  const [reviewError, setReviewError] = useState<string | null>(null);

  const isLead = currentUserRole === 'LEAD' || currentUserRole === 'ADMIN';

  // Load summary and initial tab data
  const loadInitialData = async () => {
    if (!currentProject) return;
    try {
      setLoading(true);
      setError(null);
      const [sumRes, assessRes] = await Promise.all([
        api.getRiskSummary(currentProject.id),
        api.listRiskAssessments(currentProject.id),
      ]);
      setSummary(sumRes);
      setAssessments(assessRes);
    } catch (err: any) {
      setError(err.message || 'Failed to load risk intelligence');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadInitialData();
  }, [currentProject?.id]);

  // Load Remediation data on tab switch
  useEffect(() => {
    if (activeTab === 'remediations' && currentProject) {
      api.listRemediations(currentProject.id)
        .then((res) => setRemediations(res))
        .catch((err) => setError(err.message));
    }
  }, [activeTab, currentProject?.id]);

  // Trigger project-wide risk recalculation
  const handleRecalculateAll = async () => {
    if (!currentProject) return;
    try {
      setRecalculatingAll(true);
      setError(null);
      await api.recalculateAllProjectRisks(currentProject.id);
      await loadInitialData();
    } catch (err: any) {
      setError(err.message || 'Failed to recalculate project risks');
    } finally {
      setRecalculatingAll(false);
    }
  };

  // Recalculate single finding risk
  const handleRecalculateFinding = async (findingId: string) => {
    if (!currentProject) return;
    try {
      setRecalculatingId(findingId);
      const updated = await api.recalculateFindingRisk(currentProject.id, findingId);
      setAssessments((prev) => prev.map((a) => (a.finding_id === findingId ? updated : a)));
      if (selectedAssessment?.finding_id === findingId) {
        setSelectedAssessment(updated);
      }
      const sum = await api.getRiskSummary(currentProject.id);
      setSummary(sum);
    } catch (err: any) {
      setError(err.message || 'Failed to recalculate finding risk');
    } finally {
      setRecalculatingId(null);
    }
  };

  // Trigger attack path analysis
  const handleAnalyzePaths = async () => {
    if (!currentProject) return;
    try {
      setPathLoading(true);
      setError(null);
      const res = await api.analyzeAttackPaths(currentProject.id, {
        max_depth: pathDepth,
        max_paths: 6,
      });
      setPathResults(res);
    } catch (err: any) {
      setError(err.message || 'Failed to analyze attack paths');
    } finally {
      setPathLoading(false);
    }
  };

  // Submit remediation review
  const handleSubmitReview = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!currentProject || !selectedRemediation) return;
    try {
      setReviewSubmitting(true);
      setReviewError(null);
      const updated = await api.reviewRemediation(currentProject.id, selectedRemediation.id, {
        status: reviewAction,
        review_notes: reviewNotes,
      });
      setRemediations((prev) => prev.map((r) => (r.id === updated.id ? updated : r)));
      setSelectedRemediation(updated);
      setReviewModalOpen(false);
      setReviewNotes('');
    } catch (err: any) {
      setReviewError(err.message || 'Failed to review recommendation');
    } finally {
      setReviewSubmitting(false);
    }
  };

  // Filtered assessments
  const filteredAssessments = assessments.filter((a) => {
    if (priorityFilter !== 'ALL' && a.priority !== priorityFilter) return false;
    return true;
  });

  // Filtered remediations
  const filteredRemediations = remediations.filter((r) => {
    if (remediationFilter !== 'ALL' && r.status !== remediationFilter) return false;
    return true;
  });

  if (!currentProject) {
    return (
      <div className="text-center text-slate-500 py-12 font-mono text-sm">
        Select a project to access contextual risk intelligence and attack paths.
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-amber-500/10 text-amber-400 border border-amber-500/30 uppercase font-semibold">
              Contextual Risk Intelligence (v1.0.0)
            </span>
            <span className="text-xs text-slate-500 font-mono">
              Index Range: 0–100 (Prioritization Measure)
            </span>
          </div>
          <h1 className="text-2xl font-bold text-slate-100 flex items-center gap-2">
            <ShieldAlert className="w-6 h-6 text-amber-400" />
            Risk Intelligence & Attack Paths
          </h1>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={handleRecalculateAll}
            disabled={recalculatingAll || !isLead}
            title={!isLead ? 'Lead role required to trigger full recalculation' : 'Recalculate project risks'}
            className="px-3.5 py-1.5 rounded-lg border border-amber-500/30 bg-amber-500/10 text-amber-400 text-xs font-mono font-medium hover:bg-amber-500/20 disabled:opacity-50 transition-colors flex items-center gap-2 shadow-sm"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${recalculatingAll ? 'animate-spin' : ''}`} />
            Recalculate All
          </button>
        </div>
      </div>

      {/* Error Alert */}
      {error && (
        <div className="p-3 bg-red-500/10 border border-red-500/30 rounded-xl flex items-center justify-between text-xs text-red-300 font-mono">
          <div className="flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />
            <span>{error}</span>
          </div>
          <button onClick={() => setError(null)} className="text-red-400 hover:text-red-200">
            <X className="w-4 h-4" />
          </button>
        </div>
      )}

      {/* Epistemic Transparency Banner */}
      <div className="p-3 bg-cyber-900/60 border border-cyan-500/20 rounded-xl flex items-start gap-3 text-xs text-slate-400 font-mono">
        <Info className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
        <div>
          <span className="text-cyan-300 font-semibold">Methodological Transparency: </span>
          Contextual risk scores prioritize issues based on observed asset criticality, exposure, evidence freshness, and mitigating controls. Scores represent defensive urgency indices, not calibrated probabilities of compromise. Unverified relationships and missing attributes are explicitly recorded.
        </div>
      </div>

      {/* Summary KPI Cards */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        <div className="p-4 rounded-xl bg-cyber-900 border border-cyber-750">
          <div className="text-xs text-slate-400 font-mono mb-1">Total Assessed</div>
          <div className="text-2xl font-bold text-slate-100 font-mono">{summary?.total_assessed ?? 0}</div>
          <div className="text-[10px] text-slate-500 font-mono mt-1">Findings Evaluated</div>
        </div>
        <div className="p-4 rounded-xl bg-cyber-900 border border-cyber-750">
          <div className="text-xs text-slate-400 font-mono mb-1">Average Risk Score</div>
          <div className="text-2xl font-bold text-amber-400 font-mono">
            {summary ? summary.average_score.toFixed(1) : '0.0'}
          </div>
          <div className="text-[10px] text-slate-500 font-mono mt-1">Across Active Scope</div>
        </div>
        <div className="p-4 rounded-xl bg-cyber-900 border border-cyber-750">
          <div className="text-xs text-slate-400 font-mono mb-1">Highest Risk Score</div>
          <div className="text-2xl font-bold text-red-400 font-mono">
            {summary ? summary.highest_score.toFixed(1) : '0.0'}
          </div>
          <div className="text-[10px] text-slate-500 font-mono mt-1">Max Severity Anchor</div>
        </div>
        <div className="p-4 rounded-xl bg-cyber-900 border border-red-500/20 bg-red-500/5">
          <div className="text-xs text-red-400 font-mono mb-1">Critical Urgency</div>
          <div className="text-2xl font-bold text-red-300 font-mono">{summary?.critical_count ?? 0}</div>
          <div className="text-[10px] text-red-400/80 font-mono mt-1">Score &ge; 80.0</div>
        </div>
        <div className="p-4 rounded-xl bg-cyber-900 border border-orange-500/20 bg-orange-500/5">
          <div className="text-xs text-orange-400 font-mono mb-1">High Urgency</div>
          <div className="text-2xl font-bold text-orange-300 font-mono">{summary?.high_count ?? 0}</div>
          <div className="text-[10px] text-orange-400/80 font-mono mt-1">60.0 &le; Score &lt; 80.0</div>
        </div>
      </div>

      {/* Main Tab Controls */}
      <div className="flex border-b border-cyber-750 text-xs font-mono">
        <button
          onClick={() => setActiveTab('assessments')}
          className={`px-4 py-2.5 font-semibold transition-colors border-b-2 flex items-center gap-2 ${
            activeTab === 'assessments'
              ? 'border-amber-400 text-amber-400 bg-amber-500/5'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <Flame className="w-4 h-4" />
          Prioritized Findings ({assessments.length})
        </button>
        <button
          onClick={() => {
            setActiveTab('paths');
            if (!pathResults) handleAnalyzePaths();
          }}
          className={`px-4 py-2.5 font-semibold transition-colors border-b-2 flex items-center gap-2 ${
            activeTab === 'paths'
              ? 'border-cyan-400 text-cyan-400 bg-cyan-500/5'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <GitFork className="w-4 h-4" />
          Attack Paths ({pathResults?.total_paths_found ?? 0})
        </button>
        <button
          onClick={() => setActiveTab('remediations')}
          className={`px-4 py-2.5 font-semibold transition-colors border-b-2 flex items-center gap-2 ${
            activeTab === 'remediations'
              ? 'border-emerald-400 text-emerald-400 bg-emerald-500/5'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <FileCheck2 className="w-4 h-4" />
          Remediation Playbooks ({remediations.length})
        </button>
      </div>

      {/* TAB 1: PRIORITIZED RISK ASSESSMENTS */}
      {activeTab === 'assessments' && (
        <div className="space-y-4">
          {/* Priority Filter Chips */}
          <div className="flex flex-wrap items-center gap-2">
            {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL'].map((pri) => (
              <button
                key={pri}
                onClick={() => setPriorityFilter(pri)}
                className={`px-3 py-1 rounded-lg text-xs font-mono transition-colors border ${
                  priorityFilter === pri
                    ? 'bg-amber-500/10 border-amber-500/40 text-amber-300 font-semibold'
                    : 'bg-cyber-900 border-cyber-750 text-slate-400 hover:text-slate-200'
                }`}
              >
                {pri}
              </button>
            ))}
          </div>

          {/* Table / List */}
          {loading ? (
            <div className="p-12 text-center text-slate-500 font-mono text-xs">
              <RefreshCw className="w-6 h-6 animate-spin mx-auto mb-2 text-amber-400" />
              Evaluating contextual risk factors across asset inventory...
            </div>
          ) : filteredAssessments.length === 0 ? (
            <div className="p-12 bg-cyber-900 border border-cyber-750 rounded-xl text-center text-slate-500 font-mono text-xs">
              No risk assessments match the selected filter.
            </div>
          ) : (
            <div className="grid grid-cols-1 gap-3">
              {filteredAssessments.map((a) => {
                const priCfg = PRIORITY_CONFIG[a.priority] || PRIORITY_CONFIG.MEDIUM;
                return (
                  <div
                    key={a.id}
                    onClick={() => setSelectedAssessment(a)}
                    className="p-4 rounded-xl bg-cyber-900 border border-cyber-750 hover:border-cyber-600 transition-all cursor-pointer flex flex-col md:flex-row md:items-center justify-between gap-4 shadow-sm"
                  >
                    <div className="flex items-start gap-4">
                      {/* Score Gauge */}
                      <div className="flex flex-col items-center justify-center p-2 rounded-lg bg-cyber-950 border border-cyber-800 min-w-[70px]">
                        <span className="text-xl font-bold font-mono text-slate-100">{a.score.toFixed(1)}</span>
                        <div className="w-10 h-1.5 rounded-full bg-slate-800 mt-1 overflow-hidden">
                          <div className={`h-full ${priCfg.barColor}`} style={{ width: `${a.score}%` }} />
                        </div>
                        <span className={`text-[9px] font-mono mt-1 uppercase font-semibold ${priCfg.text}`}>
                          {a.priority}
                        </span>
                      </div>

                      {/* Finding Details */}
                      <div>
                        <div className="flex items-center gap-2 mb-1">
                          <span className={`text-[10px] font-mono px-2 py-0.5 rounded border ${priCfg.bg} ${priCfg.text} ${priCfg.border} font-semibold uppercase`}>
                            {a.priority} Priority
                          </span>
                          <span className="text-xs text-slate-500 font-mono">
                            {new Date(a.calculated_at).toLocaleDateString()}
                          </span>
                          {a.missing_factors.length > 0 && (
                            <span className="flex items-center gap-1 text-[10px] text-amber-400/80 font-mono bg-amber-500/10 px-2 py-0.5 rounded border border-amber-500/20">
                              <AlertTriangle className="w-3 h-3" />
                              Uncertainty ({a.missing_factors.length})
                            </span>
                          )}
                        </div>
                        <div className="text-sm font-semibold text-slate-100 mb-1">
                          {a.input_snapshot?.finding_severity && (
                            <span className="text-slate-400 font-mono text-xs mr-2 font-normal">
                              [Raw: {a.input_snapshot.finding_severity}]
                            </span>
                          )}
                          Finding ID: {a.finding_id.slice(0, 12)}...
                        </div>
                        {/* Contributing Factors chips */}
                        <div className="flex flex-wrap gap-1 mt-2">
                          {a.contributing_factors.slice(0, 3).map((f, i) => (
                            <span
                              key={i}
                              className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyber-800 text-slate-300 border border-cyber-700"
                            >
                              {f.length > 60 ? `${f.slice(0, 60)}...` : f}
                            </span>
                          ))}
                        </div>
                      </div>
                    </div>

                    <div className="flex items-center gap-2 self-end md:self-center">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          handleRecalculateFinding(a.finding_id);
                        }}
                        disabled={recalculatingId === a.finding_id}
                        className="px-2.5 py-1 text-xs font-mono rounded bg-cyber-800 hover:bg-cyber-700 text-slate-300 border border-cyber-700 transition-colors flex items-center gap-1"
                      >
                        <RefreshCw className={`w-3 h-3 ${recalculatingId === a.finding_id ? 'animate-spin' : ''}`} />
                        Recalculate
                      </button>
                      <button
                        onClick={() => setSelectedAssessment(a)}
                        className="px-3 py-1 text-xs font-mono rounded bg-amber-500/10 hover:bg-amber-500/20 text-amber-300 border border-amber-500/30 transition-colors flex items-center gap-1"
                      >
                        <Eye className="w-3 h-3" />
                        Inspect Factors
                      </button>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}

      {/* TAB 2: EVIDENCE-AWARE ATTACK PATHS */}
      {activeTab === 'paths' && (
        <div className="space-y-4">
          <div className="p-4 rounded-xl bg-cyber-900 border border-cyber-750 flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div>
              <div className="text-sm font-semibold text-slate-100 flex items-center gap-2">
                <GitFork className="w-4 h-4 text-cyan-400" />
                Directed Graph Path Discovery
              </div>
              <div className="text-xs text-slate-400 font-mono mt-0.5">
                Discovers exposure chains constrained by persisted graph relationships and epistemic verification status.
              </div>
            </div>

            <div className="flex items-center gap-3">
              <div className="flex items-center gap-2">
                <span className="text-xs font-mono text-slate-400">Max Depth:</span>
                <select
                  value={pathDepth}
                  onChange={(e) => setPathDepth(Number(e.target.value))}
                  className="bg-cyber-950 border border-cyber-750 rounded px-2.5 py-1 text-xs font-mono text-slate-200"
                >
                  <option value={2}>2 Steps</option>
                  <option value={3}>3 Steps</option>
                  <option value={4}>4 Steps (Max)</option>
                </select>
              </div>

              <button
                onClick={handleAnalyzePaths}
                disabled={pathLoading}
                className="px-3.5 py-1.5 rounded-lg border border-cyan-500/30 bg-cyan-500/10 text-cyan-400 text-xs font-mono font-medium hover:bg-cyan-500/20 transition-colors flex items-center gap-2"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${pathLoading ? 'animate-spin' : ''}`} />
                Analyze Paths
              </button>
            </div>
          </div>

          {pathLoading ? (
            <div className="p-12 text-center text-slate-500 font-mono text-xs">
              <RefreshCw className="w-6 h-6 animate-spin mx-auto mb-2 text-cyan-400" />
              Traversing directed graph relationships for potential exposure paths...
            </div>
          ) : !pathResults || pathResults.paths.length === 0 ? (
            <div className="p-12 bg-cyber-900 border border-cyber-750 rounded-xl text-center text-slate-500 font-mono text-xs">
              No continuous exposure paths identified within current depth boundaries.
            </div>
          ) : (
            <div className="space-y-4">
              {pathResults.paths.map((p, idx) => {
                const isVerified = p.path_verification_status === 'VERIFIED';
                const isMixed = p.path_verification_status === 'MIXED_EVIDENCE';
                const isStale = p.path_verification_status === 'STALE';
                const statusBg = isVerified
                  ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                  : isMixed
                  ? 'bg-amber-500/10 text-amber-400 border-amber-500/30'
                  : isStale
                  ? 'bg-rose-500/10 text-rose-400 border-rose-500/30'
                  : 'bg-purple-500/10 text-purple-400 border-purple-500/30';

                return (
                  <div
                    key={idx}
                    className="p-5 rounded-xl bg-cyber-900 border border-cyber-750 space-y-3"
                  >
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-cyber-800 pb-3">
                      <div className="flex items-center gap-2">
                        <span className={`text-[10px] font-mono px-2.5 py-0.5 rounded border uppercase font-semibold ${statusBg}`}>
                          {p.path_verification_status} PATH
                        </span>
                        <span className="text-xs text-slate-400 font-mono">
                          Cumulative Confidence: {(p.cumulative_confidence * 100).toFixed(0)}%
                        </span>
                        <span className="text-xs text-slate-500 font-mono">
                          ({p.step_count} Hops)
                        </span>
                      </div>
                      <span className="text-xs font-mono text-slate-500">Path #{idx + 1}</span>
                    </div>

                    {/* Node Sequence Chain */}
                    <div className="py-2 overflow-x-auto">
                      <div className="flex items-center gap-2 text-xs font-mono min-w-max">
                        {p.nodes.map((node, i) => (
                          <React.Fragment key={node.id}>
                            <div className="p-2.5 rounded-lg bg-cyber-950 border border-cyber-800 flex flex-col items-center">
                              <span className="text-[10px] text-cyan-400 font-semibold uppercase">{node.category}</span>
                              <span className="text-slate-200 font-medium">{node.label}</span>
                            </div>
                            {i < p.relationships.length && (
                              <div className="flex flex-col items-center px-1 text-slate-500">
                                <span className="text-[9px] text-slate-400 font-mono">
                                  {p.relationships[i].relationship_type}
                                </span>
                                <span>&rarr;</span>
                              </div>
                            )}
                          </React.Fragment>
                        ))}
                      </div>
                    </div>

                    {/* Missing Evidence / Uncertainty Callout */}
                    {p.missing_evidence.length > 0 && (
                      <div className="p-3 rounded-lg bg-amber-500/5 border border-amber-500/20 text-xs font-mono space-y-1">
                        <div className="text-amber-400 font-semibold flex items-center gap-1.5">
                          <AlertTriangle className="w-3.5 h-3.5" />
                          Missing Evidence to Validate Path:
                        </div>
                        {p.missing_evidence.map((me, k) => (
                          <div key={k} className="text-slate-400 pl-5 text-[11px]">
                            &bull; {me}
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}

      {/* TAB 3: REMEDIATION PLAYBOOKS */}
      {activeTab === 'remediations' && (
        <div className="space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-4">
            <div className="flex items-center gap-2">
              {['ALL', 'PENDING_REVIEW', 'APPROVED', 'DEFERRED', 'REJECTED'].map((st) => (
                <button
                  key={st}
                  onClick={() => setRemediationFilter(st)}
                  className={`px-3 py-1 rounded-lg text-xs font-mono transition-colors border ${
                    remediationFilter === st
                      ? 'bg-emerald-500/10 border-emerald-500/40 text-emerald-300 font-semibold'
                      : 'bg-cyber-900 border-cyber-750 text-slate-400 hover:text-slate-200'
                  }`}
                >
                  {st.replace('_', ' ')}
                </button>
              ))}
            </div>
          </div>

          {filteredRemediations.length === 0 ? (
            <div className="p-12 bg-cyber-900 border border-cyber-750 rounded-xl text-center text-slate-500 font-mono text-xs">
              No remediation playbooks match the filter criteria.
            </div>
          ) : (
            <div className="grid grid-cols-1 gap-4">
              {filteredRemediations.map((r) => {
                const actCfg = ACTION_TYPE_CONFIG[r.action_type] || ACTION_TYPE_CONFIG.CODE_REFACTOR;
                const isApproved = r.status === 'APPROVED';
                const isPending = r.status === 'PENDING_REVIEW';

                return (
                  <div
                    key={r.id}
                    className="p-5 rounded-xl bg-cyber-900 border border-cyber-750 space-y-3"
                  >
                    <div className="flex flex-col md:flex-row md:items-center justify-between gap-2 border-b border-cyber-800 pb-3">
                      <div>
                        <div className="flex items-center gap-2 mb-1">
                          <span className={`text-[10px] font-mono px-2.5 py-0.5 rounded border uppercase font-semibold ${actCfg.bg} ${actCfg.text} ${actCfg.border}`}>
                            {actCfg.label}
                          </span>
                          <span className={`text-[10px] font-mono px-2 py-0.5 rounded border font-semibold ${
                            isApproved
                              ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                              : isPending
                              ? 'bg-amber-500/10 text-amber-400 border-amber-500/30'
                              : 'bg-zinc-500/10 text-zinc-400 border-zinc-500/30'
                          }`}>
                            {r.status.replace('_', ' ')}
                          </span>
                          {r.estimated_risk_reduction && (
                            <span className="text-xs text-emerald-400 font-mono">
                              Est. Reduction: {(r.estimated_risk_reduction * 100).toFixed(0)}%
                            </span>
                          )}
                        </div>
                        <h3 className="text-base font-bold text-slate-100">{r.title}</h3>
                      </div>

                      <div className="flex items-center gap-2">
                        {isLead && isPending && (
                          <button
                            onClick={() => {
                              setSelectedRemediation(r);
                              setReviewModalOpen(true);
                            }}
                            className="px-3 py-1.5 rounded-lg border border-emerald-500/30 bg-emerald-500/10 text-emerald-300 hover:bg-emerald-500/20 text-xs font-mono transition-colors flex items-center gap-1.5"
                          >
                            <FileCheck2 className="w-3.5 h-3.5" />
                            Review / Sign-off
                          </button>
                        )}
                      </div>
                    </div>

                    <div className="text-xs text-slate-300 font-sans leading-relaxed">
                      {r.description}
                    </div>

                    {/* Operational Impact & Rollback Grid */}
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-2 text-xs font-mono">
                      <div className="p-3 rounded-lg bg-cyber-950 border border-cyber-800 space-y-1">
                        <span className="text-slate-400 font-semibold block">Operational Impact:</span>
                        <span className="text-slate-300">{r.operational_impact}</span>
                      </div>
                      <div className="p-3 rounded-lg bg-cyber-950 border border-cyber-800 space-y-1">
                        <span className="text-slate-400 font-semibold block">Rollback Procedure:</span>
                        <span className="text-slate-300">{r.rollback_procedure}</span>
                      </div>
                    </div>

                    {/* Verification Criteria */}
                    <div className="p-3 rounded-lg bg-cyber-950 border border-cyber-800 text-xs font-mono">
                      <span className="text-cyan-400 font-semibold block mb-0.5">Independent Verification Criteria:</span>
                      <span className="text-slate-300">{r.verification_criteria}</span>
                      {r.verification_test_profile && (
                        <div className="text-[10px] text-slate-500 mt-1">
                          Test Profile: <span className="text-slate-400">{r.verification_test_profile}</span>
                        </div>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}

      {/* FACTOR INSPECTOR DRAWER */}
      {selectedAssessment && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm z-50 flex justify-end">
          <div className="w-full max-w-xl bg-cyber-950 border-l border-cyber-750 p-6 overflow-y-auto space-y-5 animate-in slide-in-from-right duration-200">
            <div className="flex items-center justify-between border-b border-cyber-800 pb-3">
              <div>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-amber-500/10 text-amber-400 border border-amber-500/30 uppercase font-semibold">
                  Scoring Version: {selectedAssessment.scoring_version}
                </span>
                <h2 className="text-lg font-bold text-slate-100 mt-1">Contextual Risk Decomposition</h2>
              </div>
              <button
                onClick={() => setSelectedAssessment(null)}
                className="text-slate-400 hover:text-slate-200 p-1"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Score & Priority Banner */}
            <div className="p-4 rounded-xl bg-cyber-900 border border-cyber-800 flex items-center justify-between">
              <div>
                <div className="text-xs text-slate-400 font-mono">Contextual Risk Score</div>
                <div className="text-3xl font-bold font-mono text-amber-400">
                  {selectedAssessment.score.toFixed(1)} / 100
                </div>
              </div>
              <div className="text-right">
                <span className="text-xs text-slate-400 font-mono block">Categorical Priority</span>
                <span className="text-sm font-bold font-mono text-slate-100">
                  {selectedAssessment.priority}
                </span>
              </div>
            </div>

            {/* Factor Decomposition Grid */}
            <div className="space-y-2">
              <h3 className="text-xs font-semibold text-slate-300 font-mono uppercase">
                Mathematical Factor Multipliers
              </h3>
              <div className="grid grid-cols-2 gap-2 text-xs font-mono">
                <div className="p-2.5 rounded bg-cyber-900 border border-cyber-800">
                  <span className="text-slate-500 block text-[10px]">Base Severity Score:</span>
                  <span className="text-slate-200 font-semibold">
                    {selectedAssessment.factor_breakdown?.base_score ?? 'N/A'}
                  </span>
                </div>
                <div className="p-2.5 rounded bg-cyber-900 border border-cyber-800">
                  <span className="text-slate-500 block text-[10px]">Confidence Weight:</span>
                  <span className="text-slate-200 font-semibold">
                    {selectedAssessment.factor_breakdown?.confidence_weight ?? 'N/A'}
                  </span>
                </div>
                <div className="p-2.5 rounded bg-cyber-900 border border-cyber-800">
                  <span className="text-slate-500 block text-[10px]">Asset Criticality Multiplier:</span>
                  <span className="text-slate-200 font-semibold">
                    {selectedAssessment.factor_breakdown?.criticality_multiplier ?? 'N/A'}x
                  </span>
                </div>
                <div className="p-2.5 rounded bg-cyber-900 border border-cyber-800">
                  <span className="text-slate-500 block text-[10px]">Reachability / Exposure:</span>
                  <span className="text-slate-200 font-semibold">
                    {selectedAssessment.factor_breakdown?.exposure_multiplier ?? 'N/A'}x
                  </span>
                </div>
                <div className="p-2.5 rounded bg-cyber-900 border border-cyber-800">
                  <span className="text-slate-500 block text-[10px]">Evidence Freshness Decay:</span>
                  <span className="text-slate-200 font-semibold">
                    {selectedAssessment.factor_breakdown?.freshness_multiplier ?? 'N/A'}x
                  </span>
                </div>
                <div className="p-2.5 rounded bg-cyber-900 border border-cyber-800">
                  <span className="text-slate-500 block text-[10px]">Lifecycle Mitigating Multiplier:</span>
                  <span className="text-slate-200 font-semibold">
                    {selectedAssessment.factor_breakdown?.lifecycle_multiplier ?? 'N/A'}x
                  </span>
                </div>
              </div>
            </div>

            {/* Contributing Rationale */}
            <div className="space-y-2">
              <h3 className="text-xs font-semibold text-slate-300 font-mono uppercase">
                Principal Contributing Rationale
              </h3>
              <div className="space-y-1.5">
                {selectedAssessment.contributing_factors.map((cf, i) => (
                  <div key={i} className="p-2.5 rounded bg-cyber-900 border border-cyber-800 text-xs text-slate-300 font-mono">
                    &bull; {cf}
                  </div>
                ))}
              </div>
            </div>

            {/* Missing Factors */}
            {selectedAssessment.missing_factors.length > 0 && (
              <div className="space-y-2">
                <h3 className="text-xs font-semibold text-amber-400 font-mono uppercase flex items-center gap-1.5">
                  <AlertTriangle className="w-3.5 h-3.5" />
                  Recorded Information Gaps / Uncertainty
                </h3>
                <div className="space-y-1.5">
                  {selectedAssessment.missing_factors.map((mf, i) => (
                    <div key={i} className="p-2.5 rounded bg-amber-500/10 border border-amber-500/20 text-xs text-amber-300 font-mono">
                      &bull; {mf}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Input Snapshot */}
            <div className="space-y-2">
              <h3 className="text-xs font-semibold text-slate-400 font-mono uppercase">
                Reproducible Input Snapshot
              </h3>
              <pre className="p-3 rounded bg-cyber-900 border border-cyber-800 text-[10px] text-slate-400 font-mono overflow-x-auto max-h-48">
                {JSON.stringify(selectedAssessment.input_snapshot, null, 2)}
              </pre>
            </div>
          </div>
        </div>
      )}

      {/* REMEDIATION REVIEW MODAL */}
      {reviewModalOpen && selectedRemediation && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="w-full max-w-md bg-cyber-950 border border-cyber-750 rounded-xl p-6 space-y-4 shadow-xl">
            <div className="flex items-center justify-between border-b border-cyber-800 pb-3">
              <h3 className="text-base font-bold text-slate-100 flex items-center gap-2">
                <FileCheck2 className="w-5 h-5 text-emerald-400" />
                Review Remediation Playbook
              </h3>
              <button
                onClick={() => setReviewModalOpen(false)}
                className="text-slate-400 hover:text-slate-200"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <form onSubmit={handleSubmitReview} className="space-y-4 text-xs font-mono">
              <div>
                <label className="text-slate-300 block mb-1">Playbook Target:</label>
                <div className="text-slate-100 font-semibold p-2 bg-cyber-900 rounded border border-cyber-800">
                  {selectedRemediation.title}
                </div>
              </div>

              <div>
                <label className="text-slate-300 block mb-1">Disposition Decision:</label>
                <div className="grid grid-cols-3 gap-2">
                  {(['APPROVED', 'DEFERRED', 'REJECTED'] as RecommendationStatus[]).map((st) => (
                    <button
                      key={st}
                      type="button"
                      onClick={() => setReviewAction(st)}
                      className={`p-2 rounded border text-center font-semibold transition-colors ${
                        reviewAction === st
                          ? 'bg-emerald-500/20 border-emerald-500/50 text-emerald-300'
                          : 'bg-cyber-900 border-cyber-800 text-slate-400 hover:text-slate-200'
                      }`}
                    >
                      {st}
                    </button>
                  ))}
                </div>
              </div>

              <div>
                <label className="text-slate-300 block mb-1">Review Notes & Justification (Mandatory):</label>
                <textarea
                  value={reviewNotes}
                  onChange={(e) => setReviewNotes(e.target.value)}
                  placeholder="Record verification rationale or operational scheduling notes..."
                  rows={3}
                  required
                  className="w-full bg-cyber-900 border border-cyber-800 rounded p-2 text-slate-200 focus:outline-none focus:border-emerald-500/50"
                />
              </div>

              {reviewError && (
                <div className="p-2.5 rounded bg-red-500/10 border border-red-500/20 text-red-400 text-xs">
                  {reviewError}
                </div>
              )}

              <div className="flex justify-end gap-2 pt-2 border-t border-cyber-800">
                <button
                  type="button"
                  onClick={() => setReviewModalOpen(false)}
                  className="px-3 py-1.5 rounded bg-cyber-800 text-slate-300 hover:bg-cyber-700 transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={reviewSubmitting || reviewNotes.trim().length < 3}
                  className="px-4 py-1.5 rounded bg-emerald-600 hover:bg-emerald-500 text-white font-semibold transition-colors disabled:opacity-50"
                >
                  {reviewSubmitting ? 'Submitting...' : 'Record Review'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
