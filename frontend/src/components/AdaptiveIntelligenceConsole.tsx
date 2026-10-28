import React, { useState, useEffect } from 'react';
import {
  Brain,
  ShieldAlert,
  Target,
  Sparkles,
  RefreshCw,
  AlertTriangle,
  PlayCircle,
  Activity,
  Clock,
  Compass,
  ArrowRight,
  Database,
  ChevronDown,
  ChevronUp,
} from 'lucide-react';
import { api } from '../services/api';
import type {
  ProjectIntelligenceSummary,
  AdaptivePlan,
  PlannedCheck,
  SkippedCheck,
  HighestPriorityFinding,
} from '../types';

interface AdaptiveIntelligenceConsoleProps {
  projectId: string;
  onNavigateToFindings?: () => void;
  onNavigateToAssessments?: () => void;
  onNavigateToAssets?: () => void;
  onNavigateToVerification?: () => void;
}

export const AdaptiveIntelligenceConsole: React.FC<AdaptiveIntelligenceConsoleProps> = ({
  projectId,
  onNavigateToFindings,
  onNavigateToAssessments,
  onNavigateToAssets,
  onNavigateToVerification,
}) => {
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [summary, setSummary] = useState<ProjectIntelligenceSummary | null>(null);
  const [plan, setPlan] = useState<AdaptivePlan | null>(null);
  const [generatingPlan, setGeneratingPlan] = useState<boolean>(false);
  const [executingCheckId, setExecutingCheckId] = useState<string | null>(null);
  const [expandedFindingId, setExpandedFindingId] = useState<string | null>(null);
  const [actionSuccessMessage, setActionSuccessMessage] = useState<string | null>(null);

  const fetchIntelligenceData = async () => {
    try {
      setLoading(true);
      setError(null);
      const [sumRes, planRes] = await Promise.all([
        api.getIntelligenceSummary(projectId),
        api.getLatestAdaptivePlan(projectId),
      ]);
      setSummary(sumRes);
      setPlan(planRes);
    } catch (err: any) {
      setError(err?.message || 'Failed to load security intelligence overview.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchIntelligenceData();
  }, [projectId]);

  const handleGeneratePlan = async () => {
    try {
      setGeneratingPlan(true);
      setActionSuccessMessage(null);
      const newPlan = await api.generateAdaptivePlan(projectId, 10);
      setPlan(newPlan);
      setActionSuccessMessage(`Adaptive assessment plan '${newPlan.plan_name}' generated with ${newPlan.total_recommended} recommended checks.`);
    } catch (err: any) {
      setError(err?.message || 'Failed to generate adaptive assessment plan.');
    } finally {
      setGeneratingPlan(false);
    }
  };

  const handleExecuteCheck = async (planId: string, checkId: string) => {
    try {
      setExecutingCheckId(checkId);
      setActionSuccessMessage(null);
      const res = await api.executePlannedCheck(projectId, planId, checkId);
      setActionSuccessMessage(`Assessment check dispatched successfully! Job ID: ${res.job_id}`);
      // Refresh plan state
      const updatedPlan = await api.getLatestAdaptivePlan(projectId);
      setPlan(updatedPlan);
    } catch (err: any) {
      setError(err?.message || 'Failed to dispatch planned check.');
    } finally {
      setExecutingCheckId(null);
    }
  };

  if (loading) {
    return (
      <div className="bg-cyber-850 border border-cyber-750 rounded-xl p-8 text-center shadow-lg">
        <div className="flex items-center justify-center gap-3">
          <RefreshCw className="w-5 h-5 text-accent-cyan animate-spin" />
          <span className="text-sm font-mono text-slate-300">
            Synthesizing evidence-driven security intelligence...
          </span>
        </div>
      </div>
    );
  }

  if (error && !summary) {
    return (
      <div className="bg-cyber-850 border border-rose-500/30 rounded-xl p-6 text-center shadow-lg">
        <AlertTriangle className="w-8 h-8 text-rose-400 mx-auto mb-2" />
        <h3 className="text-sm font-semibold text-white">Security Intelligence Unavailable</h3>
        <p className="text-xs text-rose-300 mt-1 max-w-md mx-auto">{error}</p>
        <button
          onClick={fetchIntelligenceData}
          className="mt-4 px-3 py-1.5 bg-cyber-750 hover:bg-cyber-700 text-xs font-semibold text-slate-200 rounded-lg inline-flex items-center gap-2"
        >
          <RefreshCw className="w-3.5 h-3.5" /> Retry
        </button>
      </div>
    );
  }

  if (!summary) return null;

  const {
    risk_summary,
    coverage_audit,
    attack_paths,
    remediation_intelligence,
    monitoring_and_changes,
    learning_pipeline,
    data_provenance,
  } = summary;

  return (
    <div className="space-y-6">
      {/* 1. Header Banner */}
      <div className="bg-gradient-to-r from-cyber-900 via-cyber-850 to-cyber-800 border border-accent-cyan/30 rounded-xl p-5 shadow-lg">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="flex items-start gap-3">
            <div className="p-2.5 rounded-lg bg-accent-cyan/10 border border-accent-cyan/30 text-accent-cyan">
              <Brain className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-base font-bold text-white tracking-tight">
                  Evidence-Driven Adaptive Security Intelligence
                </h3>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-accent-blue/15 text-accent-blue border border-accent-blue/30 font-semibold uppercase">
                  Engine {risk_summary.highest_priority_findings[0]?.scoring_version || 'v2.0.0'}
                </span>
              </div>
              <p className="text-xs text-slate-400 mt-1 leading-relaxed">
                Deterministic risk prioritization, coverage audit, attack path epistemic analysis, and adaptive assessment recommendations grounded strictly in verified evidence.
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={handleGeneratePlan}
              disabled={generatingPlan}
              className="px-3.5 py-2 bg-accent-cyan hover:bg-cyan-400 disabled:opacity-50 text-cyber-950 text-xs font-bold rounded-lg transition-colors flex items-center gap-1.5 shadow-sm"
            >
              <Compass className={`w-4 h-4 ${generatingPlan ? 'animate-spin' : ''}`} />
              {generatingPlan ? 'Generating Plan...' : 'Generate Adaptive Plan'}
            </button>
            <button
              onClick={fetchIntelligenceData}
              className="p-2 bg-cyber-750 hover:bg-cyber-700 text-slate-300 hover:text-white rounded-lg transition-colors border border-cyber-700"
              title="Refresh Intelligence Data"
            >
              <RefreshCw className="w-4 h-4" />
            </button>
          </div>
        </div>

        {actionSuccessMessage && (
          <div className="mt-4 p-2.5 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-xs text-emerald-300 flex items-center justify-between">
            <span>{actionSuccessMessage}</span>
            <button onClick={() => setActionSuccessMessage(null)} className="text-slate-400 hover:text-white font-bold ml-2">×</button>
          </div>
        )}
      </div>

      {/* 2. Key Telemetry Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Risk Posture */}
        <div className="bg-cyber-850 border border-cyber-750 rounded-xl p-4 shadow-sm">
          <div className="flex items-center justify-between text-slate-400 text-xs mb-1">
            <span>Contextual Risk Index</span>
            <ShieldAlert className="w-4 h-4 text-rose-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-rose-400">
            {risk_summary.average_risk_score}
            <span className="text-xs text-slate-500 ml-1 font-normal">/ 100</span>
          </div>
          <div className="text-[11px] text-slate-400 mt-2 flex items-center justify-between">
            <span>Critical: {risk_summary.risk_distribution.CRITICAL || 0}</span>
            <span>High: {risk_summary.risk_distribution.HIGH || 0}</span>
            <span>Med: {risk_summary.risk_distribution.MEDIUM || 0}</span>
          </div>
        </div>

        {/* Assessment Coverage */}
        <div className="bg-cyber-850 border border-cyber-750 rounded-xl p-4 shadow-sm">
          <div className="flex items-center justify-between text-slate-400 text-xs mb-1">
            <span>Assessment Coverage</span>
            <Target className="w-4 h-4 text-accent-cyan" />
          </div>
          <div className="text-2xl font-bold font-mono text-accent-cyan">
            {coverage_audit.coverage_percentage}%
          </div>
          <div className="text-[11px] text-slate-400 mt-2 flex items-center justify-between">
            <span>Covered: {coverage_audit.covered_assets_count}</span>
            <span className="text-amber-400 font-semibold">Stale: {coverage_audit.stale_assets_count}</span>
          </div>
        </div>

        {/* Attack Path Telemetry */}
        <div className="bg-cyber-850 border border-cyber-750 rounded-xl p-4 shadow-sm">
          <div className="flex items-center justify-between text-slate-400 text-xs mb-1">
            <span>Attack Paths Telemetry</span>
            <Activity className="w-4 h-4 text-purple-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-purple-400">
            {attack_paths.verified_paths_count}
            <span className="text-xs text-slate-500 ml-1 font-normal font-sans">verified</span>
          </div>
          <div className="text-[11px] text-slate-400 mt-2 flex items-center justify-between">
            <span>Hypothetical: {attack_paths.hypothetical_paths_count}</span>
            <span>Edges: {attack_paths.total_relationships}</span>
          </div>
        </div>

        {/* Learning Governance */}
        <div className="bg-cyber-850 border border-cyber-750 rounded-xl p-4 shadow-sm">
          <div className="flex items-center justify-between text-slate-400 text-xs mb-1">
            <span>Model Governance</span>
            <Brain className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-sm font-bold font-mono text-emerald-400 truncate">
            {learning_pipeline.model_version}
          </div>
          <div className="text-[11px] text-slate-400 mt-2 flex items-center justify-between">
            <span className="px-1.5 py-0.5 rounded bg-cyber-900 border border-cyber-750 text-[10px]">
              {learning_pipeline.learning_data_sufficiency}
            </span>
            <span>Inconclusive: {(learning_pipeline.inconclusive_rate * 100).toFixed(1)}%</span>
          </div>
        </div>
      </div>

      {/* 2.5 Remediation & Monitoring Status Strip */}
      <div className="bg-cyber-850/80 border border-cyber-750 rounded-lg p-3 flex flex-wrap items-center justify-between gap-3 text-xs">
        <div className="flex flex-wrap items-center gap-4 text-slate-300">
          <span>
            <strong className="text-emerald-400 font-mono">{remediation_intelligence.remediation_verification_rate}%</strong> Fix Verification Rate ({remediation_intelligence.verified_fixed_count} fixed / {remediation_intelligence.total_verifications} tests)
          </span>
          <span>·</span>
          <span>
            <strong className="text-amber-400 font-mono">{monitoring_and_changes.unhandled_changes_count}</strong> Changes Requiring Attention
          </span>
        </div>

        <div className="flex items-center gap-2">
          {onNavigateToAssets && (
            <button
              onClick={onNavigateToAssets}
              className="px-2.5 py-1 rounded bg-cyber-800 hover:bg-cyber-750 text-[11px] text-slate-300 hover:text-white transition-colors border border-cyber-700"
            >
              Assets
            </button>
          )}
          {onNavigateToAssessments && (
            <button
              onClick={onNavigateToAssessments}
              className="px-2.5 py-1 rounded bg-cyber-800 hover:bg-cyber-750 text-[11px] text-slate-300 hover:text-white transition-colors border border-cyber-700"
            >
              Assessment Jobs
            </button>
          )}
          {onNavigateToVerification && (
            <button
              onClick={onNavigateToVerification}
              className="px-2.5 py-1 rounded bg-cyber-800 hover:bg-cyber-750 text-[11px] text-slate-300 hover:text-white transition-colors border border-cyber-700"
            >
              Remediation Retest
            </button>
          )}
        </div>
      </div>

      {/* 3. Highest Priority Evidence-Backed Findings */}
      <div className="bg-cyber-850 border border-cyber-750 rounded-xl p-5 shadow-lg">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2">
            <ShieldAlert className="w-4 h-4 text-rose-400" />
            <h3 className="text-sm font-bold text-white">
              Highest-Priority Evidence-Backed Findings (Decomposed Score)
            </h3>
          </div>
          {onNavigateToFindings && (
            <button
              onClick={onNavigateToFindings}
              className="text-xs text-accent-cyan hover:underline flex items-center gap-1 font-mono"
            >
              View All Tracked Findings <ArrowRight className="w-3.5 h-3.5" />
            </button>
          )}
        </div>

        {risk_summary.highest_priority_findings.length === 0 ? (
          <div className="p-6 text-center text-xs text-slate-500 bg-cyber-900/40 rounded-lg border border-cyber-800">
            No active findings recorded for this project yet. Use Assessment Jobs to initiate testing.
          </div>
        ) : (
          <div className="space-y-3">
            {risk_summary.highest_priority_findings.map((f: HighestPriorityFinding) => {
              const isExpanded = expandedFindingId === f.finding_id;
              return (
                <div
                  key={f.finding_id}
                  className="bg-cyber-900/80 border border-cyber-800 hover:border-cyber-700 rounded-lg p-3.5 text-xs transition-colors"
                >
                  <div className="flex flex-col md:flex-row md:items-center justify-between gap-2">
                    <div className="space-y-1">
                      <div className="flex items-center gap-2">
                        <span
                          className={`text-[10px] font-bold px-2 py-0.5 rounded border ${
                            f.priority === 'CRITICAL'
                              ? 'bg-rose-500/20 text-rose-400 border-rose-500/40'
                              : f.priority === 'HIGH'
                              ? 'bg-amber-500/20 text-amber-400 border-amber-500/40'
                              : 'bg-accent-blue/20 text-accent-blue border-accent-blue/40'
                          }`}
                        >
                          {f.priority} ({f.risk_score})
                        </span>
                        <span className="font-semibold text-slate-100">{f.title}</span>
                      </div>
                      <div className="text-[11px] text-slate-400 font-mono flex items-center gap-2">
                        <span>Target: {f.target_value}</span>
                        <span>·</span>
                        <span>Severity: {f.severity}</span>
                        <span>·</span>
                        <span>Confidence: {f.confidence}</span>
                        {f.inherent_score !== undefined && f.residual_score !== undefined && (
                          <>
                            <span>·</span>
                            <span className="text-slate-300">
                              Inherent: {f.inherent_score} | Residual: {f.residual_score}
                            </span>
                          </>
                        )}
                      </div>
                    </div>

                    <button
                      onClick={() => setExpandedFindingId(isExpanded ? null : f.finding_id)}
                      className="px-2.5 py-1 rounded bg-cyber-800 hover:bg-cyber-750 text-slate-300 hover:text-white text-[11px] flex items-center gap-1 self-start md:self-auto transition-colors border border-cyber-700"
                    >
                      {isExpanded ? (
                        <>Hide Factors <ChevronUp className="w-3.5 h-3.5" /></>
                      ) : (
                        <>Explain Score <ChevronDown className="w-3.5 h-3.5" /></>
                      )}
                    </button>
                  </div>

                  {/* Expandable Factor Breakdown */}
                  {isExpanded && (
                    <div className="mt-3 pt-3 border-t border-cyber-800 space-y-2 text-[11px]">
                      <div>
                        <span className="text-slate-400 font-semibold block mb-1">Contributing Factors:</span>
                        <ul className="space-y-1 pl-4 list-disc text-slate-300">
                          {f.contributing_factors.map((cf, idx) => (
                            <li key={idx}>{cf}</li>
                          ))}
                        </ul>
                      </div>

                      {f.missing_factors.length > 0 && (
                        <div>
                          <span className="text-amber-400 font-semibold block mb-1">Missing / Unconfigured Factors (Neutralized):</span>
                          <ul className="space-y-1 pl-4 list-disc text-slate-400">
                            {f.missing_factors.map((mf, idx) => (
                              <li key={idx}>{mf}</li>
                            ))}
                          </ul>
                        </div>
                      )}

                      {f.uncertainty_range && (
                        <div className="flex items-center gap-4 text-slate-400 pt-1 font-mono text-[10px]">
                          <span>
                            Heuristic Uncertainty Range: [{f.uncertainty_range.min_score} - {f.uncertainty_range.max_score}]
                          </span>
                          <span>Margin: ±{f.uncertainty_range.uncertainty_margin}</span>
                          <span>Confidence Band: {f.uncertainty_range.confidence_band}</span>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* 4. Adaptive Assessment Planner Console */}
      <div className="bg-cyber-850 border border-cyber-750 rounded-xl p-5 shadow-lg">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2">
            <Compass className="w-4 h-4 text-accent-cyan" />
            <h3 className="text-sm font-bold text-white">Adaptive Assessment Planner</h3>
          </div>
          {plan && (
            <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-cyber-800 text-slate-300 border border-cyber-700">
              Budget: {plan.scan_budget} checks · {plan.status}
            </span>
          )}
        </div>

        {!plan || (plan.recommended_checks.length === 0 && plan.skipped_checks.length === 0) ? (
          <div className="p-6 text-center text-xs text-slate-500 bg-cyber-900/40 rounded-lg border border-cyber-800">
            No adaptive assessment plan generated yet. Click "Generate Adaptive Plan" to evaluate stale assets, environmental changes, and pending verifications.
          </div>
        ) : (
          <div className="space-y-4">
            {/* Recommended Checks */}
            <div>
              <h4 className="text-xs font-semibold text-slate-300 mb-2 flex items-center gap-1.5">
                <Sparkles className="w-3.5 h-3.5 text-accent-cyan" />
                Recommended Next Probes ({plan.recommended_checks.length})
              </h4>
              <div className="space-y-2">
                {plan.recommended_checks.map((chk: PlannedCheck) => (
                  <div
                    key={chk.check_id}
                    className="p-3 bg-cyber-900/80 border border-cyber-800 rounded-lg flex flex-col md:flex-row md:items-center justify-between gap-3 text-xs"
                  >
                    <div>
                      <div className="flex items-center gap-2 font-mono">
                        <span
                          className={`text-[10px] font-bold px-1.5 py-0.5 rounded ${
                            chk.priority === 'HIGH'
                              ? 'bg-amber-500/20 text-amber-400'
                              : 'bg-accent-blue/20 text-accent-blue'
                          }`}
                        >
                          {chk.reason_category}
                        </span>
                        <span className="font-semibold text-slate-200">{chk.target}</span>
                        <span className="text-[10px] text-slate-500">({chk.adapter_name})</span>
                      </div>
                      <p className="text-[11px] text-slate-400 mt-1 leading-relaxed">{chk.rationale}</p>
                    </div>

                    <button
                      onClick={() => handleExecuteCheck(plan.id, chk.check_id)}
                      disabled={executingCheckId === chk.check_id}
                      className="px-3 py-1.5 bg-accent-blue hover:bg-blue-600 disabled:opacity-50 text-white font-bold text-xs rounded-lg transition-colors flex items-center gap-1.5 self-start md:self-auto shrink-0"
                    >
                      <PlayCircle className="w-3.5 h-3.5" />
                      {executingCheckId === chk.check_id ? 'Dispatching...' : 'Execute Probe'}
                    </button>
                  </div>
                ))}
              </div>
            </div>

            {/* Skipped Checks */}
            {plan.skipped_checks.length > 0 && (
              <div>
                <h4 className="text-xs font-semibold text-slate-400 mb-2 flex items-center gap-1.5">
                  <Clock className="w-3.5 h-3.5 text-slate-500" />
                  Skipped / Deferred Probes ({plan.skipped_checks.length})
                </h4>
                <div className="space-y-1.5">
                  {plan.skipped_checks.slice(0, 5).map((skp: SkippedCheck, idx: number) => (
                    <div
                      key={idx}
                      className="p-2.5 bg-cyber-950/60 border border-cyber-850 rounded-lg text-xs font-mono text-slate-400 flex flex-col sm:flex-row sm:items-center justify-between gap-2"
                    >
                      <div className="flex items-center gap-2">
                        <span className="text-[10px] px-1.5 py-0.5 rounded bg-cyber-900 border border-cyber-800 text-slate-400">
                          {skp.skip_reason}
                        </span>
                        <span className="text-slate-300">{skp.target}</span>
                      </div>
                      <span className="text-[10px] text-slate-500">{skp.rationale}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </div>

      {/* 5. Provenance & Cryptographic Anchor Footer */}
      <div className="bg-cyber-900 border border-cyber-800 rounded-lg p-3 text-[11px] font-mono text-slate-500 flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <Database className="w-3.5 h-3.5 text-accent-cyan" />
          <span>Real Persisted Telemetry</span>
          <span>·</span>
          <span>{data_provenance.total_jobs} Jobs</span>
          <span>·</span>
          <span>{data_provenance.total_assets} Assets</span>
          <span>·</span>
          <span>{data_provenance.total_findings} Findings</span>
          <span>·</span>
          <span>{data_provenance.total_evidence_records} Evidence Records</span>
        </div>
        <div className="text-slate-400">
          Last Synchronized: {new Date(data_provenance.generated_at).toLocaleTimeString()}
        </div>
      </div>
    </div>
  );
};
