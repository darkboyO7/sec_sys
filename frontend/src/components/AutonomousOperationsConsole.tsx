import React, { useState, useEffect, useCallback } from 'react';
import {
  Bot,
  Sparkles,
  RefreshCw,
  Play,
  CheckCircle2,
  Activity,
  Lock,
  Compass,
} from 'lucide-react';
import { api } from '../services/api';
import type {
  ClosedLoopOverview,
  SecurityDecision,
  PostureChange,
  DecisionActionType,
  ChangeType,
} from '../types';

interface AutonomousOperationsConsoleProps {
  projectId: string;
  onNavigateToFindings?: () => void;
  onNavigateToAssets?: () => void;
  onNavigateToVerification?: () => void;
  onNavigateToAssessments?: () => void;
}

export const AutonomousOperationsConsole: React.FC<AutonomousOperationsConsoleProps> = ({
  projectId,
  onNavigateToFindings,
  onNavigateToAssets,
  onNavigateToVerification,
  onNavigateToAssessments,
}) => {
  const [overview, setOverview] = useState<ClosedLoopOverview | null>(null);
  const [decisions, setDecisions] = useState<SecurityDecision[]>([]);
  const [changes, setChanges] = useState<PostureChange[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [isEvaluating, setIsEvaluating] = useState(false);
  const [executingDecisionId, setExecutingDecisionId] = useState<string | null>(null);
  const [actionMessage, setActionMessage] = useState<{ text: string; isError?: boolean } | null>(null);

  const loadData = useCallback(async () => {
    if (!projectId) return;
    setIsLoading(true);
    try {
      const [ov, decList, chList] = await Promise.all([
        api.getClosedLoopOverview(projectId).catch(() => null),
        api.listSecurityDecisions(projectId).catch(() => []),
        api.listPostureChanges(projectId, 25).catch(() => []),
      ]);
      setOverview(ov);
      setDecisions(decList);
      setChanges(chList);
    } catch (err: any) {
      console.error('Failed to load autonomous security loop data:', err);
    } finally {
      setIsLoading(false);
    }
  }, [projectId]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  const handleEvaluate = async () => {
    setIsEvaluating(true);
    setActionMessage(null);
    try {
      const result = await api.evaluateDecisions(projectId);
      setActionMessage({
        text: `Evaluation complete: Evaluated asset and finding changes; ${result.length} actionable decision(s) active.`,
      });
      await loadData();
    } catch (err: any) {
      setActionMessage({
        text: `Evaluation error: ${err.message || 'Failed to evaluate decisions'}`,
        isError: true,
      });
    } finally {
      setIsEvaluating(false);
    }
  };

  const handleExecute = async (decisionId: string) => {
    setExecutingDecisionId(decisionId);
    setActionMessage(null);
    try {
      const updated = await api.executeDecision(projectId, decisionId, {
        notes: 'Executed via unified security operations dashboard',
        force: false,
      });
      const improvement = updated.posture_improvement_measured?.improvement_score ?? 0;
      setActionMessage({
        text: `Decision executed successfully! Action: ${updated.selected_action}. Posture improvement measured: +${improvement.toFixed(1)} pts.`,
      });
      await loadData();
    } catch (err: any) {
      setActionMessage({
        text: `Execution failed: ${err.message || 'Execution failed'}`,
        isError: true,
      });
    } finally {
      setExecutingDecisionId(null);
    }
  };

  const getActionBadgeColor = (action: DecisionActionType) => {
    switch (action) {
      case 'REASSESS_CHANGED_ASSET':
        return 'bg-blue-500/10 text-blue-400 border-blue-500/30';
      case 'PRIORITIZE_REMEDIATION':
        return 'bg-rose-500/10 text-rose-400 border-rose-500/30';
      case 'VERIFY_APPLIED_FIX':
        return 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30';
      case 'VALIDATE_UNCERTAIN_FINDING':
        return 'bg-amber-500/10 text-amber-400 border-amber-500/30';
      case 'INVESTIGATE_HIGH_IMPACT_EXPOSURE':
        return 'bg-purple-500/10 text-purple-400 border-purple-500/30';
      case 'REFRESH_STALE_EVIDENCE':
        return 'bg-cyan-500/10 text-cyan-400 border-cyan-500/30';
      case 'RECALCULATE_RISK_AND_PATHS':
        return 'bg-indigo-500/10 text-indigo-400 border-indigo-500/30';
      default:
        return 'bg-slate-500/10 text-slate-400 border-slate-500/30';
    }
  };

  const getChangeBadgeColor = (changeType: ChangeType) => {
    switch (changeType) {
      case 'NEW_VULNERABILITY':
      case 'SEVERITY_CHANGED':
        return 'bg-rose-500/15 text-rose-400 border-rose-500/30';
      case 'RESOLVED_VULNERABILITY':
      case 'REMEDIATION_OUTCOME':
        return 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30';
      case 'NEW_ASSET':
      case 'NEW_SERVICE':
        return 'bg-cyan-500/15 text-cyan-400 border-cyan-500/30';
      case 'CHANGED_HTTP_STATUS':
      case 'CHANGED_TLS_CONFIG':
        return 'bg-purple-500/15 text-purple-400 border-purple-500/30';
      case 'INCONCLUSIVE_PROBE':
        return 'bg-slate-500/15 text-slate-400 border-slate-500/30';
      default:
        return 'bg-amber-500/15 text-amber-400 border-amber-500/30';
    }
  };

  const pendingDecisions = decisions.filter(
    (d) => d.status === 'PROPOSED' || d.status === 'APPROVED'
  );
  const executedDecisions = decisions.filter((d) => d.status === 'EXECUTED');

  return (
    <div className="bg-cyber-850 border border-cyber-750 rounded-xl p-5 shadow-lg space-y-5">
      {/* 1. Header & Actions */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-cyber-750">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-lg bg-accent-cyan/10 border border-accent-cyan/20 text-accent-cyan">
            <Bot className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-sm font-bold text-white tracking-wide">
                Autonomous Security Intelligence Loop
              </h3>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-500/15 text-emerald-400 border border-emerald-500/30 font-semibold flex items-center gap-1">
                <Sparkles className="w-3 h-3" />
                Active Closed-Loop Controller
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              Change detection · Contextual decision proposals · Governance-gated execution · Posture delta measurement
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={loadData}
            disabled={isLoading}
            className="p-2 rounded-lg bg-cyber-800 hover:bg-cyber-750 text-slate-300 hover:text-white border border-cyber-700 transition-colors"
            title="Refresh Intelligence Telemetry"
          >
            <RefreshCw className={`w-4 h-4 ${isLoading ? 'animate-spin text-accent-cyan' : ''}`} />
          </button>
          <button
            onClick={handleEvaluate}
            disabled={isEvaluating}
            className="px-3 py-1.5 rounded-lg bg-accent-cyan/20 hover:bg-accent-cyan/30 text-xs font-semibold text-accent-cyan border border-accent-cyan/40 transition-colors flex items-center gap-1.5 disabled:opacity-50"
          >
            {isEvaluating ? (
              <>
                <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                Analyzing Deltas...
              </>
            ) : (
              <>
                <Sparkles className="w-3.5 h-3.5" />
                Scan Deltas & Propose Next Decisions
              </>
            )}
          </button>
        </div>
      </div>

      {/* Action Notification Banner */}
      {actionMessage && (
        <div
          className={`p-3 rounded-lg text-xs font-mono border flex items-center justify-between ${
            actionMessage.isError
              ? 'bg-rose-500/10 text-rose-300 border-rose-500/30'
              : 'bg-emerald-500/10 text-emerald-300 border-emerald-500/30'
          }`}
        >
          <span>{actionMessage.text}</span>
          <button
            onClick={() => setActionMessage(null)}
            className="text-[10px] underline ml-2 hover:opacity-80"
          >
            Dismiss
          </button>
        </div>
      )}

      {/* 2. Closed-Loop Metrics KPI row */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <div className="bg-cyber-900/80 border border-cyber-800 rounded-lg p-3">
          <div className="text-[11px] text-slate-400 flex items-center justify-between">
            <span>Posture Deltas Detected</span>
            <Activity className="w-3.5 h-3.5 text-cyan-400" />
          </div>
          <div className="text-xl font-bold font-mono text-white mt-1">
            {overview?.total_posture_changes ?? changes.length}
          </div>
          <div className="text-[10px] text-slate-500 mt-0.5">
            {changes.filter((c) => c.is_confirmed).length} confirmed · {changes.filter((c) => !c.is_confirmed).length} unconfirmed
          </div>
        </div>

        <div className="bg-cyber-900/80 border border-cyber-800 rounded-lg p-3">
          <div className="text-[11px] text-slate-400 flex items-center justify-between">
            <span>Actionable Decisions</span>
            <Bot className="w-3.5 h-3.5 text-amber-400" />
          </div>
          <div className="text-xl font-bold font-mono text-amber-400 mt-1">
            {pendingDecisions.length}
          </div>
          <div className="text-[10px] text-slate-500 mt-0.5">
            {pendingDecisions.filter((d) => d.required_approval_role).length} require lead sign-off
          </div>
        </div>

        <div className="bg-cyber-900/80 border border-cyber-800 rounded-lg p-3">
          <div className="text-[11px] text-slate-400 flex items-center justify-between">
            <span>Executed Actions</span>
            <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
          </div>
          <div className="text-xl font-bold font-mono text-emerald-400 mt-1">
            {executedDecisions.length}
          </div>
          <div className="text-[10px] text-slate-500 mt-0.5">
            Verified across execution loop
          </div>
        </div>

        <div className="bg-cyber-900/80 border border-cyber-800 rounded-lg p-3">
          <div className="text-[11px] text-slate-400 flex items-center justify-between">
            <span>Posture Improvement</span>
            <Sparkles className="w-3.5 h-3.5 text-purple-400" />
          </div>
          <div className="text-xl font-bold font-mono text-purple-400 mt-1">
            {overview?.verified_improvements_count ?? 0}
          </div>
          <div className="text-[10px] text-slate-500 mt-0.5">
            Risk & path deltas reduced
          </div>
        </div>
      </div>

      {/* 3. Actionable Decisions Section */}
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Compass className="w-4 h-4 text-accent-cyan" />
            <h4 className="text-xs font-bold text-white uppercase tracking-wider font-mono">
              Actionable Next Security Decisions ({pendingDecisions.length})
            </h4>
          </div>
          <span className="text-[11px] text-slate-500 font-mono">
            Ranked by priority & risk reduction potential
          </span>
        </div>

        {pendingDecisions.length === 0 ? (
          <div className="p-6 text-center text-xs text-slate-500 bg-cyber-900/40 rounded-lg border border-cyber-800">
            No pending security decisions proposed. Click "Scan Deltas & Propose Next Decisions" to evaluate recent assessment changes.
          </div>
        ) : (
          <div className="space-y-2">
            {pendingDecisions.map((decision) => (
              <div
                key={decision.id}
                className="p-4 bg-cyber-900/90 border border-cyber-800 hover:border-cyber-700 rounded-lg transition-colors space-y-2"
              >
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <span
                      className={`text-[10px] font-mono px-2 py-0.5 rounded font-bold border ${getActionBadgeColor(
                        decision.action_type
                      )}`}
                    >
                      {decision.action_type.replace(/_/g, ' ')}
                    </span>
                    <span className="text-xs font-semibold text-white">
                      {decision.title}
                    </span>
                  </div>

                  <div className="flex items-center gap-2 text-[11px] font-mono">
                    <span className="text-slate-400">
                      Priority: <strong className="text-accent-cyan">{(decision.confidence * 100).toFixed(0)}%</strong>
                    </span>
                    <span className="text-slate-600">·</span>
                    <span className="text-slate-400">
                      Uncertainty: <strong className="text-amber-400">{(decision.uncertainty * 100).toFixed(0)}%</strong>
                    </span>
                    {decision.required_approval_role && (
                      <span className="flex items-center gap-1 text-amber-400 bg-amber-500/10 px-2 py-0.5 rounded border border-amber-500/30 text-[10px]">
                        <Lock className="w-3 h-3" />
                        {decision.required_approval_role} Approval Required
                      </span>
                    )}
                  </div>
                </div>

                <p className="text-xs text-slate-300 leading-relaxed font-sans">
                  {decision.rationale}
                </p>

                <div className="text-[11px] text-slate-400 font-mono flex flex-wrap items-center justify-between gap-2 pt-2 border-t border-cyber-800">
                  <div className="flex items-center gap-3">
                    {decision.target_resource && (
                      <span>Target: <span className="text-cyan-300 font-semibold">{decision.target_resource}</span></span>
                    )}
                    <span>Action: <span className="text-slate-200">{decision.selected_action}</span></span>
                  </div>

                  <div className="flex items-center gap-2">
                    {/* Navigation buttons based on action type */}
                    {decision.target_id && onNavigateToFindings && decision.action_type.includes('FINDING') && (
                      <button
                        onClick={onNavigateToFindings}
                        className="px-2 py-1 rounded bg-cyber-800 hover:bg-cyber-750 text-slate-300 text-[11px] transition-colors"
                      >
                        View Finding
                      </button>
                    )}
                    {decision.target_id && onNavigateToAssets && decision.action_type.includes('ASSET') && (
                      <button
                        onClick={onNavigateToAssets}
                        className="px-2 py-1 rounded bg-cyber-800 hover:bg-cyber-750 text-slate-300 text-[11px] transition-colors"
                      >
                        View Asset
                      </button>
                    )}
                    {decision.action_type === 'VERIFY_APPLIED_FIX' && onNavigateToVerification && (
                      <button
                        onClick={onNavigateToVerification}
                        className="px-2 py-1 rounded bg-cyber-800 hover:bg-cyber-750 text-slate-300 text-[11px] transition-colors"
                      >
                        Verification Desk
                      </button>
                    )}
                    {decision.action_type === 'REASSESS_CHANGED_ASSET' && onNavigateToAssessments && (
                      <button
                        onClick={onNavigateToAssessments}
                        className="px-2 py-1 rounded bg-cyber-800 hover:bg-cyber-750 text-slate-300 text-[11px] transition-colors"
                      >
                        Assessments
                      </button>
                    )}

                    {/* Execution Action Button */}
                    <button
                      onClick={() => handleExecute(decision.id)}
                      disabled={executingDecisionId === decision.id}
                      className="px-3 py-1 rounded bg-accent-blue hover:bg-accent-blue/80 text-white font-semibold text-[11px] transition-colors flex items-center gap-1.5 shadow-sm disabled:opacity-50"
                    >
                      {executingDecisionId === decision.id ? (
                        <>
                          <RefreshCw className="w-3 h-3 animate-spin" />
                          Executing...
                        </>
                      ) : (
                        <>
                          <Play className="w-3 h-3 fill-current" />
                          {decision.required_approval_role ? 'Approve & Execute' : 'Execute Decision'}
                        </>
                      )}
                    </button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* 4. Security Posture Changes Timeline */}
      <div className="space-y-3 pt-2">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Activity className="w-4 h-4 text-emerald-400" />
            <h4 className="text-xs font-bold text-white uppercase tracking-wider font-mono">
              Detected Posture Changes ({changes.length})
            </h4>
          </div>
          <span className="text-[11px] text-slate-500 font-mono">
            Fail-closed telemetry delta history
          </span>
        </div>

        {changes.length === 0 ? (
          <div className="p-4 text-center text-xs text-slate-500 bg-cyber-900/40 rounded-lg border border-cyber-800 font-mono">
            No posture change records found for this workspace. Changes are recorded whenever an assessment job completes.
          </div>
        ) : (
          <div className="space-y-2 max-h-56 overflow-y-auto">
            {changes.slice(0, 10).map((change) => (
              <div
                key={change.id}
                className="p-2.5 bg-cyber-900/70 border border-cyber-800 rounded-lg flex items-center justify-between text-xs font-mono"
              >
                <div className="space-y-0.5">
                  <div className="flex items-center gap-2">
                    <span
                      className={`text-[9px] px-1.5 py-0.5 rounded font-bold border ${getChangeBadgeColor(
                        change.change_type
                      )}`}
                    >
                      {change.change_type}
                    </span>
                    <span className="text-slate-200 font-semibold">{change.title}</span>
                    {!change.is_confirmed && (
                      <span className="text-[9px] px-1 rounded bg-slate-700/60 text-slate-400 border border-slate-600/30">
                        INCONCLUSIVE / UNCONFIRMED
                      </span>
                    )}
                  </div>
                  <div className="text-[10px] text-slate-400 flex items-center gap-2">
                    <span>Target: {change.target_resource}</span>
                    <span>·</span>
                    <span className="text-slate-500">{change.evidence_summary}</span>
                  </div>
                </div>

                <div className="text-right text-[10px] text-slate-500 whitespace-nowrap ml-4">
                  {new Date(change.created_at).toLocaleTimeString([], {
                    hour: '2-digit',
                    minute: '2-digit',
                    second: '2-digit',
                  })}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};
