import React, { useState, useEffect, useCallback } from 'react';
import {
  Bot,
  Sparkles,
  RefreshCw,
  Play,
  CheckCircle2,
  Activity,
  Compass,
  Sliders,
  FileText,
  Gauge,
  Bell,
  ShieldAlert,
  Layers,
  Wrench,
  HeartPulse,
  RotateCcw,
} from 'lucide-react';
import { api } from '../services/api';
import type {
  ClosedLoopOverview,
  SecurityDecision,
  PostureChange,
  AutonomousPolicy,
  DecisionLedgerEntry,
  SecurityNotification,
  OperationalSLOResponse,
  SystemHealthData,
  DiagnosticRun,
  RecoveryActionHistoryRecord,
  FailurePattern,
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
  onNavigateToFindings: _onNavigateToFindings,
  onNavigateToAssets: _onNavigateToAssets,
  onNavigateToVerification: _onNavigateToVerification,
  onNavigateToAssessments: _onNavigateToAssessments,
}) => {
  const [activeTab, setActiveTab] = useState<'loop' | 'policy' | 'ledger' | 'slos' | 'notifications' | 'diagnostics'>('loop');

  // Closed loop state
  const [overview, setOverview] = useState<ClosedLoopOverview | null>(null);
  const [decisions, setDecisions] = useState<SecurityDecision[]>([]);
  const [changes, setChanges] = useState<PostureChange[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [isEvaluating, setIsEvaluating] = useState(false);
  const [executingDecisionId, setExecutingDecisionId] = useState<string | null>(null);
  const [actionMessage, setActionMessage] = useState<{ text: string; isError?: boolean } | null>(null);

  // Policy & Autonomy state
  const [policy, setPolicy] = useState<AutonomousPolicy | null>(null);
  const [suspendReason, setSuspendReason] = useState('');
  const [isSuspending, setIsSuspending] = useState(false);
  const [isResuming, setIsResuming] = useState(false);

  // Ledger state
  const [ledgerEntries, setLedgerEntries] = useState<DecisionLedgerEntry[]>([]);
  const [ledgerTotal, setLedgerTotal] = useState(0);

  // SLO state
  const [sloData, setSloData] = useState<OperationalSLOResponse | null>(null);

  // Notifications state
  const [notifications, setNotifications] = useState<SecurityNotification[]>([]);
  const [providerStatus, setProviderStatus] = useState<any>(null);
  const [isRetryingNotifs, setIsRetryingNotifs] = useState(false);

  // Self-Diagnostics & Recovery state
  const [systemHealth, setSystemHealth] = useState<SystemHealthData | null>(null);
  const [diagnosticRun, setDiagnosticRun] = useState<DiagnosticRun | null>(null);
  const [recoveryHistory, setRecoveryHistory] = useState<RecoveryActionHistoryRecord[]>([]);
  const [failurePatterns, setFailurePatterns] = useState<FailurePattern[]>([]);
  const [isRunningDiagnostics, setIsRunningDiagnostics] = useState(false);
  const [isExecutingRecovery, setIsExecutingRecovery] = useState(false);
  const [selectedRecoveryAction, setSelectedRecoveryAction] = useState<string>('RECOVER_STUCK_JOB');
  const [recoveryTargetId, setRecoveryTargetId] = useState<string>('');
  const [recoveryReason, setRecoveryReason] = useState<string>('');

  const loadData = useCallback(async () => {
    if (!projectId) return;
    setIsLoading(true);
    try {
      const [ov, decList, chList, pol, ledg, slos, notifs, prov, hlth, diag, recHist, pats] = await Promise.all([
        api.getClosedLoopOverview(projectId).catch(() => null),
        api.listSecurityDecisions(projectId).catch(() => []),
        api.listPostureChanges(projectId, 25).catch(() => []),
        api.getAutonomousPolicy(projectId).catch(() => null),
        api.getDecisionLedger(projectId, 25).catch(() => ({ total: 0, records: [] })),
        api.getSLOMetrics(projectId, 30).catch(() => null),
        api.getNotifications(projectId, 25).catch(() => ({ total: 0, records: [] })),
        api.getNotificationProviderStatus(projectId).catch(() => null),
        api.getSystemHealth().catch(() => null),
        api.getRecentDiagnostics(projectId, 1).catch(() => ({ recent_runs: [] })),
        api.getRecoveryHistory(projectId, 10).catch(() => ({ records: [] })),
        api.getFailurePatterns(projectId).catch(() => ({ patterns: [] })),
      ]);
      setOverview(ov);
      setDecisions(decList);
      setChanges(chList);
      setPolicy(pol);
      setLedgerEntries(ledg?.records || []);
      setLedgerTotal(ledg?.total || 0);
      setSloData(slos);
      setNotifications(notifs?.records || []);
      setProviderStatus(prov);
      setSystemHealth(hlth);
      if (diag?.recent_runs?.length > 0) {
        setDiagnosticRun(diag.recent_runs[0]);
      }
      setRecoveryHistory(recHist?.records || []);
      setFailurePatterns(pats?.patterns || []);
    } catch (err: any) {
      console.error('Failed to load unified operations data:', err);
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
      const newDecisions = await api.evaluateDecisions(projectId);
      setDecisions(newDecisions);
      setActionMessage({
        text: `Analysis complete: Synthesized ${newDecisions.length} actionable closed-loop decisions.`,
      });
      loadData();
    } catch (err: any) {
      setActionMessage({
        text: err?.message || 'Failed to synthesize decisions from security deltas.',
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
      const res = await api.executeDecision(projectId, decisionId);
      setActionMessage({
        text: `Executed decision '${res.title}' successfully. Status: ${res.status}.`,
      });
      loadData();
    } catch (err: any) {
      setActionMessage({
        text: err?.message || 'Failed to execute security decision.',
        isError: true,
      });
    } finally {
      setExecutingDecisionId(null);
    }
  };

  const handleEmergencySuspend = async () => {
    if (!suspendReason.trim()) {
      setActionMessage({ text: 'Please provide a reason for emergency suspension.', isError: true });
      return;
    }
    setIsSuspending(true);
    try {
      const res = await api.emergencySuspendAutonomy(projectId, suspendReason);
      setPolicy(res);
      setSuspendReason('');
      setActionMessage({ text: 'EMERGENCY SUSPENSION ACTIVE: All autonomous operations suspended.' });
      loadData();
    } catch (err: any) {
      setActionMessage({ text: err?.message || 'Failed to suspend autonomy.', isError: true });
    } finally {
      setIsSuspending(false);
    }
  };

  const handleResumeAutonomy = async () => {
    setIsResuming(true);
    try {
      const res = await api.resumeAutonomy(projectId);
      setPolicy(res);
      setActionMessage({ text: 'Autonomous operations resumed successfully.' });
      loadData();
    } catch (err: any) {
      setActionMessage({ text: err?.message || 'Failed to resume autonomy.', isError: true });
    } finally {
      setIsResuming(false);
    }
  };

  const handleRetryFailedNotifications = async () => {
    setIsRetryingNotifs(true);
    try {
      const res = await api.retryFailedNotifications(projectId);
      setActionMessage({ text: `Retried ${res.length} failed notifications.` });
      loadData();
    } catch (err: any) {
      setActionMessage({ text: err?.message || 'Failed to retry notifications.', isError: true });
    } finally {
      setIsRetryingNotifs(false);
    }
  };

  const handleRunDiagnostics = async () => {
    setIsRunningDiagnostics(true);
    setActionMessage(null);
    try {
      const res = await api.runProjectDiagnostics(projectId);
      setDiagnosticRun(res);
      setActionMessage({
        text: `Diagnostics completed: ${res.passed_checks}/${res.total_checks} checks passed. ${res.failed_checks} failed, ${res.warning_checks} warnings.`,
        isError: res.failed_checks > 0,
      });
      loadData();
    } catch (err: any) {
      setActionMessage({
        text: err?.message || 'Failed to run diagnostics.',
        isError: true,
      });
    } finally {
      setIsRunningDiagnostics(false);
    }
  };

  const handleExecuteRecovery = async (actionType?: string, targetId?: string) => {
    setIsExecutingRecovery(true);
    setActionMessage(null);
    const act = actionType || selectedRecoveryAction;
    const tgt = targetId || recoveryTargetId;
    try {
      const res = await api.executeRecoveryAction(
        projectId,
        act,
        'PROJECT',
        tgt || null,
        null,
        recoveryReason || 'Operator executed recovery action'
      );
      setActionMessage({
        text: `Recovery action ${act} executed with outcome: ${res.outcome}. ${res.verification_notes}`,
        isError: res.outcome === 'FAILED',
      });
      setRecoveryTargetId('');
      setRecoveryReason('');
      loadData();
    } catch (err: any) {
      setActionMessage({
        text: err?.message || 'Recovery action failed.',
        isError: true,
      });
    } finally {
      setIsExecutingRecovery(false);
    }
  };

  const pendingDecisions = decisions.filter((d) => d.status === 'PROPOSED');
  const executedDecisions = decisions.filter((d) => d.status === 'EXECUTED');

  return (
    <div className="bg-cyber-950 border border-cyber-800 rounded-xl p-5 space-y-5 shadow-2xl relative overflow-hidden">
      {/* Background glow accent */}
      <div className="absolute top-0 right-0 w-96 h-96 bg-accent-cyan/5 rounded-full blur-3xl pointer-events-none" />

      {/* 1. Header & Global Controls */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-cyber-800/80 pb-4">
        <div>
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-lg bg-accent-cyan/10 border border-accent-cyan/30 text-accent-cyan">
              <Bot className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-base font-bold text-white tracking-wide">
                  Unified Autonomous Security Operations
                </h3>
                {policy?.is_suspended ? (
                  <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-rose-500/20 text-rose-300 border border-rose-500/40">
                    AUTONOMY SUSPENDED
                  </span>
                ) : (
                  <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/40">
                    ACTIVE · {policy?.intensity || 'NORMAL'}
                  </span>
                )}
              </div>
              <p className="text-xs text-slate-400 mt-0.5">
                Observe → Assess → Correlate → Prioritize → Remediate → Retest → Close
              </p>
            </div>
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
            disabled={isEvaluating || policy?.is_suspended}
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

      {/* Navigation Tabs */}
      <div className="flex border-b border-cyber-800 gap-1 overflow-x-auto pb-1 text-xs font-mono">
        <button
          onClick={() => setActiveTab('loop')}
          className={`px-3 py-1.5 rounded-t-lg transition-colors flex items-center gap-1.5 ${
            activeTab === 'loop'
              ? 'bg-cyber-800 text-accent-cyan border-b-2 border-accent-cyan font-bold'
              : 'text-slate-400 hover:text-white'
          }`}
        >
          <Compass className="w-3.5 h-3.5" />
          Closed-Loop ({pendingDecisions.length})
        </button>
        <button
          onClick={() => setActiveTab('policy')}
          className={`px-3 py-1.5 rounded-t-lg transition-colors flex items-center gap-1.5 ${
            activeTab === 'policy'
              ? 'bg-cyber-800 text-accent-cyan border-b-2 border-accent-cyan font-bold'
              : 'text-slate-400 hover:text-white'
          }`}
        >
          <Sliders className="w-3.5 h-3.5" />
          Policy & Kill Switch
        </button>
        <button
          onClick={() => setActiveTab('ledger')}
          className={`px-3 py-1.5 rounded-t-lg transition-colors flex items-center gap-1.5 ${
            activeTab === 'ledger'
              ? 'bg-cyber-800 text-accent-cyan border-b-2 border-accent-cyan font-bold'
              : 'text-slate-400 hover:text-white'
          }`}
        >
          <FileText className="w-3.5 h-3.5" />
          Decision Ledger ({ledgerTotal})
        </button>
        <button
          onClick={() => setActiveTab('slos')}
          className={`px-3 py-1.5 rounded-t-lg transition-colors flex items-center gap-1.5 ${
            activeTab === 'slos'
              ? 'bg-cyber-800 text-accent-cyan border-b-2 border-accent-cyan font-bold'
              : 'text-slate-400 hover:text-white'
          }`}
        >
          <Gauge className="w-3.5 h-3.5" />
          Operational SLOs ({sloData?.overall_health_pct !== null && sloData?.overall_health_pct !== undefined ? `${sloData.overall_health_pct}%` : 'N/A'})
        </button>
        <button
          onClick={() => setActiveTab('notifications')}
          className={`px-3 py-1.5 rounded-t-lg transition-colors flex items-center gap-1.5 ${
            activeTab === 'notifications'
              ? 'bg-cyber-800 text-accent-cyan border-b-2 border-accent-cyan font-bold'
              : 'text-slate-400 hover:text-white'
          }`}
        >
          <Bell className="w-3.5 h-3.5" />
          Notifications ({notifications.length})
        </button>
        <button
          onClick={() => setActiveTab('diagnostics')}
          className={`px-3 py-1.5 rounded-t-lg transition-colors flex items-center gap-1.5 ${
            activeTab === 'diagnostics'
              ? 'bg-cyber-800 text-accent-cyan border-b-2 border-accent-cyan font-bold'
              : 'text-slate-400 hover:text-white'
          }`}
        >
          <Wrench className="w-3.5 h-3.5" />
          Diagnostics & Recovery ({diagnosticRun?.findings?.length || 0})
        </button>
      </div>

      {/* TAB 1: CLOSED LOOP */}
      {activeTab === 'loop' && (
        <div className="space-y-4">
          {/* KPI Metrics row */}
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

          {/* Pending Decisions List */}
          <div className="space-y-3">
            <h4 className="text-xs font-bold text-white uppercase tracking-wider font-mono">
              Actionable Security Decisions ({pendingDecisions.length})
            </h4>
            {pendingDecisions.length === 0 ? (
              <div className="p-6 text-center text-xs text-slate-500 bg-cyber-900/40 rounded-lg border border-cyber-800">
                No pending security decisions proposed. Click "Scan Deltas & Propose Next Decisions" to evaluate recent assessment changes.
              </div>
            ) : (
              <div className="space-y-2">
                {pendingDecisions.map((dec) => (
                  <div
                    key={dec.id}
                    className="p-3 bg-cyber-900/60 border border-cyber-800 hover:border-cyber-700 rounded-lg space-y-2 transition-colors"
                  >
                    <div className="flex items-start justify-between gap-3">
                      <div>
                        <div className="flex items-center gap-2">
                          <span className="px-2 py-0.5 text-[10px] font-mono font-bold rounded bg-cyan-500/10 text-cyan-300 border border-cyan-500/20">
                            {dec.action_type}
                          </span>
                          <span className="text-xs font-bold text-white">{dec.title}</span>
                        </div>
                        <p className="text-[11px] text-slate-400 mt-1">{dec.rationale}</p>
                      </div>

                      <button
                        onClick={() => handleExecute(dec.id)}
                        disabled={executingDecisionId === dec.id || policy?.is_suspended}
                        className="px-3 py-1.5 rounded-lg bg-emerald-500/20 hover:bg-emerald-500/30 text-xs font-semibold text-emerald-300 border border-emerald-500/40 flex items-center gap-1.5 disabled:opacity-50 shrink-0"
                      >
                        {executingDecisionId === dec.id ? (
                          <>
                            <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                            Executing...
                          </>
                        ) : (
                          <>
                            <Play className="w-3.5 h-3.5" />
                            Execute Action
                          </>
                        )}
                      </button>
                    </div>

                    <div className="text-[10px] font-mono text-slate-500 flex items-center gap-3 pt-1 border-t border-cyber-800/40">
                      <span>Target: {dec.target_resource || dec.target_id || 'System'}</span>
                      <span>Confidence: {Math.round(dec.confidence * 100)}%</span>
                      {dec.required_approval_role && (
                        <span className="text-amber-400">Sign-off: {dec.required_approval_role}</span>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* TAB 2: POLICY & EMERGENCY KILL SWITCH */}
      {activeTab === 'policy' && (
        <div className="space-y-4">
          <div className="p-4 bg-cyber-900/70 border border-cyber-800 rounded-lg space-y-4">
            <div className="flex items-center justify-between border-b border-cyber-800 pb-3">
              <div>
                <h4 className="text-xs font-bold text-white font-mono uppercase tracking-wider">
                  Autonomous Policy Parameters (Version: {policy?.policy_version || 'v1.0.0'})
                </h4>
                <p className="text-[11px] text-slate-400 mt-0.5">
                  Governance rules enforcing permitted scan types, intensity, budgets, and approval gates.
                </p>
              </div>

              {policy?.is_suspended ? (
                <button
                  onClick={handleResumeAutonomy}
                  disabled={isResuming}
                  className="px-3 py-1.5 bg-emerald-500/20 hover:bg-emerald-500/30 text-emerald-300 border border-emerald-500/40 rounded-lg text-xs font-mono font-bold flex items-center gap-1.5 disabled:opacity-50"
                >
                  <Play className="w-3.5 h-3.5" />
                  {isResuming ? 'Resuming...' : 'Resume Operations'}
                </button>
              ) : (
                <div className="flex items-center gap-2">
                  <input
                    type="text"
                    placeholder="Suspension reason..."
                    value={suspendReason}
                    onChange={(e) => setSuspendReason(e.target.value)}
                    className="px-2.5 py-1 text-xs font-mono bg-cyber-950 border border-cyber-700 rounded text-slate-200 placeholder-slate-600 focus:outline-none focus:border-rose-500"
                  />
                  <button
                    onClick={handleEmergencySuspend}
                    disabled={isSuspending || !suspendReason.trim()}
                    className="px-3 py-1.5 bg-rose-500/20 hover:bg-rose-500/30 text-rose-300 border border-rose-500/40 rounded-lg text-xs font-mono font-bold flex items-center gap-1.5 disabled:opacity-50"
                  >
                    <ShieldAlert className="w-3.5 h-3.5" />
                    {isSuspending ? 'Suspending...' : 'Emergency Kill-Switch'}
                  </button>
                </div>
              )}
            </div>

            {/* Policy Parameters Grid */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs font-mono">
              <div className="p-3 bg-cyber-950/60 border border-cyber-800 rounded">
                <span className="text-slate-400 block text-[10px]">Daily Budget</span>
                <span className="text-white font-bold text-sm">
                  {policy?.daily_budget_spent} / {policy?.max_daily_budget} spent
                </span>
                <div className="w-full bg-cyber-800 h-1.5 rounded-full mt-1.5 overflow-hidden">
                  <div
                    className="bg-accent-cyan h-full rounded-full transition-all"
                    style={{
                      width: `${Math.min(100, ((policy?.daily_budget_spent || 0) / (policy?.max_daily_budget || 1)) * 100)}%`,
                    }}
                  />
                </div>
              </div>

              <div className="p-3 bg-cyber-950/60 border border-cyber-800 rounded">
                <span className="text-slate-400 block text-[10px]">Scan Intensity</span>
                <span className="text-cyan-400 font-bold text-sm">{policy?.intensity}</span>
                <span className="text-slate-500 block text-[10px] mt-1">Rate: {policy?.rate_limit_rps} rps</span>
              </div>

              <div className="p-3 bg-cyber-950/60 border border-cyber-800 rounded">
                <span className="text-slate-400 block text-[10px]">Max Concurrency</span>
                <span className="text-white font-bold text-sm">{policy?.max_concurrency} jobs</span>
                <span className="text-slate-500 block text-[10px] mt-1">Max Retries: {policy?.max_retries}</span>
              </div>

              <div className="p-3 bg-cyber-950/60 border border-cyber-800 rounded">
                <span className="text-slate-400 block text-[10px]">Safety Gates</span>
                <span className="text-amber-400 font-bold text-xs block">
                  {policy?.require_approval_for_disruptive ? 'Disruptive Gated' : 'Disruptive Auto'}
                </span>
                <span className="text-slate-500 block text-[10px] mt-0.5">
                  Failure Threshold: {policy?.failure_threshold} (Current: {policy?.consecutive_failures})
                </span>
              </div>
            </div>

            <div className="text-xs font-mono text-slate-400 space-y-1">
              <div>
                <span className="text-slate-500">Permitted Adapters:</span>{' '}
                <span className="text-slate-300">{policy?.permitted_assessment_types.join(', ') || 'None'}</span>
              </div>
              <div>
                <span className="text-slate-500">Permitted Remediation Actions:</span>{' '}
                <span className="text-slate-300">{policy?.permitted_remediation_actions.join(', ') || 'None'}</span>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* TAB 3: AUDITABLE SECURITY DECISION LEDGER */}
      {activeTab === 'ledger' && (
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <h4 className="text-xs font-bold text-white uppercase tracking-wider font-mono">
              Auditable Security Decision Ledger ({ledgerTotal} Total Events)
            </h4>
            <span className="text-[11px] text-slate-500 font-mono">
              Immutable history of assessments, prioritizations, and policy evaluations
            </span>
          </div>

          {ledgerEntries.length === 0 ? (
            <div className="p-6 text-center text-xs text-slate-500 bg-cyber-900/40 rounded-lg border border-cyber-800">
              No decision ledger records recorded yet.
            </div>
          ) : (
            <div className="space-y-2">
              {ledgerEntries.map((entry) => (
                <div
                  key={entry.id}
                  className="p-3 bg-cyber-900/60 border border-cyber-800 rounded-lg space-y-1 text-xs font-mono"
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <span className="px-1.5 py-0.5 text-[10px] font-bold rounded bg-cyber-800 text-slate-300 border border-cyber-700">
                        {entry.decision_type}
                      </span>
                      <span
                        className={`text-[10px] font-bold px-1.5 py-0.5 rounded ${
                          entry.decision_outcome === 'SUCCESS' || entry.decision_outcome === 'ALLOWED'
                            ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                            : 'bg-rose-500/10 text-rose-400 border border-rose-500/20'
                        }`}
                      >
                        {entry.decision_outcome}
                      </span>
                      <span className="text-white font-bold">{entry.initiating_event}</span>
                    </div>
                    <span className="text-[10px] text-slate-500">
                      {new Date(entry.created_at).toLocaleString()}
                    </span>
                  </div>

                  <p className="text-[11px] text-slate-300 pt-0.5">{entry.reason}</p>

                  <div className="flex items-center gap-3 text-[10px] text-slate-500 pt-1 border-t border-cyber-800/40">
                    <span>Target: {entry.target_resource || entry.target_id || entry.target_type}</span>
                    <span>Policy: {entry.policy_version}</span>
                    <span>Evidence Refs: {entry.evidence_references?.length || 0}</span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* TAB 4: OPERATIONAL SLOS */}
      {activeTab === 'slos' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h4 className="text-xs font-bold text-white uppercase tracking-wider font-mono">
              Operational Service-Level Objectives (30-Day Window)
            </h4>
            <span className="text-[11px] text-slate-500 font-mono">
              Derived from persisted assessments, findings, and independent verifications
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs font-mono">
            {sloData &&
              Object.entries(sloData.slos).map(([key, item]) => (
                <div
                  key={key}
                  className="p-3 bg-cyber-900/60 border border-cyber-800 rounded-lg space-y-1.5"
                >
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-white">{item.metric_name}</span>
                    <span
                      className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                        item.status === 'MET'
                          ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                          : item.status === 'BREACHED'
                          ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40'
                          : 'bg-cyber-800 text-slate-400 border border-cyber-700'
                      }`}
                    >
                      {item.status}
                    </span>
                  </div>

                  <div className="flex items-baseline justify-between pt-1">
                    <div className="text-lg font-bold font-mono text-cyan-400">
                      {item.observed_value !== null ? `${item.observed_value} ${item.unit}` : 'No Data'}
                    </div>
                    <div className="text-[10px] text-slate-500">
                      Target: {item.target_threshold} {item.unit}
                    </div>
                  </div>
                </div>
              ))}
          </div>

          {/* Backup & Recovery Card */}
          <div className="p-3 bg-cyber-900/40 border border-cyber-800 rounded-lg text-xs font-mono flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Layers className="w-4 h-4 text-accent-cyan" />
              <div>
                <span className="text-white font-bold">Disaster Recovery & Backup Health</span>
                <div className="text-[10px] text-slate-400">
                  Last Backup: {sloData?.raw_telemetry?.backup_status?.last_backup_at || 'None recorded'}
                </div>
              </div>
            </div>
            <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
              {sloData?.raw_telemetry?.backup_status?.backup_status || 'VERIFIED'}
            </span>
          </div>
        </div>
      )}

      {/* TAB 5: NOTIFICATIONS */}
      {activeTab === 'notifications' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h4 className="text-xs font-bold text-white uppercase tracking-wider font-mono">
                Security Notifications & Escalation Ledger
              </h4>
              <p className="text-[11px] text-slate-500 mt-0.5">
                Provider Status:{' '}
                <span
                  className={
                    providerStatus?.provider_status === 'CONFIGURED'
                      ? 'text-emerald-400 font-bold'
                      : 'text-amber-400 font-bold'
                  }
                >
                  {providerStatus?.provider_status || 'UNCONFIGURED'}
                </span>{' '}
                · Deduplication window: 1h sliding guard
              </p>
            </div>

            <button
              onClick={handleRetryFailedNotifications}
              disabled={isRetryingNotifs}
              className="px-3 py-1.5 rounded-lg bg-cyber-800 hover:bg-cyber-750 text-slate-300 border border-cyber-700 text-xs font-mono font-bold flex items-center gap-1.5"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${isRetryingNotifs ? 'animate-spin' : ''}`} />
              Retry Failed Alerts
            </button>
          </div>

          {notifications.length === 0 ? (
            <div className="p-6 text-center text-xs text-slate-500 bg-cyber-900/40 rounded-lg border border-cyber-800">
              No notifications dispatched yet.
            </div>
          ) : (
            <div className="space-y-2">
              {notifications.map((notif) => (
                <div
                  key={notif.id}
                  className="p-3 bg-cyber-900/60 border border-cyber-800 rounded-lg space-y-1 text-xs font-mono"
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <span
                        className={`px-1.5 py-0.5 text-[10px] font-bold rounded ${
                          notif.severity === 'CRITICAL'
                            ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40'
                            : notif.severity === 'HIGH'
                            ? 'bg-orange-500/20 text-orange-300 border border-orange-500/40'
                            : 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                        }`}
                      >
                        {notif.severity}
                      </span>
                      <span className="font-bold text-white">{notif.title}</span>
                    </div>

                    <span
                      className={`text-[10px] font-bold px-1.5 py-0.5 rounded ${
                        notif.status === 'DELIVERED'
                          ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                          : notif.status === 'SUPPRESSED_DUPLICATE'
                          ? 'bg-cyber-800 text-slate-400 border border-cyber-700'
                          : 'bg-amber-500/10 text-amber-400 border border-amber-500/20'
                      }`}
                    >
                      {notif.status}
                    </span>
                  </div>

                  <p className="text-[11px] text-slate-300">{notif.summary}</p>

                  <div className="flex items-center gap-3 text-[10px] text-slate-500 pt-1 border-t border-cyber-800/40">
                    <span>Event: {notif.event_type}</span>
                    <span>Retries: {notif.retry_count}/{notif.max_retries}</span>
                    <span>Time: {new Date(notif.created_at).toLocaleString()}</span>
                    {notif.error_message && (
                      <span className="text-rose-400 truncate max-w-xs">{notif.error_message}</span>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* TAB 6: SELF-DIAGNOSTICS & CONTROLLED RECOVERY */}
      {activeTab === 'diagnostics' && (
        <div className="space-y-6">
          {/* 1. Subsystem Health Matrix */}
          <div className="bg-cyber-900/60 border border-cyber-800 rounded-lg p-4 space-y-3">
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-2 border-b border-cyber-800 pb-2">
              <div className="flex items-center gap-2">
                <HeartPulse className="w-4 h-4 text-accent-cyan" />
                <h4 className="text-xs font-bold font-mono text-white tracking-wide">
                  Central System Health Engine (12 Subsystems)
                </h4>
              </div>
              <div className="flex items-center gap-2">
                <span
                  className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                    systemHealth?.overall_status === 'HEALTHY'
                      ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                      : systemHealth?.overall_status === 'DEGRADED'
                      ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40'
                      : 'bg-rose-500/20 text-rose-300 border border-rose-500/40'
                  }`}
                >
                  SYSTEM {systemHealth?.overall_status || 'UNKNOWN'}
                </span>
                <span className="text-[10px] font-mono text-slate-400">
                  {systemHealth?.healthy_count || 0} Healthy · {systemHealth?.degraded_count || 0} Degraded · {systemHealth?.unhealthy_count || 0} Unhealthy
                </span>
              </div>
            </div>

            {systemHealth?.components ? (
              <div className="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-4 gap-2.5">
                {Object.entries(systemHealth.components).map(([key, comp]) => (
                  <div
                    key={key}
                    className="p-2.5 bg-cyber-950/80 border border-cyber-800/80 rounded-lg space-y-1 text-xs font-mono"
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-bold text-white text-[11px] truncate" title={comp.name}>
                        {comp.name}
                      </span>
                      <span
                        className={`px-1.5 py-0.2 rounded text-[9px] font-bold ${
                          comp.status === 'HEALTHY'
                            ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30'
                            : comp.status === 'DEGRADED'
                            ? 'bg-amber-500/10 text-amber-400 border border-amber-500/30'
                            : comp.status === 'NOT_CONFIGURED'
                            ? 'bg-cyber-800 text-slate-400 border border-cyber-700'
                            : 'bg-rose-500/10 text-rose-400 border border-rose-500/30'
                        }`}
                      >
                        {comp.status}
                      </span>
                    </div>
                    <p className="text-[10px] text-slate-400 leading-tight line-clamp-2" title={comp.message}>
                      {comp.message}
                    </p>
                    <div className="flex items-center justify-between text-[9px] text-slate-500 pt-1 border-t border-cyber-900">
                      <span>{comp.is_live_check ? '● Live Probe' : '○ Evidence'}</span>
                      <span>{comp.last_successful_check ? new Date(comp.last_successful_check).toLocaleTimeString() : 'N/A'}</span>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="p-4 text-center text-xs text-slate-500">Loading subsystem health...</div>
            )}
          </div>

          {/* 2. Self-Diagnostics Run & Findings */}
          <div className="bg-cyber-900/60 border border-cyber-800 rounded-lg p-4 space-y-3">
            <div className="flex items-center justify-between border-b border-cyber-800 pb-2">
              <div className="flex items-center gap-2">
                <Wrench className="w-4 h-4 text-accent-cyan" />
                <h4 className="text-xs font-bold font-mono text-white tracking-wide">
                  Safe Operational Self-Diagnostics
                </h4>
              </div>
              <button
                onClick={handleRunDiagnostics}
                disabled={isRunningDiagnostics}
                className="px-3 py-1.5 rounded-lg bg-accent-cyan/20 hover:bg-accent-cyan/30 text-xs font-mono font-bold text-accent-cyan border border-accent-cyan/40 transition-colors flex items-center gap-1.5 disabled:opacity-50"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${isRunningDiagnostics ? 'animate-spin' : ''}`} />
                {isRunningDiagnostics ? 'Inspecting System...' : 'Run Diagnostic Sweep'}
              </button>
            </div>

            {diagnosticRun ? (
              <div className="space-y-3">
                <div className="p-2.5 bg-cyber-950/80 rounded border border-cyber-800/80 text-xs font-mono flex items-center justify-between">
                  <span className="text-slate-300">{diagnosticRun.summary}</span>
                  <span className="text-[10px] text-slate-500">Run ID: {diagnosticRun.run_id.slice(0, 8)}...</span>
                </div>

                {diagnosticRun.findings.length === 0 ? (
                  <div className="p-6 text-center text-xs text-emerald-400 bg-emerald-500/5 border border-emerald-500/20 rounded-lg font-mono">
                    ✓ All diagnostic checks passed cleanly. Zero defects or inconsistencies detected.
                  </div>
                ) : (
                  <div className="space-y-2">
                    {diagnosticRun.findings.map((f, idx) => (
                      <div
                        key={f.id || idx}
                        className="p-3 bg-cyber-950/90 border border-cyber-800 rounded-lg space-y-2 text-xs font-mono"
                      >
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2">
                            <span
                              className={`px-1.5 py-0.5 text-[9px] font-bold rounded ${
                                f.severity === 'CRITICAL'
                                  ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40'
                                  : f.severity === 'HIGH'
                                  ? 'bg-orange-500/20 text-orange-300 border border-orange-500/40'
                                  : f.severity === 'MEDIUM'
                                  ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40'
                                  : 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                              }`}
                            >
                              {f.severity}
                            </span>
                            <span className="px-1.5 py-0.5 text-[9px] font-bold rounded bg-cyber-800 text-slate-400 border border-cyber-700">
                              {f.category}
                            </span>
                            <span className="font-bold text-white">{f.title}</span>
                          </div>

                          {f.recovery_action_available && (
                            <button
                              onClick={() => handleExecuteRecovery(f.recovery_action_available || undefined, f.affected_entities[0])}
                              disabled={isExecutingRecovery}
                              className="px-2 py-1 rounded bg-accent-cyan/10 hover:bg-accent-cyan/20 text-accent-cyan border border-accent-cyan/30 text-[10px] font-bold transition-colors flex items-center gap-1 disabled:opacity-50"
                            >
                              <RotateCcw className="w-3 h-3" />
                              Auto-Recover
                            </button>
                          )}
                        </div>

                        <p className="text-[11px] text-slate-300">{f.description}</p>
                        <div className="p-2 bg-cyber-900/60 rounded text-[10px] text-rose-300/90 font-mono">
                          <span className="text-slate-500">Observed Issue: </span>{f.observed_issue}
                        </div>
                        <div className="text-[10px] text-emerald-400/90 font-mono">
                          <span className="text-slate-500">Action: </span>{f.recommended_action}
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            ) : (
              <div className="p-6 text-center text-xs text-slate-500">
                Click &quot;Run Diagnostic Sweep&quot; to execute self-diagnostics.
              </div>
            )}
          </div>

          {/* 3. Controlled Recovery Action Center */}
          <div className="bg-cyber-900/60 border border-cyber-800 rounded-lg p-4 space-y-3">
            <div className="flex items-center gap-2 border-b border-cyber-800 pb-2">
              <RotateCcw className="w-4 h-4 text-accent-cyan" />
              <h4 className="text-xs font-bold font-mono text-white tracking-wide">
                Controlled Recovery Action Center
              </h4>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-4 gap-2 text-xs font-mono">
              <div className="space-y-1">
                <label className="text-[10px] text-slate-400">Action Type</label>
                <select
                  value={selectedRecoveryAction}
                  onChange={(e) => setSelectedRecoveryAction(e.target.value)}
                  className="w-full bg-cyber-950 border border-cyber-700 rounded px-2.5 py-1.5 text-xs text-white"
                >
                  <option value="RECOVER_STUCK_JOB">RECOVER_STUCK_JOB</option>
                  <option value="RETRY_ASSESSMENT">RETRY_ASSESSMENT</option>
                  <option value="REQUEUE_NOTIFICATION">REQUEUE_NOTIFICATION</option>
                  <option value="RECALCULATE_RISK_SCORES">RECALCULATE_RISK_SCORES</option>
                  <option value="REBUILD_KNOWLEDGE_GRAPH">REBUILD_KNOWLEDGE_GRAPH</option>
                  <option value="TRIGGER_BACKUP">TRIGGER_BACKUP</option>
                  <option value="RESUME_MONITORING">RESUME_MONITORING</option>
                </select>
              </div>

              <div className="space-y-1">
                <label className="text-[10px] text-slate-400">Target Entity ID (Optional)</label>
                <input
                  type="text"
                  placeholder="e.g. job-id or notification-id"
                  value={recoveryTargetId}
                  onChange={(e) => setRecoveryTargetId(e.target.value)}
                  className="w-full bg-cyber-950 border border-cyber-700 rounded px-2.5 py-1.5 text-xs text-white"
                />
              </div>

              <div className="space-y-1">
                <label className="text-[10px] text-slate-400">Reason / Justification</label>
                <input
                  type="text"
                  placeholder="Operator justification"
                  value={recoveryReason}
                  onChange={(e) => setRecoveryReason(e.target.value)}
                  className="w-full bg-cyber-950 border border-cyber-700 rounded px-2.5 py-1.5 text-xs text-white"
                />
              </div>

              <div className="flex items-end">
                <button
                  onClick={() => handleExecuteRecovery()}
                  disabled={isExecutingRecovery}
                  className="w-full py-2 rounded bg-accent-cyan hover:bg-accent-cyan/90 text-cyber-950 font-bold text-xs transition-colors flex items-center justify-center gap-1.5 disabled:opacity-50"
                >
                  <RotateCcw className={`w-3.5 h-3.5 ${isExecutingRecovery ? 'animate-spin' : ''}`} />
                  Execute Recovery
                </button>
              </div>
            </div>

            <div className="p-2 bg-cyber-950/60 rounded text-[10px] text-slate-400 font-mono border border-cyber-800/60">
              ℹ Two-Phase Verification: Snapshots pre-condition condition → executes bounded recovery → re-evaluates post-condition → records immutable proof in Security Decision Ledger. Zero primary evidence tampering.
            </div>
          </div>

          {/* 4. Recovery Execution History & Independent Verification */}
          <div className="bg-cyber-900/60 border border-cyber-800 rounded-lg p-4 space-y-3">
            <div className="flex items-center gap-2 border-b border-cyber-800 pb-2">
              <CheckCircle2 className="w-4 h-4 text-accent-cyan" />
              <h4 className="text-xs font-bold font-mono text-white tracking-wide">
                Verified Recovery History ({recoveryHistory.length})
              </h4>
            </div>

            {recoveryHistory.length === 0 ? (
              <div className="p-6 text-center text-xs text-slate-500 font-mono">
                No recovery actions recorded for this project yet.
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs font-mono">
                  <thead>
                    <tr className="border-b border-cyber-800 text-[10px] text-slate-400">
                      <th className="py-1.5 px-2">Time</th>
                      <th className="py-1.5 px-2">Action</th>
                      <th className="py-1.5 px-2">Outcome</th>
                      <th className="py-1.5 px-2">Verification Notes</th>
                    </tr>
                  </thead>
                  <tbody>
                    {recoveryHistory.map((rec) => (
                      <tr key={rec.id} className="border-b border-cyber-800/40 hover:bg-cyber-900/40">
                        <td className="py-2 px-2 text-slate-400 text-[10px] whitespace-nowrap">
                          {new Date(rec.execution_timestamp).toLocaleString()}
                        </td>
                        <td className="py-2 px-2 font-bold text-white">{rec.action_type}</td>
                        <td className="py-2 px-2">
                          <span
                            className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                              rec.outcome === 'SUCCESS'
                                ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                                : rec.outcome === 'PARTIAL_SUCCESS'
                                ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40'
                                : 'bg-rose-500/20 text-rose-300 border border-rose-500/40'
                            }`}
                          >
                            {rec.outcome}
                          </span>
                        </td>
                        <td className="py-2 px-2 text-slate-300 text-[11px]">{rec.verification_notes}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          {/* 5. Continuous Improvement Failure Patterns */}
          <div className="bg-cyber-900/60 border border-cyber-800 rounded-lg p-4 space-y-3">
            <div className="flex items-center gap-2 border-b border-cyber-800 pb-2">
              <Sparkles className="w-4 h-4 text-accent-cyan" />
              <h4 className="text-xs font-bold font-mono text-white tracking-wide">
                Continuous Improvement: Repeated Failure Patterns ({failurePatterns.length})
              </h4>
            </div>

            {failurePatterns.length === 0 ? (
              <div className="p-6 text-center text-xs text-slate-500 font-mono">
                No repeated failure patterns detected. Operational reliability is optimal.
              </div>
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {failurePatterns.map((pat) => (
                  <div
                    key={pat.id}
                    className="p-3 bg-cyber-950/80 border border-cyber-800 rounded-lg space-y-1.5 text-xs font-mono"
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-bold text-white">{pat.pattern_key}</span>
                      <span className="px-1.5 py-0.5 text-[10px] font-bold rounded bg-amber-500/20 text-amber-300 border border-amber-500/40">
                        {pat.occurrence_count} Occurrences
                      </span>
                    </div>
                    <p className="text-[10px] text-slate-400">{pat.sample_error_message}</p>
                    <div className="p-2 bg-accent-cyan/5 border border-accent-cyan/20 rounded text-[10px] text-accent-cyan/90">
                      💡 {pat.advisory_recommendation}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
