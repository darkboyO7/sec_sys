import React, { useState, useEffect, useCallback } from 'react';
import {
  ShieldAlert,
  AlertTriangle,
  CheckCircle2,
  HelpCircle,
  ArrowRight,
  RefreshCw,
  XCircle,
  Zap,
  ListOrdered,
  Clock,
  Compass,
} from 'lucide-react';
import { api } from '../services/api';
import type {
  UnifiedOpsDashboardResponse,
  PriorityQueueResponse,
  PriorityQueueItem,
  OperatorCoreQuestion,
} from '../types';

interface UnifiedOperationsCockpitProps {
  projectId?: string;
  onNavigate?: (route: string) => void;
}

export const UnifiedOperationsCockpit: React.FC<UnifiedOperationsCockpitProps> = ({
  projectId,
  onNavigate,
}) => {
  const [summary, setSummary] = useState<UnifiedOpsDashboardResponse | null>(null);
  const [queue, setQueue] = useState<PriorityQueueResponse | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [filterCategory, setFilterCategory] = useState<string>('ALL');
  const [dismissingId, setDismissingId] = useState<string | null>(null);
  const [expandedQuestion, setExpandedQuestion] = useState<number | null>(null);

  const fetchData = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const [sumRes, queueRes] = await Promise.all([
        api.getCockpitSummary(projectId),
        api.getPriorityQueue(projectId),
      ]);
      setSummary(sumRes);
      setQueue(queueRes);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Failed to retrieve operations telemetry';
      setError(msg);
    } finally {
      setLoading(false);
    }
  }, [projectId]);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  const handleDismiss = async (itemId: string) => {
    try {
      setDismissingId(itemId);
      await api.dismissPriorityQueueItem(itemId);
      if (queue) {
        setQueue({
          ...queue,
          items: queue.items.filter((item) => item.item_id !== itemId),
          total_items: Math.max(0, queue.total_items - 1),
        });
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Failed to dismiss item';
      alert(`Dismiss error: ${msg}`);
    } finally {
      setDismissingId(null);
    }
  };

  const getPostureColor = (posture: string) => {
    switch (posture) {
      case 'HEALTHY':
        return 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30';
      case 'ATTENTION_REQUIRED':
        return 'text-amber-400 bg-amber-500/10 border-amber-500/30';
      case 'ELEVATED_RISK':
      default:
        return 'text-rose-400 bg-rose-500/10 border-rose-500/30';
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'PASS':
        return <CheckCircle2 className="w-4 h-4 text-emerald-400" aria-label="Pass" />;
      case 'WARN':
        return <AlertTriangle className="w-4 h-4 text-amber-400" aria-label="Warning" />;
      case 'FAIL':
        return <XCircle className="w-4 h-4 text-rose-400" aria-label="Fail" />;
      case 'INFO':
      default:
        return <HelpCircle className="w-4 h-4 text-cyan-400" aria-label="Information" />;
    }
  };

  const filteredQueueItems = queue?.items.filter((item: PriorityQueueItem) => {
    if (filterCategory === 'ALL') return true;
    return item.category === filterCategory;
  }) || [];

  return (
    <section aria-label="Unified Operations Command Center" className="space-y-6">
      {/* 1. Header Posture Banner */}
      <div className="bg-cyber-850 border border-cyber-750 rounded-xl p-5 shadow-lg">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <Compass className="w-5 h-5 text-accent-cyan" />
              <h2 className="text-lg font-bold text-white tracking-wide">
                Unified Operations Command Cockpit
              </h2>
              {summary && (
                <span
                  className={`text-xs px-2.5 py-0.5 rounded-full font-mono font-semibold border ${getPostureColor(
                    summary.overall_posture
                  )}`}
                >
                  {summary.overall_posture.replace('_', ' ')}
                </span>
              )}
            </div>
            <p className="text-xs text-slate-400">
              Live synthesized security posture, actionable priority queue, and authoritative answers to the 12 core operational questions.
            </p>
          </div>

          <div className="flex items-center gap-3">
            {summary && (
              <span className="text-[11px] font-mono text-slate-400 flex items-center gap-1">
                <Clock className="w-3.5 h-3.5 text-slate-500" />
                Freshness: {summary.data_freshness_seconds}s
              </span>
            )}
            <button
              onClick={fetchData}
              disabled={loading}
              className="px-3 py-1.5 rounded-lg bg-cyber-800 hover:bg-cyber-700 border border-cyber-700 text-xs text-slate-200 flex items-center gap-1.5 transition-colors disabled:opacity-50"
              aria-label="Refresh operational telemetry"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
              Refresh
            </button>
          </div>
        </div>

        {error && (
          <div className="mt-4 p-3 bg-rose-500/10 border border-rose-500/30 rounded-lg text-rose-300 text-xs flex items-center gap-2">
            <XCircle className="w-4 h-4 shrink-0" />
            <span>{error}</span>
          </div>
        )}

        {/* Dynamic Next Action Guidance */}
        {summary && summary.recommended_next_action && (
          <div className="mt-4 p-3 bg-cyber-900 border border-accent-cyan/30 rounded-lg flex items-start gap-3">
            <Zap className="w-4 h-4 text-accent-cyan shrink-0 mt-0.5" />
            <div>
              <div className="text-[11px] font-semibold text-accent-cyan uppercase tracking-wider">
                Recommended Next Operational Action
              </div>
              <p className="text-xs text-slate-200 mt-0.5">{summary.recommended_next_action}</p>
            </div>
          </div>
        )}
      </div>

      {/* 2. Actionable Security Priority Queue */}
      <div className="bg-cyber-850 border border-cyber-750 rounded-xl p-5 shadow-lg">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-4">
          <div className="flex items-center gap-2">
            <ListOrdered className="w-4 h-4 text-amber-400" />
            <h3 className="text-sm font-semibold text-white">Actionable Security Priority Queue</h3>
            {queue && (
              <span className="text-xs font-mono px-2 py-0.5 rounded bg-amber-500/10 text-amber-400 border border-amber-500/30 font-bold">
                {queue.total_items} items ({queue.urgent_items_count} urgent)
              </span>
            )}
          </div>

          <div className="flex items-center gap-2">
            <label htmlFor="priority-filter" className="text-xs text-slate-400">
              Filter:
            </label>
            <select
              id="priority-filter"
              value={filterCategory}
              onChange={(e) => setFilterCategory(e.target.value)}
              className="bg-cyber-900 border border-cyber-700 text-xs text-slate-200 rounded px-2.5 py-1"
            >
              <option value="ALL">All Categories</option>
              <option value="REMEDIATION_APPROVAL">Remediation Approvals</option>
              <option value="RETEST_FAILED">Failed Retests</option>
              <option value="JOB_FAILED">Failed Assessments</option>
              <option value="EXPOSURE_DRIFT">Exposure Drift</option>
              <option value="INTEGRITY_ALERT">Integrity Alerts</option>
              <option value="RETENTION_EXPIRATION">Retention Expiration</option>
              <option value="SCOPE_EXPIRING">Scope Expiring</option>
            </select>
          </div>
        </div>

        {loading && !queue ? (
          <div className="p-8 text-center text-xs text-slate-500 font-mono">
            Loading priority queue telemetry...
          </div>
        ) : filteredQueueItems.length === 0 ? (
          <div className="p-6 text-center text-xs text-slate-500 bg-cyber-900/40 rounded-lg border border-cyber-800">
            No pending priority queue items found matching the selected filter.
          </div>
        ) : (
          <div className="space-y-3">
            {filteredQueueItems.map((item: PriorityQueueItem) => (
              <div
                key={item.item_id}
                className="p-3.5 bg-cyber-900/90 border border-cyber-800 hover:border-cyber-700 rounded-lg flex flex-col md:flex-row md:items-center justify-between gap-3 text-xs"
              >
                <div className="space-y-1">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span
                      className={`text-[10px] font-mono px-1.5 py-0.5 rounded font-bold ${
                        item.priority_score >= 80
                          ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40'
                          : item.priority_score >= 60
                          ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40'
                          : 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                      }`}
                    >
                      P{item.priority_score}
                    </span>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyber-800 text-slate-400">
                      {item.category.replace('_', ' ')}
                    </span>
                    <span className="font-semibold text-slate-100">{item.title}</span>
                  </div>
                  <p className="text-[11px] text-slate-400">{item.reason}</p>
                  <div className="flex items-center gap-3 text-[10px] text-slate-500 font-mono">
                    {item.affected_asset && <span>Asset: {item.affected_asset}</span>}
                    <span>Role: {item.required_role}</span>
                    <span>Action: {item.permitted_action}</span>
                  </div>
                </div>

                <div className="flex items-center gap-2 shrink-0">
                  {onNavigate && (
                    <button
                      onClick={() => onNavigate(item.target_route)}
                      className="px-3 py-1.5 rounded bg-accent-blue/20 hover:bg-accent-blue/30 text-accent-blue border border-accent-blue/40 text-xs font-semibold flex items-center gap-1 transition-colors"
                    >
                      Resolve <ArrowRight className="w-3 h-3" />
                    </button>
                  )}
                  <button
                    onClick={() => handleDismiss(item.item_id)}
                    disabled={dismissingId === item.item_id}
                    className="px-2.5 py-1.5 rounded bg-cyber-800 hover:bg-cyber-750 text-slate-400 hover:text-slate-200 text-xs transition-colors disabled:opacity-50"
                    title="Acknowledge and dismiss from queue"
                  >
                    Dismiss
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* 3. The 12 Core Operational Questions Matrix */}
      <div className="bg-cyber-850 border border-cyber-750 rounded-xl p-5 shadow-lg">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2">
            <ShieldAlert className="w-4 h-4 text-accent-cyan" />
            <h3 className="text-sm font-semibold text-white">
              The 12 Core Security Operations Invariants
            </h3>
          </div>
          <span className="text-xs text-slate-400">
            Real-time authoritative evaluations derived from live assessment, evidence, and audit stores
          </span>
        </div>

        {loading && !summary ? (
          <div className="p-8 text-center text-xs text-slate-500 font-mono">
            Evaluating operational invariants...
          </div>
        ) : summary && summary.core_questions ? (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {summary.core_questions.map((q: OperatorCoreQuestion) => {
              const isExpanded = expandedQuestion === q.question_id;
              return (
                <div
                  key={q.question_id}
                  className="p-3 bg-cyber-900/80 border border-cyber-800 rounded-lg hover:border-cyber-700 transition-all text-xs"
                >
                  <div
                    className="flex items-start justify-between gap-2 cursor-pointer"
                    onClick={() => setExpandedQuestion(isExpanded ? null : q.question_id)}
                  >
                    <div className="flex items-start gap-2">
                      <span className="shrink-0 mt-0.5">{getStatusIcon(q.status)}</span>
                      <div>
                        <div className="font-semibold text-slate-200">
                          {q.question_id}. {q.question_text}
                        </div>
                        <p className="text-[11px] text-slate-400 mt-0.5">{q.summary}</p>
                      </div>
                    </div>
                    <span
                      className={`text-[9px] font-mono px-1.5 py-0.5 rounded font-bold shrink-0 ${
                        q.status === 'PASS'
                          ? 'bg-emerald-500/10 text-emerald-400'
                          : q.status === 'WARN'
                          ? 'bg-amber-500/10 text-amber-400'
                          : 'bg-rose-500/10 text-rose-400'
                      }`}
                    >
                      {q.status}
                    </span>
                  </div>

                  {isExpanded && q.details && Object.keys(q.details).length > 0 && (
                    <div className="mt-2.5 pt-2 border-t border-cyber-800/80 text-[10px] font-mono text-slate-400 space-y-1">
                      {Object.entries(q.details).map(([k, v]) => (
                        <div key={k} className="flex items-center justify-between">
                          <span className="text-slate-500">{k}:</span>
                          <span className="text-slate-300 truncate max-w-[240px]">
                            {typeof v === 'object' ? JSON.stringify(v) : String(v)}
                          </span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        ) : null}
      </div>
    </section>
  );
};
