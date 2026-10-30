import React, { useState, useEffect, useCallback } from 'react';
import {
  ShieldCheck,
  RefreshCw,
  KeyRound,
  AlertTriangle,
  History,
  MessageSquare,
  ChevronDown,
  ChevronUp,
  Sparkles,
  Info,
  Clock,
  Layers,
} from 'lucide-react';
import { api } from '../services/api';
import type {
  Project,
  RemediationRecommendation,
  RecommendationFeedbackType,
  RecommendationUsefulnessMetrics,
  GuidanceType,
  BusinessPriority,
} from '../types';

interface Props {
  currentProject: Project;
}

export const RemediationVerificationView: React.FC<Props> = ({ currentProject }) => {
  const [remediations, setRemediations] = useState<RemediationRecommendation[]>([]);
  const [metrics, setMetrics] = useState<RecommendationUsefulnessMetrics | null>(null);
  const [loading, setLoading] = useState(false);
  const [actionTicketRef, setActionTicketRef] = useState('');
  const [selectedRecId, setSelectedRecId] = useState<string | null>(null);
  const [statusMessage, setStatusMessage] = useState<string | null>(null);

  // Prompt 51: Explainability expand/collapse
  const [expandedRecs, setExpandedRecs] = useState<Record<string, boolean>>({});

  // Prompt 51: Feedback Modal State
  const [feedbackModalRec, setFeedbackModalRec] = useState<RemediationRecommendation | null>(null);
  const [feedbackType, setFeedbackType] = useState<RecommendationFeedbackType>('HELPFUL');
  const [feedbackRating, setFeedbackRating] = useState<number>(5);
  const [feedbackComment, setFeedbackComment] = useState<string>('');
  const [feedbackActionable, setFeedbackActionable] = useState<boolean>(true);
  const [feedbackApplied, setFeedbackApplied] = useState<boolean>(true);
  const [submittingFeedback, setSubmittingFeedback] = useState<boolean>(false);

  // Prompt 51: Version History Modal State
  const [versionModalRec, setVersionModalRec] = useState<RemediationRecommendation | null>(null);
  const [versionList, setVersionList] = useState<RemediationRecommendation[]>([]);
  const [loadingVersions, setLoadingVersions] = useState<boolean>(false);

  const loadData = useCallback(async () => {
    setLoading(true);
    try {
      const [recs, usefulness] = await Promise.all([
        api.listRemediations(currentProject.id, { latest_only: true }),
        api.getRecommendationUsefulnessMetrics(currentProject.id).catch(() => null),
      ]);
      setRemediations(recs);
      setMetrics(usefulness);
    } catch (err: any) {
      console.error('Failed to load remediations or metrics:', err);
    } finally {
      setLoading(false);
    }
  }, [currentProject.id]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  const toggleExpand = (id: string) => {
    setExpandedRecs((prev) => ({ ...prev, [id]: !prev[id] }));
  };

  const handleAuthorizeChange = async (recId: string) => {
    if (!actionTicketRef.trim()) {
      alert('Please specify an external change ticket reference.');
      return;
    }
    try {
      await api.authorizeChange(currentProject.id, recId, actionTicketRef.trim());
      setStatusMessage(`Change authorization recorded for recommendation ${recId.slice(0, 8)}.`);
      setActionTicketRef('');
      setSelectedRecId(null);
      loadData();
    } catch (err: any) {
      alert(err.message);
    }
  };

  const handleRetest = async (findingId: string) => {
    try {
      const res = await api.retestFinding(currentProject.id, findingId);
      setStatusMessage(`Independent verification probe completed. Outcome: ${res.outcome}`);
      loadData();
    } catch (err: any) {
      alert(err.message);
    }
  };

  const handleOpenFeedback = (rec: RemediationRecommendation) => {
    setFeedbackModalRec(rec);
    setFeedbackType('HELPFUL');
    setFeedbackRating(5);
    setFeedbackComment('');
    setFeedbackActionable(true);
    setFeedbackApplied(true);
  };

  const handleSubmitFeedback = async () => {
    if (!feedbackModalRec) return;
    setSubmittingFeedback(true);
    try {
      await api.submitRecommendationFeedback(currentProject.id, feedbackModalRec.id, {
        feedback_type: feedbackType,
        rating: feedbackRating,
        comment: feedbackComment.trim() || undefined,
        was_actionable: feedbackActionable,
        applied_as_instructed: feedbackApplied,
      });
      setStatusMessage(`Feedback recorded for recommendation ${feedbackModalRec.id.slice(0, 8)}.`);
      setFeedbackModalRec(null);
      loadData();
    } catch (err: any) {
      alert(`Feedback submission failed: ${err.message}`);
    } finally {
      setSubmittingFeedback(false);
    }
  };

  const handleOpenVersionHistory = async (rec: RemediationRecommendation) => {
    setVersionModalRec(rec);
    setLoadingVersions(true);
    try {
      const versions = await api.getRecommendationVersions(currentProject.id, rec.id);
      setVersionList(versions);
    } catch (err: any) {
      alert(`Failed to load versions: ${err.message}`);
    } finally {
      setLoadingVersions(false);
    }
  };

  const getGuidanceBadge = (type?: GuidanceType) => {
    switch (type) {
      case 'VERIFIED_INSTRUCTION':
        return (
          <span className="px-2.5 py-0.5 text-xs rounded-full bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 flex items-center gap-1 font-semibold">
            <ShieldCheck className="w-3.5 h-3.5" />
            Verified Instruction
          </span>
        );
      case 'UNVERIFIED_SUGGESTION':
        return (
          <span className="px-2.5 py-0.5 text-xs rounded-full bg-purple-500/20 text-purple-300 border border-purple-500/40 flex items-center gap-1 font-semibold">
            <Sparkles className="w-3.5 h-3.5 text-purple-400" />
            Unverified Suggestion
          </span>
        );
      default:
        return (
          <span className="px-2.5 py-0.5 text-xs rounded-full bg-amber-500/20 text-amber-300 border border-amber-500/40 flex items-center gap-1 font-semibold">
            <Info className="w-3.5 h-3.5" />
            General Guidance
          </span>
        );
    }
  };

  const getBusinessPriorityBadge = (p?: BusinessPriority) => {
    switch (p) {
      case 'P1_CRITICAL':
        return <span className="px-2 py-0.5 text-xs rounded font-bold bg-rose-500/20 text-rose-300 border border-rose-500/40">P1 CRITICAL</span>;
      case 'P2_HIGH':
        return <span className="px-2 py-0.5 text-xs rounded font-bold bg-orange-500/20 text-orange-300 border border-orange-500/40">P2 HIGH</span>;
      case 'P3_MEDIUM':
        return <span className="px-2 py-0.5 text-xs rounded font-semibold bg-amber-500/20 text-amber-300 border border-amber-500/40">P3 MEDIUM</span>;
      default:
        return <span className="px-2 py-0.5 text-xs rounded text-slate-300 bg-slate-800 border border-slate-700">P4 LOW</span>;
    }
  };

  return (
    <div className="space-y-6">
      {/* 1. Header Bar */}
      <div className="flex justify-between items-center bg-cyber-850 p-6 rounded-xl border border-cyber-700">
        <div>
          <h2 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <ShieldCheck className="w-6 h-6 text-accent-cyan" />
            Explainable Remediation Prioritization & Verification
          </h2>
          <p className="text-sm text-slate-400 mt-1">
            Evidence-backed remediation guidance (Prompt 51) with multi-dimensional prioritization, governance controls, and independent verification re-tests.
          </p>
        </div>
        <button
          onClick={loadData}
          disabled={loading}
          className="px-3.5 py-2 bg-cyber-750 hover:bg-cyber-700 text-slate-200 text-xs rounded-lg flex items-center gap-2 border border-cyber-600 transition"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          Refresh
        </button>
      </div>

      {statusMessage && (
        <div className="p-4 bg-accent-cyan/10 border border-accent-cyan/30 text-accent-cyan rounded-lg text-sm flex items-center justify-between">
          <span>{statusMessage}</span>
          <button onClick={() => setStatusMessage(null)} className="text-xs hover:underline">Dismiss</button>
        </div>
      )}

      {/* 2. Objective Usefulness Metrics Dashboard (Prompt 51) */}
      {metrics && (
        <div className="bg-cyber-850 p-5 rounded-xl border border-cyber-700 space-y-4">
          <div className="flex justify-between items-center">
            <div className="flex items-center gap-2 text-sm font-semibold text-slate-200">
              <Sparkles className="w-4 h-4 text-accent-cyan" />
              Remediation Usefulness & Governance Ledger
            </div>
            <span className="text-[11px] text-slate-500 font-mono">
              Grounded in actual historical decisions & outcome telemetry
            </span>
          </div>

          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-xs">
            <div className="bg-cyber-900/60 p-3.5 rounded-lg border border-cyber-750">
              <span className="text-slate-400 block mb-1">Total Recommendations</span>
              <div className="text-lg font-bold text-slate-100">{metrics.total_recommendations}</div>
              <span className="text-[10px] text-slate-500">
                {metrics.reviewed_count} reviewed ({metrics.approval_rate != null ? `${Math.round(metrics.approval_rate * 100)}% approved` : '0%'})
              </span>
            </div>

            <div className="bg-cyber-900/60 p-3.5 rounded-lg border border-cyber-750">
              <span className="text-slate-400 block mb-1">Feedback Submissions</span>
              <div className="text-lg font-bold text-slate-100">{metrics.total_feedback_count}</div>
              <span className="text-[10px] text-emerald-400">
                {metrics.actionable_ratio != null ? `${Math.round(metrics.actionable_ratio * 100)}% actionable` : 'No reviews'}
                {metrics.average_rating ? ` • ★ ${metrics.average_rating}/5` : ''}
              </span>
            </div>

            <div className="bg-cyber-900/60 p-3.5 rounded-lg border border-cyber-750">
              <span className="text-slate-400 block mb-1">Verified Resolution Rate</span>
              <div className="text-lg font-bold text-accent-cyan">
                {metrics.verified_resolution_rate != null ? `${Math.round(metrics.verified_resolution_rate * 100)}%` : 'N/A'}
              </div>
              <span className="text-[10px] text-slate-500">
                {metrics.total_verified_count} total re-tests linked
              </span>
            </div>

            <div className="bg-cyber-900/60 p-3.5 rounded-lg border border-cyber-750">
              <span className="text-slate-400 block mb-1">Guidance Provenance</span>
              <div className="flex gap-2 text-[11px] mt-1 font-mono">
                <span className="text-emerald-400">{metrics.by_guidance_type?.VERIFIED_INSTRUCTION || 0} Verified</span>
                <span className="text-purple-400">{metrics.by_guidance_type?.UNVERIFIED_SUGGESTION || 0} Advisory</span>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* 3. Remediation Plans & Governance Stages */}
      <div className="bg-cyber-850 rounded-xl border border-cyber-700 overflow-hidden">
        <div className="px-6 py-4 border-b border-cyber-750 font-semibold text-sm text-slate-200 flex justify-between items-center">
          <span>Explainable Remediation Plans ({remediations.length})</span>
          <span className="text-xs text-slate-400 font-normal">Active Latest Versions</span>
        </div>

        <div className="divide-y divide-cyber-750">
          {remediations.length === 0 ? (
            <div className="p-8 text-center text-slate-400 text-sm">
              No remediation recommendations recorded for this project yet.
            </div>
          ) : (
            remediations.map((rec) => {
              const isExpanded = !!expandedRecs[rec.id];
              return (
                <div key={rec.id} className="p-6 hover:bg-cyber-800/40 transition space-y-4">
                  {/* Title & Badges Bar */}
                  <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
                    <div>
                      <div className="flex items-center gap-2 flex-wrap mb-1">
                        {getGuidanceBadge(rec.guidance_type)}
                        {getBusinessPriorityBadge(rec.business_priority)}
                        <span className="px-2 py-0.5 text-xs rounded bg-cyber-750 text-slate-300 font-mono">
                          {rec.technical_severity || 'MEDIUM'}
                        </span>
                        {rec.remediation_urgency && (
                          <span className="px-2 py-0.5 text-xs rounded bg-sky-500/10 text-sky-300 border border-sky-500/30 flex items-center gap-1">
                            <Clock className="w-3 h-3" />
                            {rec.remediation_urgency}
                          </span>
                        )}
                        {rec.confidence !== undefined && (
                          <span className="px-2 py-0.5 text-xs rounded bg-slate-800 text-slate-300 font-mono">
                            {Math.round(rec.confidence * 100)}% Confidence
                          </span>
                        )}
                        <span className="px-2 py-0.5 text-xs rounded bg-cyber-900 text-accent-cyan font-mono border border-accent-cyan/30">
                          v{rec.version || 1}
                        </span>
                      </div>
                      <h3 className="font-semibold text-slate-100 text-base">{rec.title}</h3>
                      <p className="text-xs text-slate-400 mt-1">{rec.description}</p>
                    </div>

                    <div className="flex items-center gap-2 shrink-0">
                      <span className="px-2.5 py-1 text-xs rounded-full bg-cyber-750 text-slate-300 font-mono">
                        {rec.status}
                      </span>
                      {rec.execution_governance_stage && (
                        <span className="px-2.5 py-1 text-xs rounded-full bg-indigo-500/20 text-indigo-300 border border-indigo-500/30 font-mono">
                          {rec.execution_governance_stage}
                        </span>
                      )}
                      {rec.verified_outcome && (
                        <span className={`px-2.5 py-1 text-xs rounded-full border font-mono ${
                          rec.verified_outcome === 'VERIFIED_FIXED'
                            ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40'
                            : 'bg-rose-500/20 text-rose-300 border-rose-500/40'
                        }`}>
                          {rec.verified_outcome}
                        </span>
                      )}
                    </div>
                  </div>

                  {/* Advisory Notice */}
                  {rec.advisory_disclaimer && (
                    <div className="p-3 bg-cyber-900/80 rounded-lg border border-cyber-700/80 text-xs text-slate-300 flex items-start gap-2">
                      <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
                      <div>
                        <strong className="text-amber-300">Governance & Uncertainty Disclaimer:</strong>{' '}
                        {rec.advisory_disclaimer}
                      </div>
                    </div>
                  )}

                  {/* Summary Grid */}
                  <div className="text-xs text-slate-400 grid grid-cols-1 md:grid-cols-2 gap-3 bg-cyber-800/50 p-3.5 rounded-lg border border-cyber-750">
                    <div>
                      <span className="text-slate-500">Action Type:</span>{' '}
                      <span className="text-slate-200 font-mono">{rec.action_type}</span>
                    </div>
                    <div>
                      <span className="text-slate-500">Estimated Effort:</span>{' '}
                      <span className="text-slate-200">{rec.estimated_effort || 'MEDIUM (1-2d)'}</span>
                    </div>
                    <div className="col-span-1 md:col-span-2">
                      <span className="text-slate-500">Recommended Change:</span>{' '}
                      <span className="text-slate-200">{rec.recommended_change || rec.description}</span>
                    </div>
                    <div className="col-span-1 md:col-span-2">
                      <span className="text-slate-500">Verification Criteria:</span>{' '}
                      <span className="text-slate-300">{rec.verification_criteria}</span>
                    </div>
                    {rec.external_change_ticket_ref && (
                      <div className="col-span-1 md:col-span-2">
                        <span className="text-slate-500">Authorized Change Ticket:</span>{' '}
                        <span className="text-accent-cyan font-mono">{rec.external_change_ticket_ref}</span>
                      </div>
                    )}
                  </div>

                  {/* Expandable Explainability & Risk Breakdown */}
                  {isExpanded && (
                    <div className="space-y-3 p-4 bg-cyber-900/60 rounded-lg border border-cyber-700 text-xs text-slate-300 animate-fadeIn">
                      <div className="font-semibold text-accent-cyan flex items-center gap-1.5 border-b border-cyber-750 pb-2">
                        <Layers className="w-4 h-4" />
                        Explainability & Ranking Factors Breakdown (Prompt 51)
                      </div>

                      {rec.ranking_factors && (
                        <div className="space-y-2">
                          <p className="text-slate-300 italic">
                            "{rec.ranking_factors.factor_explanation || 'Ranked according to technical severity and asset context.'}"
                          </p>
                          <div className="grid grid-cols-2 md:grid-cols-4 gap-2 pt-1 font-mono text-[11px]">
                            <div className="bg-cyber-950 p-2 rounded">
                              <span className="text-slate-500 block">Evidence Status:</span>
                              <span className="text-emerald-400">{rec.ranking_factors.evidence_strength || 'CONFIRMED'}</span>
                            </div>
                            <div className="bg-cyber-950 p-2 rounded">
                              <span className="text-slate-500 block">Evidence Items:</span>
                              <span className="text-slate-200">{rec.ranking_factors.evidence_item_count || (rec.source_evidence_ids?.length ?? 0)} items</span>
                            </div>
                            <div className="bg-cyber-950 p-2 rounded">
                              <span className="text-slate-500 block">Asset Criticality:</span>
                              <span className="text-slate-200">{rec.ranking_factors.asset_criticality || 'MEDIUM'}</span>
                            </div>
                            <div className="bg-cyber-950 p-2 rounded">
                              <span className="text-slate-500 block">Internet Exposed:</span>
                              <span className="text-slate-200">{rec.ranking_factors.is_internet_facing ? 'YES' : 'NO'}</span>
                            </div>
                          </div>
                        </div>
                      )}

                      {rec.missing_prerequisites && rec.missing_prerequisites.length > 0 && (
                        <div className="pt-2">
                          <span className="text-amber-400 font-semibold block mb-1 flex items-center gap-1">
                            <AlertTriangle className="w-3.5 h-3.5" />
                            Missing Prerequisites & Pre-Conditions:
                          </span>
                          <ul className="list-disc list-inside space-y-0.5 text-slate-400 pl-1">
                            {rec.missing_prerequisites.map((p, idx) => (
                              <li key={idx}>{p}</li>
                            ))}
                          </ul>
                        </div>
                      )}

                      {rec.compatibility_concerns && rec.compatibility_concerns.length > 0 && (
                        <div className="pt-1">
                          <span className="text-slate-400 font-semibold block mb-1">Compatibility & Operational Risks:</span>
                          <ul className="list-disc list-inside space-y-0.5 text-slate-400 pl-1">
                            {rec.compatibility_concerns.map((c, idx) => (
                              <li key={idx}>{c}</li>
                            ))}
                          </ul>
                        </div>
                      )}

                      <div className="pt-1">
                        <span className="text-slate-400 font-semibold block mb-0.5">Rollback Procedure:</span>
                        <p className="text-slate-300 font-mono text-[11px] bg-cyber-950 p-2 rounded">
                          {rec.rollback_procedure}
                        </p>
                      </div>
                    </div>
                  )}

                  {/* Action Buttons Bar */}
                  <div className="flex flex-wrap items-center justify-between gap-3 pt-2">
                    <div className="flex items-center gap-2">
                      <button
                        onClick={() => handleRetest(rec.finding_id)}
                        className="px-3 py-1.5 bg-accent-cyan/20 hover:bg-accent-cyan/30 text-accent-cyan border border-accent-cyan/40 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition"
                      >
                        <RefreshCw className="w-3.5 h-3.5" />
                        Independent Re-test Probe
                      </button>

                      {rec.execution_governance_stage !== 'CHANGE_AUTHORIZED' && (
                        <button
                          onClick={() => setSelectedRecId(selectedRecId === rec.id ? null : rec.id)}
                          className="px-3 py-1.5 bg-cyber-750 hover:bg-cyber-700 text-slate-200 border border-cyber-600 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition"
                        >
                          <KeyRound className="w-3.5 h-3.5" />
                          Authorize Change
                        </button>
                      )}

                      <button
                        onClick={() => handleOpenFeedback(rec)}
                        className="px-3 py-1.5 bg-cyber-750 hover:bg-cyber-700 text-slate-300 border border-cyber-600 rounded-lg text-xs flex items-center gap-1.5 transition"
                      >
                        <MessageSquare className="w-3.5 h-3.5" />
                        Submit Feedback
                      </button>

                      <button
                        onClick={() => handleOpenVersionHistory(rec)}
                        className="px-3 py-1.5 bg-cyber-750 hover:bg-cyber-700 text-slate-300 border border-cyber-600 rounded-lg text-xs flex items-center gap-1.5 transition"
                      >
                        <History className="w-3.5 h-3.5" />
                        Version History
                      </button>
                    </div>

                    <button
                      onClick={() => toggleExpand(rec.id)}
                      className="text-xs text-accent-cyan hover:underline flex items-center gap-1"
                    >
                      {isExpanded ? (
                        <>
                          Hide Explainability <ChevronUp className="w-3.5 h-3.5" />
                        </>
                      ) : (
                        <>
                          Explain Prioritization <ChevronDown className="w-3.5 h-3.5" />
                        </>
                      )}
                    </button>
                  </div>

                  {/* Change Ticket Drawer */}
                  {selectedRecId === rec.id && (
                    <div className="mt-3 p-4 bg-cyber-800 rounded-lg border border-cyber-600 space-y-3">
                      <label className="text-xs font-semibold text-slate-300 block">
                        External Change Request / Ticket Identifier (e.g., CHG-2026-9041):
                      </label>
                      <div className="flex gap-2">
                        <input
                          type="text"
                          value={actionTicketRef}
                          onChange={(e) => setActionTicketRef(e.target.value)}
                          placeholder="CHG-2026-XXXX"
                          className="flex-1 bg-cyber-900 border border-cyber-700 rounded-lg px-3 py-1.5 text-xs text-slate-100 focus:outline-none focus:border-accent-cyan font-mono"
                        />
                        <button
                          onClick={() => handleAuthorizeChange(rec.id)}
                          className="px-4 py-1.5 bg-accent-cyan text-cyber-900 font-semibold rounded-lg text-xs hover:bg-cyan-400 transition"
                        >
                          Authorize
                        </button>
                      </div>
                    </div>
                  )}
                </div>
              );
            })
          )}
        </div>
      </div>

      {/* 4. Feedback Submission Modal (Prompt 51) */}
      {feedbackModalRec && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
          <div className="bg-cyber-850 border border-cyber-600 rounded-xl p-6 max-w-md w-full space-y-4 shadow-xl">
            <div className="flex justify-between items-center border-b border-cyber-750 pb-3">
              <h3 className="text-base font-bold text-slate-100 flex items-center gap-2">
                <MessageSquare className="w-4 h-4 text-accent-cyan" />
                Submit Recommendation Feedback
              </h3>
              <button
                onClick={() => setFeedbackModalRec(null)}
                className="text-slate-400 hover:text-slate-200 text-sm"
              >
                ✕
              </button>
            </div>

            <div className="space-y-3 text-xs">
              <div>
                <label className="text-slate-300 block mb-1 font-semibold">Feedback Type:</label>
                <select
                  value={feedbackType}
                  onChange={(e) => setFeedbackType(e.target.value as RecommendationFeedbackType)}
                  className="w-full bg-cyber-900 border border-cyber-700 rounded-lg p-2 text-slate-200 focus:outline-none focus:border-accent-cyan"
                >
                  <option value="HELPFUL">HELPFUL — Clear, accurate, and solved finding</option>
                  <option value="UNHELPFUL">UNHELPFUL — Did not resolve vulnerability</option>
                  <option value="INACCURATE">INACCURATE — Incorrect technical premise</option>
                  <option value="INCOMPLETE">INCOMPLETE — Missing critical steps or prerequisites</option>
                  <option value="OUTDATED">OUTDATED — Superseded by modern security controls</option>
                  <option value="IRRELEVANT">IRRELEVANT — Not applicable to target environment</option>
                </select>
              </div>

              <div>
                <label className="text-slate-300 block mb-1 font-semibold">Rating (1 to 5 Stars):</label>
                <div className="flex gap-2">
                  {[1, 2, 3, 4, 5].map((star) => (
                    <button
                      key={star}
                      type="button"
                      onClick={() => setFeedbackRating(star)}
                      className={`px-3 py-1.5 rounded-lg border font-mono font-bold ${
                        feedbackRating === star
                          ? 'bg-accent-cyan text-cyber-900 border-accent-cyan'
                          : 'bg-cyber-900 text-slate-300 border-cyber-700'
                      }`}
                    >
                      {star}★
                    </button>
                  ))}
                </div>
              </div>

              <div>
                <label className="text-slate-300 block mb-1 font-semibold">Comments / Review Notes:</label>
                <textarea
                  value={feedbackComment}
                  onChange={(e) => setFeedbackComment(e.target.value)}
                  placeholder="Describe your review feedback or reasons for rating..."
                  rows={3}
                  className="w-full bg-cyber-900 border border-cyber-700 rounded-lg p-2 text-slate-200 focus:outline-none focus:border-accent-cyan"
                />
              </div>

              <div className="flex items-center gap-4 pt-1">
                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={feedbackActionable}
                    onChange={(e) => setFeedbackActionable(e.target.checked)}
                    className="rounded bg-cyber-900 border-cyber-700 text-accent-cyan focus:ring-0"
                  />
                  <span className="text-slate-300">Was Actionable</span>
                </label>

                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={feedbackApplied}
                    onChange={(e) => setFeedbackApplied(e.target.checked)}
                    className="rounded bg-cyber-900 border-cyber-700 text-accent-cyan focus:ring-0"
                  />
                  <span className="text-slate-300">Applied to Code/Config</span>
                </label>
              </div>
            </div>

            <div className="flex justify-end gap-2 pt-3 border-t border-cyber-750">
              <button
                type="button"
                onClick={() => setFeedbackModalRec(null)}
                className="px-4 py-2 bg-cyber-750 text-slate-300 text-xs rounded-lg hover:bg-cyber-700 transition"
              >
                Cancel
              </button>
              <button
                type="button"
                disabled={submittingFeedback}
                onClick={handleSubmitFeedback}
                className="px-4 py-2 bg-accent-cyan text-cyber-900 font-semibold text-xs rounded-lg hover:bg-cyan-400 transition"
              >
                {submittingFeedback ? 'Submitting...' : 'Record Feedback'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* 5. Version History Modal (Prompt 51) */}
      {versionModalRec && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
          <div className="bg-cyber-850 border border-cyber-600 rounded-xl p-6 max-w-xl w-full space-y-4 shadow-xl max-h-[80vh] flex flex-col">
            <div className="flex justify-between items-center border-b border-cyber-750 pb-3">
              <h3 className="text-base font-bold text-slate-100 flex items-center gap-2">
                <History className="w-4 h-4 text-accent-cyan" />
                Version Lineage & Audit History
              </h3>
              <button
                onClick={() => setVersionModalRec(null)}
                className="text-slate-400 hover:text-slate-200 text-sm"
              >
                ✕
              </button>
            </div>

            <div className="overflow-y-auto space-y-3 flex-1 text-xs">
              {loadingVersions ? (
                <div className="p-6 text-center text-slate-400">Loading version history...</div>
              ) : versionList.length === 0 ? (
                <div className="p-6 text-center text-slate-400">No prior versions recorded.</div>
              ) : (
                versionList.map((ver) => (
                  <div
                    key={ver.id}
                    className={`p-3.5 rounded-lg border space-y-1.5 ${
                      ver.is_latest
                        ? 'bg-cyber-800/80 border-accent-cyan/50'
                        : 'bg-cyber-900/60 border-cyber-750 opacity-80'
                    }`}
                  >
                    <div className="flex justify-between items-center">
                      <div className="flex items-center gap-2">
                        <span className="font-mono font-bold text-accent-cyan">v{ver.version || 1}</span>
                        {ver.is_latest ? (
                          <span className="px-2 py-0.5 text-[10px] bg-emerald-500/20 text-emerald-300 rounded-full font-semibold">
                            LATEST
                          </span>
                        ) : (
                          <span className="px-2 py-0.5 text-[10px] bg-slate-800 text-slate-400 rounded-full">
                            SUPERSEDED
                          </span>
                        )}
                        <span className="text-slate-400 font-mono">[{ver.status}]</span>
                      </div>
                      <span className="text-[10px] text-slate-500 font-mono">
                        {new Date(ver.created_at).toLocaleString()}
                      </span>
                    </div>

                    <p className="font-semibold text-slate-200">{ver.title}</p>
                    <p className="text-slate-400 text-[11px]">{ver.recommended_change || ver.description}</p>

                    {ver.review_notes && (
                      <div className="pt-1 text-[11px] text-slate-400">
                        <span className="text-slate-500">Review Notes:</span> {ver.review_notes}
                      </div>
                    )}
                  </div>
                ))
              )}
            </div>

            <div className="flex justify-end pt-3 border-t border-cyber-750">
              <button
                type="button"
                onClick={() => setVersionModalRec(null)}
                className="px-4 py-2 bg-cyber-750 text-slate-300 text-xs rounded-lg hover:bg-cyber-700 transition"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
