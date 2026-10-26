import React, { useState, useEffect, useCallback } from 'react';
import { Bot, Shield, RefreshCw, AlertTriangle } from 'lucide-react';
import { api } from '../services/api';
import type { Project, AIAnalystDraft } from '../types';

interface Props {
  currentProject: Project;
}

export const AIAnalystView: React.FC<Props> = ({ currentProject }) => {
  const [drafts, setDrafts] = useState<AIAnalystDraft[]>([]);
  const [loading, setLoading] = useState(false);
  const [selectedDraftId, setSelectedDraftId] = useState<string | null>(null);
  const [reviewNotes, setReviewNotes] = useState('');
  const [statusMessage, setStatusMessage] = useState<string | null>(null);

  const loadDrafts = useCallback(async () => {
    setLoading(true);
    try {
      const list = await api.listAIDrafts(currentProject.id);
      setDrafts(list);
    } catch (err: any) {
      console.error('Failed to load AI drafts:', err);
    } finally {
      setLoading(false);
    }
  }, [currentProject.id]);

  useEffect(() => {
    loadDrafts();
  }, [loadDrafts]);

  const handleReview = async (draftId: string, approved: boolean) => {
    if (!reviewNotes.trim() || reviewNotes.trim().length < 3) {
      alert('Review notes are required (minimum 3 characters).');
      return;
    }
    try {
      await api.reviewAIDraft(currentProject.id, draftId, approved, reviewNotes.trim());
      setStatusMessage(`AI draft ${draftId.slice(0, 8)} ${approved ? 'APPROVED' : 'REJECTED'}.`);
      setSelectedDraftId(null);
      setReviewNotes('');
      loadDrafts();
    } catch (err: any) {
      alert(err.message);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center bg-cyber-850 p-6 rounded-xl border border-cyber-700">
        <div>
          <h2 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <Bot className="w-6 h-6 text-accent-cyan" />
            Controlled AI Security Analyst Workspace
          </h2>
          <p className="text-sm text-slate-400 mt-1">
            Evidence-grounded, non-authoritative advisory synthesis with quarantined untrusted inputs and human review gates (Phase 18).
          </p>
        </div>
        <button
          onClick={loadDrafts}
          disabled={loading}
          className="px-3.5 py-2 bg-cyber-750 hover:bg-cyber-700 text-slate-200 text-xs rounded-lg flex items-center gap-2 border border-cyber-600 transition"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          Refresh
        </button>
      </div>

      {/* Safety Notice */}
      <div className="p-4 bg-amber-500/10 border border-amber-500/30 text-amber-300 rounded-xl text-xs space-y-1">
        <span className="font-bold flex items-center gap-1.5">
          <AlertTriangle className="w-4 h-4 text-amber-400" />
          GOVERNANCE GUARDRAILS ACTIVE
        </span>
        <p>
          AI decision-support drafts are advisory only. They never automatically alter finding lifecycle statuses, authorize scopes, or modify production infrastructure. Every conclusion is separated from authoritative security state and requires human analyst verification.
        </p>
      </div>

      {statusMessage && (
        <div className="p-4 bg-accent-cyan/10 border border-accent-cyan/30 text-accent-cyan rounded-lg text-sm flex items-center justify-between">
          <span>{statusMessage}</span>
          <button onClick={() => setStatusMessage(null)} className="text-xs hover:underline">Dismiss</button>
        </div>
      )}

      {/* Drafts List */}
      <div className="bg-cyber-850 rounded-xl border border-cyber-700 overflow-hidden">
        <div className="px-6 py-4 border-b border-cyber-750 font-semibold text-sm text-slate-200 flex justify-between items-center">
          <span>Advisory Syntheses & Draft Ledger ({drafts.length})</span>
        </div>
        <div className="divide-y divide-cyber-750">
          {drafts.length === 0 ? (
            <div className="p-8 text-center text-slate-400 text-sm">
              No AI decision-support drafts generated for this project yet. Use finding or attack-path action menus to request grounded explanations.
            </div>
          ) : (
            drafts.map((d) => (
              <div key={d.id} className="p-6 hover:bg-cyber-800/40 transition space-y-3">
                <div className="flex justify-between items-start">
                  <div>
                    <h3 className="font-semibold text-slate-100 text-sm flex items-center gap-2">
                      {d.title}
                    </h3>
                    <p className="text-xs text-slate-400 mt-0.5">{d.summary}</p>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="px-2 py-0.5 text-[10px] rounded bg-cyber-750 text-slate-300 font-mono">
                      {d.draft_type}
                    </span>
                    <span className={`px-2 py-0.5 text-[10px] rounded font-mono ${
                      d.status === 'REVIEWED_APPROVED'
                        ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
                        : d.status === 'REVIEWED_REJECTED'
                        ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30'
                        : 'bg-indigo-500/20 text-indigo-300 border border-indigo-500/30'
                    }`}>
                      {d.status}
                    </span>
                  </div>
                </div>

                {/* Citations & Uncertainty */}
                <div className="bg-cyber-900 p-3.5 rounded-lg border border-cyber-750 text-xs space-y-2">
                  {d.uncertainty_notes && (
                    <div className="text-amber-400 font-mono">
                      Uncertainty: {d.uncertainty_notes}
                    </div>
                  )}
                  {d.prompt_injection_flags && d.prompt_injection_flags.length > 0 && (
                    <div className="text-rose-400 font-mono">
                      Quarantine Triggers: {d.prompt_injection_flags.join(', ')}
                    </div>
                  )}
                  <div className="text-slate-400">
                    <span className="text-slate-500 block mb-1">Validated Grounding Citations:</span>
                    <div className="flex flex-wrap gap-2">
                      {d.citations.map((c, idx) => (
                        <span key={idx} className="px-2 py-0.5 bg-cyber-800 text-slate-300 rounded border border-cyber-700 font-mono text-[10px]">
                          [{c.citation_type}] {c.label}
                        </span>
                      ))}
                    </div>
                  </div>
                </div>

                {/* Review Gate Actions */}
                {!d.is_reviewed && (
                  <div className="pt-2">
                    {selectedDraftId === d.id ? (
                      <div className="p-4 bg-cyber-800 rounded-lg border border-cyber-600 space-y-3">
                        <label className="text-xs font-semibold text-slate-300 block">
                          Analyst Verification & Review Comments (Lead/Tester):
                        </label>
                        <textarea
                          value={reviewNotes}
                          onChange={(e) => setReviewNotes(e.target.value)}
                          placeholder="Document your verification of this AI analysis..."
                          className="w-full bg-cyber-900 border border-cyber-700 rounded-lg p-2.5 text-xs text-slate-100 focus:outline-none focus:border-accent-cyan h-20"
                        />
                        <div className="flex gap-2 justify-end">
                          <button
                            onClick={() => handleReview(d.id, false)}
                            className="px-4 py-1.5 bg-rose-500/20 hover:bg-rose-500/30 text-rose-300 border border-rose-500/40 rounded-lg text-xs font-semibold transition"
                          >
                            Reject Draft
                          </button>
                          <button
                            onClick={() => handleReview(d.id, true)}
                            className="px-4 py-1.5 bg-emerald-500 text-cyber-900 font-bold rounded-lg text-xs hover:bg-emerald-400 transition"
                          >
                            Approve Synthesis
                          </button>
                        </div>
                      </div>
                    ) : (
                      <button
                        onClick={() => setSelectedDraftId(d.id)}
                        className="px-3 py-1.5 bg-cyber-750 hover:bg-cyber-700 text-accent-cyan border border-cyber-600 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition"
                      >
                        <Shield className="w-3.5 h-3.5" />
                        Enter Analyst Review Gate
                      </button>
                    )}
                  </div>
                )}
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
};
