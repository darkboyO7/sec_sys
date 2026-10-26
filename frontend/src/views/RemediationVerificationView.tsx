import React, { useState, useEffect, useCallback } from 'react';
import { ShieldCheck, RefreshCw, KeyRound } from 'lucide-react';
import { api } from '../services/api';
import type { Project, RemediationRecommendation } from '../types';

interface Props {
  currentProject: Project;
}

export const RemediationVerificationView: React.FC<Props> = ({ currentProject }) => {
  const [remediations, setRemediations] = useState<RemediationRecommendation[]>([]);
  const [loading, setLoading] = useState(false);
  const [actionTicketRef, setActionTicketRef] = useState('');
  const [selectedRecId, setSelectedRecId] = useState<string | null>(null);
  const [statusMessage, setStatusMessage] = useState<string | null>(null);

  const loadData = useCallback(async () => {
    setLoading(true);
    try {
      const recs = await api.listRemediations(currentProject.id);
      setRemediations(recs);
    } catch (err: any) {
      console.error('Failed to load remediations:', err);
    } finally {
      setLoading(false);
    }
  }, [currentProject.id]);

  useEffect(() => {
    loadData();
  }, [loadData]);

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

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center bg-cyber-850 p-6 rounded-xl border border-cyber-700">
        <div>
          <h2 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <ShieldCheck className="w-6 h-6 text-accent-cyan" />
            Remediation Planning & Independent Verification
          </h2>
          <p className="text-sm text-slate-400 mt-1">
            Governs change authorizations (Phase 13) and enforces objective, multi-outcome verification re-tests (Phase 14).
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

      <div className="bg-cyber-850 rounded-xl border border-cyber-700 overflow-hidden">
        <div className="px-6 py-4 border-b border-cyber-750 font-semibold text-sm text-slate-200">
          Remediation Plans & Governance Stages
        </div>
        <div className="divide-y divide-cyber-750">
          {remediations.length === 0 ? (
            <div className="p-8 text-center text-slate-400 text-sm">
              No remediation recommendations recorded for this project yet.
            </div>
          ) : (
            remediations.map((rec) => (
              <div key={rec.id} className="p-6 hover:bg-cyber-800/40 transition space-y-3">
                <div className="flex justify-between items-start">
                  <div>
                    <h3 className="font-semibold text-slate-100 text-base">{rec.title}</h3>
                    <p className="text-xs text-slate-400 mt-0.5">{rec.description}</p>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="px-2.5 py-1 text-xs rounded-full bg-cyber-750 text-slate-300 font-mono">
                      {rec.status}
                    </span>
                    {rec.execution_governance_stage && (
                      <span className="px-2.5 py-1 text-xs rounded-full bg-indigo-500/20 text-indigo-300 border border-indigo-500/30 font-mono">
                        {rec.execution_governance_stage}
                      </span>
                    )}
                  </div>
                </div>

                <div className="text-xs text-slate-400 grid grid-cols-2 gap-4 bg-cyber-800/50 p-3 rounded-lg border border-cyber-750">
                  <div>
                    <span className="text-slate-500">Action Type:</span> <span className="text-slate-300">{rec.action_type}</span>
                  </div>
                  <div>
                    <span className="text-slate-500">Operational Impact:</span> <span className="text-slate-300">{rec.operational_impact}</span>
                  </div>
                  <div className="col-span-2">
                    <span className="text-slate-500">Verification Criteria:</span> <span className="text-slate-300">{rec.verification_criteria}</span>
                  </div>
                  {rec.external_change_ticket_ref && (
                    <div className="col-span-2">
                      <span className="text-slate-500">Authorized Change Ticket:</span> <span className="text-accent-cyan font-mono">{rec.external_change_ticket_ref}</span>
                    </div>
                  )}
                </div>

                <div className="flex items-center gap-3 pt-2">
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
                      Authorize Change Ticket
                    </button>
                  )}
                </div>

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
            ))
          )}
        </div>
      </div>
    </div>
  );
};
