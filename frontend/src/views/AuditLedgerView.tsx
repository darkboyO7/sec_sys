import React, { useState } from 'react';
import { FileText, ShieldAlert, CheckCircle, Ban, Filter, RefreshCw, Eye, X } from 'lucide-react';
import type { AuditEvent, Project } from '../types';
import { EmptyState } from '../components/EmptyState';

interface AuditLedgerViewProps {
  events: AuditEvent[];
  activeProject: Project | null;
  onRefresh: () => void;
  loading: boolean;
}

export const AuditLedgerView: React.FC<AuditLedgerViewProps> = ({
  events,
  onRefresh,
  loading,
}) => {
  const [filterOutcome, setFilterOutcome] = useState<string>('ALL');
  const [selectedEvent, setSelectedEvent] = useState<AuditEvent | null>(null);

  const filteredEvents = events.filter((e) => {
    if (filterOutcome !== 'ALL' && e.outcome !== filterOutcome) return false;
    return true;
  });

  const getOutcomeBadge = (outcome: string) => {
    switch (outcome) {
      case 'SUCCESS':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
            <CheckCircle className="w-3 h-3" /> SUCCESS
          </span>
        );
      case 'DENIED':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-amber-500/10 text-amber-400 border border-amber-500/30">
            <Ban className="w-3 h-3" /> DENIED
          </span>
        );
      case 'FAILURE':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-rose-500/10 text-rose-400 border border-rose-500/30">
            <ShieldAlert className="w-3 h-3" /> FAILURE
          </span>
        );
      default:
        return null;
    }
  };

  return (
    <div className="space-y-6">
      {/* Header and Filter Controls */}
      <div className="bg-cyber-850 border border-cyber-750 rounded-xl p-5 shadow-lg flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <FileText className="w-5 h-5 text-accent-cyan" />
            <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono">
              Immutable Security Audit Ledger
            </h3>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Tamper-evident record of state mutations, authentication outcomes, scope approvals, and access denials.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2 bg-cyber-900 border border-cyber-700 px-2.5 py-1.5 rounded-lg text-xs">
            <Filter className="w-3.5 h-3.5 text-slate-400" />
            <span className="text-slate-400">Outcome:</span>
            <select
              value={filterOutcome}
              onChange={(e) => setFilterOutcome(e.target.value)}
              className="bg-transparent text-white focus:outline-none font-mono text-xs"
            >
              <option value="ALL">All Outcomes</option>
              <option value="SUCCESS">Success Only</option>
              <option value="DENIED">Denied Only</option>
              <option value="FAILURE">Failure Only</option>
            </select>
          </div>

          <button
            onClick={onRefresh}
            disabled={loading}
            className="p-2 rounded-lg bg-cyber-800 hover:bg-cyber-750 text-slate-400 hover:text-white transition-colors"
            title="Refresh Ledger"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin text-accent-cyan' : ''}`} />
          </button>
        </div>
      </div>

      {/* Ledger Table */}
      <div className="bg-cyber-850 border border-cyber-750 rounded-xl overflow-hidden shadow-lg">
        {filteredEvents.length === 0 ? (
          <div className="p-8">
            <EmptyState
              icon={FileText}
              title="No Audit Records Found"
              description="No audit events matching current filters exist in the secure ledger."
            />
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-xs font-mono">
              <thead>
                <tr className="border-b border-cyber-750 bg-cyber-900/60 text-slate-400 text-[11px]">
                  <th className="py-3 px-4">Timestamp (UTC)</th>
                  <th className="py-3 px-4">Actor</th>
                  <th className="py-3 px-4">Security Action</th>
                  <th className="py-3 px-4">Target Entity</th>
                  <th className="py-3 px-4">Outcome</th>
                  <th className="py-3 px-4">IP Address</th>
                  <th className="py-3 px-4 text-right">Details</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-cyber-800">
                {filteredEvents.map((ev) => (
                  <tr key={ev.id} className="hover:bg-cyber-800/40 transition-colors">
                    <td className="py-3 px-4 text-slate-300">
                      {new Date(ev.timestamp).toISOString().replace('T', ' ').slice(0, 19)}
                    </td>
                    <td className="py-3 px-4 font-semibold text-slate-200">
                      {ev.actor_email || ev.actor_id || 'SYSTEM_DAEMON'}
                    </td>
                    <td className="py-3 px-4 text-accent-cyan">{ev.action}</td>
                    <td className="py-3 px-4 text-slate-400">
                      <span>{ev.target_type}</span>
                      {ev.target_id && <span className="text-slate-500 block text-[10px] truncate max-w-[120px]">{ev.target_id}</span>}
                    </td>
                    <td className="py-3 px-4">{getOutcomeBadge(ev.outcome)}</td>
                    <td className="py-3 px-4 text-slate-500">{ev.ip_address || 'local/internal'}</td>
                    <td className="py-3 px-4 text-right">
                      <button
                        onClick={() => setSelectedEvent(ev)}
                        className="inline-flex items-center gap-1 px-2 py-1 rounded bg-cyber-800 hover:bg-cyber-700 text-slate-300 hover:text-white text-[11px] transition-colors"
                      >
                        <Eye className="w-3 h-3" /> Inspect
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Inspect Event Modal */}
      {selectedEvent && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm">
          <div className="w-full max-w-lg bg-cyber-850 border border-cyber-700 rounded-xl shadow-2xl p-5 font-mono text-xs">
            <div className="flex items-center justify-between pb-3 border-b border-cyber-750">
              <div className="flex items-center gap-2">
                <FileText className="w-4 h-4 text-accent-cyan" />
                <h4 className="font-bold text-white uppercase">Audit Event Metadata</h4>
              </div>
              <button
                onClick={() => setSelectedEvent(null)}
                className="text-slate-400 hover:text-white p-1 rounded hover:bg-cyber-750"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="mt-4 space-y-2">
              <div>
                <span className="text-slate-500">Event ID: </span>
                <span className="text-slate-300">{selectedEvent.id}</span>
              </div>
              <div>
                <span className="text-slate-500">Timestamp: </span>
                <span className="text-slate-300">{selectedEvent.timestamp}</span>
              </div>
              <div>
                <span className="text-slate-500">Actor: </span>
                <span className="text-accent-cyan">{selectedEvent.actor_email || selectedEvent.actor_id}</span>
              </div>
              <div>
                <span className="text-slate-500">Action: </span>
                <span className="text-white font-bold">{selectedEvent.action}</span>
              </div>
              <div>
                <span className="text-slate-500">Outcome: </span>
                <span>{getOutcomeBadge(selectedEvent.outcome)}</span>
              </div>

              <div className="pt-2">
                <div className="text-slate-500 mb-1 font-semibold">Structured Details:</div>
                <pre className="p-3 bg-cyber-900 border border-cyber-800 rounded-lg text-slate-300 text-[11px] overflow-x-auto max-h-60">
                  {JSON.stringify(selectedEvent.details, null, 2)}
                </pre>
              </div>
            </div>

            <div className="mt-5 flex justify-end">
              <button
                onClick={() => setSelectedEvent(null)}
                className="px-3 py-1.5 rounded bg-cyber-750 hover:bg-cyber-700 text-white text-xs font-semibold"
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
