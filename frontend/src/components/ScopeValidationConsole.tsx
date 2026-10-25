import React, { useState } from 'react';
import { Search, ShieldAlert, ShieldCheck, Clock, Ban, AlertOctagon, Terminal } from 'lucide-react';
import { api } from '../services/api';
import type { ScopeValidationResult } from '../types';

interface ScopeValidationConsoleProps {
  projectId: string;
}

export const ScopeValidationConsole: React.FC<ScopeValidationConsoleProps> = ({ projectId }) => {
  const [candidate, setCandidate] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<ScopeValidationResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleValidate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!candidate.trim()) return;

    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const res = await api.validateTarget(projectId, candidate.trim());
      setResult(res);
    } catch (err: any) {
      setError(err.message || 'Validation request failed');
    } finally {
      setLoading(false);
    }
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'AUTHORIZED':
        return {
          icon: ShieldCheck,
          text: 'AUTHORIZED',
          badgeClass: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30',
          titleColor: 'text-emerald-400',
        };
      case 'EXCLUDED':
        return {
          icon: ShieldAlert,
          text: 'STRICTLY EXCLUDED',
          badgeClass: 'bg-rose-500/15 text-rose-400 border-rose-500/30',
          titleColor: 'text-rose-400',
        };
      case 'PENDING_APPROVAL':
        return {
          icon: Clock,
          text: 'PENDING APPROVAL',
          badgeClass: 'bg-amber-500/15 text-amber-400 border-amber-500/30',
          titleColor: 'text-amber-400',
        };
      case 'REVOKED':
        return {
          icon: Ban,
          text: 'REVOKED',
          badgeClass: 'bg-rose-500/10 text-rose-300 border-rose-500/20',
          titleColor: 'text-rose-300',
        };
      case 'EXPIRED':
        return {
          icon: Clock,
          text: 'EXPIRED',
          badgeClass: 'bg-amber-500/10 text-amber-300 border-amber-500/20',
          titleColor: 'text-amber-300',
        };
      default:
        return {
          icon: AlertOctagon,
          text: 'NOT IN SCOPE (DENIED)',
          badgeClass: 'bg-slate-700/30 text-slate-300 border-slate-600',
          titleColor: 'text-slate-300',
        };
    }
  };

  return (
    <div className="bg-cyber-850 border border-cyber-750 rounded-xl p-5 shadow-lg">
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2">
          <Terminal className="w-4 h-4 text-accent-cyan" />
          <h3 className="text-sm font-semibold text-white">Pre-Flight Scope Authorization Validator</h3>
        </div>
        <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyber-800 border border-cyber-700 text-slate-400">
          Non-Invasive · Server-Side
        </span>
      </div>

      <p className="text-xs text-slate-400 mb-4 leading-relaxed">
        Test candidate IP addresses, CIDR ranges, subdomains, or HTTP/HTTPS endpoints against active Rules of
        Engagement. This console checks server-side scope boundaries and exclusions in-memory without initiating network
        probes.
      </p>

      <form onSubmit={handleValidate} className="flex gap-2 mb-4">
        <div className="relative flex-1">
          <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
          <input
            type="text"
            value={candidate}
            onChange={(e) => setCandidate(e.target.value)}
            placeholder="e.g. 192.168.1.50, 10.0.0.0/16, api.target.corp, https://target.corp/login"
            className="w-full bg-cyber-900 border border-cyber-700 rounded-lg pl-9 pr-3 py-2 text-xs font-mono text-white placeholder-slate-500 focus:outline-none focus:border-accent-cyan"
          />
        </div>
        <button
          type="submit"
          disabled={loading || !candidate.trim()}
          className="px-4 py-2 bg-accent-blue hover:bg-accent-blue/90 disabled:bg-cyber-750 disabled:text-slate-500 text-white rounded-lg text-xs font-semibold transition-colors flex items-center gap-1.5"
        >
          {loading ? 'Evaluating...' : 'Validate Scope'}
        </button>
      </form>

      {error && (
        <div className="p-3 bg-rose-500/10 border border-rose-500/20 rounded-lg text-xs text-rose-300 mb-3">
          {error}
        </div>
      )}

      {result && (
        <div className="bg-cyber-900 border border-cyber-750 rounded-lg p-4 font-mono text-xs">
          {(() => {
            const badge = getStatusBadge(result.status);
            const Icon = badge.icon;
            return (
              <div>
                <div className="flex items-center justify-between pb-3 border-b border-cyber-800">
                  <div className="flex items-center gap-2">
                    <Icon className={`w-5 h-5 ${badge.titleColor}`} />
                    <span className="font-semibold text-slate-200">{result.normalized_target}</span>
                  </div>
                  <span className={`px-2.5 py-1 rounded text-[11px] font-bold border ${badge.badgeClass}`}>
                    {badge.text}
                  </span>
                </div>

                <div className="mt-3 space-y-2 text-slate-300">
                  <div>
                    <span className="text-slate-500">Decision Reason: </span>
                    <span className={badge.titleColor}>{result.reason}</span>
                  </div>

                  {result.matched_rule && (
                    <div className="p-2.5 bg-cyber-800/60 rounded border border-cyber-750/70 text-[11px] space-y-1">
                      <div className="text-slate-400 font-semibold">Matched Scope Rule:</div>
                      <div className="text-slate-300">Target: {result.matched_rule.target_value}</div>
                      {result.matched_rule.evidence && (
                        <div className="text-slate-400">ROE Evidence: {result.matched_rule.evidence}</div>
                      )}
                      {result.matched_rule.expires_at && (
                        <div className="text-slate-400">Expires: {new Date(result.matched_rule.expires_at).toLocaleString()}</div>
                      )}
                    </div>
                  )}

                  {result.matched_exclusion && (
                    <div className="p-2.5 bg-rose-950/20 rounded border border-rose-800/40 text-[11px] space-y-1">
                      <div className="text-rose-400 font-semibold">Exclusion Conflict:</div>
                      <div className="text-slate-300">Exclusion Rule: {result.matched_exclusion.target_value}</div>
                      <div className="text-rose-300">Reason: {result.matched_exclusion.reason}</div>
                    </div>
                  )}

                  <div className="text-[10px] text-slate-500 pt-1 flex justify-between">
                    <span>Evaluated at: {new Date(result.evaluated_at).toISOString()}</span>
                    <span>Fail-Closed Enforced</span>
                  </div>
                </div>
              </div>
            );
          })()}
        </div>
      )}
    </div>
  );
};
