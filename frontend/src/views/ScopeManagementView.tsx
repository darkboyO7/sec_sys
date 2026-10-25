import React, { useState } from 'react';
import {
  Target,
  ShieldAlert,
  Plus,
  CheckCircle,
  Ban,
  Trash2,
  Clock,
} from 'lucide-react';
import type { Project, ScopeTarget, ScopeExclusion, User } from '../types';
import { api } from '../services/api';
import { EmptyState } from '../components/EmptyState';
import { ScopeValidationConsole } from '../components/ScopeValidationConsole';

interface ScopeManagementViewProps {
  project: Project;
  targets: ScopeTarget[];
  exclusions: ScopeExclusion[];
  currentUser: User | null;
  onRefresh: () => void;
}

export const ScopeManagementView: React.FC<ScopeManagementViewProps> = ({
  project,
  targets,
  exclusions,
  onRefresh,
}) => {
  // Modals state
  const [isAddTargetOpen, setIsAddTargetOpen] = useState(false);
  const [isAuthorizeOpen, setIsAuthorizeOpen] = useState(false);
  const [isRevokeOpen, setIsRevokeOpen] = useState(false);
  const [isAddExclusionOpen, setIsAddExclusionOpen] = useState(false);

  const [selectedTarget, setSelectedTarget] = useState<ScopeTarget | null>(null);

  // Form states
  const [targetValue, setTargetValue] = useState('');
  const [targetDescription, setTargetDescription] = useState('');
  const [evidence, setEvidence] = useState('');
  const [expirationDate, setExpirationDate] = useState('');
  const [revocationReason, setRevocationReason] = useState('');
  const [exclusionValue, setExclusionValue] = useState('');
  const [exclusionReason, setExclusionReason] = useState('');

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Handlers
  const handleRegisterTarget = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!targetValue.trim()) return;

    setLoading(true);
    setError(null);
    try {
      await api.registerScopeTarget(project.id, {
        target_value: targetValue.trim(),
        description: targetDescription.trim(),
      });
      setIsAddTargetOpen(false);
      setTargetValue('');
      setTargetDescription('');
      onRefresh();
    } catch (err: any) {
      setError(err.message || 'Failed to register target');
    } finally {
      setLoading(false);
    }
  };

  const handleAuthorizeTarget = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedTarget || !evidence.trim()) return;

    setLoading(true);
    setError(null);
    try {
      await api.authorizeScopeTarget(project.id, selectedTarget.id, {
        evidence: evidence.trim(),
        expires_at: expirationDate ? new Date(expirationDate).toISOString() : null,
      });
      setIsAuthorizeOpen(false);
      setSelectedTarget(null);
      setEvidence('');
      setExpirationDate('');
      onRefresh();
    } catch (err: any) {
      setError(err.message || 'Failed to authorize target');
    } finally {
      setLoading(false);
    }
  };

  const handleRevokeTarget = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedTarget || !revocationReason.trim()) return;

    setLoading(true);
    setError(null);
    try {
      await api.revokeScopeTarget(project.id, selectedTarget.id, {
        reason: revocationReason.trim(),
      });
      setIsRevokeOpen(false);
      setSelectedTarget(null);
      setRevocationReason('');
      onRefresh();
    } catch (err: any) {
      setError(err.message || 'Failed to revoke target');
    } finally {
      setLoading(false);
    }
  };

  const handleAddExclusion = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!exclusionValue.trim() || !exclusionReason.trim()) return;

    setLoading(true);
    setError(null);
    try {
      await api.addScopeExclusion(project.id, {
        target_value: exclusionValue.trim(),
        reason: exclusionReason.trim(),
      });
      setIsAddExclusionOpen(false);
      setExclusionValue('');
      setExclusionReason('');
      onRefresh();
    } catch (err: any) {
      setError(err.message || 'Failed to add exclusion');
    } finally {
      setLoading(false);
    }
  };

  const handleRemoveExclusion = async (id: string) => {
    if (!window.confirm('Are you sure you want to remove this scope exclusion?')) return;
    try {
      await api.removeScopeExclusion(project.id, id);
      onRefresh();
    } catch (err: any) {
      alert(err.message || 'Failed to remove exclusion');
    }
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'AUTHORIZED':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
            <CheckCircle className="w-3 h-3" /> AUTHORIZED
          </span>
        );
      case 'PENDING':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-amber-500/10 text-amber-400 border border-amber-500/30">
            <Clock className="w-3 h-3" /> PENDING APPROVAL
          </span>
        );
      case 'REVOKED':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-rose-500/10 text-rose-400 border border-rose-500/30">
            <Ban className="w-3 h-3" /> REVOKED
          </span>
        );
      case 'EXPIRED':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-500/10 text-slate-400 border border-slate-500/30">
            <Clock className="w-3 h-3" /> EXPIRED
          </span>
        );
      default:
        return null;
    }
  };

  return (
    <div className="space-y-8">
      {/* Scope Validation Console Embedded */}
      <ScopeValidationConsole projectId={project.id} />

      {/* Target Scopes Section */}
      <div className="bg-cyber-850 border border-cyber-750 rounded-xl overflow-hidden shadow-lg">
        <div className="p-5 border-b border-cyber-750 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <div className="flex items-center gap-2">
              <Target className="w-5 h-5 text-accent-cyan" />
              <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono">
                Scope Target Inventory
              </h3>
            </div>
            <p className="text-xs text-slate-400 mt-1">
              Registered network boundaries, domain trees, and web applications. Registration requires explicit signed
              authorization evidence before scanning is permitted.
            </p>
          </div>

          <button
            onClick={() => {
              setError(null);
              setIsAddTargetOpen(true);
            }}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-accent-blue hover:bg-accent-blue/90 text-white text-xs font-semibold transition-colors shrink-0"
          >
            <Plus className="w-3.5 h-3.5" />
            Register Scope Target
          </button>
        </div>

        {targets.length === 0 ? (
          <div className="p-8">
            <EmptyState
              icon={Target}
              title="No Scope Targets Registered"
              description="No IP addresses, CIDR blocks, or domains have been registered for this assessment project yet."
              actionLabel="Register First Target"
              onAction={() => setIsAddTargetOpen(true)}
            />
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="border-b border-cyber-750 bg-cyber-900/60 text-slate-400 font-mono text-[11px]">
                  <th className="py-3 px-4">Target Value</th>
                  <th className="py-3 px-4">Type</th>
                  <th className="py-3 px-4">Authorization Status</th>
                  <th className="py-3 px-4">ROE / Proof of Authorization</th>
                  <th className="py-3 px-4">Expiration</th>
                  <th className="py-3 px-4 text-right">Scope Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-cyber-800 font-mono">
                {targets.map((t) => (
                  <tr key={t.id} className="hover:bg-cyber-800/40 transition-colors">
                    <td className="py-3 px-4 font-semibold text-slate-200">
                      <div>{t.target_value}</div>
                      {t.description && (
                        <div className="text-[10px] font-sans text-slate-400 font-normal">{t.description}</div>
                      )}
                    </td>
                    <td className="py-3 px-4 text-slate-400">{t.target_type}</td>
                    <td className="py-3 px-4">{getStatusBadge(t.authorization_status)}</td>
                    <td className="py-3 px-4 text-slate-300">
                      {t.authorization_evidence ? (
                        <span className="text-[11px] text-slate-300 truncate max-w-xs block" title={t.authorization_evidence}>
                          {t.authorization_evidence}
                        </span>
                      ) : (
                        <span className="text-[11px] text-slate-500 italic">None (Unauthorized)</span>
                      )}
                      {t.revocation_reason && (
                        <div className="text-[10px] text-rose-400 mt-0.5">Revocation: {t.revocation_reason}</div>
                      )}
                    </td>
                    <td className="py-3 px-4 text-slate-400 text-[11px]">
                      {t.expires_at ? new Date(t.expires_at).toLocaleDateString() : 'Continuous Review'}
                    </td>
                    <td className="py-3 px-4 text-right space-x-1">
                      {t.authorization_status !== 'AUTHORIZED' && (
                        <button
                          onClick={() => {
                            setSelectedTarget(t);
                            setError(null);
                            setIsAuthorizeOpen(true);
                          }}
                          className="px-2 py-1 bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 rounded text-[10px] font-semibold transition-colors"
                        >
                          Authorize
                        </button>
                      )}
                      {t.authorization_status === 'AUTHORIZED' && (
                        <button
                          onClick={() => {
                            setSelectedTarget(t);
                            setError(null);
                            setIsRevokeOpen(true);
                          }}
                          className="px-2 py-1 bg-rose-500/10 hover:bg-rose-500/20 text-rose-400 border border-rose-500/30 rounded text-[10px] font-semibold transition-colors"
                        >
                          Revoke
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Scope Exclusions Section */}
      <div className="bg-cyber-850 border border-cyber-750 rounded-xl overflow-hidden shadow-lg">
        <div className="p-5 border-b border-cyber-750 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <div className="flex items-center gap-2">
              <ShieldAlert className="w-5 h-5 text-rose-400" />
              <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono">
                Mandatory Scope Exclusions
              </h3>
            </div>
            <p className="text-xs text-slate-400 mt-1">
              Strictly prohibited targets. Exclusions take precedence over any broader authorized ranges or wildcard
              domains and immediately fail closed.
            </p>
          </div>

          <button
            onClick={() => {
              setError(null);
              setIsAddExclusionOpen(true);
            }}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-rose-500/20 hover:bg-rose-500/30 text-rose-300 border border-rose-500/40 text-xs font-semibold transition-colors shrink-0"
          >
            <Plus className="w-3.5 h-3.5" />
            Add Scope Exclusion
          </button>
        </div>

        {exclusions.length === 0 ? (
          <div className="p-8">
            <EmptyState
              icon={ShieldAlert}
              title="No Scope Exclusions Configured"
              description="No hosts or subdomains have been explicitly blacklisted for this project."
              actionLabel="Add Scope Exclusion"
              onAction={() => setIsAddExclusionOpen(true)}
            />
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-xs font-mono">
              <thead>
                <tr className="border-b border-cyber-750 bg-cyber-900/60 text-slate-400 text-[11px]">
                  <th className="py-3 px-4">Excluded Target</th>
                  <th className="py-3 px-4">Type</th>
                  <th className="py-3 px-4">Mandate / Reason for Exclusion</th>
                  <th className="py-3 px-4">Registered Date</th>
                  <th className="py-3 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-cyber-800">
                {exclusions.map((e) => (
                  <tr key={e.id} className="hover:bg-cyber-800/40 transition-colors">
                    <td className="py-3 px-4 font-semibold text-rose-300">{e.target_value}</td>
                    <td className="py-3 px-4 text-slate-400">{e.target_type}</td>
                    <td className="py-3 px-4 text-slate-300 font-sans text-xs">{e.reason}</td>
                    <td className="py-3 px-4 text-slate-400 text-[11px]">
                      {new Date(e.created_at).toLocaleDateString()}
                    </td>
                    <td className="py-3 px-4 text-right">
                      <button
                        onClick={() => handleRemoveExclusion(e.id)}
                        className="p-1 rounded text-slate-400 hover:text-rose-400 hover:bg-cyber-800 transition-colors"
                        title="Remove Exclusion"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Modal: Register Scope Target */}
      {isAddTargetOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm">
          <div className="w-full max-w-md bg-cyber-850 border border-cyber-700 rounded-xl shadow-2xl p-5">
            <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono mb-1">
              Register Candidate Scope Target
            </h3>
            <p className="text-xs text-amber-400 mb-4 font-mono">
              CRITICAL: Target is created in PENDING status. It cannot be scanned until explicit authorization proof is
              recorded.
            </p>

            {error && <div className="p-2.5 bg-rose-500/10 border border-rose-500/20 rounded text-xs text-rose-300 mb-3">{error}</div>}

            <form onSubmit={handleRegisterTarget} className="space-y-4">
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">Target Value</label>
                <input
                  type="text"
                  required
                  value={targetValue}
                  onChange={(e) => setTargetValue(e.target.value)}
                  placeholder="e.g. 192.168.1.0/24, *.app.bank.com, https://api.bank.com"
                  className="w-full bg-cyber-900 border border-cyber-700 rounded-lg px-3 py-2 text-xs font-mono text-white placeholder-slate-500 focus:outline-none focus:border-accent-cyan"
                />
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">Description / Enclave Role</label>
                <input
                  type="text"
                  value={targetDescription}
                  onChange={(e) => setTargetDescription(e.target.value)}
                  placeholder="e.g. DMZ Customer Portal APIs"
                  className="w-full bg-cyber-900 border border-cyber-700 rounded-lg px-3 py-2 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-accent-cyan"
                />
              </div>

              <div className="flex justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setIsAddTargetOpen(false)}
                  className="px-3 py-1.5 text-xs text-slate-400 hover:text-white"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={loading || !targetValue.trim()}
                  className="px-4 py-2 bg-accent-blue hover:bg-accent-blue/90 disabled:bg-cyber-750 text-white rounded-lg text-xs font-semibold"
                >
                  {loading ? 'Registering...' : 'Register Scope Target'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Modal: Authorize Target */}
      {isAuthorizeOpen && selectedTarget && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm">
          <div className="w-full max-w-md bg-cyber-850 border border-cyber-700 rounded-xl shadow-2xl p-5">
            <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono mb-1">
              Grant Explicit Scope Authorization
            </h3>
            <p className="text-xs text-slate-400 mb-4">
              Target: <span className="font-mono text-emerald-400 font-semibold">{selectedTarget.target_value}</span>
            </p>

            {error && <div className="p-2.5 bg-rose-500/10 border border-rose-500/20 rounded text-xs text-rose-300 mb-3">{error}</div>}

            <form onSubmit={handleAuthorizeTarget} className="space-y-4">
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">
                  Proof of Authorization / Evidence Reference *
                </label>
                <textarea
                  rows={3}
                  required
                  value={evidence}
                  onChange={(e) => setEvidence(e.target.value)}
                  placeholder="e.g. ROE-2026-BANK-SEC-941, Written CISO Approval Jira SEC-402"
                  className="w-full bg-cyber-900 border border-cyber-700 rounded-lg px-3 py-2 text-xs font-mono text-white placeholder-slate-500 focus:outline-none focus:border-accent-cyan"
                />
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">Authorization Expiry (Optional)</label>
                <input
                  type="datetime-local"
                  value={expirationDate}
                  onChange={(e) => setExpirationDate(e.target.value)}
                  className="w-full bg-cyber-900 border border-cyber-700 rounded-lg px-3 py-2 text-xs font-mono text-white focus:outline-none focus:border-accent-cyan"
                />
              </div>

              <div className="flex justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setIsAuthorizeOpen(false)}
                  className="px-3 py-1.5 text-xs text-slate-400 hover:text-white"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={loading || !evidence.trim()}
                  className="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 disabled:bg-cyber-750 text-white rounded-lg text-xs font-semibold"
                >
                  {loading ? 'Recording...' : 'Grant Scope Authorization'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Modal: Revoke Target */}
      {isRevokeOpen && selectedTarget && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm">
          <div className="w-full max-w-md bg-cyber-850 border border-cyber-700 rounded-xl shadow-2xl p-5">
            <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono mb-1 text-rose-400">
              Revoke Scope Authorization
            </h3>
            <p className="text-xs text-slate-400 mb-4">
              Target: <span className="font-mono text-white font-semibold">{selectedTarget.target_value}</span>
            </p>

            {error && <div className="p-2.5 bg-rose-500/10 border border-rose-500/20 rounded text-xs text-rose-300 mb-3">{error}</div>}

            <form onSubmit={handleRevokeTarget} className="space-y-4">
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">Revocation Mandate / Reason *</label>
                <textarea
                  rows={3}
                  required
                  value={revocationReason}
                  onChange={(e) => setRevocationReason(e.target.value)}
                  placeholder="e.g. System undergoing live production update; Testing window closed by management"
                  className="w-full bg-cyber-900 border border-cyber-700 rounded-lg px-3 py-2 text-xs font-mono text-white placeholder-slate-500 focus:outline-none focus:border-accent-cyan"
                />
              </div>

              <div className="flex justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setIsRevokeOpen(false)}
                  className="px-3 py-1.5 text-xs text-slate-400 hover:text-white"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={loading || !revocationReason.trim()}
                  className="px-4 py-2 bg-rose-600 hover:bg-rose-500 disabled:bg-cyber-750 text-white rounded-lg text-xs font-semibold"
                >
                  {loading ? 'Revoking...' : 'Confirm Revocation'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Modal: Add Exclusion */}
      {isAddExclusionOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm">
          <div className="w-full max-w-md bg-cyber-850 border border-cyber-700 rounded-xl shadow-2xl p-5">
            <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono mb-1 text-rose-400">
              Add Scope Exclusion Rule
            </h3>
            <p className="text-xs text-slate-400 mb-4">
              Excluded targets will be unconditionally denied by the scope engine even if inside an authorized subnet or
              domain.
            </p>

            {error && <div className="p-2.5 bg-rose-500/10 border border-rose-500/20 rounded text-xs text-rose-300 mb-3">{error}</div>}

            <form onSubmit={handleAddExclusion} className="space-y-4">
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">Target to Exclude *</label>
                <input
                  type="text"
                  required
                  value={exclusionValue}
                  onChange={(e) => setExclusionValue(e.target.value)}
                  placeholder="e.g. 192.168.1.1, gateway.bank.corp, payment.bank.corp"
                  className="w-full bg-cyber-900 border border-cyber-700 rounded-lg px-3 py-2 text-xs font-mono text-white placeholder-slate-500 focus:outline-none focus:border-accent-cyan"
                />
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">Reason / Mandate *</label>
                <textarea
                  rows={2}
                  required
                  value={exclusionReason}
                  onChange={(e) => setExclusionReason(e.target.value)}
                  placeholder="e.g. Shared 3rd-party SaaS gateway; Critical patient life-support system"
                  className="w-full bg-cyber-900 border border-cyber-700 rounded-lg px-3 py-2 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-accent-cyan"
                />
              </div>

              <div className="flex justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setIsAddExclusionOpen(false)}
                  className="px-3 py-1.5 text-xs text-slate-400 hover:text-white"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={loading || !exclusionValue.trim() || !exclusionReason.trim()}
                  className="px-4 py-2 bg-rose-600 hover:bg-rose-500 disabled:bg-cyber-750 text-white rounded-lg text-xs font-semibold"
                >
                  {loading ? 'Adding...' : 'Enforce Exclusion'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
