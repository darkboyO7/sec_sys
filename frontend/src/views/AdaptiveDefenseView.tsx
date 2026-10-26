import React, { useState, useEffect } from 'react';
import { api } from '../services/api';
import type { MorphStatePosture, MorphStateHistory } from '../types';

interface AdaptiveDefenseViewProps {
  projectId: string;
}

export const AdaptiveDefenseView: React.FC<AdaptiveDefenseViewProps> = ({ projectId }) => {
  const [posture, setPosture] = useState<MorphStatePosture | null>(null);
  const [history, setHistory] = useState<MorphStateHistory[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  // Kill Switch Modals
  const [showEngageModal, setShowEngageModal] = useState(false);
  const [engageReason, setEngageReason] = useState('');

  const [showDisengageModal, setShowDisengageModal] = useState(false);
  const [disengageJustification, setDisengageJustification] = useState('');

  const loadData = async () => {
    try {
      setLoading(true);
      setError(null);
      const [pos, hist] = await Promise.all([
        api.getAdaptivePosture(projectId),
        api.getPostureHistory(projectId),
      ]);
      setPosture(pos);
      setHistory(hist || []);
    } catch (err: any) {
      setError(err.message || 'Failed to load adaptive defense posture');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, [projectId]);

  const handleEvaluate = async () => {
    try {
      setLoading(true);
      setError(null);
      const res = await api.evaluateAdaptivePosture(projectId);
      setPosture(res);
      setSuccess(`Adaptive posture evaluated. Current state: ${res.current_state}`);
      const hist = await api.getPostureHistory(projectId);
      setHistory(hist || []);
    } catch (err: any) {
      setError(err.message || 'Evaluation failed');
    } finally {
      setLoading(false);
    }
  };

  const handleEngageKillSwitch = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      setLoading(true);
      setError(null);
      const res = await api.engageKillSwitch(projectId, engageReason);
      setPosture(res);
      setSuccess('EMERGENCY KILL SWITCH ENGAGED. Monitoring cadence locked and state set to MANUAL_REVIEW_REQUIRED.');
      setShowEngageModal(false);
      setEngageReason('');
      const hist = await api.getPostureHistory(projectId);
      setHistory(hist || []);
    } catch (err: any) {
      setError(err.message || 'Failed to engage kill switch');
    } finally {
      setLoading(false);
    }
  };

  const handleDisengageKillSwitch = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      setLoading(true);
      setError(null);
      const res = await api.disengageKillSwitch(projectId, disengageJustification);
      setPosture(res);
      setSuccess('Kill switch disengaged. Posture returned to operational baseline.');
      setShowDisengageModal(false);
      setDisengageJustification('');
      const hist = await api.getPostureHistory(projectId);
      setHistory(hist || []);
    } catch (err: any) {
      setError(err.message || 'Failed to disengage kill switch');
    } finally {
      setLoading(false);
    }
  };

  const getStateBadgeStyle = (state?: string) => {
    switch (state) {
      case 'NORMAL':
        return 'bg-emerald-950 text-emerald-400 border-emerald-700';
      case 'ELEVATED_MONITORING':
        return 'bg-cyan-950 text-cyan-400 border-cyan-700';
      case 'INVESTIGATION_REQUIRED':
        return 'bg-amber-950 text-amber-400 border-amber-700';
      case 'CONTAINMENT_RECOMMENDED':
        return 'bg-orange-950 text-orange-400 border-orange-700';
      case 'RECOVERY_IN_PROGRESS':
        return 'bg-purple-950 text-purple-400 border-purple-700';
      case 'RECOVERY_VERIFICATION_REQUIRED':
        return 'bg-blue-950 text-blue-400 border-blue-700';
      case 'RECOVERY_COMPLETE':
        return 'bg-teal-950 text-teal-400 border-teal-700';
      case 'MANUAL_REVIEW_REQUIRED':
        return 'bg-red-950 text-red-400 border-red-700 font-bold';
      default:
        return 'bg-slate-800 text-slate-300 border-slate-700';
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="bg-slate-900 border border-slate-800 rounded-lg p-6 shadow-sm">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <h1 className="text-2xl font-bold text-white tracking-tight flex items-center gap-2">
              <span className="text-cyan-400">🛡️</span> Morph-State Adaptive Defense & Recovery
            </h1>
            <p className="text-sm text-slate-400 mt-1">
              Phase 20: 8-state adaptive defense lifecycle, cadence modulation, emergency kill switch, and recovery verification.
            </p>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={handleEvaluate}
              disabled={loading}
              className="px-3 py-1.5 bg-cyan-700 hover:bg-cyan-600 text-white text-xs font-semibold rounded shadow transition"
            >
              {loading ? 'Evaluating...' : 'Evaluate Operational Signals'}
            </button>
            <button
              onClick={loadData}
              disabled={loading}
              className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs rounded border border-slate-700 transition"
            >
              Refresh
            </button>
          </div>
        </div>

        <div className="mt-4 p-3 bg-cyan-950/30 border border-cyan-800/40 rounded text-xs text-cyan-300 flex items-center gap-2">
          <span>🔒</span>
          <span>
            <strong>Defensive Governance Invariant:</strong> Adaptive posture transitions are strictly governed by provenance-backed operational signals (findings, regression alerts, verification checks). AI hypotheses cannot alter posture state. Remediation remains non-disruptive decision-support.
          </span>
        </div>
      </div>

      {error && (
        <div className="bg-red-950/40 border border-red-800/60 p-4 rounded-lg text-sm text-red-300 flex items-center justify-between">
          <span>{error}</span>
          <button onClick={() => setError(null)} className="text-red-400 hover:text-red-200">✕</button>
        </div>
      )}

      {success && (
        <div className="bg-emerald-950/40 border border-emerald-800/60 p-4 rounded-lg text-sm text-emerald-300 flex items-center justify-between">
          <span>{success}</span>
          <button onClick={() => setSuccess(null)} className="text-emerald-400 hover:text-emerald-200">✕</button>
        </div>
      )}

      {/* Posture Overview Card */}
      {posture && (
        <div className="bg-slate-900 border border-slate-800 rounded-lg p-6 space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            {/* Current State */}
            <div className="bg-slate-800/80 border border-slate-700 rounded-lg p-4">
              <div className="text-xs text-slate-400 uppercase font-semibold tracking-wider">Current Posture</div>
              <div className="mt-2 flex items-center gap-2">
                <span className={`px-2.5 py-1 rounded border text-xs font-bold ${getStateBadgeStyle(posture.current_state)}`}>
                  {posture.current_state}
                </span>
              </div>
              <div className="text-[11px] text-slate-500 mt-2">
                Previous: <span className="text-slate-400">{posture.previous_state || 'None'}</span>
              </div>
            </div>

            {/* Monitoring Cadence Multiplier */}
            <div className="bg-slate-800/80 border border-slate-700 rounded-lg p-4">
              <div className="text-xs text-slate-400 uppercase font-semibold tracking-wider">Cadence Multiplier</div>
              <div className="mt-2 text-2xl font-bold text-cyan-300">
                {posture.monitoring_cadence_multiplier?.toFixed(1)}x
              </div>
              <div className="text-[11px] text-slate-500 mt-1">
                {posture.monitoring_cadence_multiplier > 1.0 ? 'Accelerated observation window' : 'Nominal schedule'}
              </div>
            </div>

            {/* Emergency Kill Switch */}
            <div className="bg-slate-800/80 border border-slate-700 rounded-lg p-4">
              <div className="text-xs text-slate-400 uppercase font-semibold tracking-wider">Emergency Kill Switch</div>
              <div className="mt-2 flex items-center gap-2">
                {posture.kill_switch_active ? (
                  <span className="px-2.5 py-1 rounded bg-red-950 text-red-400 border border-red-700 text-xs font-bold animate-pulse">
                    ACTIVE / LOCKED
                  </span>
                ) : (
                  <span className="px-2.5 py-1 rounded bg-emerald-950 text-emerald-400 border border-emerald-700 text-xs font-medium">
                    DISENGAGED (NORMAL)
                  </span>
                )}
              </div>
              <div className="mt-2">
                {posture.kill_switch_active ? (
                  <button
                    onClick={() => setShowDisengageModal(true)}
                    className="text-[11px] text-emerald-400 hover:text-emerald-300 underline font-semibold"
                  >
                    Disengage Kill Switch
                  </button>
                ) : (
                  <button
                    onClick={() => setShowEngageModal(true)}
                    className="text-[11px] text-red-400 hover:text-red-300 underline font-semibold"
                  >
                    Engage Emergency Kill Switch
                  </button>
                )}
              </div>
            </div>

            {/* State Metadata */}
            <div className="bg-slate-800/80 border border-slate-700 rounded-lg p-4">
              <div className="text-xs text-slate-400 uppercase font-semibold tracking-wider">State Version & Sync</div>
              <div className="mt-2 text-xl font-bold text-slate-200">
                v{posture.state_version}
              </div>
              <div className="text-[11px] text-slate-400 mt-1">
                Last evaluated: {posture.last_evaluated_at ? new Date(posture.last_evaluated_at).toLocaleTimeString() : 'N/A'}
              </div>
            </div>
          </div>

          {/* Kill switch reason if active */}
          {posture.kill_switch_active && (
            <div className="p-4 bg-red-950/60 border border-red-700 rounded-lg text-xs text-red-200">
              <div className="font-bold flex items-center gap-2 text-sm text-red-300">
                <span>⚠️</span> EMERGENCY KILL SWITCH IS CURRENTLY ENGAGED
              </div>
              <p className="mt-1"><strong>Reason:</strong> {posture.kill_switch_reason}</p>
              <p className="mt-0.5 text-slate-400 text-[11px]">Engaged at: {new Date(posture.kill_switch_engaged_at || '').toLocaleString()}</p>
            </div>
          )}

          {/* Active Recommendations & Prerequisites */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="bg-slate-800/60 border border-slate-700/70 rounded-lg p-4">
              <h3 className="text-xs font-bold text-slate-300 uppercase tracking-wider mb-2">
                Active Posture Recommendations ({posture.active_recommendations?.length || 0})
              </h3>
              {(!posture.active_recommendations || posture.active_recommendations.length === 0) ? (
                <p className="text-xs text-slate-500 italic">No specific recommendations active for current state.</p>
              ) : (
                <ul className="space-y-1.5 text-xs text-slate-300">
                  {posture.active_recommendations.map((rec, idx) => (
                    <li key={idx} className="flex items-start gap-2 bg-slate-900/50 p-2 rounded border border-slate-800">
                      <span className="text-cyan-400">•</span>
                      <span>{typeof rec === 'string' ? rec : JSON.stringify(rec)}</span>
                    </li>
                  ))}
                </ul>
              )}
            </div>

            <div className="bg-slate-800/60 border border-slate-700/70 rounded-lg p-4">
              <h3 className="text-xs font-bold text-slate-300 uppercase tracking-wider mb-2">
                Recovery Prerequisites ({posture.recovery_prerequisites?.length || 0})
              </h3>
              {(!posture.recovery_prerequisites || posture.recovery_prerequisites.length === 0) ? (
                <p className="text-xs text-slate-500 italic">No pending recovery prerequisites.</p>
              ) : (
                <ul className="space-y-1.5 text-xs text-slate-300">
                  {posture.recovery_prerequisites.map((prereq, idx) => (
                    <li key={idx} className="flex items-start gap-2 bg-slate-900/50 p-2 rounded border border-slate-800">
                      <span className="text-amber-400">✓</span>
                      <span>{typeof prereq === 'string' ? prereq : JSON.stringify(prereq)}</span>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Posture Transition Timeline */}
      <div className="bg-slate-900 border border-slate-800 rounded-lg p-5">
        <h2 className="text-base font-semibold text-white mb-3">Immutable Transition Audit Log ({history.length})</h2>
        {history.length === 0 ? (
          <p className="text-xs text-slate-500 italic py-8 text-center">No transition records logged yet.</p>
        ) : (
          <div className="space-y-3">
            {history.map((h) => (
              <div key={h.id} className="bg-slate-800/70 border border-slate-700/60 rounded p-3 text-xs space-y-1.5">
                <div className="flex flex-col md:flex-row md:items-center justify-between gap-1">
                  <div className="flex items-center gap-2">
                    <span className={`px-2 py-0.5 rounded text-[10px] font-semibold border ${getStateBadgeStyle(h.from_state)}`}>
                      {h.from_state}
                    </span>
                    <span className="text-slate-500">→</span>
                    <span className={`px-2 py-0.5 rounded text-[10px] font-semibold border ${getStateBadgeStyle(h.to_state)}`}>
                      {h.to_state}
                    </span>
                    <span className="text-slate-400 text-[11px] bg-slate-700/60 px-1.5 py-0.5 rounded font-mono">
                      {h.trigger}
                    </span>
                  </div>
                  <div className="text-[11px] text-slate-500">
                    {new Date(h.created_at).toLocaleString()}
                  </div>
                </div>
                <div className="text-slate-300 text-xs">
                  <strong>Rationale:</strong> {h.evidence_rationale}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Engage Kill Switch Modal */}
      {showEngageModal && (
        <div className="fixed inset-0 bg-black/80 flex items-center justify-center p-4 z-50">
          <div className="bg-slate-900 border border-red-700 rounded-lg max-w-md w-full p-6 shadow-2xl space-y-4">
            <h3 className="text-lg font-bold text-red-400 flex items-center gap-2">
              <span>🛑</span> Engage Emergency Kill Switch
            </h3>
            <p className="text-xs text-slate-300">
              Engaging the Emergency Kill Switch will immediately throttle all monitoring cadence to baseline and transition the posture state to <strong>MANUAL_REVIEW_REQUIRED</strong>.
            </p>

            <form onSubmit={handleEngageKillSwitch} className="space-y-4">
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">Emergency Justification / Reason</label>
                <textarea
                  value={engageReason}
                  onChange={(e) => setEngageReason(e.target.value)}
                  required
                  rows={3}
                  placeholder="Record detected operational anomalies, suspected unauthorized behavior, or emergency override rationale..."
                  className="w-full bg-slate-800 border border-slate-700 rounded p-2 text-xs text-white"
                />
              </div>

              <div className="flex justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setShowEngageModal(false)}
                  className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs rounded border border-slate-700"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={loading}
                  className="px-3 py-1.5 bg-red-600 hover:bg-red-500 text-white text-xs font-bold rounded shadow transition"
                >
                  ENGAGE EMERGENCY SWITCH
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Disengage Kill Switch Modal */}
      {showDisengageModal && (
        <div className="fixed inset-0 bg-black/80 flex items-center justify-center p-4 z-50">
          <div className="bg-slate-900 border border-emerald-700 rounded-lg max-w-md w-full p-6 shadow-2xl space-y-4">
            <h3 className="text-lg font-bold text-emerald-400 flex items-center gap-2">
              <span>✅</span> Disengage Emergency Kill Switch
            </h3>
            <p className="text-xs text-slate-300">
              Provide justification for disengaging the emergency kill switch and resuming nominal defensive operations.
            </p>

            <form onSubmit={handleDisengageKillSwitch} className="space-y-4">
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">Disengage Justification</label>
                <textarea
                  value={disengageJustification}
                  onChange={(e) => setDisengageJustification(e.target.value)}
                  required
                  rows={3}
                  placeholder="Record resolved conditions, verification audit reference, and justification to return to operational status..."
                  className="w-full bg-slate-800 border border-slate-700 rounded p-2 text-xs text-white"
                />
              </div>

              <div className="flex justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setShowDisengageModal(false)}
                  className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs rounded border border-slate-700"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={loading}
                  className="px-3 py-1.5 bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold rounded shadow transition"
                >
                  Disengage & Resume
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
