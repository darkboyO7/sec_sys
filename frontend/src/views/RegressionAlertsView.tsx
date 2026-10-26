import React, { useState, useEffect, useCallback } from 'react';
import { AlertCircle, CheckCircle, RefreshCw, Eye } from 'lucide-react';
import { api } from '../services/api';
import type { Project, RegressionAlert, RegressionBaseline } from '../types';

interface Props {
  currentProject: Project;
}

export const RegressionAlertsView: React.FC<Props> = ({ currentProject }) => {
  const [alerts, setAlerts] = useState<RegressionAlert[]>([]);
  const [baseline, setBaseline] = useState<RegressionBaseline | null>(null);
  const [loading, setLoading] = useState(false);
  const [evaluating, setEvaluating] = useState(false);
  const [selectedAlertId, setSelectedAlertId] = useState<string | null>(null);
  const [resolutionNotes, setResolutionNotes] = useState('');
  const [statusMessage, setStatusMessage] = useState<string | null>(null);

  const loadData = useCallback(async () => {
    setLoading(true);
    try {
      const [b, aList] = await Promise.all([
        api.getRegressionBaseline(currentProject.id),
        api.listRegressionAlerts(currentProject.id),
      ]);
      setBaseline(b);
      setAlerts(aList);
    } catch (err: any) {
      console.error('Failed to load regression data:', err);
    } finally {
      setLoading(false);
    }
  }, [currentProject.id]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  const handleEvaluate = async () => {
    setEvaluating(true);
    try {
      const res = await api.evaluateRegressions(currentProject.id);
      setStatusMessage(`Regression evaluation completed. Active alerts: ${res.active_alerts_count}.`);
      loadData();
    } catch (err: any) {
      alert(err.message);
    } finally {
      setEvaluating(false);
    }
  };

  const handleAcknowledge = async (alertId: string) => {
    try {
      await api.acknowledgeRegressionAlert(currentProject.id, alertId, 'Acknowledged by security triage engineer.');
      setStatusMessage(`Alert ${alertId.slice(0, 8)} acknowledged.`);
      loadData();
    } catch (err: any) {
      alert(err.message);
    }
  };

  const handleResolve = async (alertId: string) => {
    if (!resolutionNotes.trim()) {
      alert('Please provide resolution justification notes (min 3 chars).');
      return;
    }
    try {
      await api.resolveRegressionAlert(currentProject.id, alertId, resolutionNotes.trim());
      setStatusMessage(`Alert ${alertId.slice(0, 8)} resolved.`);
      setSelectedAlertId(null);
      setResolutionNotes('');
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
            <AlertCircle className="w-6 h-6 text-accent-cyan" />
            Regression Detection & Change Intelligence
          </h2>
          <p className="text-sm text-slate-400 mt-1">
            Detects recurring flaws, broken remediations, stale evidence, and perimeter exposures against active baseline (Phase 17).
          </p>
        </div>
        <div className="flex gap-3">
          <button
            onClick={handleEvaluate}
            disabled={evaluating}
            className="px-4 py-2 bg-accent-cyan hover:bg-cyan-400 text-cyber-900 font-bold rounded-lg text-xs flex items-center gap-2 transition"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${evaluating ? 'animate-spin' : ''}`} />
            {evaluating ? 'Evaluating...' : 'Run Empirical Evaluation'}
          </button>
          <button
            onClick={loadData}
            disabled={loading}
            className="px-3.5 py-2 bg-cyber-750 hover:bg-cyber-700 text-slate-200 text-xs rounded-lg flex items-center gap-2 border border-cyber-600 transition"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </button>
        </div>
      </div>

      {statusMessage && (
        <div className="p-4 bg-accent-cyan/10 border border-accent-cyan/30 text-accent-cyan rounded-lg text-sm flex items-center justify-between">
          <span>{statusMessage}</span>
          <button onClick={() => setStatusMessage(null)} className="text-xs hover:underline">Dismiss</button>
        </div>
      )}

      {/* Baseline Overview */}
      {baseline && (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 bg-cyber-850 p-5 rounded-xl border border-cyber-700">
          <div>
            <span className="text-xs text-slate-500 block font-semibold">Active Baseline Anchor</span>
            <span className="text-sm font-bold text-slate-200">{baseline.name}</span>
          </div>
          <div>
            <span className="text-xs text-slate-500 block font-semibold">Risk Delta Threshold</span>
            <span className="text-sm font-bold text-slate-200 font-mono">+{baseline.risk_score_threshold_delta} pts</span>
          </div>
          <div>
            <span className="text-xs text-slate-500 block font-semibold">Evidence Staleness Window</span>
            <span className="text-sm font-bold text-slate-200 font-mono">{baseline.evidence_stale_days} Days</span>
          </div>
        </div>
      )}

      {/* Regression Alerts Table */}
      <div className="bg-cyber-850 rounded-xl border border-cyber-700 overflow-hidden">
        <div className="px-6 py-4 border-b border-cyber-750 font-semibold text-sm text-slate-200 flex justify-between items-center">
          <span>Active Regression Alerts ({alerts.filter((a) => a.status === 'ACTIVE').length})</span>
        </div>
        <div className="divide-y divide-cyber-750">
          {alerts.length === 0 ? (
            <div className="p-8 text-center text-slate-400 text-sm">
              Zero security regressions detected against the active baseline.
            </div>
          ) : (
            alerts.map((alert) => (
              <div key={alert.id} className="p-6 hover:bg-cyber-800/40 transition space-y-3">
                <div className="flex justify-between items-start">
                  <div>
                    <h3 className="font-semibold text-slate-100 text-sm flex items-center gap-2">
                      <span className={`w-2 h-2 rounded-full ${
                        alert.severity === 'CRITICAL' ? 'bg-rose-500' : alert.severity === 'HIGH' ? 'bg-orange-500' : 'bg-amber-500'
                      }`} />
                      {alert.title}
                    </h3>
                    <p className="text-xs text-slate-400 mt-0.5">{alert.description}</p>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="px-2 py-0.5 text-[10px] rounded bg-cyber-750 text-slate-300 font-mono">
                      {alert.alert_type}
                    </span>
                    <span className={`px-2 py-0.5 text-[10px] rounded font-mono ${
                      alert.status === 'ACTIVE'
                        ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30'
                        : alert.status === 'ACKNOWLEDGED'
                        ? 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
                        : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
                    }`}>
                      {alert.status}
                    </span>
                  </div>
                </div>

                <div className="text-xs text-slate-400 bg-cyber-800/60 p-3 rounded-lg border border-cyber-750">
                  <span className="text-slate-500 font-semibold block mb-1">Empirical Rationale:</span>
                  <span>{alert.evidence_rationale}</span>
                  {alert.resolution_notes && (
                    <div className="mt-2 text-emerald-400 border-t border-cyber-750 pt-1">
                      Resolution Notes: {alert.resolution_notes}
                    </div>
                  )}
                </div>

                {alert.status === 'ACTIVE' && (
                  <div className="flex items-center gap-3 pt-1">
                    <button
                      onClick={() => handleAcknowledge(alert.id)}
                      className="px-3 py-1.5 bg-cyber-750 hover:bg-cyber-700 text-amber-300 border border-cyber-600 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition"
                    >
                      <Eye className="w-3.5 h-3.5" />
                      Acknowledge Alert
                    </button>
                    <button
                      onClick={() => setSelectedAlertId(selectedAlertId === alert.id ? null : alert.id)}
                      className="px-3 py-1.5 bg-emerald-500/20 hover:bg-emerald-500/30 text-emerald-300 border border-emerald-500/40 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition"
                    >
                      <CheckCircle className="w-3.5 h-3.5" />
                      Resolve Alert
                    </button>
                  </div>
                )}

                {selectedAlertId === alert.id && (
                  <div className="p-4 bg-cyber-800 rounded-lg border border-cyber-600 space-y-3">
                    <label className="text-xs font-semibold text-slate-300 block">
                      Resolution Justification Notes:
                    </label>
                    <div className="flex gap-2">
                      <input
                        type="text"
                        value={resolutionNotes}
                        onChange={(e) => setResolutionNotes(e.target.value)}
                        placeholder="e.g., Regression patched in release tag v2.4.1"
                        className="flex-1 bg-cyber-900 border border-cyber-700 rounded-lg px-3 py-1.5 text-xs text-slate-100 focus:outline-none focus:border-accent-cyan"
                      />
                      <button
                        onClick={() => handleResolve(alert.id)}
                        className="px-4 py-1.5 bg-emerald-500 text-cyber-900 font-bold rounded-lg text-xs hover:bg-emerald-400 transition"
                      >
                        Confirm Resolution
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
