import React, { useState, useEffect, useCallback } from 'react';
import { Camera, GitCompare, RefreshCw, Clock, TrendingUp, TrendingDown, Minus } from 'lucide-react';
import { api } from '../services/api';
import type { Project, SecuritySnapshot, SnapshotDiffResponse } from '../types';

interface Props {
  currentProject: Project;
}

export const DigitalTwinView: React.FC<Props> = ({ currentProject }) => {
  const [snapshots, setSnapshots] = useState<SecuritySnapshot[]>([]);
  const [loading, setLoading] = useState(false);
  const [capturing, setCapturing] = useState(false);
  const [snapshotName, setSnapshotName] = useState('');
  const [snapshotDesc, setSnapshotDesc] = useState('');

  // Comparator states
  const [snapshotA, setSnapshotA] = useState<string>('');
  const [snapshotB, setSnapshotB] = useState<string>('');
  const [diffResult, setDiffResult] = useState<SnapshotDiffResponse | null>(null);
  const [comparing, setComparing] = useState(false);
  const [statusMessage, setStatusMessage] = useState<string | null>(null);

  const loadSnapshots = useCallback(async () => {
    setLoading(true);
    try {
      const list = await api.listSnapshots(currentProject.id);
      setSnapshots(list);
      if (list.length >= 2 && !snapshotA && !snapshotB) {
        setSnapshotA(list[1].id);
        setSnapshotB(list[0].id);
      }
    } catch (err: any) {
      console.error('Failed to load snapshots:', err);
    } finally {
      setLoading(false);
    }
  }, [currentProject.id, snapshotA, snapshotB]);

  useEffect(() => {
    loadSnapshots();
  }, [loadSnapshots]);

  const handleCapture = async () => {
    if (!snapshotName.trim()) {
      alert('Please enter a snapshot name.');
      return;
    }
    setCapturing(true);
    try {
      const res = await api.captureSnapshot(currentProject.id, snapshotName.trim(), snapshotDesc.trim());
      setStatusMessage(`Security snapshot captured (Manifest SHA: ${res.manifest_sha256.slice(0, 16)}...).`);
      setSnapshotName('');
      setSnapshotDesc('');
      loadSnapshots();
    } catch (err: any) {
      alert(err.message);
    } finally {
      setCapturing(false);
    }
  };

  const handleCompare = async () => {
    if (!snapshotA || !snapshotB) {
      alert('Select two snapshots to compare.');
      return;
    }
    setComparing(true);
    try {
      const res = await api.compareSnapshots(currentProject.id, snapshotA, snapshotB);
      setDiffResult(res);
    } catch (err: any) {
      alert(err.message);
    } finally {
      setComparing(false);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center bg-cyber-850 p-6 rounded-xl border border-cyber-700">
        <div>
          <h2 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <Clock className="w-6 h-6 text-accent-cyan" />
            Historical Security Digital Twin
          </h2>
          <p className="text-sm text-slate-400 mt-1">
            Freezes immutable point-in-time security postures and computes multi-dimensional state diffs across assessment timelines (Phase 16).
          </p>
        </div>
        <button
          onClick={loadSnapshots}
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

      {/* Snapshot Capture Form */}
      <div className="bg-cyber-850 p-6 rounded-xl border border-cyber-700 space-y-4">
        <h3 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
          <Camera className="w-4 h-4 text-accent-cyan" />
          Capture Point-in-Time Security Snapshot
        </h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <label className="text-xs font-semibold text-slate-400 block mb-1.5">Snapshot Name</label>
            <input
              type="text"
              value={snapshotName}
              onChange={(e) => setSnapshotName(e.target.value)}
              placeholder="e.g., Post-Sprint-42 Milestone"
              className="w-full bg-cyber-900 border border-cyber-700 rounded-lg px-3 py-2 text-xs text-slate-100 focus:outline-none focus:border-accent-cyan"
            />
          </div>
          <div>
            <label className="text-xs font-semibold text-slate-400 block mb-1.5">Description / Operational Context</label>
            <input
              type="text"
              value={snapshotDesc}
              onChange={(e) => setSnapshotDesc(e.target.value)}
              placeholder="Captured prior to perimeter gateway upgrade"
              className="w-full bg-cyber-900 border border-cyber-700 rounded-lg px-3 py-2 text-xs text-slate-100 focus:outline-none focus:border-accent-cyan"
            />
          </div>
        </div>
        <div className="flex justify-end">
          <button
            onClick={handleCapture}
            disabled={capturing}
            className="px-5 py-2 bg-accent-cyan hover:bg-cyan-400 text-cyber-900 font-bold rounded-lg text-xs flex items-center gap-2 transition"
          >
            <Camera className="w-4 h-4" />
            {capturing ? 'Freezing State...' : 'Freeze Snapshot'}
          </button>
        </div>
      </div>

      {/* Semantic Comparator (A vs B) */}
      <div className="bg-cyber-850 p-6 rounded-xl border border-cyber-700 space-y-4">
        <h3 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
          <GitCompare className="w-4 h-4 text-accent-cyan" />
          Snapshot Diff & Posture Drift Comparator
        </h3>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 items-end">
          <div>
            <label className="text-xs font-semibold text-slate-400 block mb-1.5">Snapshot A (Baseline)</label>
            <select
              value={snapshotA}
              onChange={(e) => setSnapshotA(e.target.value)}
              className="w-full bg-cyber-900 border border-cyber-700 rounded-lg px-3 py-2 text-xs text-slate-100 focus:outline-none focus:border-accent-cyan"
            >
              <option value="">Select Baseline Snapshot...</option>
              {snapshots.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.name} ({new Date(s.snapshot_timestamp).toLocaleDateString()})
                </option>
              ))}
            </select>
          </div>
          <div>
            <label className="text-xs font-semibold text-slate-400 block mb-1.5">Snapshot B (Comparison)</label>
            <select
              value={snapshotB}
              onChange={(e) => setSnapshotB(e.target.value)}
              className="w-full bg-cyber-900 border border-cyber-700 rounded-lg px-3 py-2 text-xs text-slate-100 focus:outline-none focus:border-accent-cyan"
            >
              <option value="">Select Comparison Snapshot...</option>
              {snapshots.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.name} ({new Date(s.snapshot_timestamp).toLocaleDateString()})
                </option>
              ))}
            </select>
          </div>
          <div>
            <button
              onClick={handleCompare}
              disabled={comparing || !snapshotA || !snapshotB}
              className="w-full py-2 bg-indigo-600 hover:bg-indigo-500 text-white font-bold rounded-lg text-xs flex items-center justify-center gap-2 transition"
            >
              <GitCompare className="w-4 h-4" />
              {comparing ? 'Computing Diff...' : 'Compare A vs B'}
            </button>
          </div>
        </div>

        {/* Diff Results Output */}
        {diffResult && (
          <div className="mt-4 p-5 bg-cyber-900 rounded-lg border border-cyber-700 space-y-4">
            <div className="flex justify-between items-center border-b border-cyber-750 pb-3">
              <span className="text-xs text-slate-400 font-semibold">Overall Posture Trend:</span>
              <span className={`px-3 py-1 rounded-full text-xs font-bold font-mono flex items-center gap-1.5 ${
                diffResult.overall_posture_trend === 'IMPROVED'
                  ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
                  : diffResult.overall_posture_trend === 'DEGRADED'
                  ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30'
                  : 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
              }`}>
                {diffResult.overall_posture_trend === 'IMPROVED' && <TrendingDown className="w-3.5 h-3.5" />}
                {diffResult.overall_posture_trend === 'DEGRADED' && <TrendingUp className="w-3.5 h-3.5" />}
                {diffResult.overall_posture_trend === 'STABLE' && <Minus className="w-3.5 h-3.5" />}
                {diffResult.overall_posture_trend}
              </span>
            </div>

            <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-center">
              <div className="p-3 bg-cyber-850 rounded-lg border border-cyber-750">
                <span className="text-xs text-slate-500 block">New Flaws</span>
                <span className="text-lg font-bold text-rose-400 font-mono">{diffResult.new_findings.length}</span>
              </div>
              <div className="p-3 bg-cyber-850 rounded-lg border border-cyber-750">
                <span className="text-xs text-slate-500 block">Resolved Flaws</span>
                <span className="text-lg font-bold text-emerald-400 font-mono">{diffResult.resolved_findings.length}</span>
              </div>
              <div className="p-3 bg-cyber-850 rounded-lg border border-cyber-750">
                <span className="text-xs text-slate-500 block">Recurring Flaws</span>
                <span className="text-lg font-bold text-amber-400 font-mono">{diffResult.recurring_findings.length}</span>
              </div>
              <div className="p-3 bg-cyber-850 rounded-lg border border-cyber-750">
                <span className="text-xs text-slate-500 block">Perimeter Drift</span>
                <span className="text-lg font-bold text-cyan-400 font-mono">+{diffResult.added_assets.length} / -{diffResult.removed_assets.length}</span>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Historical Snapshots List */}
      <div className="bg-cyber-850 rounded-xl border border-cyber-700 overflow-hidden">
        <div className="px-6 py-4 border-b border-cyber-750 font-semibold text-sm text-slate-200">
          Point-in-Time Snapshot Manifests
        </div>
        <div className="divide-y divide-cyber-750">
          {snapshots.length === 0 ? (
            <div className="p-8 text-center text-slate-400 text-sm">
              No historical snapshots captured yet.
            </div>
          ) : (
            snapshots.map((s) => (
              <div key={s.id} className="p-6 hover:bg-cyber-800/40 transition flex items-center justify-between">
                <div>
                  <h4 className="font-semibold text-slate-100 text-sm">{s.name}</h4>
                  {s.description && <p className="text-xs text-slate-400 mt-0.5">{s.description}</p>}
                  <div className="text-xs text-slate-500 font-mono mt-1 flex items-center gap-4">
                    <span>Manifest SHA-256: {s.manifest_sha256}</span>
                    <span>Captured: {new Date(s.snapshot_timestamp).toLocaleString()}</span>
                  </div>
                </div>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
};
