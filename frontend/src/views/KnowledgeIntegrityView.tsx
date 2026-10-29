import React, { useState, useEffect } from 'react';
import {
  Shield,
  GitCommit,
  AlertTriangle,
  RefreshCw,
  XCircle,
  Database,
  ArrowRight,
  Layers,
} from 'lucide-react';
import { api } from '../services/api';
import type {
  ExplainableAttackPath,
  KnowledgeReconciliationAudit,
  KnowledgeDependencyRecord,
  FindingEpistemicExplanation,
} from '../types';

interface KnowledgeIntegrityViewProps {
  projectId: string;
}

export const KnowledgeIntegrityView: React.FC<KnowledgeIntegrityViewProps> = ({ projectId }) => {
  const [activeTab, setActiveTab] = useState<'paths' | 'reconcile' | 'dependencies' | 'inspector'>('paths');
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // Data states
  const [attackPaths, setAttackPaths] = useState<ExplainableAttackPath[]>([]);
  const [selectedPath, setSelectedPath] = useState<ExplainableAttackPath | null>(null);
  const [audits, setAudits] = useState<KnowledgeReconciliationAudit[]>([]);
  const [selectedAudit, setSelectedAudit] = useState<KnowledgeReconciliationAudit | null>(null);
  const [dependencies, setDependencies] = useState<KnowledgeDependencyRecord[]>([]);
  const [depFilter, setDepFilter] = useState<string>('ALL');

  // Inspector states
  const [lookupFindingId, setLookupFindingId] = useState<string>('');
  const [findingExplanation, setFindingExplanation] = useState<FindingEpistemicExplanation | null>(null);
  const [inspectorLoading, setInspectorLoading] = useState<boolean>(false);

  // Reconciliation run states
  const [reconciling, setReconciling] = useState<boolean>(false);
  const [autoRepair, setAutoRepair] = useState<boolean>(true);

  const fetchData = async () => {
    setLoading(true);
    setError(null);
    try {
      const [pathsRes, auditsRes, depsRes] = await Promise.all([
        api.listExplainableAttackPaths(projectId, { compute_fresh: true }).catch(() => []),
        api.listReconciliationAudits(projectId).catch(() => []),
        api.listKnowledgeDependencies(projectId).catch(() => []),
      ]);
      setAttackPaths(pathsRes);
      if (pathsRes.length > 0 && !selectedPath) {
        setSelectedPath(pathsRes[0]);
      }
      setAudits(auditsRes);
      setDependencies(depsRes);
    } catch (err: any) {
      setError(err?.message || 'Failed to load knowledge integrity telemetry.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (projectId) {
      fetchData();
    }
  }, [projectId]);

  const handleTriggerReconcile = async () => {
    setReconciling(true);
    try {
      const audit = await api.triggerKnowledgeReconciliation(projectId, autoRepair);
      setAudits((prev) => [audit, ...prev]);
      setSelectedAudit(audit);
      await fetchData();
    } catch (err: any) {
      alert(`Reconciliation error: ${err?.message || 'Failed to execute audit'}`);
    } finally {
      setReconciling(false);
    }
  };

  const handleLookupFinding = async () => {
    if (!lookupFindingId.trim()) return;
    setInspectorLoading(true);
    try {
      const exp = await api.explainFinding(projectId, lookupFindingId.trim());
      setFindingExplanation(exp);
    } catch (err: any) {
      alert(`Finding explanation lookup failed: ${err?.message || 'Not found'}`);
      setFindingExplanation(null);
    } finally {
      setInspectorLoading(false);
    }
  };

  const filteredDependencies = dependencies.filter((d) => {
    if (depFilter === 'VALID') return d.is_valid;
    if (depFilter === 'INVALIDATED') return !d.is_valid;
    return true;
  });

  const verifiedPathsCount = attackPaths.filter((p) => p.path_status === 'VERIFIED').length;
  const hypotheticalPathsCount = attackPaths.filter((p) => p.path_status === 'HYPOTHETICAL').length;
  const invalidPathsCount = attackPaths.filter((p) => p.is_invalidated || !p.is_scope_compliant).length;

  return (
    <div className="space-y-6">
      {/* Top Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-slate-900/90 border border-slate-800 p-6 rounded-xl shadow-lg">
        <div>
          <div className="flex items-center gap-3">
            <div className="p-2 bg-indigo-500/10 text-indigo-400 rounded-lg border border-indigo-500/20">
              <Shield className="w-6 h-6" />
            </div>
            <div>
              <h1 className="text-xl font-bold text-white tracking-wide">
                Universal Knowledge Integrity & Explainable Attack Paths
              </h1>
              <p className="text-sm text-slate-400">
                Epistemic relationship auditing, scope boundary enforcement, and dependency invalidation.
              </p>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={fetchData}
            disabled={loading}
            className="flex items-center gap-2 px-3.5 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg text-sm border border-slate-700 transition"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </button>
          <button
            onClick={handleTriggerReconcile}
            disabled={reconciling}
            className="flex items-center gap-2 px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg text-sm font-medium transition shadow-sm"
          >
            <GitCommit className={`w-4 h-4 ${reconciling ? 'animate-spin' : ''}`} />
            {reconciling ? 'Auditing...' : 'Run Integrity Audit'}
          </button>
        </div>
      </div>

      {/* Metrics Ribbon */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="bg-slate-900/60 border border-slate-800 p-4 rounded-xl">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Attack Paths Discovered</span>
            <Layers className="w-4 h-4 text-indigo-400" />
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-2xl font-bold text-white">{attackPaths.length}</span>
            <span className="text-xs text-emerald-400">{verifiedPathsCount} verified</span>
          </div>
        </div>

        <div className="bg-slate-900/60 border border-slate-800 p-4 rounded-xl">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Hypothetical / Inferred</span>
            <AlertTriangle className="w-4 h-4 text-amber-400" />
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-2xl font-bold text-amber-300">{hypotheticalPathsCount}</span>
            <span className="text-xs text-slate-400">non-authoritative</span>
          </div>
        </div>

        <div className="bg-slate-900/60 border border-slate-800 p-4 rounded-xl">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Invalidated / Out-of-Scope</span>
            <XCircle className="w-4 h-4 text-rose-400" />
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-2xl font-bold text-rose-300">{invalidPathsCount}</span>
            <span className="text-xs text-slate-400">blocked traversal</span>
          </div>
        </div>

        <div className="bg-slate-900/60 border border-slate-800 p-4 rounded-xl">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Tracked Dependencies</span>
            <Database className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-2xl font-bold text-white">{dependencies.length}</span>
            <span className="text-xs text-emerald-400">
              {dependencies.filter((d) => d.is_valid).length} valid
            </span>
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div className="border-b border-slate-800 flex gap-4">
        <button
          onClick={() => setActiveTab('paths')}
          className={`pb-3 text-sm font-medium transition border-b-2 ${
            activeTab === 'paths'
              ? 'border-indigo-500 text-indigo-400'
              : 'border-transparent text-slate-400 hover:text-slate-300'
          }`}
        >
          Explainable Attack Paths ({attackPaths.length})
        </button>
        <button
          onClick={() => setActiveTab('reconcile')}
          className={`pb-3 text-sm font-medium transition border-b-2 ${
            activeTab === 'reconcile'
              ? 'border-indigo-500 text-indigo-400'
              : 'border-transparent text-slate-400 hover:text-slate-300'
          }`}
        >
          Knowledge Reconciliation Audits ({audits.length})
        </button>
        <button
          onClick={() => setActiveTab('dependencies')}
          className={`pb-3 text-sm font-medium transition border-b-2 ${
            activeTab === 'dependencies'
              ? 'border-indigo-500 text-indigo-400'
              : 'border-transparent text-slate-400 hover:text-slate-300'
          }`}
        >
          Dependency Invalidation Ledger ({dependencies.length})
        </button>
        <button
          onClick={() => setActiveTab('inspector')}
          className={`pb-3 text-sm font-medium transition border-b-2 ${
            activeTab === 'inspector'
              ? 'border-indigo-500 text-indigo-400'
              : 'border-transparent text-slate-400 hover:text-slate-300'
          }`}
        >
          Finding Epistemic Inspector
        </button>
      </div>

      {/* Error banner */}
      {error && (
        <div className="p-4 bg-rose-500/10 border border-rose-500/20 rounded-lg text-rose-300 text-sm flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* TAB 1: Explainable Attack Paths */}
      {activeTab === 'paths' && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* Path list */}
          <div className="lg:col-span-5 space-y-3">
            <h3 className="text-sm font-semibold text-slate-300">Discovered Attack Chains</h3>
            {attackPaths.length === 0 ? (
              <div className="p-8 text-center text-slate-500 bg-slate-900/40 border border-slate-800 rounded-xl">
                No attack paths currently discovered.
              </div>
            ) : (
              attackPaths.map((p) => {
                const isSelected = selectedPath?.id === p.id;
                return (
                  <div
                    key={p.id}
                    onClick={() => setSelectedPath(p)}
                    className={`p-4 rounded-xl border cursor-pointer transition ${
                      isSelected
                        ? 'bg-slate-800/90 border-indigo-500 shadow-md'
                        : 'bg-slate-900/60 border-slate-800 hover:border-slate-700'
                    }`}
                  >
                    <div className="flex items-center justify-between gap-2">
                      <span
                        className={`text-xs px-2 py-0.5 rounded font-mono font-medium ${
                          p.path_status === 'VERIFIED'
                            ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                            : p.path_status === 'PLAUSIBLE'
                            ? 'bg-blue-500/10 text-blue-400 border border-blue-500/20'
                            : p.path_status === 'INVALIDATED'
                            ? 'bg-rose-500/10 text-rose-400 border border-rose-500/20'
                            : 'bg-amber-500/10 text-amber-400 border border-amber-500/20'
                        }`}
                      >
                        {p.path_status}
                      </span>
                      <span className="text-xs font-mono text-slate-400">
                        Conf: {(p.cumulative_confidence * 100).toFixed(0)}%
                      </span>
                    </div>

                    <h4 className="mt-2 text-sm font-medium text-white line-clamp-2">{p.name}</h4>

                    <div className="mt-3 flex items-center justify-between text-xs text-slate-400 border-t border-slate-800/60 pt-2">
                      <span>{p.step_count} step{p.step_count > 1 ? 's' : ''}</span>
                      <span className={p.is_scope_compliant ? 'text-emerald-400' : 'text-rose-400'}>
                        {p.is_scope_compliant ? '✓ Scope Compliant' : '⚠ Scope Exclusion Violation'}
                      </span>
                    </div>
                  </div>
                );
              })
            )}
          </div>

          {/* Selected Path Detail */}
          <div className="lg:col-span-7">
            {selectedPath ? (
              <div className="bg-slate-900/70 border border-slate-800 rounded-xl p-6 space-y-6">
                <div>
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-xs font-mono text-slate-400">Path ID: {selectedPath.id}</span>
                    <span className="text-xs text-slate-500">Version: {selectedPath.calculation_version}</span>
                  </div>
                  <h3 className="text-base font-bold text-white mt-1">{selectedPath.name}</h3>
                </div>

                {/* Scope violation warning if applicable */}
                {!selectedPath.is_scope_compliant && selectedPath.scope_violations.length > 0 && (
                  <div className="p-3 bg-rose-500/10 border border-rose-500/20 rounded-lg space-y-1">
                    <div className="text-xs font-bold text-rose-400 flex items-center gap-1.5">
                      <AlertTriangle className="w-4 h-4" /> Scope Exclusion Policy Violation
                    </div>
                    {selectedPath.scope_violations.map((v, i) => (
                      <p key={i} className="text-xs text-rose-300">
                        Node '{v.node_label}' matches exclusion '{v.exclusion_value}': {v.reason}
                      </p>
                    ))}
                  </div>
                )}

                {/* Step-by-step explainability cards */}
                <div className="space-y-4">
                  <h4 className="text-xs font-semibold text-slate-300 uppercase tracking-wider">
                    Step-by-Step Epistemic Traversal
                  </h4>
                  {selectedPath.steps_explanation.map((step) => (
                    <div
                      key={step.step}
                      className="p-4 bg-slate-950/60 border border-slate-800 rounded-lg space-y-3"
                    >
                      <div className="flex items-center justify-between text-xs">
                        <span className="font-bold text-indigo-400">Step {step.step}</span>
                        <div className="flex items-center gap-2">
                          <span className="font-mono text-slate-400">{step.relationship_type}</span>
                          <span className="px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 font-mono text-[10px]">
                            {step.epistemic_status}
                          </span>
                        </div>
                      </div>

                      {/* Endpoint transition */}
                      <div className="flex items-center gap-2 text-sm text-white font-mono bg-slate-900/60 p-2.5 rounded border border-slate-800/80">
                        <span className="text-slate-300 font-medium">{step.from_node.label}</span>
                        <ArrowRight className="w-4 h-4 text-slate-500 shrink-0" />
                        <span className="text-slate-300 font-medium">{step.to_node.label}</span>
                      </div>

                      {/* Required Assumptions */}
                      {step.required_assumptions.length > 0 && (
                        <div className="text-xs space-y-1">
                          <span className="text-slate-400 font-medium">Required Assumptions:</span>
                          <ul className="list-disc list-inside text-slate-300 space-y-0.5">
                            {step.required_assumptions.map((asm, idx) => (
                              <li key={idx}>{asm}</li>
                            ))}
                          </ul>
                        </div>
                      )}

                      {/* Unverified Conditions */}
                      {step.unverified_conditions.length > 0 && (
                        <div className="text-xs space-y-1">
                          <span className="text-amber-400 font-medium">Unverified Conditions:</span>
                          <ul className="list-disc list-inside text-amber-200/80 space-y-0.5">
                            {step.unverified_conditions.map((uv, idx) => (
                              <li key={idx}>{uv}</li>
                            ))}
                          </ul>
                        </div>
                      )}

                      {/* Invalidation Triggers */}
                      {step.invalidation_triggers.length > 0 && (
                        <div className="text-xs space-y-1">
                          <span className="text-cyan-400 font-medium">Defensive Invalidation Trigger:</span>
                          <p className="text-slate-300">{step.invalidation_triggers[0]}</p>
                        </div>
                      )}
                    </div>
                  ))}
                </div>

                <div className="text-[11px] text-slate-500 italic p-3 bg-slate-950/40 rounded border border-slate-800/50">
                  Defensive Principle: Adjacency and graph reachability represent potential exposure channels.
                  Speculative paths are not treated as confirmed breach chains without empirical verification.
                </div>
              </div>
            ) : (
              <div className="h-full flex items-center justify-center p-12 text-slate-500 bg-slate-900/40 border border-slate-800 rounded-xl">
                Select an attack path from the list to inspect its step-by-step explainability.
              </div>
            )}
          </div>
        </div>
      )}

      {/* TAB 2: Knowledge Reconciliation Audits */}
      {activeTab === 'reconcile' && (
        <div className="space-y-6">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold text-slate-300">Knowledge Graph Audits & Repairs</h3>
            <div className="flex items-center gap-3">
              <label className="flex items-center gap-2 text-xs text-slate-400 cursor-pointer">
                <input
                  type="checkbox"
                  checked={autoRepair}
                  onChange={(e) => setAutoRepair(e.target.checked)}
                  className="rounded border-slate-700 bg-slate-800 text-indigo-600 focus:ring-0"
                />
                Auto-Repair Unambiguous Inconsistencies
              </label>
              <button
                onClick={handleTriggerReconcile}
                disabled={reconciling}
                className="px-3 py-1.5 bg-indigo-600 hover:bg-indigo-500 text-white rounded text-xs font-medium transition"
              >
                {reconciling ? 'Running Audit...' : 'Execute Audit'}
              </button>
            </div>
          </div>

          <div className="bg-slate-900/60 border border-slate-800 rounded-xl overflow-hidden">
            <table className="w-full text-left text-xs text-slate-300">
              <thead className="bg-slate-800/60 text-slate-400 uppercase text-[11px] border-b border-slate-800">
                <tr>
                  <th className="py-3 px-4">Audit ID</th>
                  <th className="py-3 px-4">Status</th>
                  <th className="py-3 px-4">Nodes Audited</th>
                  <th className="py-3 px-4">Dangling Refs</th>
                  <th className="py-3 px-4">Duplicates Pruned</th>
                  <th className="py-3 px-4">Auto-Repairs</th>
                  <th className="py-3 px-4">Started At</th>
                  <th className="py-3 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {audits.map((a) => (
                  <tr key={a.id} className="hover:bg-slate-800/30">
                    <td className="py-3 px-4 font-mono">{a.id.slice(0, 8)}</td>
                    <td className="py-3 px-4">
                      <span className="px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-mono">
                        {a.status}
                      </span>
                    </td>
                    <td className="py-3 px-4">{a.total_nodes_audited} nodes / {a.total_relationships_audited} edges</td>
                    <td className="py-3 px-4 text-amber-400">{a.dangling_references_detected}</td>
                    <td className="py-3 px-4">{a.duplicate_relationships_detected}</td>
                    <td className="py-3 px-4 text-emerald-400 font-semibold">{a.auto_repaired_count}</td>
                    <td className="py-3 px-4 text-slate-400">{new Date(a.started_at).toLocaleString()}</td>
                    <td className="py-3 px-4 text-right">
                      <button
                        onClick={() => setSelectedAudit(a)}
                        className="text-indigo-400 hover:text-indigo-300 font-medium"
                      >
                        View Log
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Audit Log Modal */}
          {selectedAudit && (
            <div className="fixed inset-0 z-50 bg-black/70 flex items-center justify-center p-4">
              <div className="bg-slate-900 border border-slate-800 rounded-xl max-w-3xl w-full p-6 space-y-4 max-h-[85vh] flex flex-col">
                <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                  <h3 className="text-base font-bold text-white">
                    Reconciliation Audit Log ({selectedAudit.id.slice(0, 8)})
                  </h3>
                  <button
                    onClick={() => setSelectedAudit(null)}
                    className="text-slate-400 hover:text-white text-lg font-bold"
                  >
                    ×
                  </button>
                </div>

                <div className="overflow-y-auto space-y-2 flex-1 pr-2">
                  {selectedAudit.reconciliation_log.length === 0 ? (
                    <p className="text-xs text-slate-500 py-4 text-center">
                      No defects detected during this audit. Graph is consistent.
                    </p>
                  ) : (
                    selectedAudit.reconciliation_log.map((item, idx) => (
                      <div
                        key={idx}
                        className="p-3 bg-slate-950/60 border border-slate-800 rounded-lg text-xs space-y-1"
                      >
                        <div className="flex items-center justify-between">
                          <span className="font-mono font-bold text-indigo-400">{item.item_type}</span>
                          <span
                            className={`px-1.5 py-0.5 rounded text-[10px] font-mono ${
                              item.repaired ? 'bg-emerald-500/20 text-emerald-300' : 'bg-slate-800 text-slate-400'
                            }`}
                          >
                            {item.repaired ? 'REPAIRED' : 'LOGGED'}
                          </span>
                        </div>
                        <p className="text-slate-300">{item.description}</p>
                      </div>
                    ))
                  )}
                </div>

                <div className="border-t border-slate-800 pt-3 flex justify-end">
                  <button
                    onClick={() => setSelectedAudit(null)}
                    className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-white rounded text-xs font-medium transition"
                  >
                    Close
                  </button>
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* TAB 3: Dependency Invalidation Ledger */}
      {activeTab === 'dependencies' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold text-slate-300">Registered Knowledge Dependencies</h3>
            <div className="flex items-center gap-2">
              <button
                onClick={() => setDepFilter('ALL')}
                className={`px-3 py-1 rounded text-xs font-medium transition ${
                  depFilter === 'ALL' ? 'bg-indigo-600 text-white' : 'bg-slate-800 text-slate-400'
                }`}
              >
                All ({dependencies.length})
              </button>
              <button
                onClick={() => setDepFilter('VALID')}
                className={`px-3 py-1 rounded text-xs font-medium transition ${
                  depFilter === 'VALID' ? 'bg-emerald-600 text-white' : 'bg-slate-800 text-slate-400'
                }`}
              >
                Valid ({dependencies.filter((d) => d.is_valid).length})
              </button>
              <button
                onClick={() => setDepFilter('INVALIDATED')}
                className={`px-3 py-1 rounded text-xs font-medium transition ${
                  depFilter === 'INVALIDATED' ? 'bg-rose-600 text-white' : 'bg-slate-800 text-slate-400'
                }`}
              >
                Invalidated ({dependencies.filter((d) => !d.is_valid).length})
              </button>
            </div>
          </div>

          <div className="bg-slate-900/60 border border-slate-800 rounded-xl overflow-hidden">
            <table className="w-full text-left text-xs text-slate-300">
              <thead className="bg-slate-800/60 text-slate-400 uppercase text-[11px] border-b border-slate-800">
                <tr>
                  <th className="py-3 px-4">Source Entity</th>
                  <th className="py-3 px-4">Dependency Type</th>
                  <th className="py-3 px-4">Dependent Entity</th>
                  <th className="py-3 px-4">Status</th>
                  <th className="py-3 px-4">Invalidation Reason</th>
                  <th className="py-3 px-4">Updated At</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {filteredDependencies.map((d) => (
                  <tr key={d.id} className="hover:bg-slate-800/30">
                    <td className="py-3 px-4 font-mono">
                      {d.source_entity_type}: {d.source_entity_id.slice(0, 8)}
                    </td>
                    <td className="py-3 px-4 text-cyan-400 font-mono">{d.dependency_type}</td>
                    <td className="py-3 px-4 font-mono">
                      {d.dependent_entity_type}: {d.dependent_entity_id.slice(0, 8)}
                    </td>
                    <td className="py-3 px-4">
                      <span
                        className={`px-2 py-0.5 rounded font-mono text-[10px] ${
                          d.is_valid
                            ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                            : 'bg-rose-500/10 text-rose-400 border border-rose-500/20'
                        }`}
                      >
                        {d.is_valid ? 'VALID' : 'INVALIDATED'}
                      </span>
                    </td>
                    <td className="py-3 px-4 text-slate-400">{d.invalidation_reason || '—'}</td>
                    <td className="py-3 px-4 text-slate-500">{new Date(d.updated_at).toLocaleString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* TAB 4: Finding Epistemic Inspector */}
      {activeTab === 'inspector' && (
        <div className="space-y-6">
          <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-6 space-y-4">
            <h3 className="text-sm font-semibold text-white">Inspect Finding Epistemic Provenance</h3>
            <div className="flex gap-3">
              <input
                type="text"
                placeholder="Enter Vulnerability Finding ID..."
                value={lookupFindingId}
                onChange={(e) => setLookupFindingId(e.target.value)}
                className="flex-1 bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-indigo-500 font-mono"
              />
              <button
                onClick={handleLookupFinding}
                disabled={inspectorLoading}
                className="px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg text-sm font-medium transition"
              >
                {inspectorLoading ? 'Inspecting...' : 'Lookup'}
              </button>
            </div>
          </div>

          {findingExplanation && (
            <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-6 space-y-6">
              <div>
                <span className="text-xs font-mono text-indigo-400">{findingExplanation.finding_id}</span>
                <h4 className="text-base font-bold text-white mt-1">{findingExplanation.title}</h4>
                <div className="flex gap-2 mt-2">
                  <span className="px-2 py-0.5 rounded bg-rose-500/10 text-rose-400 border border-rose-500/20 text-xs font-mono">
                    {findingExplanation.severity}
                  </span>
                  <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 text-xs font-mono">
                    Status: {findingExplanation.lifecycle_status}
                  </span>
                </div>
              </div>

              {/* Contextual Risk & Delta */}
              {findingExplanation.contextual_risk && (
                <div className="p-4 bg-slate-950/60 border border-slate-800 rounded-lg space-y-3">
                  <h5 className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
                    Contextual Risk & Score Delta
                  </h5>
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                    <div>
                      <span className="text-xs text-slate-500">Current Score</span>
                      <p className="text-lg font-bold text-white">{findingExplanation.contextual_risk.score.toFixed(1)}</p>
                    </div>
                    <div>
                      <span className="text-xs text-slate-500">Score Delta</span>
                      <p className="text-lg font-bold text-cyan-400">
                        {typeof findingExplanation.contextual_risk.score_delta === 'number'
                          ? `${findingExplanation.contextual_risk.score_delta > 0 ? '+' : ''}${findingExplanation.contextual_risk.score_delta.toFixed(1)}`
                          : '—'}
                      </p>
                    </div>
                    <div>
                      <span className="text-xs text-slate-500">Assessment Label</span>
                      <p className="text-xs font-mono text-slate-300 mt-1">
                        {findingExplanation.contextual_risk.qualitative_label}
                      </p>
                    </div>
                    <div>
                      <span className="text-xs text-slate-500">Unverified Penalty</span>
                      <p className="text-xs font-mono text-amber-400 mt-1">
                        -{findingExplanation.contextual_risk.unverified_penalty.toFixed(1)} pts
                      </p>
                    </div>
                  </div>

                  {findingExplanation.contextual_risk.delta_reasons.length > 0 && (
                    <div className="text-xs space-y-1 border-t border-slate-800 pt-2">
                      <span className="text-slate-400 font-medium">Delta Explanation:</span>
                      <ul className="list-disc list-inside text-slate-300 space-y-0.5">
                        {findingExplanation.contextual_risk.delta_reasons.map((r, i) => (
                          <li key={i}>{r}</li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
};
