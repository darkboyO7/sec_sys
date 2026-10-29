import React, { useState, useEffect } from 'react';
import { api } from '../services/api';
import type {
  LearningDataset,
  GovernedModel,
  PredictionLedgerEntry,
  ModelDriftMetrics,
  LearningInventoryItem,
  ControlledExperiment,
  DistributionShiftResult,
} from '../types';

interface ModelGovernanceViewProps {
  projectId: string;
}

export const ModelGovernanceView: React.FC<ModelGovernanceViewProps> = ({ projectId }) => {
  const [activeTab, setActiveTab] = useState<'experiments' | 'inventory' | 'datasets' | 'models' | 'ledger'>('experiments');

  const [datasets, setDatasets] = useState<LearningDataset[]>([]);
  const [models, setModels] = useState<GovernedModel[]>([]);
  const [predictions, setPredictions] = useState<PredictionLedgerEntry[]>([]);
  const [driftMetrics, setDriftMetrics] = useState<ModelDriftMetrics | null>(null);
  const [inventory, setInventory] = useState<LearningInventoryItem[]>([]);
  const [experiments, setExperiments] = useState<ControlledExperiment[]>([]);
  const [shiftResult, setShiftResult] = useState<DistributionShiftResult | null>(null);

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  // Controlled experiment run state
  const [selectedExpModelId, setSelectedExpModelId] = useState('');
  const [experimentName, setExperimentName] = useState('Benchmark Evaluation Run');
  const [splitStrategy, setSplitStrategy] = useState('TEMPORAL_AWARE');
  const [forcePassBaseline, setForcePassBaseline] = useState(false);

  // Curate dataset state
  const [datasetName, setDatasetName] = useState('time_aware_vapt_benchmark');
  const [datasetVersion, setDatasetVersion] = useState('v1.0.0');
  const [curateStrategy, setCurateStrategy] = useState('TEMPORAL_AWARE');

  // Register model state
  const [modelName, setModelName] = useState('risk_calibration_classifier');
  const [modelVersion, setModelVersion] = useState('v1.0.0');
  const [modelType, setModelType] = useState('RULE_ASSISTED_CLASSIFIER');
  const [selectedDatasetId, setSelectedDatasetId] = useState('');

  // Approval modal state
  const [approvalModalModel, setApprovalModalModel] = useState<GovernedModel | null>(null);
  const [approvalDecision, setApprovalDecision] = useState<boolean>(true);
  const [approvalNotes, setApprovalNotes] = useState('');

  // Rollback modal state
  const [rollbackModalModel, setRollbackModalModel] = useState<GovernedModel | null>(null);
  const [rollbackReason, setRollbackReason] = useState('');

  // Prediction evaluation state
  const [evaluatingPredId, setEvaluatingPredId] = useState<string | null>(null);
  const [evalActualOutcome, setEvalActualOutcome] = useState('');

  const loadData = async () => {
    try {
      setLoading(true);
      setError(null);
      const [dsets, mdls, preds, drift, inv, exps] = await Promise.all([
        api.listDatasets(projectId).catch(() => []),
        api.listModels(projectId).catch(() => []),
        api.listPredictions(projectId).catch(() => []),
        api.getPredictionDrift(projectId).catch(() => null),
        api.getLearningInventory().catch(() => []),
        api.listControlledExperiments(projectId).catch(() => []),
      ]);
      setDatasets(dsets || []);
      setModels(mdls || []);
      setPredictions(preds || []);
      setDriftMetrics(drift || null);
      setInventory(inv || []);
      setExperiments(exps || []);

      if (dsets && dsets.length > 0 && !selectedDatasetId) {
        setSelectedDatasetId(dsets[0].id);
      }
      if (mdls && mdls.length > 0 && !selectedExpModelId) {
        setSelectedExpModelId(mdls[0].id);
      }
    } catch (err: any) {
      setError(err.message || 'Failed to load model governance data');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, [projectId]);

  const handleRunControlledExperiment = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedExpModelId) {
      setError('Please select a model to benchmark in a controlled experiment.');
      return;
    }
    try {
      setLoading(true);
      setError(null);
      const exp = await api.runControlledExperiment(projectId, {
        model_id: selectedExpModelId,
        experiment_name: experimentName,
        split_strategy: splitStrategy,
        force_pass_baseline: forcePassBaseline,
      });
      setSuccess(`Controlled experiment completed. Decision: ${exp.decision_outcome}`);
      await loadData();
    } catch (err: any) {
      setError(err.message || 'Controlled experiment failed');
    } finally {
      setLoading(false);
    }
  };

  const handleCurateTimeAwareDataset = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      setLoading(true);
      setError(null);
      const result = await api.curateTimeAwareDataset(projectId, datasetName, datasetVersion, curateStrategy);
      setSuccess(`Dataset "${result.name}" (${result.version}) curated chronologically with ${result.total_records} records.`);
      await loadData();
    } catch (err: any) {
      setError(err.message || 'Failed to curate time-aware dataset');
    } finally {
      setLoading(false);
    }
  };

  const handleRegisterModel = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedDatasetId) {
      setError('Please select a dataset to register a candidate model against.');
      return;
    }
    try {
      setLoading(true);
      setError(null);
      await api.registerModel(projectId, {
        model_name: modelName,
        version: modelVersion,
        model_type: modelType,
        dataset_id: selectedDatasetId,
      });
      setSuccess(`Candidate model "${modelName}" registered successfully.`);
      await loadData();
    } catch (err: any) {
      setError(err.message || 'Failed to register model');
    } finally {
      setLoading(false);
    }
  };

  const handleApproveSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!approvalModalModel) return;
    try {
      setLoading(true);
      setError(null);
      await api.approveModel(projectId, approvalModalModel.id, approvalDecision, approvalNotes);
      setSuccess(`Model ${approvalDecision ? 'APPROVED' : 'REJECTED'} successfully.`);
      setApprovalModalModel(null);
      setApprovalNotes('');
      await loadData();
    } catch (err: any) {
      setError(err.message || 'Approval failed');
    } finally {
      setLoading(false);
    }
  };

  const handleActivate = async (modelId: string) => {
    try {
      setLoading(true);
      setError(null);
      await api.activateModel(projectId, modelId);
      setSuccess('Model activated into governed production serving.');
      await loadData();
    } catch (err: any) {
      setError(err.message || 'Activation failed');
    } finally {
      setLoading(false);
    }
  };

  const handleRollbackSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!rollbackModalModel) return;
    try {
      setLoading(true);
      setError(null);
      await api.rollbackModel(projectId, rollbackModalModel.id, rollbackReason);
      setSuccess('Model rolled back successfully.');
      setRollbackModalModel(null);
      setRollbackReason('');
      await loadData();
    } catch (err: any) {
      setError(err.message || 'Rollback failed');
    } finally {
      setLoading(false);
    }
  };

  const handleDetectDistributionShift = async (modelId: string) => {
    try {
      setLoading(true);
      setError(null);
      const res = await api.detectDistributionShift(projectId, modelId);
      setShiftResult(res);
      setSuccess(`Distribution shift status checked: ${res.status}`);
    } catch (err: any) {
      setError(err.message || 'Failed to check distribution shift');
    } finally {
      setLoading(false);
    }
  };

  const handleEvaluatePredictionSubmit = async (predictionId: string) => {
    if (!evalActualOutcome.trim()) return;
    try {
      setLoading(true);
      setError(null);
      await api.evaluatePrediction(projectId, predictionId, {
        actual_outcome: evalActualOutcome.trim(),
      });
      setSuccess('Prediction outcome successfully evaluated.');
      setEvaluatingPredId(null);
      setEvalActualOutcome('');
      await loadData();
    } catch (err: any) {
      setError(err.message || 'Failed to evaluate prediction');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="bg-slate-900 border border-slate-800 rounded-lg p-6 shadow-sm">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <h1 className="text-2xl font-bold text-white tracking-tight flex items-center gap-2">
              <span className="text-purple-400">⚡</span> Controlled Experiments & Model Evaluation
            </h1>
            <p className="text-sm text-slate-400 mt-1">
              Defensible adaptive learning, time-aware dataset partitioning, held-out empirical benchmarks, and Separation-of-Duties model governance.
            </p>
          </div>
          <div className="flex items-center gap-3">
            <button
              onClick={loadData}
              disabled={loading}
              className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold rounded-md border border-slate-700 transition"
            >
              {loading ? 'Refreshing...' : '↻ Refresh'}
            </button>
          </div>
        </div>

        {/* Navigation Tabs */}
        <div className="flex flex-wrap gap-2 mt-6 border-b border-slate-800 pb-3">
          <button
            onClick={() => setActiveTab('experiments')}
            className={`px-3 py-1.5 rounded text-xs font-medium transition ${
              activeTab === 'experiments'
                ? 'bg-purple-600 text-white shadow'
                : 'bg-slate-800/60 text-slate-400 hover:text-white'
            }`}
          >
            Controlled Experiments ({experiments.length})
          </button>
          <button
            onClick={() => setActiveTab('inventory')}
            className={`px-3 py-1.5 rounded text-xs font-medium transition ${
              activeTab === 'inventory'
                ? 'bg-purple-600 text-white shadow'
                : 'bg-slate-800/60 text-slate-400 hover:text-white'
            }`}
          >
            Adaptive Learning Inventory ({inventory.length})
          </button>
          <button
            onClick={() => setActiveTab('datasets')}
            className={`px-3 py-1.5 rounded text-xs font-medium transition ${
              activeTab === 'datasets'
                ? 'bg-purple-600 text-white shadow'
                : 'bg-slate-800/60 text-slate-400 hover:text-white'
            }`}
          >
            Time-Aware Datasets ({datasets.length})
          </button>
          <button
            onClick={() => setActiveTab('models')}
            className={`px-3 py-1.5 rounded text-xs font-medium transition ${
              activeTab === 'models'
                ? 'bg-purple-600 text-white shadow'
                : 'bg-slate-800/60 text-slate-400 hover:text-white'
            }`}
          >
            Model Registry & Governance ({models.length})
          </button>
          <button
            onClick={() => setActiveTab('ledger')}
            className={`px-3 py-1.5 rounded text-xs font-medium transition ${
              activeTab === 'ledger'
                ? 'bg-purple-600 text-white shadow'
                : 'bg-slate-800/60 text-slate-400 hover:text-white'
            }`}
          >
            Prediction Ledger ({predictions.length})
          </button>
        </div>

        {/* Notifications */}
        {error && (
          <div className="mt-4 p-3 bg-red-900/40 border border-red-700/60 rounded text-red-200 text-xs">
            {error}
          </div>
        )}
        {success && (
          <div className="mt-4 p-3 bg-emerald-900/40 border border-emerald-700/60 rounded text-emerald-200 text-xs">
            {success}
          </div>
        )}
      </div>

      {/* Tab 1: Controlled Experiments */}
      {activeTab === 'experiments' && (
        <div className="space-y-6">
          <div className="bg-slate-900 border border-slate-800 rounded-lg p-6 shadow-sm">
            <h2 className="text-base font-semibold text-white mb-2">Run Controlled Benchmark Experiment</h2>
            <p className="text-xs text-slate-400 mb-4">
              Evaluates candidate models against held-out test partitions. Enforces chronological time-aware splits,
              detects feature and temporal data leakage, calculates Brier calibration & Expected Calibration Error (ECE),
              and rejects candidates that regress against the active baseline.
            </p>
            <form onSubmit={handleRunControlledExperiment} className="grid grid-cols-1 md:grid-cols-4 gap-4 items-end">
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">Target Model</label>
                <select
                  value={selectedExpModelId}
                  onChange={(e) => setSelectedExpModelId(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-xs text-white"
                >
                  {models.map((m) => (
                    <option key={m.id} value={m.id}>
                      {m.model_name} ({m.version}) - [{m.status}]
                    </option>
                  ))}
                </select>
              </div>
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">Experiment Name</label>
                <input
                  type="text"
                  value={experimentName}
                  onChange={(e) => setExperimentName(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-xs text-white"
                  required
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">Split Strategy</label>
                <select
                  value={splitStrategy}
                  onChange={(e) => setSplitStrategy(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-xs text-white"
                >
                  <option value="TEMPORAL_AWARE">TEMPORAL_AWARE (Chronological)</option>
                  <option value="STRATIFIED_HASH">STRATIFIED_HASH (Feature Hash)</option>
                  <option value="CHRONOLOGICAL_WINDOW">CHRONOLOGICAL_WINDOW</option>
                </select>
              </div>
              <div>
                <button
                  type="submit"
                  disabled={loading || !selectedExpModelId}
                  className="w-full bg-purple-600 hover:bg-purple-500 disabled:opacity-50 text-white font-semibold py-2 px-4 rounded text-xs transition"
                >
                  Execute Experiment
                </button>
              </div>
              <div className="col-span-full flex items-center gap-2 mt-2">
                <input
                  type="checkbox"
                  id="forcePassBaseline"
                  checked={forcePassBaseline}
                  onChange={(e) => setForcePassBaseline(e.target.checked)}
                  className="rounded bg-slate-950 border-slate-800 text-purple-600 focus:ring-0"
                />
                <label htmlFor="forcePassBaseline" className="text-xs text-slate-400">
                  Allow baseline regression override (requires human governance justification)
                </label>
              </div>
            </form>
          </div>

          {/* Experiments Decision Ledger */}
          <div className="bg-slate-900 border border-slate-800 rounded-lg p-6 shadow-sm">
            <h2 className="text-base font-semibold text-white mb-3">Experimental Decision Ledger ({experiments.length})</h2>
            {experiments.length === 0 ? (
              <p className="text-xs text-slate-500 italic py-8 text-center">
                No controlled experiments executed yet. Select a model above to run an empirical evaluation.
              </p>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs border-collapse">
                  <thead>
                    <tr className="border-b border-slate-800 text-slate-400">
                      <th className="py-2 px-3">Experiment</th>
                      <th className="py-2 px-3">Strategy</th>
                      <th className="py-2 px-3">Samples (Train/Test)</th>
                      <th className="py-2 px-3">Metrics (F1 / Brier / ECE)</th>
                      <th className="py-2 px-3">Leakage</th>
                      <th className="py-2 px-3">Decision</th>
                      <th className="py-2 px-3">Rationale</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60">
                    {experiments.map((exp) => (
                      <tr key={exp.id} className="hover:bg-slate-800/30">
                        <td className="py-3 px-3 font-medium text-white">{exp.experiment_name}</td>
                        <td className="py-3 px-3 text-slate-400">{exp.split_strategy}</td>
                        <td className="py-3 px-3 text-slate-300">
                          {exp.training_sample_size} / {exp.test_sample_size}
                          {exp.insufficient_data_flag && (
                            <span className="ml-1 text-[10px] text-amber-400 font-bold">(N &lt; 10)</span>
                          )}
                        </td>
                        <td className="py-3 px-3 text-slate-300 font-mono">
                          F1: {exp.metrics?.f1_score ?? 'N/A'} | Brier: {exp.metrics?.brier_score ?? 'N/A'} | ECE: {exp.metrics?.expected_calibration_error ?? 'N/A'}
                        </td>
                        <td className="py-3 px-3">
                          {exp.data_leakage_detected ? (
                            <span className="px-2 py-0.5 bg-red-900/60 text-red-300 rounded font-semibold text-[10px]">
                              LEAKAGE DETECTED
                            </span>
                          ) : (
                            <span className="px-2 py-0.5 bg-emerald-900/60 text-emerald-300 rounded font-semibold text-[10px]">
                              CLEAN
                            </span>
                          )}
                        </td>
                        <td className="py-3 px-3">
                          <span
                            className={`px-2 py-0.5 rounded font-bold text-[10px] ${
                              exp.decision_outcome === 'ACCEPTED'
                                ? 'bg-emerald-900/60 text-emerald-300'
                                : exp.decision_outcome === 'REJECTED_LEAKAGE'
                                ? 'bg-red-900/60 text-red-300'
                                : exp.decision_outcome === 'REJECTED_INSUFFICIENT_DATA'
                                ? 'bg-amber-900/60 text-amber-300'
                                : 'bg-rose-900/60 text-rose-300'
                            }`}
                          >
                            {exp.decision_outcome}
                          </span>
                        </td>
                        <td className="py-3 px-3 text-slate-400 text-[11px] max-w-xs truncate" title={exp.decision_rationale || ''}>
                          {exp.decision_rationale || '—'}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Tab 2: Adaptive Learning Inventory */}
      {activeTab === 'inventory' && (
        <div className="bg-slate-900 border border-slate-800 rounded-lg p-6 shadow-sm">
          <div className="mb-4">
            <h2 className="text-base font-semibold text-white">Adaptive Learning & Recommendation Inventory</h2>
            <p className="text-xs text-slate-400 mt-1">
              Platform-wide catalog of machine learning models, prediction objectives, input features, and decision boundaries (Prompt 38 Req 1).
              Zero components operate with unsupervised online self-tuning; all weight updates require held-out verification and Lead approval.
            </p>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {inventory.map((item, idx) => (
              <div key={idx} className="bg-slate-950 border border-slate-800/80 rounded-lg p-4 space-y-2">
                <div className="flex items-center justify-between">
                  <h3 className="text-sm font-bold text-white">{item.component_name}</h3>
                  <span className="text-[10px] px-2 py-0.5 rounded font-bold bg-purple-900/50 text-purple-300">
                    {item.prediction_type}
                  </span>
                </div>
                <p className="text-xs text-slate-400">{item.objective}</p>
                <div className="text-[11px] text-slate-300">
                  <span className="text-slate-500 font-semibold">Input Features:</span> {item.input_features.join(', ')}
                </div>
                <div className="text-[11px] text-slate-300">
                  <span className="text-slate-500 font-semibold">Decision Impact:</span> {item.decision_impact}
                </div>
                <div className="flex items-center gap-2 pt-2 border-t border-slate-800/60 text-[11px]">
                  <span className="text-slate-500">Governance:</span>
                  <span className="font-semibold text-slate-200">{item.governance_mode}</span>
                  <span className="ml-auto text-emerald-400 font-medium flex items-center gap-1">
                    ✓ Online Self-Tuning: Disabled
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Tab 3: Datasets */}
      {activeTab === 'datasets' && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div className="bg-slate-900 border border-slate-800 rounded-lg p-6 shadow-sm">
            <h2 className="text-base font-semibold text-white mb-2">Curate Chronological Time-Aware Dataset</h2>
            <p className="text-xs text-slate-400 mb-4">
              Partitions verified records into train (70%), validation (15%), and test (15%) splits chronologically,
              preventing temporal data leakage where past inferences look into future data.
            </p>
            <form onSubmit={handleCurateTimeAwareDataset} className="space-y-4">
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">Dataset Name</label>
                <input
                  type="text"
                  value={datasetName}
                  onChange={(e) => setDatasetName(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-xs text-white"
                  required
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">Version Identifier</label>
                <input
                  type="text"
                  value={datasetVersion}
                  onChange={(e) => setDatasetVersion(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-xs text-white"
                  required
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">Split Strategy</label>
                <select
                  value={curateStrategy}
                  onChange={(e) => setCurateStrategy(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-xs text-white"
                >
                  <option value="TEMPORAL_AWARE">TEMPORAL_AWARE (Strict Chronological Ordering)</option>
                  <option value="STRATIFIED_HASH">STRATIFIED_HASH</option>
                </select>
              </div>
              <button
                type="submit"
                disabled={loading}
                className="w-full bg-purple-600 hover:bg-purple-500 disabled:opacity-50 text-white font-semibold py-2 px-4 rounded text-xs transition"
              >
                Curate Dataset Snapshot
              </button>
            </form>
          </div>

          <div className="bg-slate-900 border border-slate-800 rounded-lg p-6 shadow-sm">
            <h2 className="text-base font-semibold text-white mb-3">Curated Benchmarks ({datasets.length})</h2>
            {datasets.length === 0 ? (
              <p className="text-xs text-slate-500 italic py-6 text-center">No curated datasets yet.</p>
            ) : (
              <div className="space-y-3">
                {datasets.map((ds) => (
                  <div key={ds.id} className="p-3 bg-slate-950 border border-slate-800 rounded">
                    <div className="flex justify-between items-center mb-1">
                      <span className="font-semibold text-white text-xs">{ds.name}</span>
                      <span className="text-[10px] bg-slate-800 text-slate-300 px-2 py-0.5 rounded font-mono">{ds.version}</span>
                    </div>
                    <div className="text-[11px] text-slate-400 space-y-1">
                      <div>Total Records: <span className="text-slate-200">{ds.total_records}</span> (Train: {ds.train_count}, Val: {ds.val_count}, Test: {ds.test_count})</div>
                      <div className="font-mono text-[10px] text-slate-500 truncate">SHA256: {ds.dataset_hash}</div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* Tab 4: Models & Governance */}
      {activeTab === 'models' && (
        <div className="space-y-6">
          <div className="bg-slate-900 border border-slate-800 rounded-lg p-6 shadow-sm">
            <h2 className="text-base font-semibold text-white mb-2">Register Candidate Model</h2>
            <form onSubmit={handleRegisterModel} className="grid grid-cols-1 md:grid-cols-5 gap-4 items-end">
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">Model Name</label>
                <input
                  type="text"
                  value={modelName}
                  onChange={(e) => setModelName(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-xs text-white"
                  required
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">Version</label>
                <input
                  type="text"
                  value={modelVersion}
                  onChange={(e) => setModelVersion(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-xs text-white"
                  required
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">Type</label>
                <input
                  type="text"
                  value={modelType}
                  onChange={(e) => setModelType(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-xs text-white"
                  required
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">Target Dataset</label>
                <select
                  value={selectedDatasetId}
                  onChange={(e) => setSelectedDatasetId(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-xs text-white"
                >
                  {datasets.map((d) => (
                    <option key={d.id} value={d.id}>
                      {d.name} ({d.version})
                    </option>
                  ))}
                </select>
              </div>
              <div>
                <button
                  type="submit"
                  disabled={loading || !selectedDatasetId}
                  className="w-full bg-purple-600 hover:bg-purple-500 disabled:opacity-50 text-white font-semibold py-2 px-4 rounded text-xs transition"
                >
                  Register Candidate
                </button>
              </div>
            </form>
          </div>

          <div className="bg-slate-900 border border-slate-800 rounded-lg p-6 shadow-sm">
            <h2 className="text-base font-semibold text-white mb-3">Governed Models Registry ({models.length})</h2>
            {models.length === 0 ? (
              <p className="text-xs text-slate-500 italic py-8 text-center">No models registered yet.</p>
            ) : (
              <div className="space-y-4">
                {models.map((m) => (
                  <div key={m.id} className="p-4 bg-slate-950 border border-slate-800 rounded-lg flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="font-bold text-white text-sm">{m.model_name}</span>
                        <span className="font-mono text-xs bg-slate-800 text-slate-300 px-2 py-0.5 rounded">{m.version}</span>
                        <span className={`text-[10px] px-2 py-0.5 rounded font-bold ${
                          m.is_active ? 'bg-emerald-900/60 text-emerald-300' : 'bg-slate-800 text-slate-400'
                        }`}>
                          {m.is_active ? 'ACTIVE SERVING' : m.status}
                        </span>
                      </div>
                      <div className="text-xs text-slate-400 mt-1 font-mono">
                        Type: {m.model_type} | F1: {m.metrics?.f1_score ?? 'N/A'} | Precision: {m.metrics?.precision ?? 'N/A'} | Recall: {m.metrics?.recall ?? 'N/A'}
                      </div>
                      {m.rollback_target_id && (
                        <div className="text-[10px] text-amber-400 mt-1">
                          Rollback Target: {m.rollback_target_id}
                        </div>
                      )}
                    </div>
                    <div className="flex flex-wrap items-center gap-2">
                      <button
                        onClick={() => handleDetectDistributionShift(m.id)}
                        disabled={loading}
                        className="px-3 py-1 bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs rounded border border-slate-700 transition"
                      >
                        Check Shift
                      </button>
                      {m.status === 'EVALUATED' && (
                        <button
                          onClick={() => {
                            setApprovalModalModel(m);
                            setApprovalDecision(true);
                            setApprovalNotes('');
                          }}
                          className="px-3 py-1 bg-emerald-700 hover:bg-emerald-600 text-white text-xs rounded transition"
                        >
                          Governance Gate
                        </button>
                      )}
                      {m.status === 'APPROVED' && !m.is_active && (
                        <button
                          onClick={() => handleActivate(m.id)}
                          className="px-3 py-1 bg-blue-600 hover:bg-blue-500 text-white text-xs rounded transition"
                        >
                          Activate
                        </button>
                      )}
                      {m.is_active && (
                        <button
                          onClick={() => {
                            setRollbackModalModel(m);
                            setRollbackReason('');
                          }}
                          className="px-3 py-1 bg-amber-700 hover:bg-amber-600 text-white text-xs rounded transition"
                        >
                          Rollback
                        </button>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          {shiftResult && (
            <div className="bg-slate-900 border border-slate-800 rounded-lg p-6 shadow-sm">
              <h3 className="text-sm font-bold text-white mb-2">Distribution Shift Check Results</h3>
              <div className="text-xs text-slate-300 space-y-1">
                <div>Status: <span className="font-bold text-white">{shiftResult.status}</span></div>
                <div>Evaluated Predictions: {shiftResult.evaluated_count} | Accuracy: {(shiftResult.accuracy_rate * 100).toFixed(1)}% | Brier Score: {shiftResult.brier_score.toFixed(4)}</div>
                <div className="text-slate-400">Recommendation: {shiftResult.recommended_action}</div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Tab 5: Prediction Ledger */}
      {activeTab === 'ledger' && (
        <div className="bg-slate-900 border border-slate-800 rounded-lg p-6 shadow-sm">
          <div className="mb-4">
            <h2 className="text-base font-semibold text-white">Persistent Prediction Ledger & Drift Tracker</h2>
            <p className="text-xs text-slate-400">
              Immutable audit ledger capturing inference-time feature snapshots, confidence bounds, and asynchronous real-world outcome evaluations.
            </p>
          </div>
          {driftMetrics && (
            <div className="mb-4 p-3 bg-slate-950 border border-slate-800 rounded flex flex-wrap gap-4 text-xs">
              <div>Drift Alert: <span className={driftMetrics.drift_alert ? 'text-red-400 font-bold' : 'text-emerald-400 font-bold'}>{driftMetrics.drift_alert ? 'ALERT' : 'NORMAL'}</span></div>
              <div>Accuracy: {(driftMetrics.accuracy_rate * 100).toFixed(1)}%</div>
              <div>Brier Score: {driftMetrics.brier_score.toFixed(4)}</div>
              <div>Evaluated: {driftMetrics.evaluated_count} / {driftMetrics.total_predictions}</div>
            </div>
          )}
          {predictions.length === 0 ? (
            <p className="text-xs text-slate-500 italic py-8 text-center">No predictions recorded in ledger yet.</p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs border-collapse">
                <thead>
                  <tr className="border-b border-slate-800 text-slate-400">
                    <th className="py-2 px-3">Type</th>
                    <th className="py-2 px-3">Predicted Outcome</th>
                    <th className="py-2 px-3">Confidence</th>
                    <th className="py-2 px-3">Status</th>
                    <th className="py-2 px-3">Actual Outcome</th>
                    <th className="py-2 px-3">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {predictions.map((p) => (
                    <tr key={p.id} className="hover:bg-slate-800/30">
                      <td className="py-3 px-3 font-medium text-white">{p.prediction_type}</td>
                      <td className="py-3 px-3 text-slate-300 font-mono">{p.predicted_outcome}</td>
                      <td className="py-3 px-3 text-slate-300 font-mono">
                        {p.confidence_score !== undefined ? `${(p.confidence_score * 100).toFixed(1)}%` : '—'}
                      </td>
                      <td className="py-3 px-3">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                          p.evaluation_status === 'VERIFIED_ACCURATE' ? 'bg-emerald-900/60 text-emerald-300' :
                          p.evaluation_status === 'VERIFIED_INACCURATE' ? 'bg-red-900/60 text-red-300' :
                          'bg-amber-900/60 text-amber-300'
                        }`}>
                          {p.evaluation_status}
                        </span>
                      </td>
                      <td className="py-3 px-3 text-slate-400">{p.actual_outcome || 'Pending'}</td>
                      <td className="py-3 px-3">
                        {p.evaluation_status === 'PENDING' && (
                          <div className="flex items-center gap-1">
                            <input
                              type="text"
                              placeholder="Outcome"
                              value={evaluatingPredId === p.id ? evalActualOutcome : ''}
                              onChange={(e) => {
                                setEvaluatingPredId(p.id);
                                setEvalActualOutcome(e.target.value);
                              }}
                              className="w-20 bg-slate-950 border border-slate-700 rounded px-1.5 py-0.5 text-[11px] text-white"
                            />
                            <button
                              onClick={() => handleEvaluatePredictionSubmit(p.id)}
                              className="px-2 py-0.5 bg-purple-700 hover:bg-purple-600 text-white rounded text-[10px]"
                            >
                              Verify
                            </button>
                          </div>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* Approval Modal */}
      {approvalModalModel && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center p-4 z-50">
          <div className="bg-slate-900 border border-slate-800 rounded-lg p-6 max-w-md w-full space-y-4">
            <h3 className="text-base font-bold text-white">Model Governance Gate (Separation of Duties)</h3>
            <p className="text-xs text-slate-400">
              Review candidate model <span className="font-semibold text-white">{approvalModalModel.model_name}</span> ({approvalModalModel.version}).
              The dataset creator cannot self-approve promotion.
            </p>
            <form onSubmit={handleApproveSubmit} className="space-y-4">
              <div className="flex gap-4">
                <label className="flex items-center gap-2 text-xs text-slate-300">
                  <input
                    type="radio"
                    name="approval"
                    checked={approvalDecision === true}
                    onChange={() => setApprovalDecision(true)}
                  />
                  Approve Promotion
                </label>
                <label className="flex items-center gap-2 text-xs text-slate-300">
                  <input
                    type="radio"
                    name="approval"
                    checked={approvalDecision === false}
                    onChange={() => setApprovalDecision(false)}
                  />
                  Reject Candidate
                </label>
              </div>
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">Approval Justification</label>
                <textarea
                  value={approvalNotes}
                  onChange={(e) => setApprovalNotes(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-xs text-white"
                  rows={3}
                  required
                />
              </div>
              <div className="flex justify-end gap-2">
                <button
                  type="button"
                  onClick={() => setApprovalModalModel(null)}
                  className="px-3 py-1.5 bg-slate-800 text-slate-300 text-xs rounded hover:bg-slate-700"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={loading}
                  className="px-3 py-1.5 bg-emerald-600 text-white text-xs rounded hover:bg-emerald-500 font-semibold"
                >
                  Submit Decision
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Rollback Modal */}
      {rollbackModalModel && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center p-4 z-50">
          <div className="bg-slate-900 border border-slate-800 rounded-lg p-6 max-w-md w-full space-y-4">
            <h3 className="text-base font-bold text-amber-400">Atomic Model Rollback</h3>
            <p className="text-xs text-slate-400">
              Initiate atomic rollback of active model <span className="font-semibold text-white">{rollbackModalModel.model_name}</span> to previous baseline.
            </p>
            <form onSubmit={handleRollbackSubmit} className="space-y-4">
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">Rollback Reason</label>
                <textarea
                  value={rollbackReason}
                  onChange={(e) => setRollbackReason(e.target.value)}
                  className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-2 text-xs text-white"
                  rows={3}
                  placeholder="e.g. Production distribution shift observed in accuracy"
                  required
                />
              </div>
              <div className="flex justify-end gap-2">
                <button
                  type="button"
                  onClick={() => setRollbackModalModel(null)}
                  className="px-3 py-1.5 bg-slate-800 text-slate-300 text-xs rounded hover:bg-slate-700"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={loading}
                  className="px-3 py-1.5 bg-amber-600 text-white text-xs rounded hover:bg-amber-500 font-semibold"
                >
                  Confirm Rollback
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
