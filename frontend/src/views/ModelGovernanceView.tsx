import React, { useState, useEffect } from 'react';
import { api } from '../services/api';
import type { LearningDataset, GovernedModel } from '../types';

interface ModelGovernanceViewProps {
  projectId: string;
}

export const ModelGovernanceView: React.FC<ModelGovernanceViewProps> = ({ projectId }) => {
  const [datasets, setDatasets] = useState<LearningDataset[]>([]);
  const [models, setModels] = useState<GovernedModel[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  // Curate dataset state
  const [datasetName, setDatasetName] = useState('curated_vapt_benchmark');
  const [datasetVersion, setDatasetVersion] = useState('v1.0.0');

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

  const loadData = async () => {
    try {
      setLoading(true);
      setError(null);
      const [dsets, mdls] = await Promise.all([
        api.listDatasets(projectId),
        api.listModels(projectId),
      ]);
      setDatasets(dsets || []);
      setModels(mdls || []);
      if (dsets && dsets.length > 0 && !selectedDatasetId) {
        setSelectedDatasetId(dsets[0].id);
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

  const handleCurateDataset = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      setLoading(true);
      setError(null);
      const result = await api.curateDataset(projectId, datasetName, datasetVersion);
      setSuccess(`Dataset "${result.name}" (${result.version}) curated successfully with ${result.total_records} records.`);
      await loadData();
    } catch (err: any) {
      setError(err.message || 'Failed to curate dataset');
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

  const handleEvaluate = async (modelId: string) => {
    try {
      setLoading(true);
      setError(null);
      const res = await api.evaluateModel(projectId, modelId);
      setSuccess(`Model evaluated: F1=${res.metrics?.f1_score?.toFixed(3) ?? 'N/A'}, Precision=${res.metrics?.precision?.toFixed(3) ?? 'N/A'}, Recall=${res.metrics?.recall?.toFixed(3) ?? 'N/A'}`);
      await loadData();
    } catch (err: any) {
      setError(err.message || 'Evaluation failed');
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

  return (
    <div className="space-y-6">
      <div className="bg-slate-900 border border-slate-800 rounded-lg p-6 shadow-sm">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <h1 className="text-2xl font-bold text-white tracking-tight flex items-center gap-2">
              <span className="text-purple-400">⚖️</span> Controlled Learning & Model Governance
            </h1>
            <p className="text-sm text-slate-400 mt-1">
              Phase 19: Offline dataset curation, privacy sanitization, held-out evaluation, and human governance gates.
            </p>
          </div>
          <button
            onClick={loadData}
            disabled={loading}
            className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs rounded border border-slate-700 transition"
          >
            {loading ? 'Refreshing...' : 'Refresh Models'}
          </button>
        </div>

        <div className="mt-4 p-3 bg-purple-950/30 border border-purple-800/40 rounded text-xs text-purple-300 flex items-center gap-2">
          <span>🛡️</span>
          <span>
            <strong>Anti-Self-Modification Policy:</strong> Production models cannot modify their own weights, schemas, or behaviors at runtime. Deployments require privacy sanitization, deterministic hash generation, held-out evaluation, and explicit human authorization.
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

      {/* Dataset Curation Section */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="bg-slate-900 border border-slate-800 rounded-lg p-5">
          <h2 className="text-base font-semibold text-white mb-3">1. Curate Clean Dataset</h2>
          <p className="text-xs text-slate-400 mb-4">
            Curates verified database records into 70/15/15 train/val/test splits with sensitive credential & IP sanitization.
          </p>
          <form onSubmit={handleCurateDataset} className="space-y-3">
            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">Dataset Name</label>
              <input
                type="text"
                value={datasetName}
                onChange={(e) => setDatasetName(e.target.value)}
                required
                className="w-full bg-slate-800 border border-slate-700 rounded px-3 py-1.5 text-xs text-white"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">Version</label>
              <input
                type="text"
                value={datasetVersion}
                onChange={(e) => setDatasetVersion(e.target.value)}
                required
                className="w-full bg-slate-800 border border-slate-700 rounded px-3 py-1.5 text-xs text-white"
              />
            </div>
            <button
              type="submit"
              disabled={loading}
              className="w-full py-2 bg-purple-600 hover:bg-purple-500 disabled:opacity-50 text-white text-xs font-semibold rounded shadow transition"
            >
              Curate from Verified Findings
            </button>
          </form>
        </div>

        <div className="lg:col-span-2 bg-slate-900 border border-slate-800 rounded-lg p-5">
          <h2 className="text-base font-semibold text-white mb-3">Curated Benchmarks ({datasets.length})</h2>
          {datasets.length === 0 ? (
            <p className="text-xs text-slate-500 italic py-6 text-center">No curated datasets yet. Use the form to curate one.</p>
          ) : (
            <div className="space-y-3 max-h-56 overflow-y-auto pr-1">
              {datasets.map((ds) => (
                <div key={ds.id} className="bg-slate-800/70 border border-slate-700/60 rounded p-3 text-xs flex flex-col md:flex-row md:items-center justify-between gap-2">
                  <div>
                    <div className="font-semibold text-white flex items-center gap-2">
                      <span>{ds.name}</span>
                      <span className="text-slate-400 text-[10px] bg-slate-700 px-1.5 py-0.5 rounded">{ds.version}</span>
                    </div>
                    <div className="text-[11px] text-slate-400 mt-1 font-mono">
                      SHA: {ds.dataset_hash?.slice(0, 16)}...
                    </div>
                  </div>
                  <div className="flex items-center gap-3 text-right">
                    <span className="text-slate-400">Total: <strong className="text-slate-200">{ds.total_records}</strong></span>
                    <span className="text-purple-400">Train: {ds.train_count}</span>
                    <span className="text-blue-400">Val: {ds.val_count}</span>
                    <span className="text-emerald-400">Test: {ds.test_count}</span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Model Registration Section */}
      <div className="bg-slate-900 border border-slate-800 rounded-lg p-5">
        <h2 className="text-base font-semibold text-white mb-3">2. Register Candidate Model</h2>
        <form onSubmit={handleRegisterModel} className="grid grid-cols-1 md:grid-cols-5 gap-4 items-end">
          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1">Model Name</label>
            <input
              type="text"
              value={modelName}
              onChange={(e) => setModelName(e.target.value)}
              required
              className="w-full bg-slate-800 border border-slate-700 rounded px-3 py-1.5 text-xs text-white"
            />
          </div>
          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1">Version</label>
            <input
              type="text"
              value={modelVersion}
              onChange={(e) => setModelVersion(e.target.value)}
              required
              className="w-full bg-slate-800 border border-slate-700 rounded px-3 py-1.5 text-xs text-white"
            />
          </div>
          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1">Model Type</label>
            <select
              value={modelType}
              onChange={(e) => setModelType(e.target.value)}
              className="w-full bg-slate-800 border border-slate-700 rounded px-3 py-1.5 text-xs text-white"
            >
              <option value="RULE_ASSISTED_CLASSIFIER">Rule Assisted Classifier</option>
              <option value="ENSEMBLE_BAYESIAN">Ensemble Bayesian</option>
              <option value="GRADIENT_BOOSTED_TREES">Gradient Boosted Trees</option>
            </select>
          </div>
          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1">Dataset Reference</label>
            <select
              value={selectedDatasetId}
              onChange={(e) => setSelectedDatasetId(e.target.value)}
              required
              className="w-full bg-slate-800 border border-slate-700 rounded px-3 py-1.5 text-xs text-white"
            >
              {datasets.map((ds) => (
                <option key={ds.id} value={ds.id}>{ds.name} ({ds.version})</option>
              ))}
            </select>
          </div>
          <div>
            <button
              type="submit"
              disabled={loading || datasets.length === 0}
              className="w-full py-1.5 bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white text-xs font-semibold rounded shadow transition"
            >
              Register Candidate
            </button>
          </div>
        </form>
      </div>

      {/* Governed Models List */}
      <div className="bg-slate-900 border border-slate-800 rounded-lg p-5">
        <h2 className="text-base font-semibold text-white mb-3">3. Governed Models & Evaluation Registry ({models.length})</h2>
        {models.length === 0 ? (
          <p className="text-xs text-slate-500 italic py-8 text-center">No models registered yet. Register a candidate model above.</p>
        ) : (
          <div className="space-y-4">
            {models.map((m) => {
              const statusColor =
                m.status === 'ACTIVE'
                  ? 'bg-emerald-950 text-emerald-400 border-emerald-800'
                  : m.status === 'APPROVED'
                  ? 'bg-blue-950 text-blue-400 border-blue-800'
                  : m.status === 'EVALUATED'
                  ? 'bg-purple-950 text-purple-400 border-purple-800'
                  : m.status === 'ROLLED_BACK'
                  ? 'bg-amber-950 text-amber-400 border-amber-800'
                  : 'bg-slate-800 text-slate-300 border-slate-700';

              return (
                <div key={m.id} className="bg-slate-800/80 border border-slate-700 rounded-lg p-4 text-xs space-y-3">
                  <div className="flex flex-col md:flex-row md:items-center justify-between gap-2 border-b border-slate-700/60 pb-3">
                    <div className="flex items-center gap-3">
                      <span className="font-bold text-white text-sm">{m.model_name}</span>
                      <span className="text-slate-400 bg-slate-700 px-2 py-0.5 rounded text-[11px]">{m.version}</span>
                      <span className={`px-2 py-0.5 rounded border text-[10px] font-semibold ${statusColor}`}>
                        {m.status}
                      </span>
                      {m.is_active && (
                        <span className="px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 text-[10px] font-bold">
                          PRODUCTION ACTIVE
                        </span>
                      )}
                    </div>
                    <div className="flex items-center gap-2">
                      {m.status === 'CANDIDATE' && (
                        <button
                          onClick={() => handleEvaluate(m.id)}
                          disabled={loading}
                          className="px-2.5 py-1 bg-purple-700 hover:bg-purple-600 text-white rounded text-[11px] font-medium transition"
                        >
                          Run Evaluation
                        </button>
                      )}
                      {(m.status === 'EVALUATED' || m.status === 'CANDIDATE') && (
                        <button
                          onClick={() => {
                            setApprovalModalModel(m);
                            setApprovalDecision(true);
                            setApprovalNotes('');
                          }}
                          className="px-2.5 py-1 bg-blue-700 hover:bg-blue-600 text-white rounded text-[11px] font-medium transition"
                        >
                          Review & Governance Gate
                        </button>
                      )}
                      {m.status === 'APPROVED' && !m.is_active && (
                        <button
                          onClick={() => handleActivate(m.id)}
                          disabled={loading}
                          className="px-2.5 py-1 bg-emerald-700 hover:bg-emerald-600 text-white rounded text-[11px] font-medium transition"
                        >
                          Deploy to Active
                        </button>
                      )}
                      {m.is_active && (
                        <button
                          onClick={() => {
                            setRollbackModalModel(m);
                            setRollbackReason('');
                          }}
                          className="px-2.5 py-1 bg-amber-700 hover:bg-amber-600 text-white rounded text-[11px] font-medium transition"
                        >
                          Atomic Rollback
                        </button>
                      )}
                    </div>
                  </div>

                  {/* Metrics section */}
                  {m.metrics && Object.keys(m.metrics).length > 0 && (
                    <div className="grid grid-cols-2 md:grid-cols-5 gap-2 bg-slate-900/60 p-2.5 rounded border border-slate-800">
                      <div>
                        <div className="text-[10px] text-slate-400">Precision</div>
                        <div className="font-semibold text-purple-300">{m.metrics.precision?.toFixed(3) ?? 'N/A'}</div>
                      </div>
                      <div>
                        <div className="text-[10px] text-slate-400">Recall</div>
                        <div className="font-semibold text-purple-300">{m.metrics.recall?.toFixed(3) ?? 'N/A'}</div>
                      </div>
                      <div>
                        <div className="text-[10px] text-slate-400">F1 Score</div>
                        <div className="font-semibold text-emerald-300">{m.metrics.f1_score?.toFixed(3) ?? 'N/A'}</div>
                      </div>
                      <div>
                        <div className="text-[10px] text-slate-400">False Positive Rate</div>
                        <div className="font-semibold text-amber-300">{m.metrics.false_positive_rate?.toFixed(3) ?? 'N/A'}</div>
                      </div>
                      <div>
                        <div className="text-[10px] text-slate-400">Brier Calibration</div>
                        <div className="font-semibold text-blue-300">{m.metrics.brier_score?.toFixed(4) ?? 'N/A'}</div>
                      </div>
                    </div>
                  )}

                  {m.approval_notes && (
                    <div className="text-[11px] text-slate-400">
                      <strong>Governance notes:</strong> {m.approval_notes} (at {new Date(m.approved_at || '').toLocaleString()})
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Human Approval Gate Modal */}
      {approvalModalModel && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center p-4 z-50">
          <div className="bg-slate-900 border border-slate-700 rounded-lg max-w-md w-full p-6 shadow-xl space-y-4">
            <h3 className="text-lg font-bold text-white flex items-center gap-2">
              <span>⚖️</span> Model Governance Gate
            </h3>
            <p className="text-xs text-slate-400">
              Authorizing candidate model <strong>{approvalModalModel.model_name}</strong> ({approvalModalModel.version}) requires verified evaluation metrics and explicit governance justification.
            </p>

            <form onSubmit={handleApproveSubmit} className="space-y-4">
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">Governance Decision</label>
                <div className="flex gap-4">
                  <label className="flex items-center gap-2 text-xs text-slate-200">
                    <input
                      type="radio"
                      name="decision"
                      checked={approvalDecision === true}
                      onChange={() => setApprovalDecision(true)}
                    />
                    Approve for Deployment
                  </label>
                  <label className="flex items-center gap-2 text-xs text-slate-200">
                    <input
                      type="radio"
                      name="decision"
                      checked={approvalDecision === false}
                      onChange={() => setApprovalDecision(false)}
                    />
                    Reject Candidate
                  </label>
                </div>
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">Approval / Rejection Notes</label>
                <textarea
                  value={approvalNotes}
                  onChange={(e) => setApprovalNotes(e.target.value)}
                  required
                  rows={3}
                  placeholder="Record verification checklist, benchmark performance, and rationale..."
                  className="w-full bg-slate-800 border border-slate-700 rounded p-2 text-xs text-white"
                />
              </div>

              <div className="flex justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setApprovalModalModel(null)}
                  className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs rounded border border-slate-700"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={loading}
                  className="px-3 py-1.5 bg-purple-600 hover:bg-purple-500 text-white text-xs font-semibold rounded"
                >
                  Confirm Gate Decision
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Emergency Rollback Modal */}
      {rollbackModalModel && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center p-4 z-50">
          <div className="bg-slate-900 border border-amber-700 rounded-lg max-w-md w-full p-6 shadow-xl space-y-4">
            <h3 className="text-lg font-bold text-amber-400 flex items-center gap-2">
              <span>⚠️</span> Atomic Model Rollback
            </h3>
            <p className="text-xs text-slate-300">
              Instantly demote <strong>{rollbackModalModel.model_name}</strong> from active production. A fallback or baseline model will be designated.
            </p>

            <form onSubmit={handleRollbackSubmit} className="space-y-4">
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">Reason for Rollback</label>
                <textarea
                  value={rollbackReason}
                  onChange={(e) => setRollbackReason(e.target.value)}
                  required
                  rows={3}
                  placeholder="e.g., Performance drift detected, regression anomaly in production scoring..."
                  className="w-full bg-slate-800 border border-slate-700 rounded p-2 text-xs text-white"
                />
              </div>

              <div className="flex justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setRollbackModalModel(null)}
                  className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs rounded border border-slate-700"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={loading}
                  className="px-3 py-1.5 bg-amber-600 hover:bg-amber-500 text-white text-xs font-semibold rounded"
                >
                  Execute Atomic Rollback
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
