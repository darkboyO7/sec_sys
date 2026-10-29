import React, { useState, useEffect } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  CheckCircle,
  XCircle,
  AlertTriangle,
  RefreshCw,
  Database,
  Archive,
  Play,
  RotateCcw,
  Check,
  FileCheck,
  Layers,
  HelpCircle,
} from 'lucide-react';
import { api } from '../services/api';
import type {
  DisasterRecoveryBundle,
  RestoreDrillResult,
  RotationResult,
  RecoveryStatusSummary,
} from '../types';

export const RecoveryDashboardView: React.FC = () => {
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  // Core data
  const [bundles, setBundles] = useState<DisasterRecoveryBundle[]>([]);
  const [statusSummary, setStatusSummary] = useState<RecoveryStatusSummary | null>(null);

  // Action states
  const [creatingBundle, setCreatingBundle] = useState<boolean>(false);
  const [verifyingBundleId, setVerifyingBundleId] = useState<string | null>(null);
  const [drillingBundleId, setDrillingBundleId] = useState<string | null>(null);
  const [rotating, setRotating] = useState<boolean>(false);

  // Modals & inspect states
  const [selectedBundle, setSelectedBundle] = useState<DisasterRecoveryBundle | null>(null);
  const [activeDrillResult, setActiveDrillResult] = useState<RestoreDrillResult | null>(null);
  const [liveRestoreTarget, setLiveRestoreTarget] = useState<DisasterRecoveryBundle | null>(null);
  const [confirmationPhraseInput, setConfirmationPhraseInput] = useState<string>('');
  const [restoringLive, setRestoringLive] = useState<boolean>(false);

  const fetchData = async () => {
    setLoading(true);
    setError(null);
    try {
      const [bundleList, summary] = await Promise.all([
        api.listRecoveryBundles().catch(() => []),
        api.getRecoveryStatus().catch(() => null),
      ]);
      setBundles(bundleList);
      setStatusSummary(summary);
    } catch (err: any) {
      setError(err?.message || 'Failed to load disaster recovery state.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  const handleCreateBundle = async () => {
    setCreatingBundle(true);
    setError(null);
    setSuccessMsg(null);
    try {
      const newBundle = await api.createRecoveryBundle();
      setSuccessMsg(`Disaster recovery bundle ${newBundle.bundle_id} created successfully.`);
      await fetchData();
    } catch (err: any) {
      setError(err?.message || 'Failed to create disaster recovery bundle.');
    } finally {
      setCreatingBundle(false);
    }
  };

  const handleVerifyBundle = async (bundleId: string) => {
    setVerifyingBundleId(bundleId);
    setError(null);
    setSuccessMsg(null);
    try {
      const result = await api.verifyRecoveryBundle(bundleId);
      if (result.status === 'PASSED') {
        setSuccessMsg(`Bundle ${bundleId} passed all 7 independent integrity and consistency checks.`);
      } else {
        setError(`Bundle ${bundleId} verification failed: ${result.errors.join('; ')}`);
      }
      await fetchData();
    } catch (err: any) {
      setError(err?.message || `Verification of bundle ${bundleId} failed.`);
    } finally {
      setVerifyingBundleId(null);
    }
  };

  const handleRestoreDrill = async (bundleId: string) => {
    setDrillingBundleId(bundleId);
    setError(null);
    setSuccessMsg(null);
    try {
      const result = await api.runIsolatedRestoreDrill(bundleId);
      setActiveDrillResult(result);
      setSuccessMsg(`Isolated restore drill succeeded for bundle ${bundleId}. ${result.jobs_reconciled.length} in-flight jobs reconciled to INTERRUPTED.`);
      await fetchData();
    } catch (err: any) {
      setError(err?.message || `Isolated restore drill failed for bundle ${bundleId}.`);
    } finally {
      setDrillingBundleId(null);
    }
  };

  const handleRotateBundles = async () => {
    setRotating(true);
    setError(null);
    setSuccessMsg(null);
    try {
      const result: RotationResult = await api.rotateRecoveryBundles(5, true);
      setSuccessMsg(`Rotation complete: ${result.bundles_pruned} bundles pruned, ${result.bundles_retained} retained. Last-known-good protected.`);
      await fetchData();
    } catch (err: any) {
      setError(err?.message || 'Failed to rotate backup bundles.');
    } finally {
      setRotating(false);
    }
  };

  const handleLiveRestore = async () => {
    if (!liveRestoreTarget) return;
    setRestoringLive(true);
    setError(null);
    try {
      const result = await api.liveRestoreBundle(liveRestoreTarget.bundle_id, confirmationPhraseInput);
      setSuccessMsg(`Live disaster restore completed successfully. Pre-restore rollback saved at ${result.rollback_path}.`);
      setLiveRestoreTarget(null);
      setConfirmationPhraseInput('');
      await fetchData();
    } catch (err: any) {
      setError(err?.message || 'Live disaster restore failed.');
    } finally {
      setRestoringLive(false);
    }
  };

  const formatBytes = (bytes: number) => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return `${(bytes / Math.pow(k, i)).toFixed(2)} ${sizes[i]}`;
  };

  const requiredPhrase = liveRestoreTarget ? `CONFIRM DISASTER RESTORE ${liveRestoreTarget.bundle_id}` : '';
  const isPhraseValid = confirmationPhraseInput.trim() === requiredPhrase;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-gray-800 pb-5">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
            <Database className="h-6 w-6 text-primary" />
            Disaster Recovery & Data Integrity
          </h1>
          <p className="text-sm text-gray-400 mt-1">
            Consistent SQLite WAL Online Backups, Non-Destructive Verifications, and Isolated Restoration Drills
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-3">
          <button
            onClick={fetchData}
            disabled={loading}
            className="px-3 py-2 text-sm font-medium bg-gray-800 text-gray-300 rounded hover:bg-gray-700 flex items-center gap-1.5 transition-colors disabled:opacity-50"
            title="Refresh recovery state"
          >
            <RefreshCw className={`h-4 w-4 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </button>
          <button
            onClick={handleRotateBundles}
            disabled={rotating || bundles.length === 0}
            className="px-3 py-2 text-sm font-medium bg-gray-800 text-gray-300 border border-gray-700 rounded hover:bg-gray-700 flex items-center gap-1.5 transition-colors disabled:opacity-50"
          >
            <RotateCcw className={`h-4 w-4 ${rotating ? 'animate-spin text-amber-400' : ''}`} />
            Rotate & Prune
          </button>
          <button
            onClick={handleCreateBundle}
            disabled={creatingBundle}
            className="px-4 py-2 text-sm font-medium bg-primary text-primary-foreground rounded hover:bg-primary/90 flex items-center gap-2 transition-colors disabled:opacity-50 shadow-sm"
          >
            <Archive className={`h-4 w-4 ${creatingBundle ? 'animate-spin' : ''}`} />
            {creatingBundle ? 'Creating Snapshot...' : 'Create DR Bundle'}
          </button>
        </div>
      </div>

      {/* Alert Banners */}
      {error && (
        <div className="bg-red-950/50 border border-red-800 text-red-200 px-4 py-3 rounded text-sm flex items-start gap-3">
          <XCircle className="h-5 w-5 text-red-400 shrink-0 mt-0.5" />
          <div className="flex-1">{error}</div>
          <button onClick={() => setError(null)} className="text-red-400 hover:text-red-200 text-xs">
            Dismiss
          </button>
        </div>
      )}

      {successMsg && (
        <div className="bg-emerald-950/50 border border-emerald-800 text-emerald-200 px-4 py-3 rounded text-sm flex items-start gap-3">
          <CheckCircle className="h-5 w-5 text-emerald-400 shrink-0 mt-0.5" />
          <div className="flex-1">{successMsg}</div>
          <button onClick={() => setSuccessMsg(null)} className="text-emerald-400 hover:text-emerald-200 text-xs">
            Dismiss
          </button>
        </div>
      )}

      {/* Readiness Summary Card */}
      <div className="bg-gray-900 border border-gray-800 rounded-lg p-6">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-gray-800">
          <div className="flex items-center gap-3">
            {statusSummary?.recovery_readiness === 'READY' ? (
              <div className="p-3 bg-emerald-950/60 border border-emerald-800/80 rounded-full text-emerald-400">
                <ShieldCheck className="h-7 w-7" />
              </div>
            ) : statusSummary?.recovery_readiness === 'ATTENTION_REQUIRED' ? (
              <div className="p-3 bg-amber-950/60 border border-amber-800/80 rounded-full text-amber-400">
                <AlertTriangle className="h-7 w-7" />
              </div>
            ) : (
              <div className="p-3 bg-red-950/60 border border-red-800/80 rounded-full text-red-400">
                <ShieldAlert className="h-7 w-7" />
              </div>
            )}
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-lg font-semibold text-white">Disaster Recovery Readiness:</h2>
                <span
                  className={`px-2.5 py-0.5 rounded text-xs font-bold uppercase tracking-wider ${
                    statusSummary?.recovery_readiness === 'READY'
                      ? 'bg-emerald-900/60 text-emerald-300 border border-emerald-700'
                      : statusSummary?.recovery_readiness === 'ATTENTION_REQUIRED'
                      ? 'bg-amber-900/60 text-amber-300 border border-amber-700'
                      : 'bg-red-900/60 text-red-300 border border-red-700'
                  }`}
                >
                  {statusSummary?.recovery_readiness || 'UNKNOWN'}
                </span>
              </div>
              <p className="text-xs text-gray-400 mt-1">
                {statusSummary?.recovery_readiness === 'READY'
                  ? 'All verification points passed and at least one verified bundle with a successful restore drill exists.'
                  : statusSummary?.recovery_readiness === 'ATTENTION_REQUIRED'
                  ? 'Backup bundles exist, but pending verification or isolated restore drill is recommended.'
                  : 'Degraded recovery posture. No healthy verified backups available or integrity anomalies detected.'}
              </p>
            </div>
          </div>
          <div className="text-right">
            <span className="text-xs text-gray-500 block">Total DR Storage</span>
            <span className="text-xl font-mono font-bold text-gray-200">
              {formatBytes(statusSummary?.total_storage_bytes || 0)}
            </span>
          </div>
        </div>

        {/* 4 Telemetry Metrics */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mt-5">
          <div className="bg-gray-950/60 border border-gray-800 rounded p-4">
            <span className="text-xs font-medium text-gray-400 uppercase tracking-wide">Available Bundles</span>
            <div className="text-2xl font-bold text-white mt-1">
              {statusSummary?.total_bundles || 0}
              {statusSummary?.incomplete_bundles ? (
                <span className="text-xs font-normal text-amber-400 ml-2">
                  ({statusSummary.incomplete_bundles} incomplete cleaned)
                </span>
              ) : null}
            </div>
            <span className="text-xs text-gray-500 mt-1 block">Point-in-time snapshots</span>
          </div>

          <div className="bg-gray-950/60 border border-gray-800 rounded p-4">
            <span className="text-xs font-medium text-gray-400 uppercase tracking-wide">Last Known Good</span>
            <div className="text-sm font-mono font-semibold text-purple-400 mt-1 truncate" title={statusSummary?.last_known_good_bundle_id || 'None'}>
              {statusSummary?.last_known_good_bundle_id || 'None'}
            </div>
            <span className="text-xs text-gray-500 mt-1 block">Protected from rotation</span>
          </div>

          <div className="bg-gray-950/60 border border-gray-800 rounded p-4">
            <span className="text-xs font-medium text-gray-400 uppercase tracking-wide">Last 7-Point Verification</span>
            <div className="text-sm font-medium text-white mt-1">
              {statusSummary?.last_verified_at
                ? new Date(statusSummary.last_verified_at).toLocaleString()
                : 'Never verified'}
            </div>
            <span className="text-xs text-gray-500 mt-1 block">
              {statusSummary?.last_verified_bundle_id ? `Bundle: ${statusSummary.last_verified_bundle_id}` : 'Pending verification'}
            </span>
          </div>

          <div className="bg-gray-950/60 border border-gray-800 rounded p-4">
            <span className="text-xs font-medium text-gray-400 uppercase tracking-wide">Last Restore Drill</span>
            <div className="text-sm font-medium text-white mt-1">
              {statusSummary?.last_restore_drill_at
                ? new Date(statusSummary.last_restore_drill_at).toLocaleString()
                : 'Never executed'}
            </div>
            <span className="text-xs text-gray-500 mt-1 block">
              {statusSummary?.last_restore_drill_bundle_id ? `Bundle: ${statusSummary.last_restore_drill_bundle_id}` : 'Isolated sandbox validation'}
            </span>
          </div>
        </div>
      </div>

      {/* Bundles Table */}
      <div className="bg-gray-900 border border-gray-800 rounded-lg overflow-hidden">
        <div className="px-6 py-4 border-b border-gray-800 flex items-center justify-between">
          <h3 className="text-base font-semibold text-white flex items-center gap-2">
            <Archive className="h-4 w-4 text-primary" />
            Disaster Recovery Bundles
          </h3>
          <span className="text-xs text-gray-500">
            {bundles.length} bundle{bundles.length !== 1 ? 's' : ''} cataloged
          </span>
        </div>

        {bundles.length === 0 ? (
          <div className="text-center py-12 px-4">
            <Archive className="h-10 w-10 text-gray-600 mx-auto mb-3" />
            <p className="text-sm text-gray-400">No disaster recovery bundles found.</p>
            <p className="text-xs text-gray-500 mt-1">Create an atomic point-in-time snapshot to ensure business continuity.</p>
            <button
              onClick={handleCreateBundle}
              disabled={creatingBundle}
              className="mt-4 px-4 py-2 text-xs font-semibold bg-primary text-primary-foreground rounded hover:bg-primary/90 transition-colors"
            >
              Create First DR Bundle
            </button>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm text-gray-300">
              <thead className="bg-gray-950 text-gray-400 text-xs uppercase tracking-wider border-b border-gray-800">
                <tr>
                  <th className="py-3 px-4">Bundle ID & Manifest</th>
                  <th className="py-3 px-4">Status & Health</th>
                  <th className="py-3 px-4">Created</th>
                  <th className="py-3 px-4">Storage Size</th>
                  <th className="py-3 px-4">Tables & Records</th>
                  <th className="py-3 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-800">
                {bundles.map((bundle) => {
                  const isFailed = bundle.status === 'FAILED' || bundle.status === 'CORRUPTED';

                  return (
                    <tr key={bundle.bundle_id} className="hover:bg-gray-800/40 transition-colors">
                      <td className="py-3.5 px-4 font-mono text-xs">
                        <div className="font-semibold text-white flex items-center gap-2">
                          {bundle.bundle_id}
                          {bundle.is_last_known_good && (
                            <span className="px-2 py-0.5 text-[10px] font-sans font-bold bg-purple-950 text-purple-300 border border-purple-800 rounded">
                              LKG
                            </span>
                          )}
                        </div>
                        <div className="text-[11px] text-gray-500 truncate max-w-xs mt-0.5" title={bundle.manifest_sha256}>
                          sha256:{bundle.manifest_sha256.substring(0, 16)}...
                        </div>
                      </td>

                      <td className="py-3.5 px-4">
                        <span
                          className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded text-xs font-medium ${
                            bundle.status === 'RESTORE_VERIFIED'
                              ? 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                              : bundle.status === 'VERIFIED'
                              ? 'bg-blue-950 text-blue-300 border border-blue-800'
                              : isFailed
                              ? 'bg-red-950 text-red-300 border border-red-800'
                              : 'bg-amber-950 text-amber-300 border border-amber-800'
                          }`}
                        >
                          {bundle.status === 'RESTORE_VERIFIED' ? (
                            <ShieldCheck className="h-3.5 w-3.5 text-emerald-400" />
                          ) : bundle.status === 'VERIFIED' ? (
                            <Check className="h-3.5 w-3.5 text-blue-400" />
                          ) : isFailed ? (
                            <XCircle className="h-3.5 w-3.5 text-red-400" />
                          ) : (
                            <HelpCircle className="h-3.5 w-3.5 text-amber-400" />
                          )}
                          {bundle.status}
                        </span>
                        {bundle.last_verified_at && (
                          <div className="text-[11px] text-gray-500 mt-1">
                            Verified {new Date(bundle.last_verified_at).toLocaleDateString()}
                          </div>
                        )}
                      </td>

                      <td className="py-3.5 px-4 text-xs text-gray-400 whitespace-nowrap">
                        {new Date(bundle.created_at).toLocaleString()}
                      </td>

                      <td className="py-3.5 px-4 text-xs font-mono text-gray-300">
                        {formatBytes(bundle.size_bytes)}
                      </td>

                      <td className="py-3.5 px-4 text-xs text-gray-400">
                        {bundle.table_counts ? (
                          <div>
                            <span className="text-gray-200 font-medium">
                              {Object.keys(bundle.table_counts).length} tables
                            </span>
                            <span className="text-gray-500 text-[11px] block">
                              {Object.values(bundle.table_counts).reduce((a, b) => a + b, 0)} total rows
                            </span>
                          </div>
                        ) : (
                          <span className="text-gray-500 italic">Not indexed</span>
                        )}
                      </td>

                      <td className="py-3.5 px-4 text-right space-x-2 whitespace-nowrap">
                        <button
                          onClick={() => handleVerifyBundle(bundle.bundle_id)}
                          disabled={verifyingBundleId === bundle.bundle_id}
                          className="px-2.5 py-1 text-xs font-medium bg-gray-800 text-gray-200 rounded hover:bg-gray-700 transition-colors disabled:opacity-50"
                          title="Run 7-point independent verification (checksums, SQLite PRAGMA integrity, foreign keys, schema, and audit chain)"
                        >
                          {verifyingBundleId === bundle.bundle_id ? (
                            <RefreshCw className="h-3 w-3 animate-spin inline mr-1" />
                          ) : (
                            <FileCheck className="h-3 w-3 inline mr-1 text-blue-400" />
                          )}
                          Verify
                        </button>

                        <button
                          onClick={() => handleRestoreDrill(bundle.bundle_id)}
                          disabled={drillingBundleId === bundle.bundle_id}
                          className="px-2.5 py-1 text-xs font-medium bg-gray-800 text-gray-200 rounded hover:bg-gray-700 transition-colors disabled:opacity-50"
                          title="Execute non-destructive restore drill into isolated sandbox"
                        >
                          {drillingBundleId === bundle.bundle_id ? (
                            <RefreshCw className="h-3 w-3 animate-spin inline mr-1" />
                          ) : (
                            <Play className="h-3 w-3 inline mr-1 text-emerald-400" />
                          )}
                          Restore Drill
                        </button>

                        <button
                          onClick={() => setSelectedBundle(bundle)}
                          className="px-2.5 py-1 text-xs font-medium bg-gray-800 text-gray-300 rounded hover:bg-gray-700 transition-colors"
                        >
                          Details
                        </button>

                        <button
                          onClick={() => {
                            setLiveRestoreTarget(bundle);
                            setConfirmationPhraseInput('');
                          }}
                          className="px-2.5 py-1 text-xs font-medium bg-red-950/60 text-red-300 border border-red-800/80 rounded hover:bg-red-900/80 transition-colors"
                          title="Emergency Live Restore (Governed Admin action with automatic rollback)"
                        >
                          Live Restore
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Bundle Details Modal */}
      {selectedBundle && (
        <div className="fixed inset-0 z-50 bg-black/75 flex items-center justify-center p-4">
          <div className="bg-gray-900 border border-gray-800 rounded-lg max-w-2xl w-full p-6 space-y-4 max-h-[90vh] overflow-y-auto">
            <div className="flex items-center justify-between border-b border-gray-800 pb-3">
              <h3 className="text-lg font-bold text-white flex items-center gap-2">
                <Archive className="h-5 w-5 text-primary" />
                Bundle Details: {selectedBundle.bundle_id}
              </h3>
              <button
                onClick={() => setSelectedBundle(null)}
                className="text-gray-400 hover:text-white text-sm"
              >
                ✕
              </button>
            </div>

            <div className="grid grid-cols-2 gap-4 text-xs">
              <div>
                <span className="text-gray-500 block">Created At</span>
                <span className="text-gray-200 font-medium">{new Date(selectedBundle.created_at).toLocaleString()}</span>
              </div>
              <div>
                <span className="text-gray-500 block">Storage Size</span>
                <span className="text-gray-200 font-medium">{formatBytes(selectedBundle.size_bytes)}</span>
              </div>
              <div className="col-span-2">
                <span className="text-gray-500 block">Bundle Path</span>
                <span className="text-gray-300 font-mono text-[11px] break-all">{selectedBundle.bundle_path}</span>
              </div>
              <div className="col-span-2">
                <span className="text-gray-500 block">Manifest SHA-256</span>
                <span className="text-gray-300 font-mono text-[11px] break-all">{selectedBundle.manifest_sha256}</span>
              </div>
              <div className="col-span-2">
                <span className="text-gray-500 block">Database SHA-256</span>
                <span className="text-gray-300 font-mono text-[11px] break-all">{selectedBundle.database_sha256}</span>
              </div>
            </div>

            {selectedBundle.verification_report && (
              <div className="border border-gray-800 rounded p-4 bg-gray-950/60 space-y-3">
                <h4 className="text-xs font-semibold text-gray-200 uppercase tracking-wider flex items-center gap-1.5">
                  <FileCheck className="h-4 w-4 text-blue-400" />
                  Independent 7-Point Verification Checkpoints
                </h4>
                <div className="space-y-2">
                  {Object.entries(selectedBundle.verification_report.checks || {}).map(([key, check]: [string, any]) => (
                    <div key={key} className="flex items-start justify-between text-xs py-1 border-b border-gray-900">
                      <div className="space-y-0.5">
                        <span className="font-mono text-gray-300 font-medium">{key}</span>
                        <p className="text-[11px] text-gray-500">{check.detail}</p>
                      </div>
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                          check.passed ? 'bg-emerald-950 text-emerald-400 border border-emerald-800' : 'bg-red-950 text-red-400 border border-red-800'
                        }`}
                      >
                        {check.passed ? 'PASSED' : 'FAILED'}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {selectedBundle.table_counts && (
              <div className="border border-gray-800 rounded p-4 bg-gray-950/60 space-y-2">
                <h4 className="text-xs font-semibold text-gray-200 uppercase tracking-wider flex items-center gap-1.5">
                  <Layers className="h-4 w-4 text-purple-400" />
                  Database Table Catalog
                </h4>
                <div className="grid grid-cols-2 sm:grid-cols-3 gap-2 text-xs font-mono">
                  {Object.entries(selectedBundle.table_counts).map(([tbl, count]) => (
                    <div key={tbl} className="bg-gray-900/80 p-2 rounded border border-gray-800 flex justify-between">
                      <span className="text-gray-400 truncate" title={tbl}>{tbl}</span>
                      <span className="text-white font-bold ml-2">{count}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            <div className="flex justify-end pt-2">
              <button
                onClick={() => setSelectedBundle(null)}
                className="px-4 py-2 text-xs font-medium bg-gray-800 text-gray-300 rounded hover:bg-gray-700"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Isolated Restore Drill Result Modal */}
      {activeDrillResult && (
        <div className="fixed inset-0 z-50 bg-black/75 flex items-center justify-center p-4">
          <div className="bg-gray-900 border border-gray-800 rounded-lg max-w-xl w-full p-6 space-y-4">
            <div className="flex items-center justify-between border-b border-gray-800 pb-3">
              <h3 className="text-lg font-bold text-white flex items-center gap-2">
                <Play className="h-5 w-5 text-emerald-400" />
                Isolated Restore Drill Execution Report
              </h3>
              <button
                onClick={() => setActiveDrillResult(null)}
                className="text-gray-400 hover:text-white text-sm"
              >
                ✕
              </button>
            </div>

            <div className="space-y-3 text-xs">
              <div className="bg-emerald-950/40 border border-emerald-800/80 rounded p-3 text-emerald-200">
                <div className="font-semibold">{activeDrillResult.message}</div>
                <div className="text-[11px] text-emerald-400 mt-1">
                  Drill completed in {activeDrillResult.duration_ms.toFixed(1)} ms. Active database was untouched.
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3 bg-gray-950/60 p-3 rounded border border-gray-800">
                <div>
                  <span className="text-gray-500 block">Tables Restored & Verified</span>
                  <span className="text-white font-bold text-sm">{activeDrillResult.tables_verified}</span>
                </div>
                <div>
                  <span className="text-gray-500 block">Audit Events Verified</span>
                  <span className="text-white font-bold text-sm">{activeDrillResult.audit_events_count}</span>
                </div>
                <div>
                  <span className="text-gray-500 block">Jobs Reconciled</span>
                  <span className="text-white font-bold text-sm">{activeDrillResult.jobs_reconciled.length}</span>
                </div>
                <div>
                  <span className="text-gray-500 block">Sandbox Automatic Cleanup</span>
                  <span className="text-emerald-400 font-bold text-sm">
                    {activeDrillResult.sandbox_cleaned ? 'CLEANED' : 'PRESERVED'}
                  </span>
                </div>
              </div>

              {activeDrillResult.jobs_reconciled.length > 0 && (
                <div className="space-y-1.5">
                  <span className="text-gray-400 font-medium">Reconciled In-Flight Executions:</span>
                  <div className="space-y-1 max-h-36 overflow-y-auto">
                    {activeDrillResult.jobs_reconciled.map((job) => (
                      <div key={job.job_id} className="p-2 bg-gray-950 rounded border border-gray-800 flex justify-between font-mono text-[11px]">
                        <span className="text-gray-300">{job.job_id}</span>
                        <span className="text-amber-400 font-semibold">{job.prior_status} → {job.new_status}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>

            <div className="flex justify-end pt-2">
              <button
                onClick={() => setActiveDrillResult(null)}
                className="px-4 py-2 text-xs font-medium bg-gray-800 text-gray-300 rounded hover:bg-gray-700"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Emergency Live Restore Modal */}
      {liveRestoreTarget && (
        <div className="fixed inset-0 z-50 bg-black/80 flex items-center justify-center p-4">
          <div className="bg-gray-900 border border-red-800/80 rounded-lg max-w-xl w-full p-6 space-y-4 shadow-2xl">
            <div className="flex items-center gap-3 border-b border-red-900/50 pb-3 text-red-400">
              <ShieldAlert className="h-6 w-6 shrink-0" />
              <div>
                <h3 className="text-lg font-bold text-white">Emergency Live Disaster Restore</h3>
                <span className="text-xs text-red-400">Admin Governance Gate & Non-Destructive Rollback Protection</span>
              </div>
            </div>

            <div className="space-y-3 text-xs text-gray-300">
              <div className="p-3 bg-red-950/60 border border-red-800/80 rounded space-y-1">
                <p className="font-semibold text-red-200">
                  CRITICAL: You are about to restore bundle {liveRestoreTarget.bundle_id} into the active live database.
                </p>
                <p className="text-red-300/80 text-[11px]">
                  Before swapping files, the system will automatically create a pre-restore rollback snapshot. If any post-swap integrity check fails, the live database will be immediately reverted.
                </p>
              </div>

              <div className="space-y-1.5">
                <label className="text-gray-300 font-medium">
                  To confirm, type the exact phrase below:
                </label>
                <div className="p-2 bg-gray-950 border border-gray-800 rounded font-mono text-xs text-amber-300 select-all">
                  {requiredPhrase}
                </div>
                <input
                  type="text"
                  value={confirmationPhraseInput}
                  onChange={(e) => setConfirmationPhraseInput(e.target.value)}
                  placeholder="Paste or type confirmation phrase here..."
                  className="w-full bg-gray-950 border border-gray-800 rounded px-3 py-2 text-white font-mono text-xs focus:outline-none focus:border-red-500"
                />
              </div>
            </div>

            <div className="flex justify-end gap-3 pt-3 border-t border-gray-800">
              <button
                onClick={() => {
                  setLiveRestoreTarget(null);
                  setConfirmationPhraseInput('');
                }}
                disabled={restoringLive}
                className="px-4 py-2 text-xs font-medium bg-gray-800 text-gray-300 rounded hover:bg-gray-700 transition-colors disabled:opacity-50"
              >
                Cancel
              </button>
              <button
                onClick={handleLiveRestore}
                disabled={!isPhraseValid || restoringLive}
                className="px-4 py-2 text-xs font-bold bg-red-600 text-white rounded hover:bg-red-500 transition-colors disabled:opacity-40 disabled:cursor-not-allowed flex items-center gap-2"
              >
                {restoringLive ? (
                  <>
                    <RefreshCw className="h-3.5 w-3.5 animate-spin" />
                    Executing Live Restore & Verification...
                  </>
                ) : (
                  <>
                    <ShieldAlert className="h-3.5 w-3.5" />
                    Execute Governed Live Restore
                  </>
                )}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
