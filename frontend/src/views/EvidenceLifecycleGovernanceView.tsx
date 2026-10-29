import React, { useState, useEffect } from 'react';
import { api } from '../services/api';
import type {
  RetentionPolicyModel,
  LegalHoldModel,
  DeletionTombstoneModel,
  RetentionPreviewReport,
  LegalHoldCreate,
} from '../types';

export const EvidenceLifecycleGovernanceView: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'policies' | 'preview' | 'holds' | 'tombstones'>('policies');
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  const [policies, setPolicies] = useState<RetentionPolicyModel[]>([]);
  const [holds, setHolds] = useState<LegalHoldModel[]>([]);
  const [preview, setPreview] = useState<RetentionPreviewReport | null>(null);
  const [tombstones, setTombstones] = useState<DeletionTombstoneModel[]>([]);

  // New Hold Form
  const [newHold, setNewHold] = useState<LegalHoldCreate>({
    hold_type: 'INVESTIGATION_HOLD',
    target_scope: 'EVIDENCE',
    target_id: '',
    reason: '',
  });

  const fetchData = async () => {
    setLoading(true);
    setError(null);
    try {
      const [pList, hList, tList] = await Promise.all([
        api.getRetentionPolicies(),
        api.getLegalHolds(),
        api.getDeletionTombstones(),
      ]);
      setPolicies(pList);
      setHolds(hList);
      setTombstones(tList);
    } catch (err: any) {
      setError(err?.message || 'Failed loading lifecycle telemetry');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  const handleFetchPreview = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await api.getRetentionPreview();
      setPreview(res);
      setSuccessMsg(`Generated preview (${res.total_scanned_records} scanned, ${res.eligible_records_count} eligible for action)`);
    } catch (err: any) {
      setError(err?.message || 'Failed generating retention preview');
    } finally {
      setLoading(false);
    }
  };

  const handleExecuteRetention = async () => {
    if (!preview) return;
    if (!window.confirm('Execute retention actions on all eligible records? Deletions are irreversible and generate deletion tombstones.')) {
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const res = await api.executeRetention({
        preview_id: preview.preview_id,
        dry_run_hash: preview.dry_run_hash,
        confirmed_by_lead: true,
      });
      setSuccessMsg(`Executed retention! Deleted ${res.deleted_count} records, created ${res.tombstones_created_count} suppression tombstones.`);
      await fetchData();
      await handleFetchPreview();
    } catch (err: any) {
      setError(err?.message || 'Failed executing retention policy');
    } finally {
      setLoading(false);
    }
  };

  const handleCreateHold = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newHold.target_id || !newHold.reason) {
      setError('Target ID and reason are required');
      return;
    }
    setLoading(true);
    setError(null);
    try {
      await api.createLegalHold(newHold);
      setSuccessMsg(`Legal hold placed successfully on ${newHold.target_scope} ${newHold.target_id}`);
      setNewHold({ hold_type: 'INVESTIGATION_HOLD', target_scope: 'EVIDENCE', target_id: '', reason: '' });
      const hList = await api.getLegalHolds();
      setHolds(hList);
    } catch (err: any) {
      setError(err?.message || 'Failed placing legal hold');
    } finally {
      setLoading(false);
    }
  };

  const handleReleaseHold = async (holdId: string) => {
    setLoading(true);
    setError(null);
    try {
      await api.releaseLegalHold(holdId);
      setSuccessMsg(`Hold ${holdId} released.`);
      const hList = await api.getLegalHolds();
      setHolds(hList);
    } catch (err: any) {
      setError(err?.message || 'Failed releasing hold');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Title */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight">
            Evidence Lifecycle Governance &amp; Verifiable Retention
          </h1>
          <p className="text-sm text-gray-400 mt-1">
            Data classification, retention policy enforcement, legal holds, and cryptographic deletion suppression tombstones.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={fetchData}
            disabled={loading}
            className="px-4 py-2 bg-gray-800 hover:bg-gray-700 text-gray-200 text-sm font-medium rounded-lg border border-gray-700 transition"
          >
            {loading ? 'Refreshing...' : 'Refresh Telemetry'}
          </button>
        </div>
      </div>

      {error && (
        <div className="p-4 bg-red-950/40 border border-red-800 rounded-lg text-red-300 text-sm">
          {error}
        </div>
      )}

      {successMsg && (
        <div className="p-4 bg-emerald-950/40 border border-emerald-800 rounded-lg text-emerald-300 text-sm">
          {successMsg}
        </div>
      )}

      {/* Tabs */}
      <div className="flex border-b border-gray-800 space-x-6">
        <button
          onClick={() => setActiveTab('policies')}
          className={`pb-3 text-sm font-semibold transition border-b-2 ${
            activeTab === 'policies'
              ? 'border-indigo-500 text-indigo-400'
              : 'border-transparent text-gray-400 hover:text-gray-200'
          }`}
        >
          Retention Policies ({policies.length})
        </button>
        <button
          onClick={() => {
            setActiveTab('preview');
            if (!preview) handleFetchPreview();
          }}
          className={`pb-3 text-sm font-semibold transition border-b-2 ${
            activeTab === 'preview'
              ? 'border-indigo-500 text-indigo-400'
              : 'border-transparent text-gray-400 hover:text-gray-200'
          }`}
        >
          Retention Preview &amp; Execution
        </button>
        <button
          onClick={() => setActiveTab('holds')}
          className={`pb-3 text-sm font-semibold transition border-b-2 ${
            activeTab === 'holds'
              ? 'border-indigo-500 text-indigo-400'
              : 'border-transparent text-gray-400 hover:text-gray-200'
          }`}
        >
          Legal &amp; Investigation Holds ({holds.filter((h) => h.status === 'ACTIVE').length})
        </button>
        <button
          onClick={() => setActiveTab('tombstones')}
          className={`pb-3 text-sm font-semibold transition border-b-2 ${
            activeTab === 'tombstones'
              ? 'border-indigo-500 text-indigo-400'
              : 'border-transparent text-gray-400 hover:text-gray-200'
          }`}
        >
          Suppression Tombstones ({tombstones.length})
        </button>
      </div>

      {/* Tab 1: Policies */}
      {activeTab === 'policies' && (
        <div className="space-y-6">
          <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
            <div className="p-4 border-b border-gray-800">
              <h3 className="text-sm font-semibold text-gray-200">Authoritative Data Classification Policies</h3>
              <p className="text-xs text-gray-400 mt-1">
                Enforces retention windows and verifiable removal rules by classification family.
              </p>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-sm text-gray-300">
                <thead className="bg-gray-950/60 text-xs uppercase text-gray-400 border-b border-gray-800">
                  <tr>
                    <th className="px-4 py-3">Policy ID</th>
                    <th className="px-4 py-3">Classification</th>
                    <th className="px-4 py-3">Retention Window</th>
                    <th className="px-4 py-3">Action</th>
                    <th className="px-4 py-3">Approval</th>
                    <th className="px-4 py-3">Description</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-800">
                  {policies.map((p) => (
                    <tr key={p.policy_id} className="hover:bg-gray-800/40 transition">
                      <td className="px-4 py-3 font-mono text-xs text-indigo-400 font-semibold">{p.policy_id}</td>
                      <td className="px-4 py-3 text-xs">
                        <span className="px-2 py-0.5 rounded bg-gray-800 text-gray-200 border border-gray-700">
                          {p.classification}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-xs font-semibold text-white">{p.retention_days} days</td>
                      <td className="px-4 py-3 text-xs">
                        <span
                          className={`px-2 py-0.5 rounded font-bold ${
                            p.action === 'DELETE'
                              ? 'bg-red-950 text-red-400 border border-red-800'
                              : p.action === 'REDACT'
                              ? 'bg-amber-950 text-amber-400 border border-amber-800'
                              : p.action === 'ARCHIVE'
                              ? 'bg-blue-950 text-blue-400 border border-blue-800'
                              : 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                          }`}
                        >
                          {p.action}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-xs text-gray-400">
                        {p.requires_approval ? 'Required (Lead)' : 'Automatic'}
                      </td>
                      <td className="px-4 py-3 text-xs text-gray-300">{p.description}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* Tab 2: Preview & Execution */}
      {activeTab === 'preview' && (
        <div className="space-y-6">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 bg-gray-900 border border-gray-800 rounded-xl p-4">
            <div>
              <h3 className="text-sm font-semibold text-white">Dry-Run Retention Preview</h3>
              <p className="text-xs text-gray-400 mt-1">
                Scans evidence records against active policies, legal holds, and downstream finding dependencies.
              </p>
            </div>
            <div className="flex items-center gap-3">
              <button
                onClick={handleFetchPreview}
                disabled={loading}
                className="px-3 py-1.5 bg-gray-800 hover:bg-gray-700 text-gray-200 text-xs font-medium rounded-lg border border-gray-700 transition"
              >
                Re-scan Records
              </button>
              {preview && preview.eligible_records_count > 0 && (
                <button
                  onClick={handleExecuteRetention}
                  disabled={loading}
                  className="px-3 py-1.5 bg-red-600 hover:bg-red-500 text-white text-xs font-medium rounded-lg transition"
                >
                  Execute Deletions ({preview.eligible_records_count})
                </button>
              )}
            </div>
          </div>

          {preview && (
            <>
              {/* Metrics */}
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
                <div className="bg-gray-900 border border-gray-800 rounded-xl p-4">
                  <div className="text-xs font-medium text-gray-400 uppercase">Scanned Records</div>
                  <div className="mt-2 text-2xl font-bold text-white">{preview.total_scanned_records}</div>
                  <div className="text-xs text-gray-500 mt-1">Total evidence items in catalog</div>
                </div>

                <div className="bg-gray-900 border border-gray-800 rounded-xl p-4">
                  <div className="text-xs font-medium text-gray-400 uppercase">Eligible for Action</div>
                  <div className="mt-2 text-2xl font-bold text-amber-400">{preview.eligible_records_count}</div>
                  <div className="text-xs text-gray-500 mt-1">Past retention expiration</div>
                </div>

                <div className="bg-gray-900 border border-gray-800 rounded-xl p-4">
                  <div className="text-xs font-medium text-gray-400 uppercase">Excluded by Hold</div>
                  <div className="mt-2 text-2xl font-bold text-indigo-400">{preview.excluded_by_hold_count}</div>
                  <div className="text-xs text-gray-500 mt-1">Active legal/investigation hold</div>
                </div>

                <div className="bg-gray-900 border border-gray-800 rounded-xl p-4">
                  <div className="text-xs font-medium text-gray-400 uppercase">Excluded by Deps</div>
                  <div className="mt-2 text-2xl font-bold text-emerald-400">{preview.excluded_by_dependency_count}</div>
                  <div className="text-xs text-gray-500 mt-1">Open/unresolved finding</div>
                </div>
              </div>

              {/* Table */}
              <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
                <div className="p-4 border-b border-gray-800 flex justify-between items-center">
                  <h3 className="text-sm font-semibold text-gray-200">
                    Preview Records Sample ({preview.preview_items.length})
                  </h3>
                  <div className="text-xs font-mono text-gray-500">
                    State Hash: {preview.dry_run_hash.slice(0, 16)}...
                  </div>
                </div>
                <div className="overflow-x-auto max-h-96">
                  <table className="w-full text-left text-sm text-gray-300">
                    <thead className="bg-gray-950/60 text-xs uppercase text-gray-400 border-b border-gray-800 sticky top-0">
                      <tr>
                        <th className="px-4 py-3">Record ID</th>
                        <th className="px-4 py-3">Classification</th>
                        <th className="px-4 py-3">Age</th>
                        <th className="px-4 py-3">Hold Status</th>
                        <th className="px-4 py-3">Dependency</th>
                        <th className="px-4 py-3">Action</th>
                        <th className="px-4 py-3">Eligible</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-gray-800">
                      {preview.preview_items.slice(0, 50).map((item) => (
                        <tr key={item.record_id} className="hover:bg-gray-800/40 transition">
                          <td className="px-4 py-2 font-mono text-xs text-gray-300">{item.record_id.slice(0, 12)}...</td>
                          <td className="px-4 py-2 text-xs text-indigo-300">{item.classification}</td>
                          <td className="px-4 py-2 text-xs text-gray-300">{item.age_days}d</td>
                          <td className="px-4 py-2 text-xs">
                            {item.is_held ? (
                              <span className="px-2 py-0.5 rounded bg-indigo-950 text-indigo-300 border border-indigo-800 font-bold">
                                HELD
                              </span>
                            ) : (
                              <span className="text-gray-500">No hold</span>
                            )}
                          </td>
                          <td className="px-4 py-2 text-xs">
                            {item.has_dependent_records ? (
                              <span className="text-amber-400">Active Finding</span>
                            ) : (
                              <span className="text-gray-500">None</span>
                            )}
                          </td>
                          <td className="px-4 py-2 text-xs font-bold text-gray-200">{item.recommended_action}</td>
                          <td className="px-4 py-2 text-xs">
                            <span
                              className={`px-2 py-0.5 rounded text-xs font-bold ${
                                item.eligible_for_execution
                                  ? 'bg-amber-950 text-amber-300 border border-amber-800'
                                  : 'bg-gray-800 text-gray-400'
                              }`}
                            >
                              {item.eligible_for_execution ? 'ELIGIBLE' : 'SKIPPED'}
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </>
          )}
        </div>
      )}

      {/* Tab 3: Legal Holds */}
      {activeTab === 'holds' && (
        <div className="space-y-6">
          {/* New Hold Form */}
          <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
            <h3 className="text-base font-semibold text-white">Place Binding Legal or Investigation Hold</h3>
            <p className="text-xs text-gray-400 mt-1 mb-4">
              Holds strictly prohibit deletion or redaction of the targeted entity, regardless of retention policy expiration.
            </p>
            <form onSubmit={handleCreateHold} className="grid grid-cols-1 md:grid-cols-4 gap-4">
              <div>
                <label className="text-xs text-gray-400 uppercase font-semibold">Hold Type</label>
                <select
                  value={newHold.hold_type}
                  onChange={(e) => setNewHold({ ...newHold, hold_type: e.target.value as any })}
                  className="mt-1 w-full bg-gray-950 border border-gray-800 rounded-lg px-3 py-2 text-sm text-gray-200"
                >
                  <option value="INVESTIGATION_HOLD">Investigation Hold</option>
                  <option value="LEGAL_HOLD">Legal Hold</option>
                  <option value="REGULATORY_HOLD">Regulatory Hold</option>
                </select>
              </div>

              <div>
                <label className="text-xs text-gray-400 uppercase font-semibold">Target Scope</label>
                <select
                  value={newHold.target_scope}
                  onChange={(e) => setNewHold({ ...newHold, target_scope: e.target.value })}
                  className="mt-1 w-full bg-gray-950 border border-gray-800 rounded-lg px-3 py-2 text-sm text-gray-200"
                >
                  <option value="EVIDENCE">Evidence ID</option>
                  <option value="FINDING">Finding ID</option>
                  <option value="PROJECT">Project ID</option>
                </select>
              </div>

              <div>
                <label className="text-xs text-gray-400 uppercase font-semibold">Target ID</label>
                <input
                  type="text"
                  placeholder="UUID or Target Identifier"
                  value={newHold.target_id}
                  onChange={(e) => setNewHold({ ...newHold, target_id: e.target.value })}
                  className="mt-1 w-full bg-gray-950 border border-gray-800 rounded-lg px-3 py-2 text-sm text-gray-200"
                />
              </div>

              <div>
                <label className="text-xs text-gray-400 uppercase font-semibold">Reason</label>
                <div className="flex gap-2 mt-1">
                  <input
                    type="text"
                    placeholder="e.g. Incident IR-2026-09"
                    value={newHold.reason}
                    onChange={(e) => setNewHold({ ...newHold, reason: e.target.value })}
                    className="w-full bg-gray-950 border border-gray-800 rounded-lg px-3 py-2 text-sm text-gray-200"
                  />
                  <button
                    type="submit"
                    disabled={loading}
                    className="px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold rounded-lg transition"
                  >
                    Place
                  </button>
                </div>
              </div>
            </form>
          </div>

          {/* Holds Table */}
          <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
            <div className="p-4 border-b border-gray-800">
              <h3 className="text-sm font-semibold text-gray-200">Active and Historic Holds ({holds.length})</h3>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-sm text-gray-300">
                <thead className="bg-gray-950/60 text-xs uppercase text-gray-400 border-b border-gray-800">
                  <tr>
                    <th className="px-4 py-3">Hold ID</th>
                    <th className="px-4 py-3">Type</th>
                    <th className="px-4 py-3">Target Scope</th>
                    <th className="px-4 py-3">Target ID</th>
                    <th className="px-4 py-3">Reason</th>
                    <th className="px-4 py-3">Status</th>
                    <th className="px-4 py-3">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-800">
                  {holds.map((h) => (
                    <tr key={h.hold_id} className="hover:bg-gray-800/40 transition">
                      <td className="px-4 py-3 font-mono text-xs text-indigo-400 font-semibold">{h.hold_id}</td>
                      <td className="px-4 py-3 text-xs">{h.hold_type}</td>
                      <td className="px-4 py-3 text-xs font-semibold">{h.target_scope}</td>
                      <td className="px-4 py-3 font-mono text-xs text-gray-300">{h.target_id}</td>
                      <td className="px-4 py-3 text-xs text-gray-300">{h.reason}</td>
                      <td className="px-4 py-3 text-xs">
                        <span
                          className={`px-2 py-0.5 rounded text-xs font-bold ${
                            h.status === 'ACTIVE'
                              ? 'bg-amber-950 text-amber-400 border border-amber-800'
                              : 'bg-gray-800 text-gray-400'
                          }`}
                        >
                          {h.status}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-xs">
                        {h.status === 'ACTIVE' && (
                          <button
                            onClick={() => handleReleaseHold(h.hold_id)}
                            disabled={loading}
                            className="text-xs text-red-400 hover:text-red-300 font-semibold"
                          >
                            Release
                          </button>
                        )}
                      </td>
                    </tr>
                  ))}
                  {holds.length === 0 && (
                    <tr>
                      <td colSpan={7} className="px-4 py-8 text-center text-xs text-gray-500">
                        No legal or investigation holds active.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* Tab 4: Tombstones */}
      {activeTab === 'tombstones' && (
        <div className="space-y-6">
          <div className="p-4 bg-indigo-950/20 border border-indigo-900/60 rounded-xl text-xs text-indigo-300">
            <span className="font-semibold text-indigo-200">Cryptographic Deletion Suppression Ledger:</span>{' '}
            When evidence records are permanently deleted under policy, an immutable tombstone is recorded with its
            original SHA-256 digest and HMAC signature. If a historical SQLite snapshot or backup is restored, the
            suppression ledger prevents accidental resurrection of deleted records.
          </div>

          <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
            <div className="p-4 border-b border-gray-800">
              <h3 className="text-sm font-semibold text-gray-200">Suppression Tombstones ({tombstones.length})</h3>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-sm text-gray-300">
                <thead className="bg-gray-950/60 text-xs uppercase text-gray-400 border-b border-gray-800">
                  <tr>
                    <th className="px-4 py-3">Tombstone ID</th>
                    <th className="px-4 py-3">Evidence ID</th>
                    <th className="px-4 py-3">Original SHA-256</th>
                    <th className="px-4 py-3">Policy ID</th>
                    <th className="px-4 py-3">Deleted At</th>
                    <th className="px-4 py-3">HMAC Digest</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-800">
                  {tombstones.map((t) => (
                    <tr key={t.tombstone_id} className="hover:bg-gray-800/40 transition">
                      <td className="px-4 py-3 font-mono text-xs text-indigo-400 font-semibold">{t.tombstone_id}</td>
                      <td className="px-4 py-3 font-mono text-xs text-gray-300">{t.evidence_id.slice(0, 16)}...</td>
                      <td className="px-4 py-3 font-mono text-xs text-emerald-400">{t.original_sha256_hash.slice(0, 16)}...</td>
                      <td className="px-4 py-3 text-xs text-gray-400">{t.policy_id}</td>
                      <td className="px-4 py-3 text-xs text-gray-400">{new Date(t.deleted_at).toLocaleString()}</td>
                      <td className="px-4 py-3 font-mono text-xs text-gray-500">{t.tombstone_digest.slice(0, 16)}...</td>
                    </tr>
                  ))}
                  {tombstones.length === 0 && (
                    <tr>
                      <td colSpan={6} className="px-4 py-8 text-center text-xs text-gray-500">
                        No records have been deleted under lifecycle policy yet.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
