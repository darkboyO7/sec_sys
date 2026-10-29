import React, { useState, useEffect } from 'react';
import { api } from '../services/api';
import type {
  PreflightReport,
  RedactedConfigResponse,
  UpgradePrecheckResponse,
} from '../types';

export const DeploymentGovernanceView: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'preflight' | 'config' | 'upgrade'>('preflight');
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  const [preflight, setPreflight] = useState<PreflightReport | null>(null);
  const [config, setConfig] = useState<RedactedConfigResponse | null>(null);
  const [upgrade, setUpgrade] = useState<UpgradePrecheckResponse | null>(null);

  const fetchData = async () => {
    setLoading(true);
    setError(null);
    try {
      const [pRes, cRes, uRes] = await Promise.all([
        api.getPreflightReport(),
        api.getRedactedConfig(),
        api.checkUpgradeReadiness(),
      ]);
      setPreflight(pRes);
      setConfig(cRes);
      setUpgrade(uRes);
    } catch (err: any) {
      setError(err?.message || 'Failed loading deployment governance telemetry');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  const handleRefreshPreflight = async () => {
    try {
      setLoading(true);
      const res = await api.getPreflightReport();
      setPreflight(res);
    } catch (err: any) {
      setError(err?.message || 'Failed refreshing preflight report');
    } finally {
      setLoading(false);
    }
  };

  const handleCheckUpgrade = async () => {
    try {
      setLoading(true);
      const res = await api.checkUpgradeReadiness();
      setUpgrade(res);
    } catch (err: any) {
      setError(err?.message || 'Failed checking upgrade readiness');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Title & Actions */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight">
            Deployment &amp; Configuration Governance
          </h1>
          <p className="text-sm text-gray-400 mt-1">
            Windows-first startup preflight validation, redacted configuration audit, and safe schema upgrade governance.
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

      {/* Tabs */}
      <div className="flex border-b border-gray-800 space-x-6">
        <button
          onClick={() => setActiveTab('preflight')}
          className={`pb-3 text-sm font-semibold transition border-b-2 ${
            activeTab === 'preflight'
              ? 'border-indigo-500 text-indigo-400'
              : 'border-transparent text-gray-400 hover:text-gray-200'
          }`}
        >
          Startup Preflight ({preflight ? preflight.status : 'Loading'})
        </button>
        <button
          onClick={() => setActiveTab('config')}
          className={`pb-3 text-sm font-semibold transition border-b-2 ${
            activeTab === 'config'
              ? 'border-indigo-500 text-indigo-400'
              : 'border-transparent text-gray-400 hover:text-gray-200'
          }`}
        >
          Redacted Configuration Audit
        </button>
        <button
          onClick={() => setActiveTab('upgrade')}
          className={`pb-3 text-sm font-semibold transition border-b-2 ${
            activeTab === 'upgrade'
              ? 'border-indigo-500 text-indigo-400'
              : 'border-transparent text-gray-400 hover:text-gray-200'
          }`}
        >
          Upgrade Readiness &amp; Migrations
        </button>
      </div>

      {/* Tab 1: Preflight Checks */}
      {activeTab === 'preflight' && (
        <div className="space-y-6">
          {preflight && (
            <>
              {/* Summary Cards */}
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
                <div className="bg-gray-900 border border-gray-800 rounded-xl p-4">
                  <div className="text-xs font-medium text-gray-400 uppercase tracking-wider">Overall Status</div>
                  <div className="mt-2 flex items-center gap-2">
                    <span
                      className={`px-2.5 py-1 text-xs font-bold rounded-full ${
                        preflight.status === 'PASSED'
                          ? 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                          : preflight.status === 'WARNINGS'
                          ? 'bg-amber-950 text-amber-400 border border-amber-800'
                          : 'bg-red-950 text-red-400 border border-red-800'
                      }`}
                    >
                      {preflight.status}
                    </span>
                  </div>
                  <div className="text-xs text-gray-500 mt-2">Mode: {preflight.environment}</div>
                </div>

                <div className="bg-gray-900 border border-gray-800 rounded-xl p-4">
                  <div className="text-xs font-medium text-gray-400 uppercase tracking-wider">Checks Passed</div>
                  <div className="mt-2 text-2xl font-bold text-emerald-400">
                    {preflight.passed_count} / {preflight.total_checks}
                  </div>
                  <div className="text-xs text-gray-500 mt-1">Passing all mandatory checks</div>
                </div>

                <div className="bg-gray-900 border border-gray-800 rounded-xl p-4">
                  <div className="text-xs font-medium text-gray-400 uppercase tracking-wider">Warnings</div>
                  <div className="mt-2 text-2xl font-bold text-amber-400">
                    {preflight.warning_count}
                  </div>
                  <div className="text-xs text-gray-500 mt-1">Non-fatal security recommendations</div>
                </div>

                <div className="bg-gray-900 border border-gray-800 rounded-xl p-4">
                  <div className="text-xs font-medium text-gray-400 uppercase tracking-wider">Fatal Failures</div>
                  <div className="mt-2 text-2xl font-bold text-red-400">
                    {preflight.failure_count}
                  </div>
                  <div className="text-xs text-gray-500 mt-1">Blocks production startup</div>
                </div>
              </div>

              {/* Table */}
              <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden">
                <div className="p-4 border-b border-gray-800 flex justify-between items-center">
                  <h3 className="text-sm font-semibold text-gray-200">
                    Preflight Health Invariants ({preflight.checks.length})
                  </h3>
                  <button
                    onClick={handleRefreshPreflight}
                    disabled={loading}
                    className="text-xs text-indigo-400 hover:text-indigo-300 font-medium"
                  >
                    Re-run Invariants
                  </button>
                </div>
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-sm text-gray-300">
                    <thead className="bg-gray-950/60 text-xs uppercase text-gray-400 border-b border-gray-800">
                      <tr>
                        <th className="px-4 py-3">Check Name</th>
                        <th className="px-4 py-3">Category</th>
                        <th className="px-4 py-3">Status</th>
                        <th className="px-4 py-3">Details</th>
                        <th className="px-4 py-3">Remediation</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-gray-800">
                      {preflight.checks.map((chk, idx) => (
                        <tr key={idx} className="hover:bg-gray-800/40 transition">
                          <td className="px-4 py-3 font-medium text-gray-200">{chk.name}</td>
                          <td className="px-4 py-3 text-xs text-gray-400">
                            <span className="px-2 py-0.5 rounded bg-gray-800 text-gray-300 border border-gray-700">
                              {chk.category}
                            </span>
                          </td>
                          <td className="px-4 py-3">
                            <span
                              className={`px-2 py-0.5 text-xs font-bold rounded ${
                                chk.status === 'PASS'
                                  ? 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                                  : chk.status === 'WARN'
                                  ? 'bg-amber-950 text-amber-400 border border-amber-800'
                                  : 'bg-red-950 text-red-400 border border-red-800'
                              }`}
                            >
                              {chk.status}
                            </span>
                          </td>
                          <td className="px-4 py-3 text-xs text-gray-300">{chk.details}</td>
                          <td className="px-4 py-3 text-xs text-amber-300/80">
                            {chk.remediation_advice || '—'}
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

      {/* Tab 2: Redacted Config Audit */}
      {activeTab === 'config' && (
        <div className="space-y-6">
          {config && (
            <div className="bg-gray-900 border border-gray-800 rounded-xl p-6 space-y-6">
              <div className="flex items-center justify-between border-b border-gray-800 pb-4">
                <div>
                  <h3 className="text-base font-semibold text-white">Active Non-Secret Runtime Parameters</h3>
                  <p className="text-xs text-gray-400 mt-1">
                    Effective settings with secrets, API keys, tokens, and database credentials safely masked.
                  </p>
                </div>
                <span className="px-2.5 py-1 text-xs font-bold rounded bg-indigo-950 text-indigo-300 border border-indigo-800">
                  {config.environment.toUpperCase()}
                </span>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div>
                  <label className="text-xs text-gray-400 uppercase font-semibold">Application Name</label>
                  <div className="mt-1 font-mono text-sm text-gray-200">{config.app_name}</div>
                </div>
                <div>
                  <label className="text-xs text-gray-400 uppercase font-semibold">Debug Mode</label>
                  <div className="mt-1 font-mono text-sm text-gray-200">{String(config.debug)}</div>
                </div>
                <div>
                  <label className="text-xs text-gray-400 uppercase font-semibold">Database Engine</label>
                  <div className="mt-1 font-mono text-sm text-gray-200">{config.database_type}</div>
                </div>
                <div>
                  <label className="text-xs text-gray-400 uppercase font-semibold">Redacted Connection String</label>
                  <div className="mt-1 font-mono text-xs text-emerald-400 bg-gray-950 p-2 rounded border border-gray-800">
                    {config.database_url_redacted}
                  </div>
                </div>
                <div>
                  <label className="text-xs text-gray-400 uppercase font-semibold">Allowed CORS Origins</label>
                  <div className="mt-1 font-mono text-xs text-indigo-300 bg-gray-950 p-2 rounded border border-gray-800">
                    {config.allowed_origins.join(', ')}
                  </div>
                </div>
                <div>
                  <label className="text-xs text-gray-400 uppercase font-semibold">Crypto Algorithm &amp; Token Expiry</label>
                  <div className="mt-1 font-mono text-sm text-gray-200">
                    {config.cryptographic_algorithm} (Expiry: {config.token_expiry_minutes} mins)
                  </div>
                </div>
                <div className="md:col-span-2">
                  <label className="text-xs text-gray-400 uppercase font-semibold">Designated Data Directories</label>
                  <div className="mt-2 space-y-2">
                    {Object.entries(config.data_directories).map(([key, p]) => (
                      <div key={key} className="flex justify-between items-center text-xs font-mono bg-gray-950 px-3 py-2 rounded border border-gray-800">
                        <span className="text-indigo-400 font-semibold">{key}:</span>
                        <span className="text-gray-300">{p}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Tab 3: Upgrade Readiness */}
      {activeTab === 'upgrade' && (
        <div className="space-y-6">
          {upgrade && (
            <div className="bg-gray-900 border border-gray-800 rounded-xl p-6 space-y-6">
              <div className="flex items-center justify-between border-b border-gray-800 pb-4">
                <div>
                  <h3 className="text-base font-semibold text-white">Database Migration &amp; Release Upgrade Readiness</h3>
                  <p className="text-xs text-gray-400 mt-1">
                    Verifies current schema revision against repository migration head before applying schema alterations.
                  </p>
                </div>
                <button
                  onClick={handleCheckUpgrade}
                  disabled={loading}
                  className="px-3 py-1.5 bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-medium rounded-lg transition"
                >
                  Re-evaluate Migration State
                </button>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div className="bg-gray-950 p-4 rounded-lg border border-gray-800">
                  <div className="text-xs text-gray-400">Current App Version</div>
                  <div className="text-xl font-bold text-white mt-1">{upgrade.current_version}</div>
                  <div className="text-xs text-gray-500 mt-1">Target: {upgrade.target_version}</div>
                </div>
                <div className="bg-gray-950 p-4 rounded-lg border border-gray-800">
                  <div className="text-xs text-gray-400">Alembic Schema Revision</div>
                  <div className="text-sm font-mono text-emerald-400 mt-1">{upgrade.current_db_version}</div>
                  <div className="text-xs text-gray-500 mt-1">Head: {upgrade.migration_head}</div>
                </div>
                <div className="bg-gray-950 p-4 rounded-lg border border-gray-800">
                  <div className="text-xs text-gray-400">Pending Migrations</div>
                  <div className="text-xl font-bold text-indigo-400 mt-1">{upgrade.pending_migrations_count}</div>
                  <div className="text-xs text-gray-500 mt-1">
                    {upgrade.backup_required ? 'Snapshot recommended' : 'Up to date'}
                  </div>
                </div>
              </div>

              <div className="p-4 bg-gray-950 rounded-lg border border-gray-800">
                <div className="text-xs font-semibold uppercase text-gray-400">Advisory Action</div>
                <div className="text-sm text-gray-200 mt-1">{upgrade.recommended_action}</div>
              </div>

              <div className="p-4 bg-indigo-950/20 border border-indigo-900/60 rounded-lg text-xs text-indigo-300 space-y-2">
                <div className="font-semibold text-indigo-200">Automated Operator CLI Commands (PowerShell):</div>
                <div className="font-mono bg-gray-950 p-2 rounded border border-gray-800">
                  # 1. First-time or idempotent environment setup:<br/>
                  .\.venv\Scripts\python.exe scripts\initialize_environment.py<br/><br/>
                  # 2. Safe application upgrade with pre-upgrade snapshot:<br/>
                  .\.venv\Scripts\python.exe scripts\upgrade_platform.py
                </div>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
