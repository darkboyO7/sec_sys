import React, { useState, useEffect } from 'react';
import { api } from '../services/api';
import type {
  Project,
  User,
  DetailedPermissionMatrixResponse,
  AccessDenialAudit,
} from '../types';

interface IdentityAuthorizationViewProps {
  project: Project;
  currentUser: User | null;
}

export const IdentityAuthorizationView: React.FC<IdentityAuthorizationViewProps> = ({ project, currentUser }) => {
  const [activeTab, setActiveTab] = useState<'matrix' | 'denials' | 'session' | 'invariants'>('matrix');
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  // Data states
  const [matrix, setMatrix] = useState<DetailedPermissionMatrixResponse | null>(null);
  const [denials, setDenials] = useState<AccessDenialAudit[]>([]);

  // Password state
  const [currentPw, setCurrentPw] = useState('');
  const [newPw, setNewPw] = useState('');
  const [confirmPw, setConfirmPw] = useState('');
  const [changingPw, setChangingPw] = useState(false);

  const loadData = async () => {
    setLoading(true);
    setError(null);
    try {
      const [matrixRes, denialsRes] = await Promise.all([
        api.getDetailedPermissionMatrix().catch(() => null),
        api.listProjectAccessDenials(project.id).catch(() => []),
      ]);
      setMatrix(matrixRes);
      setDenials(denialsRes);
    } catch (err: any) {
      setError(err?.message || 'Failed to load identity and authorization state');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, [project.id]);

  const handleRevokeAll = async () => {
    if (!window.confirm('Are you sure you want to invalidate all active sessions across all devices? You will be logged out.')) {
      return;
    }
    setError(null);
    try {
      const res = await api.revokeAllSessions();
      setSuccessMsg(res.message);
      setTimeout(() => {
        window.location.reload();
      }, 1500);
    } catch (err: any) {
      setError(err?.message || 'Failed to revoke sessions');
    }
  };

  const handleLogout = async () => {
    setError(null);
    try {
      await api.revokeServerSession().catch(() => {});
      api.logout();
      window.location.reload();
    } catch (err: any) {
      setError(err?.message || 'Logout failed');
    }
  };

  const handleChangePassword = async (e: React.FormEvent) => {
    e.preventDefault();
    if (newPw !== confirmPw) {
      setError('New passwords do not match');
      return;
    }
    if (newPw.length < 8) {
      setError('New password must be at least 8 characters in length');
      return;
    }
    setChangingPw(true);
    setError(null);
    setSuccessMsg(null);
    try {
      const res = await api.changePassword({ current_password: currentPw, new_password: newPw });
      setSuccessMsg(res.message);
      setCurrentPw('');
      setNewPw('');
      setConfirmPw('');
    } catch (err: any) {
      setError(err?.message || 'Failed to change password');
    } finally {
      setChangingPw(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* View Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between pb-4 border-b border-gray-700 gap-4">
        <div>
          <h1 className="text-2xl font-bold text-gray-100 flex items-center gap-2">
            <span className="p-2 rounded bg-indigo-950 text-indigo-400 border border-indigo-800">🛡️</span>
            Identity Security, Authorization Consistency & Privileged-Action Governance
          </h1>
          <p className="text-sm text-gray-400 mt-1">
            Server-enforced RBAC, attributable access denial auditing, cryptographic session revocation, and SoD guards.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={loadData}
            disabled={loading}
            className="px-3 py-2 bg-gray-700 hover:bg-gray-600 text-gray-200 rounded text-sm transition"
          >
            {loading ? 'Refreshing...' : 'Refresh'}
          </button>
          <button
            onClick={handleLogout}
            className="px-3 py-2 bg-gray-700 hover:bg-gray-600 text-red-300 rounded text-sm transition"
          >
            Sign Out
          </button>
        </div>
      </div>

      {/* Notifications */}
      {error && (
        <div className="p-4 bg-red-900/30 border border-red-700 text-red-200 rounded text-sm flex items-center justify-between">
          <span>{error}</span>
          <button onClick={() => setError(null)} className="text-red-400 hover:text-white font-bold ml-4">✕</button>
        </div>
      )}
      {successMsg && (
        <div className="p-4 bg-emerald-900/30 border border-emerald-700 text-emerald-200 rounded text-sm flex items-center justify-between">
          <span>{successMsg}</span>
          <button onClick={() => setSuccessMsg(null)} className="text-emerald-400 hover:text-white font-bold ml-4">✕</button>
        </div>
      )}

      {/* KPI Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="p-4 bg-gray-800 border border-gray-700 rounded shadow-sm">
          <div className="text-xs uppercase font-semibold text-gray-400 tracking-wider">Current Identity</div>
          <div className="mt-2 text-base font-bold text-gray-100 truncate">{currentUser?.email || 'Authenticated'}</div>
          <div className="mt-1 flex items-center gap-2">
            <span className="px-2 py-0.5 rounded text-xs bg-indigo-950 text-indigo-300 border border-indigo-800 font-mono">
              {currentUser?.system_role || 'VIEWER'}
            </span>
            <span className="text-xs text-emerald-400 font-medium">● Active</span>
          </div>
        </div>

        <div className="p-4 bg-gray-800 border border-gray-700 rounded shadow-sm">
          <div className="text-xs uppercase font-semibold text-gray-400 tracking-wider">Access Denials Logged</div>
          <div className="mt-2 flex items-baseline justify-between">
            <span className="text-2xl font-bold text-red-400">{denials.length}</span>
            <span className="text-xs text-gray-400">Project Scoped</span>
          </div>
          <div className="text-xs text-gray-400 mt-2">Attributable audit trail without secret leakage</div>
        </div>

        <div className="p-4 bg-gray-800 border border-gray-700 rounded shadow-sm">
          <div className="text-xs uppercase font-semibold text-gray-400 tracking-wider">Separation of Duties</div>
          <div className="mt-2 flex items-baseline justify-between">
            <span className="text-2xl font-bold text-emerald-400">ENFORCED</span>
            <span className="text-xs px-2 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-800">
              Active
            </span>
          </div>
          <div className="text-xs text-gray-400 mt-2">Self-approval strictly rejected</div>
        </div>

        <div className="p-4 bg-gray-800 border border-gray-700 rounded shadow-sm">
          <div className="text-xs uppercase font-semibold text-gray-400 tracking-wider">Session Security</div>
          <div className="mt-2 flex items-baseline justify-between">
            <span className="text-2xl font-bold text-indigo-400">JWT + JTI</span>
            <span className="text-xs px-2 py-0.5 rounded bg-indigo-950 text-indigo-300 border border-indigo-800">
              Revocable
            </span>
          </div>
          <div className="text-xs text-gray-400 mt-2">Immediate token blocklist termination</div>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex border-b border-gray-700 gap-6 text-sm font-medium">
        <button
          onClick={() => setActiveTab('matrix')}
          className={`pb-3 border-b-2 transition ${
            activeTab === 'matrix'
              ? 'border-indigo-500 text-indigo-400 font-semibold'
              : 'border-transparent text-gray-400 hover:text-gray-200'
          }`}
        >
          Permission Matrix & RBAC
        </button>
        <button
          onClick={() => setActiveTab('denials')}
          className={`pb-3 border-b-2 transition ${
            activeTab === 'denials'
              ? 'border-indigo-500 text-indigo-400 font-semibold'
              : 'border-transparent text-gray-400 hover:text-gray-200'
          }`}
        >
          Access Denial Audit Ledger ({denials.length})
        </button>
        <button
          onClick={() => setActiveTab('session')}
          className={`pb-3 border-b-2 transition ${
            activeTab === 'session'
              ? 'border-indigo-500 text-indigo-400 font-semibold'
              : 'border-transparent text-gray-400 hover:text-gray-200'
          }`}
        >
          Session & Credential Governance
        </button>
        <button
          onClick={() => setActiveTab('invariants')}
          className={`pb-3 border-b-2 transition ${
            activeTab === 'invariants'
              ? 'border-indigo-500 text-indigo-400 font-semibold'
              : 'border-transparent text-gray-400 hover:text-gray-200'
          }`}
        >
          Authorization Invariants
        </button>
      </div>

      {/* Tab 1: Permission Matrix */}
      {activeTab === 'matrix' && matrix && (
        <div className="space-y-6">
          <div>
            <h3 className="text-base font-bold text-gray-100 mb-3">Project Team Roles & Resource Access</h3>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              {matrix.project_roles.map((pRole) => (
                <div key={pRole.role} className="p-4 bg-gray-800 border border-gray-700 rounded space-y-3">
                  <div className="flex items-center justify-between border-b border-gray-700 pb-2">
                    <span className="font-bold text-indigo-300 font-mono">{pRole.role}</span>
                    <span className="text-xs text-gray-400">{pRole.granted_permissions.length} perms</span>
                  </div>
                  <p className="text-xs text-gray-300">{pRole.description}</p>
                  <div className="space-y-1">
                    <span className="text-[11px] font-semibold uppercase text-gray-400">Granted Permissions:</span>
                    <div className="flex flex-wrap gap-1 max-h-48 overflow-y-auto pt-1">
                      {pRole.granted_permissions.map((p) => (
                        <span key={p} className="px-2 py-0.5 rounded text-[10px] bg-gray-900 text-gray-300 font-mono border border-gray-700">
                          {p}
                        </span>
                      ))}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div>
            <h3 className="text-base font-bold text-gray-100 mb-3">System-Level Roles & Platform Governance</h3>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              {matrix.system_roles.map((sRole) => (
                <div key={sRole.role} className="p-4 bg-gray-800 border border-gray-700 rounded space-y-3">
                  <div className="flex items-center justify-between border-b border-gray-700 pb-2">
                    <span className="font-bold text-purple-300 font-mono">{sRole.role}</span>
                    <span className="text-xs text-gray-400">{sRole.granted_permissions.length} perms</span>
                  </div>
                  <p className="text-xs text-gray-300">{sRole.description}</p>
                  <div className="space-y-1">
                    <span className="text-[11px] font-semibold uppercase text-gray-400">Granted Permissions:</span>
                    <div className="flex flex-wrap gap-1 max-h-40 overflow-y-auto pt-1">
                      {sRole.granted_permissions.map((p) => (
                        <span key={p} className="px-2 py-0.5 rounded text-[10px] bg-gray-900 text-gray-300 font-mono border border-gray-700">
                          {p}
                        </span>
                      ))}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Tab 2: Access Denial Ledger */}
      {activeTab === 'denials' && (
        <div className="space-y-4">
          {denials.length === 0 ? (
            <div className="p-8 text-center bg-gray-800/40 border border-gray-700 rounded">
              <div className="text-3xl mb-2">🛡️</div>
              <p className="text-gray-300 font-medium">No access denial records logged for this project.</p>
              <p className="text-xs text-gray-400 mt-1">
                Any attempted horizontal or vertical privilege escalations will be logged with full attribution.
              </p>
            </div>
          ) : (
            <div className="overflow-x-auto border border-gray-700 rounded">
              <table className="w-full text-left text-sm text-gray-300">
                <thead className="bg-gray-800 text-xs uppercase text-gray-400 border-b border-gray-700">
                  <tr>
                    <th className="px-4 py-3">Timestamp</th>
                    <th className="px-4 py-3">Actor Email</th>
                    <th className="px-4 py-3">Endpoint & Method</th>
                    <th className="px-4 py-3">Required Privilege</th>
                    <th className="px-4 py-3">Held Role</th>
                    <th className="px-4 py-3">Denial Reason</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-700/60 bg-gray-900/60">
                  {denials.map((d) => (
                    <tr key={d.id} className="hover:bg-gray-800/50 transition">
                      <td className="px-4 py-3 font-mono text-xs text-gray-300 whitespace-nowrap">
                        {new Date(d.denied_at).toLocaleString()}
                      </td>
                      <td className="px-4 py-3 font-medium text-gray-200">
                        {d.user_email || 'Anonymous'}
                      </td>
                      <td className="px-4 py-3 font-mono text-xs">
                        <span className="px-1.5 py-0.5 rounded bg-gray-800 text-indigo-300 mr-2 font-bold">
                          {d.http_method}
                        </span>
                        {d.endpoint}
                      </td>
                      <td className="px-4 py-3 text-xs font-mono text-red-300 font-semibold">
                        {d.required_privilege}
                      </td>
                      <td className="px-4 py-3 text-xs font-mono text-gray-400">
                        {d.held_privilege || 'NONE'}
                      </td>
                      <td className="px-4 py-3 text-xs text-gray-300 max-w-sm truncate" title={d.denial_reason}>
                        {d.denial_reason}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* Tab 3: Session & Credential Governance */}
      {activeTab === 'session' && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div className="p-6 bg-gray-800 border border-gray-700 rounded space-y-4">
            <h3 className="text-base font-bold text-gray-100">Cryptographic Session Termination</h3>
            <p className="text-xs text-gray-400 leading-relaxed">
              Invalidate all active sessions across all browser tabs and client devices. Useful if you suspect your credentials
              were exposed or you signed in from an untrusted workstation.
            </p>

            <div className="pt-2">
              <button
                onClick={handleRevokeAll}
                className="px-4 py-2 bg-red-700 hover:bg-red-600 text-white font-medium text-xs rounded transition flex items-center gap-2"
              >
                <span>⚡</span> Invalidate All Active Sessions
              </button>
            </div>
          </div>

          <div className="p-6 bg-gray-800 border border-gray-700 rounded space-y-4">
            <h3 className="text-base font-bold text-gray-100">Rotate Password</h3>
            <form onSubmit={handleChangePassword} className="space-y-3 text-xs">
              <div>
                <label className="block text-gray-400 mb-1 font-medium">Current Password</label>
                <input
                  type="password"
                  value={currentPw}
                  onChange={(e) => setCurrentPw(e.target.value)}
                  required
                  className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded text-gray-100 focus:outline-none focus:border-indigo-500"
                />
              </div>
              <div>
                <label className="block text-gray-400 mb-1 font-medium">New Password (min 8 chars)</label>
                <input
                  type="password"
                  value={newPw}
                  onChange={(e) => setNewPw(e.target.value)}
                  required
                  minLength={8}
                  className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded text-gray-100 focus:outline-none focus:border-indigo-500"
                />
              </div>
              <div>
                <label className="block text-gray-400 mb-1 font-medium">Confirm New Password</label>
                <input
                  type="password"
                  value={confirmPw}
                  onChange={(e) => setConfirmPw(e.target.value)}
                  required
                  minLength={8}
                  className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded text-gray-100 focus:outline-none focus:border-indigo-500"
                />
              </div>
              <div className="pt-2">
                <button
                  type="submit"
                  disabled={changingPw}
                  className="w-full py-2 bg-indigo-700 hover:bg-indigo-600 text-white font-medium rounded transition"
                >
                  {changingPw ? 'Rotating...' : 'Change Password & Revoke Old Sessions'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Tab 4: Invariants */}
      {activeTab === 'invariants' && (
        <div className="p-6 bg-gray-800 border border-gray-700 rounded space-y-4 text-sm text-gray-300">
          <h3 className="text-lg font-bold text-gray-100">Identity Security & Authorization Invariants</h3>
          <ul className="list-disc pl-5 space-y-2 text-xs leading-relaxed">
            <li>
              <strong className="text-white">Fail-Closed Default (Requirement 5):</strong> Any request without explicit, verifiable authorization is denied by default. Unauthorized project requests return HTTP 404 to avoid leaking tenant resource existence.
            </li>
            <li>
              <strong className="text-red-400">Object-Level Ownership Verification (Requirement 6):</strong> All child resources (findings, assets, queue items, verification runs) are bound to their parent project ID on every request, preventing cross-tenant identifier substitution.
            </li>
            <li>
              <strong className="text-amber-400">Separation of Duties & Self-Approval Ban (Requirement 8):</strong> Requesters cannot approve their own scope targets, risk acceptances, or destructive changes unless explicit, documented overrides apply.
            </li>
            <li>
              <strong className="text-indigo-400">Cryptographic Session Revocation (Requirement 9):</strong> Tokens carry unique JTI identifiers. Passwords changes and logouts immediately invalidate active sessions.
            </li>
            <li>
              <strong className="text-emerald-400">Zero Secret Leakage in Logs (Requirement 10):</strong> Passwords, Bearer tokens, and cryptographic keys are strictly redacted from denial logs and audit trails.
            </li>
          </ul>
        </div>
      )}
    </div>
  );
};
