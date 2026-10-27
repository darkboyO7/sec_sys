import React, { useState, useEffect, useCallback } from 'react';
import {
  Settings,
  Users,
  Shield,
  UserPlus,
  Trash2,
  Save,
  CheckCircle,
  AlertTriangle,
  RefreshCw,
  Server,
  Lock,
  Layers,
} from 'lucide-react';
import { api } from '../services/api';
import type { Project, ProjectMember, ProjectRole, User } from '../types';

interface SettingsViewProps {
  currentProject: Project;
  currentUser: User | null;
  onProjectUpdated?: (updated: Project) => void;
}

export const SettingsView: React.FC<SettingsViewProps> = ({
  currentProject,
  currentUser,
  onProjectUpdated,
}) => {
  // Project Config Form
  const [projectName, setProjectName] = useState(currentProject.name);
  const [projectDescription, setProjectDescription] = useState(currentProject.description || '');
  const [isActive, setIsActive] = useState(currentProject.is_active);
  const [savingProject, setSavingProject] = useState(false);
  const [projectSaved, setProjectSaved] = useState(false);
  const [projectError, setProjectError] = useState<string | null>(null);

  // Members Management
  const [members, setMembers] = useState<ProjectMember[]>([]);
  const [orgUsers, setOrgUsers] = useState<User[]>([]);
  const [membersLoading, setMembersLoading] = useState(false);
  const [selectedUserId, setSelectedUserId] = useState('');
  const [selectedRole, setSelectedRole] = useState<ProjectRole>('TESTER');
  const [addingMember, setAddingMember] = useState(false);
  const [memberActionError, setMemberActionError] = useState<string | null>(null);
  const [memberSuccessMessage, setMemberSuccessMessage] = useState<string | null>(null);

  // Permission Check
  const isLeadOrAdmin =
    currentUser?.system_role === 'ADMIN' ||
    members.some((m) => m.user_id === currentUser?.id && m.role === 'LEAD');

  // Load Members and Organization Users
  const loadTeamData = useCallback(async () => {
    setMembersLoading(true);
    setMemberActionError(null);
    try {
      const [mList, uList] = await Promise.all([
        api.listProjectMembers(currentProject.id),
        api.listUsers().catch(() => []),
      ]);
      setMembers(mList);
      setOrgUsers(uList);
    } catch (err: any) {
      console.error('Failed to load project team data:', err);
    } finally {
      setMembersLoading(false);
    }
  }, [currentProject.id]);

  useEffect(() => {
    setProjectName(currentProject.name);
    setProjectDescription(currentProject.description || '');
    setIsActive(currentProject.is_active);
    loadTeamData();
  }, [currentProject, loadTeamData]);

  // Handle Project Metadata Update
  const handleSaveProject = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!projectName.trim()) {
      setProjectError('Project name cannot be empty.');
      return;
    }
    setSavingProject(true);
    setProjectError(null);
    try {
      const updated = await api.updateProject(currentProject.id, {
        name: projectName.trim(),
        description: projectDescription.trim(),
        is_active: isActive,
      });
      setProjectSaved(true);
      setTimeout(() => setProjectSaved(false), 3000);
      if (onProjectUpdated) {
        onProjectUpdated(updated);
      }
    } catch (err: any) {
      setProjectError(err.message || 'Failed to update project settings.');
    } finally {
      setSavingProject(false);
    }
  };

  // Handle Add Member
  const handleAddMember = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedUserId) {
      setMemberActionError('Please select a user to add.');
      return;
    }
    setAddingMember(true);
    setMemberActionError(null);
    try {
      await api.addProjectMember(currentProject.id, {
        user_id: selectedUserId,
        role: selectedRole,
      });
      setMemberSuccessMessage('Team member added successfully.');
      setTimeout(() => setMemberSuccessMessage(null), 3000);
      setSelectedUserId('');
      await loadTeamData();
    } catch (err: any) {
      setMemberActionError(err.message || 'Failed to add project member.');
    } finally {
      setAddingMember(false);
    }
  };

  // Handle Update Role
  const handleRoleChange = async (userId: string, newRole: ProjectRole) => {
    setMemberActionError(null);
    try {
      await api.updateProjectMemberRole(currentProject.id, userId, newRole);
      setMemberSuccessMessage('Member role updated.');
      setTimeout(() => setMemberSuccessMessage(null), 3000);
      await loadTeamData();
    } catch (err: any) {
      setMemberActionError(err.message || 'Failed to update member role.');
    }
  };

  // Handle Remove Member
  const handleRemoveMember = async (userId: string, userEmail?: string | null) => {
    const confirmMsg = `Are you sure you want to remove ${userEmail || 'this user'} from the project team?`;
    if (!window.confirm(confirmMsg)) return;

    setMemberActionError(null);
    try {
      await api.removeProjectMember(currentProject.id, userId);
      setMemberSuccessMessage('Team member removed.');
      setTimeout(() => setMemberSuccessMessage(null), 3000);
      await loadTeamData();
    } catch (err: any) {
      setMemberActionError(err.message || 'Failed to remove member.');
    }
  };

  // Users eligible to be added (not currently members)
  const availableUsers = orgUsers.filter((u) => !members.some((m) => m.user_id === u.id));

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 bg-cyber-850 p-6 rounded-xl border border-cyber-700">
        <div>
          <div className="flex items-center gap-2.5">
            <Settings className="w-6 h-6 text-accent-cyan" />
            <h2 className="text-xl font-bold text-slate-100">Project & Access Governance</h2>
            <span className="px-2 py-0.5 text-[10px] rounded bg-cyber-750 text-accent-cyan font-mono border border-accent-cyan/30">
              RBAC & Administration
            </span>
          </div>
          <p className="text-sm text-slate-400 mt-1">
            Configure project parameters, manage team memberships, assign granular RBAC roles, and review environment invariants.
          </p>
        </div>

        <button
          onClick={loadTeamData}
          disabled={membersLoading}
          className="px-3.5 py-2 bg-cyber-750 hover:bg-cyber-700 text-slate-200 text-xs rounded-lg flex items-center gap-2 border border-cyber-600 transition self-start sm:self-auto"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${membersLoading ? 'animate-spin' : ''}`} />
          Refresh
        </button>
      </div>

      {/* SECTION 1: Project Metadata & Settings */}
      <div className="bg-cyber-850 p-6 rounded-xl border border-cyber-700 space-y-4">
        <h3 className="text-xs font-bold text-slate-200 uppercase tracking-wider flex items-center gap-2">
          <Layers className="w-4 h-4 text-accent-cyan" />
          Project Workspace Configuration
        </h3>

        <form onSubmit={handleSaveProject} className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="text-xs font-semibold text-slate-400 block mb-1.5">Project Name *</label>
              <input
                type="text"
                value={projectName}
                onChange={(e) => setProjectName(e.target.value)}
                disabled={!isLeadOrAdmin}
                className="w-full bg-cyber-900 border border-cyber-700 rounded-lg px-3 py-2 text-xs text-slate-100 focus:outline-none focus:border-accent-cyan disabled:opacity-50"
              />
            </div>
            <div>
              <label className="text-xs font-semibold text-slate-400 block mb-1.5">Organization Context</label>
              <input
                type="text"
                value={currentProject.organization_id}
                disabled
                className="w-full bg-cyber-900/60 border border-cyber-800 rounded-lg px-3 py-2 text-xs text-slate-500 font-mono"
              />
            </div>
          </div>

          <div>
            <label className="text-xs font-semibold text-slate-400 block mb-1.5">Project Scope & Purpose Description</label>
            <textarea
              rows={2}
              value={projectDescription}
              onChange={(e) => setProjectDescription(e.target.value)}
              disabled={!isLeadOrAdmin}
              placeholder="e.g. Enterprise production environment security evaluation and compliance audit..."
              className="w-full bg-cyber-900 border border-cyber-700 rounded-lg px-3 py-2 text-xs text-slate-100 focus:outline-none focus:border-accent-cyan disabled:opacity-50"
            />
          </div>

          <div className="flex items-center justify-between pt-2">
            <label className="flex items-center gap-2 cursor-pointer text-xs text-slate-300">
              <input
                type="checkbox"
                checked={isActive}
                onChange={(e) => setIsActive(e.target.checked)}
                disabled={!isLeadOrAdmin}
                className="rounded bg-cyber-900 border-cyber-700 text-accent-cyan focus:ring-accent-cyan"
              />
              <span>Project Workspace Active</span>
            </label>

            {isLeadOrAdmin && (
              <button
                type="submit"
                disabled={savingProject}
                className="px-5 py-2 bg-accent-cyan hover:bg-cyan-400 text-cyber-900 font-bold rounded-lg text-xs flex items-center gap-2 transition disabled:opacity-50"
              >
                {projectSaved ? <CheckCircle className="w-3.5 h-3.5" /> : <Save className="w-3.5 h-3.5" />}
                {savingProject ? 'Saving...' : projectSaved ? 'Saved!' : 'Save Configuration'}
              </button>
            )}
          </div>

          {projectError && (
            <div className="p-3 bg-rose-500/10 border border-rose-500/30 text-rose-300 rounded-lg text-xs font-mono">
              {projectError}
            </div>
          )}
        </form>
      </div>

      {/* SECTION 2: Team Members & RBAC */}
      <div className="bg-cyber-850 p-6 rounded-xl border border-cyber-700 space-y-4">
        <div className="flex items-center justify-between">
          <h3 className="text-xs font-bold text-slate-200 uppercase tracking-wider flex items-center gap-2">
            <Users className="w-4 h-4 text-accent-cyan" />
            Project Team Members & Roles ({members.length} Enrolled)
          </h3>
          <span className="text-[11px] font-mono text-slate-400">
            Enforced RBAC: LEAD &gt; TESTER &gt; AUDITOR &gt; VIEWER
          </span>
        </div>

        {memberSuccessMessage && (
          <div className="p-3 bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 rounded-lg text-xs font-mono flex items-center gap-2">
            <CheckCircle className="w-4 h-4" />
            <span>{memberSuccessMessage}</span>
          </div>
        )}

        {memberActionError && (
          <div className="p-3 bg-rose-500/10 border border-rose-500/30 text-rose-300 rounded-lg text-xs font-mono flex items-center gap-2">
            <AlertTriangle className="w-4 h-4" />
            <span>{memberActionError}</span>
          </div>
        )}

        {/* Members Roster Table */}
        <div className="overflow-x-auto border border-cyber-750 rounded-lg">
          <table className="w-full text-left text-xs">
            <thead className="bg-cyber-800 text-slate-400 font-mono text-[11px] uppercase border-b border-cyber-750">
              <tr>
                <th className="py-3 px-4">Member Name</th>
                <th className="py-3 px-4">Email Address</th>
                <th className="py-3 px-4">Assigned Project Role</th>
                <th className="py-3 px-4">Enrolled Date</th>
                {isLeadOrAdmin && <th className="py-3 px-4 text-right">Actions</th>}
              </tr>
            </thead>
            <tbody className="divide-y divide-cyber-750 text-slate-300 font-mono">
              {members.length === 0 ? (
                <tr>
                  <td colSpan={5} className="py-8 text-center text-slate-500">
                    {membersLoading ? 'Loading team roster...' : 'No team members registered.'}
                  </td>
                </tr>
              ) : (
                members.map((m) => (
                  <tr key={m.id} className="hover:bg-cyber-800/40 transition">
                    <td className="py-3 px-4 font-semibold text-slate-100 flex items-center gap-2">
                      <div className="w-6 h-6 rounded-full bg-accent-cyan/20 border border-accent-cyan/40 text-accent-cyan flex items-center justify-center text-[10px] font-bold">
                        {(m.user_full_name || m.user_email || 'U')[0].toUpperCase()}
                      </div>
                      <span>{m.user_full_name || 'Registered User'}</span>
                    </td>
                    <td className="py-3 px-4 text-slate-300 text-[11px]">{m.user_email || m.user_id}</td>
                    <td className="py-3 px-4">
                      {isLeadOrAdmin ? (
                        <select
                          value={m.role}
                          onChange={(e) => handleRoleChange(m.user_id, e.target.value as ProjectRole)}
                          className="bg-cyber-900 border border-cyber-700 rounded px-2 py-1 text-[11px] text-accent-cyan font-bold focus:outline-none focus:border-accent-cyan"
                        >
                          <option value="LEAD">LEAD</option>
                          <option value="TESTER">TESTER</option>
                          <option value="AUDITOR">AUDITOR</option>
                          <option value="VIEWER">VIEWER</option>
                        </select>
                      ) : (
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                            m.role === 'LEAD'
                              ? 'bg-accent-cyan/20 text-accent-cyan border border-accent-cyan/30'
                              : m.role === 'TESTER'
                              ? 'bg-indigo-500/20 text-indigo-300 border border-indigo-500/30'
                              : 'bg-slate-700 text-slate-300'
                          }`}
                        >
                          {m.role}
                        </span>
                      )}
                    </td>
                    <td className="py-3 px-4 text-slate-500 text-[10px]">
                      {new Date(m.created_at).toLocaleDateString()}
                    </td>
                    {isLeadOrAdmin && (
                      <td className="py-3 px-4 text-right">
                        <button
                          onClick={() => handleRemoveMember(m.user_id, m.user_email)}
                          className="p-1 text-slate-400 hover:text-rose-400 hover:bg-rose-500/10 rounded transition"
                          title="Remove member"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      </td>
                    )}
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* Add Member Form (LEAD/ADMIN Only) */}
        {isLeadOrAdmin && (
          <div className="bg-cyber-900/60 p-4 rounded-xl border border-cyber-750/80 space-y-3">
            <h4 className="text-xs font-bold text-slate-200 flex items-center gap-1.5">
              <UserPlus className="w-4 h-4 text-accent-cyan" />
              Enroll Team Member
            </h4>
            <form onSubmit={handleAddMember} className="grid grid-cols-1 sm:grid-cols-3 gap-3">
              <div>
                <label className="text-[10px] text-slate-400 font-semibold block mb-1">Select User</label>
                <select
                  value={selectedUserId}
                  onChange={(e) => setSelectedUserId(e.target.value)}
                  className="w-full bg-cyber-900 border border-cyber-700 rounded-lg px-3 py-2 text-xs text-slate-100 focus:outline-none focus:border-accent-cyan"
                >
                  <option value="">Choose organization user...</option>
                  {availableUsers.map((u) => (
                    <option key={u.id} value={u.id}>
                      {u.full_name} ({u.email})
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label className="text-[10px] text-slate-400 font-semibold block mb-1">Project Role</label>
                <select
                  value={selectedRole}
                  onChange={(e) => setSelectedRole(e.target.value as ProjectRole)}
                  className="w-full bg-cyber-900 border border-cyber-700 rounded-lg px-3 py-2 text-xs text-slate-100 font-mono focus:outline-none focus:border-accent-cyan"
                >
                  <option value="TESTER">TESTER (Execute & Review)</option>
                  <option value="AUDITOR">AUDITOR (Read & Verify Proofs)</option>
                  <option value="VIEWER">VIEWER (Read Only)</option>
                  <option value="LEAD">LEAD (Full Project Administration)</option>
                </select>
              </div>

              <div className="flex items-end">
                <button
                  type="submit"
                  disabled={addingMember || !selectedUserId}
                  className="w-full py-2 bg-cyber-750 hover:bg-cyber-700 text-accent-cyan border border-cyber-600 font-bold rounded-lg text-xs flex items-center justify-center gap-2 transition disabled:opacity-50"
                >
                  <UserPlus className="w-3.5 h-3.5" />
                  {addingMember ? 'Adding...' : 'Enroll Member'}
                </button>
              </div>
            </form>
          </div>
        )}
      </div>

      {/* SECTION 3: Defensive Architecture & Security Governance Invariants */}
      <div className="bg-cyber-850 p-6 rounded-xl border border-cyber-700 space-y-4">
        <h3 className="text-xs font-bold text-slate-200 uppercase tracking-wider flex items-center gap-2">
          <Shield className="w-4 h-4 text-emerald-400" />
          Active Defensive Invariants & Security Architecture
        </h3>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs font-mono">
          <div className="bg-cyber-900 p-4 rounded-xl border border-cyber-800 space-y-2">
            <div className="flex items-center gap-2 text-slate-200 font-bold">
              <Server className="w-4 h-4 text-accent-cyan" />
              <span>Storage & Engine</span>
            </div>
            <div className="text-[11px] text-slate-400 space-y-1">
              <div>Mode: <span className="text-emerald-400">SQLite 3 WAL Mode</span></div>
              <div>Integrity: <span className="text-emerald-400">PRAGMA Check OK</span></div>
              <div>Isolation: <span className="text-slate-200">Strict Organization Tenant</span></div>
              <div>Anti-Enumeration: <span className="text-slate-200">HTTP 404 Enforced</span></div>
            </div>
          </div>

          <div className="bg-cyber-900 p-4 rounded-xl border border-cyber-800 space-y-2">
            <div className="flex items-center gap-2 text-slate-200 font-bold">
              <Lock className="w-4 h-4 text-amber-400" />
              <span>Execution Boundaries</span>
            </div>
            <div className="text-[11px] text-slate-400 space-y-1">
              <div>Sandbox: <span className="text-slate-200">Win32 Job Object</span></div>
              <div>Memory Ceiling: <span className="text-slate-200">512 MB Hard Cap</span></div>
              <div>Output Buffer: <span className="text-slate-200">10 MB Stdio Clamped</span></div>
              <div>Scope Evaluation: <span className="text-emerald-400">Fail-Closed Preflight</span></div>
            </div>
          </div>

          <div className="bg-cyber-900 p-4 rounded-xl border border-cyber-800 space-y-2">
            <div className="flex items-center gap-2 text-slate-200 font-bold">
              <Shield className="w-4 h-4 text-indigo-400" />
              <span>Cryptographic Proofs</span>
            </div>
            <div className="text-[11px] text-slate-400 space-y-1">
              <div>Evidence Hashes: <span className="text-slate-200">SHA-256 Byte Digests</span></div>
              <div>Proof Verification: <span className="text-slate-200">Binary Merkle Trees</span></div>
              <div>Audit Trail: <span className="text-emerald-400">Hash-Chained Events</span></div>
              <div>Webhooks: <span className="text-slate-200">HMAC-SHA256 Signed</span></div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
