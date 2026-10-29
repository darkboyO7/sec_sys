import React, { useState, useEffect } from 'react';
import {
  ShieldCheck,
  CheckCircle,
  XCircle,
  AlertTriangle,
  Lock,
  Key,
  FileCheck,
  RefreshCw,
  Sliders,
  Layers,
} from 'lucide-react';
import { api } from '../services/api';
import type {
  ProjectGovernancePolicy,
  ProjectGovernancePolicyUpdate,
  ApprovalRequestRecord,
  GovernanceApprovalStatus,
  PermissionMatrixResponse,
} from '../types';

interface GovernanceViewProps {
  projectId: string;
}

export const GovernanceView: React.FC<GovernanceViewProps> = ({ projectId }) => {
  const [activeTab, setActiveTab] = useState<'policy' | 'pending' | 'history' | 'matrix'>('pending');
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [actionSuccess, setActionSuccess] = useState<string | null>(null);

  // Policy states
  const [policy, setPolicy] = useState<ProjectGovernancePolicy | null>(null);
  const [policyForm, setPolicyForm] = useState<ProjectGovernancePolicyUpdate>({});
  const [savingPolicy, setSavingPolicy] = useState<boolean>(false);

  // Approval requests states
  const [approvals, setApprovals] = useState<ApprovalRequestRecord[]>([]);
  const [selectedApproval, setSelectedApproval] = useState<ApprovalRequestRecord | null>(null);
  const [decisionReason, setDecisionReason] = useState<string>('');
  const [deciding, setDeciding] = useState<boolean>(false);
  const [workflowFilter, setWorkflowFilter] = useState<string>('ALL');

  // Permission matrix
  const [matrixData, setMatrixData] = useState<PermissionMatrixResponse | null>(null);

  const fetchData = async () => {
    setLoading(true);
    setError(null);
    try {
      const [polRes, appRes, matRes] = await Promise.all([
        api.getGovernancePolicy(projectId).catch(() => null),
        api.listApprovals(projectId, { limit: 100 }).catch(() => []),
        api.getPermissionMatrix(projectId).catch(() => null),
      ]);
      setPolicy(polRes);
      if (polRes) {
        setPolicyForm({
          enforce_separation_of_duties: polRes.enforce_separation_of_duties,
          allow_self_approval_override: polRes.allow_self_approval_override,
          require_two_person_rule_for_purge: polRes.require_two_person_rule_for_purge,
          require_lead_for_scope_authorization: polRes.require_lead_for_scope_authorization,
          require_lead_for_risk_acceptance: polRes.require_lead_for_risk_acceptance,
          require_lead_for_remediation_approval: polRes.require_lead_for_remediation_approval,
          require_lead_for_model_promotion: polRes.require_lead_for_model_promotion,
        });
      }
      setApprovals(appRes);
      setMatrixData(matRes);
    } catch (err: any) {
      setError(err?.message || 'Failed to load governance data.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, [projectId]);

  const handleSavePolicy = async () => {
    setSavingPolicy(true);
    setError(null);
    setActionSuccess(null);
    try {
      const updated = await api.updateGovernancePolicy(projectId, policyForm);
      setPolicy(updated);
      setActionSuccess('Governance policy updated successfully.');
    } catch (err: any) {
      setError(err?.message || 'Failed to update governance policy.');
    } finally {
      setSavingPolicy(false);
    }
  };

  const handleDecideApproval = async (approvalId: string, approved: boolean) => {
    if (!decisionReason || decisionReason.trim().length < 3) {
      setError('A justification note of at least 3 characters is mandatory.');
      return;
    }
    setDeciding(true);
    setError(null);
    setActionSuccess(null);
    try {
      const result = await api.decideApproval(projectId, approvalId, {
        approved,
        reason: decisionReason.trim(),
      });
      setActionSuccess(
        `Approval request ${result.status === 'APPROVED' ? 'APPROVED' : 'REJECTED'} successfully.`
      );
      setDecisionReason('');
      setSelectedApproval(null);
      await fetchData();
    } catch (err: any) {
      setError(err?.message || 'Failed to decide approval request.');
    } finally {
      setDeciding(false);
    }
  };

  const pendingApprovals = approvals.filter(
    (a) =>
      a.status === 'PENDING' &&
      (workflowFilter === 'ALL' || a.workflow_type === workflowFilter)
  );

  const historyApprovals = approvals.filter(
    (a) =>
      a.status !== 'PENDING' &&
      (workflowFilter === 'ALL' || a.workflow_type === workflowFilter)
  );

  const getStatusBadge = (status: GovernanceApprovalStatus) => {
    switch (status) {
      case 'APPROVED':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-emerald-900/40 text-emerald-300 border border-emerald-700/50">
            <CheckCircle className="w-3 h-3" /> Approved
          </span>
        );
      case 'EXECUTED':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-blue-900/40 text-blue-300 border border-blue-700/50">
            <CheckCircle className="w-3 h-3" /> Executed
          </span>
        );
      case 'REJECTED':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-red-900/40 text-red-300 border border-red-700/50">
            <XCircle className="w-3 h-3" /> Rejected
          </span>
        );
      case 'INVALIDATED':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-amber-900/40 text-amber-300 border border-amber-700/50">
            <AlertTriangle className="w-3 h-3" /> Invalidated (Drift)
          </span>
        );
      case 'PENDING':
      default:
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-purple-900/40 text-purple-300 border border-purple-700/50 animate-pulse">
            <Lock className="w-3 h-3" /> Pending Review
          </span>
        );
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 pb-4 border-b border-slate-800">
        <div>
          <h1 className="text-2xl font-bold text-slate-100 flex items-center gap-2">
            <ShieldCheck className="w-7 h-7 text-indigo-400" />
            Governance & Separation of Duties
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Multi-tenant organizational boundary enforcement, cryptographic parameter binding, and multi-user approval gates.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={fetchData}
            disabled={loading}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium border border-slate-700 transition"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </button>
        </div>
      </div>

      {/* Notifications */}
      {error && (
        <div className="p-4 rounded-lg bg-red-950/40 border border-red-800/60 text-red-300 text-sm flex items-start gap-3">
          <AlertTriangle className="w-5 h-5 flex-shrink-0 text-red-400 mt-0.5" />
          <div>
            <div className="font-semibold">Governance Violation or Error</div>
            <div>{error}</div>
          </div>
        </div>
      )}

      {actionSuccess && (
        <div className="p-4 rounded-lg bg-emerald-950/40 border border-emerald-800/60 text-emerald-300 text-sm flex items-start gap-3">
          <CheckCircle className="w-5 h-5 flex-shrink-0 text-emerald-400 mt-0.5" />
          <div>{actionSuccess}</div>
        </div>
      )}

      {/* Tabs */}
      <div className="flex border-b border-slate-800 gap-1">
        <button
          onClick={() => setActiveTab('pending')}
          className={`flex items-center gap-2 px-4 py-2.5 text-sm font-medium border-b-2 transition ${
            activeTab === 'pending'
              ? 'border-indigo-500 text-indigo-400 bg-indigo-950/20'
              : 'border-transparent text-slate-400 hover:text-slate-200 hover:border-slate-700'
          }`}
        >
          <Lock className="w-4 h-4" />
          Pending Approvals ({pendingApprovals.length})
        </button>
        <button
          onClick={() => setActiveTab('policy')}
          className={`flex items-center gap-2 px-4 py-2.5 text-sm font-medium border-b-2 transition ${
            activeTab === 'policy'
              ? 'border-indigo-500 text-indigo-400 bg-indigo-950/20'
              : 'border-transparent text-slate-400 hover:text-slate-200 hover:border-slate-700'
          }`}
        >
          <Sliders className="w-4 h-4" />
          Separation of Duties Policy
        </button>
        <button
          onClick={() => setActiveTab('history')}
          className={`flex items-center gap-2 px-4 py-2.5 text-sm font-medium border-b-2 transition ${
            activeTab === 'history'
              ? 'border-indigo-500 text-indigo-400 bg-indigo-950/20'
              : 'border-transparent text-slate-400 hover:text-slate-200 hover:border-slate-700'
          }`}
        >
          <FileCheck className="w-4 h-4" />
          Decision History & Drift Audits ({historyApprovals.length})
        </button>
        <button
          onClick={() => setActiveTab('matrix')}
          className={`flex items-center gap-2 px-4 py-2.5 text-sm font-medium border-b-2 transition ${
            activeTab === 'matrix'
              ? 'border-indigo-500 text-indigo-400 bg-indigo-950/20'
              : 'border-transparent text-slate-400 hover:text-slate-200 hover:border-slate-700'
          }`}
        >
          <Layers className="w-4 h-4" />
          RBAC Permission Matrix
        </button>
      </div>

      {/* Content: Policy */}
      {activeTab === 'policy' && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-6">
          <div className="flex items-center justify-between pb-4 border-b border-slate-800">
            <div>
              <h2 className="text-lg font-semibold text-slate-100 flex items-center gap-2">
                <Sliders className="w-5 h-5 text-indigo-400" />
                Project Separation of Duties (SoD) Rules
              </h2>
              <p className="text-xs text-slate-400 mt-0.5">
                Configure role gates and two-person authorization policies for this project workspace.
              </p>
            </div>
            <div className="text-xs font-mono text-slate-500">
              Policy Version: {policy?.policy_version || 'v2026.2.0'}
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {/* SoD Enforcement */}
            <div className="p-4 rounded-lg bg-slate-950/60 border border-slate-800 space-y-2">
              <label className="flex items-center gap-3 cursor-pointer">
                <input
                  type="checkbox"
                  checked={policyForm.enforce_separation_of_duties ?? true}
                  onChange={(e) =>
                    setPolicyForm({ ...policyForm, enforce_separation_of_duties: e.target.checked })
                  }
                  className="w-4 h-4 rounded border-slate-700 text-indigo-600 focus:ring-indigo-500 focus:ring-offset-slate-900"
                />
                <span className="text-sm font-medium text-slate-200">
                  Enforce Strict Separation of Duties (SoD)
                </span>
              </label>
              <p className="text-xs text-slate-400 pl-7">
                Prohibits requesters from approving their own scope authorizations, remediation recommendations, security decisions, or model promotions.
              </p>
            </div>

            {/* Single-operator local mode override */}
            <div className="p-4 rounded-lg bg-amber-950/20 border border-amber-900/40 space-y-2">
              <label className="flex items-center gap-3 cursor-pointer">
                <input
                  type="checkbox"
                  checked={policyForm.allow_self_approval_override ?? false}
                  onChange={(e) =>
                    setPolicyForm({ ...policyForm, allow_self_approval_override: e.target.checked })
                  }
                  className="w-4 h-4 rounded border-amber-700 text-amber-600 focus:ring-amber-500 focus:ring-offset-slate-900"
                />
                <span className="text-sm font-medium text-amber-200">
                  Allow Self-Approval Override (Single-Operator Mode)
                </span>
              </label>
              <p className="text-xs text-amber-300/80 pl-7">
                Allows single-user developer installations to approve requests locally. Generates mandatory audited SO_D_EXCEPTION events.
              </p>
            </div>

            {/* Two-person rule for purge */}
            <div className="p-4 rounded-lg bg-slate-950/60 border border-slate-800 space-y-2">
              <label className="flex items-center gap-3 cursor-pointer">
                <input
                  type="checkbox"
                  checked={policyForm.require_two_person_rule_for_purge ?? true}
                  onChange={(e) =>
                    setPolicyForm({ ...policyForm, require_two_person_rule_for_purge: e.target.checked })
                  }
                  className="w-4 h-4 rounded border-slate-700 text-indigo-600 focus:ring-indigo-500 focus:ring-offset-slate-900"
                />
                <span className="text-sm font-medium text-slate-200">
                  Require Two-Person Rule for Data Purge
                </span>
              </label>
              <p className="text-xs text-slate-400 pl-7">
                Mandates independent review and explicit cryptographic confirmation before permanent deletion or purging of assessment evidence.
              </p>
            </div>

            {/* Require Lead for Scope */}
            <div className="p-4 rounded-lg bg-slate-950/60 border border-slate-800 space-y-2">
              <label className="flex items-center gap-3 cursor-pointer">
                <input
                  type="checkbox"
                  checked={policyForm.require_lead_for_scope_authorization ?? true}
                  onChange={(e) =>
                    setPolicyForm({ ...policyForm, require_lead_for_scope_authorization: e.target.checked })
                  }
                  className="w-4 h-4 rounded border-slate-700 text-indigo-600 focus:ring-indigo-500 focus:ring-offset-slate-900"
                />
                <span className="text-sm font-medium text-slate-200">
                  Require Project LEAD for Scope Authorization
                </span>
              </label>
              <p className="text-xs text-slate-400 pl-7">
                Only Project LEAD or System ADMIN can authorize newly registered target ranges or domains.
              </p>
            </div>

            {/* Require Lead for Risk Acceptance */}
            <div className="p-4 rounded-lg bg-slate-950/60 border border-slate-800 space-y-2">
              <label className="flex items-center gap-3 cursor-pointer">
                <input
                  type="checkbox"
                  checked={policyForm.require_lead_for_risk_acceptance ?? true}
                  onChange={(e) =>
                    setPolicyForm({ ...policyForm, require_lead_for_risk_acceptance: e.target.checked })
                  }
                  className="w-4 h-4 rounded border-slate-700 text-indigo-600 focus:ring-indigo-500 focus:ring-offset-slate-900"
                />
                <span className="text-sm font-medium text-slate-200">
                  Require Project LEAD for Risk Acceptance
                </span>
              </label>
              <p className="text-xs text-slate-400 pl-7">
                Risk acceptances must be authorized by Project LEAD with verifiable rationale and expiration timestamp.
              </p>
            </div>

            {/* Require Lead for Remediation */}
            <div className="p-4 rounded-lg bg-slate-950/60 border border-slate-800 space-y-2">
              <label className="flex items-center gap-3 cursor-pointer">
                <input
                  type="checkbox"
                  checked={policyForm.require_lead_for_remediation_approval ?? true}
                  onChange={(e) =>
                    setPolicyForm({ ...policyForm, require_lead_for_remediation_approval: e.target.checked })
                  }
                  className="w-4 h-4 rounded border-slate-700 text-indigo-600 focus:ring-indigo-500 focus:ring-offset-slate-900"
                />
                <span className="text-sm font-medium text-slate-200">
                  Require Project LEAD for Remediation & Change Approval
                </span>
              </label>
              <p className="text-xs text-slate-400 pl-7">
                Independent LEAD approval is required before remediation recommendations and change tickets can transition to implementation.
              </p>
            </div>
          </div>

          <div className="pt-4 border-t border-slate-800 flex justify-end">
            <button
              onClick={handleSavePolicy}
              disabled={savingPolicy}
              className="px-5 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white text-sm font-medium shadow-sm transition flex items-center gap-2"
            >
              {savingPolicy ? <RefreshCw className="w-4 h-4 animate-spin" /> : <CheckCircle className="w-4 h-4" />}
              Save Governance Settings
            </button>
          </div>
        </div>
      )}

      {/* Content: Pending Approvals */}
      {activeTab === 'pending' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <label className="text-xs font-medium text-slate-400">Workflow Type:</label>
              <select
                value={workflowFilter}
                onChange={(e) => setWorkflowFilter(e.target.value)}
                className="bg-slate-800 border border-slate-700 rounded text-xs px-2.5 py-1 text-slate-200"
              >
                <option value="ALL">All Workflows</option>
                <option value="SCOPE_AUTHORIZATION">Scope Authorization</option>
                <option value="SECURITY_DECISION">Security Decision</option>
                <option value="REMEDIATION_CHANGE">Remediation Change</option>
                <option value="RISK_ACCEPTANCE">Risk Acceptance</option>
                <option value="MODEL_PROMOTION">Model Promotion</option>
                <option value="DATA_PURGE">Data Purge</option>
              </select>
            </div>
          </div>

          {pendingApprovals.length === 0 ? (
            <div className="text-center py-16 bg-slate-900/40 rounded-xl border border-slate-800/80">
              <CheckCircle className="w-12 h-12 text-emerald-500/50 mx-auto mb-3" />
              <h3 className="text-sm font-medium text-slate-300">No Pending Approvals</h3>
              <p className="text-xs text-slate-500 mt-1 max-w-sm mx-auto">
                All sensitive actions in this workspace have been decided or no new approval requests are queued.
              </p>
            </div>
          ) : (
            <div className="space-y-3">
              {pendingApprovals.map((appr) => (
                <div
                  key={appr.id}
                  className="p-5 rounded-xl bg-slate-900 border border-slate-800 hover:border-slate-700 transition space-y-3"
                >
                  <div className="flex items-start justify-between gap-4">
                    <div>
                      <div className="flex items-center gap-2 mb-1">
                        <span className="px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-indigo-950/80 text-indigo-300 border border-indigo-800/50">
                          {appr.workflow_type}
                        </span>
                        {getStatusBadge(appr.status)}
                      </div>
                      <h3 className="text-base font-semibold text-slate-100">{appr.title}</h3>
                      {appr.description && (
                        <p className="text-xs text-slate-400 mt-1">{appr.description}</p>
                      )}
                    </div>
                    <div className="text-right text-xs text-slate-500 font-mono">
                      <div>Requested: {new Date(appr.requested_at).toLocaleString()}</div>
                      <div>Requester ID: {appr.requester_id.slice(0, 8)}...</div>
                    </div>
                  </div>

                  {/* Cryptographic parameter digest */}
                  <div className="p-3 rounded-lg bg-slate-950/80 border border-slate-800/80 font-mono text-xs text-slate-400 flex items-center justify-between">
                    <div className="flex items-center gap-2 overflow-hidden">
                      <Key className="w-3.5 h-3.5 text-indigo-400 flex-shrink-0" />
                      <span className="text-slate-500">Parameter Hash:</span>
                      <span className="text-indigo-300 font-semibold truncate">{appr.parameter_hash}</span>
                    </div>
                    <div className="text-[11px] text-slate-500 flex-shrink-0 ml-4">
                      Replay Protected
                    </div>
                  </div>

                  {/* Parameter Snapshot Details */}
                  {appr.parameters_snapshot && Object.keys(appr.parameters_snapshot).length > 0 && (
                    <div className="text-xs text-slate-400 bg-slate-950/40 p-2.5 rounded border border-slate-800/40">
                      <span className="font-semibold text-slate-300 block mb-1">Parameters Snapshot:</span>
                      <pre className="text-[11px] font-mono text-slate-300 whitespace-pre-wrap">
                        {JSON.stringify(appr.parameters_snapshot, null, 2)}
                      </pre>
                    </div>
                  )}

                  {/* Decision Actions */}
                  {selectedApproval?.id === appr.id ? (
                    <div className="pt-3 border-t border-slate-800 space-y-3">
                      <div>
                        <label className="text-xs font-medium text-slate-300 block mb-1">
                          Decision Justification (Mandatory):
                        </label>
                        <textarea
                          rows={2}
                          value={decisionReason}
                          onChange={(e) => setDecisionReason(e.target.value)}
                          placeholder="Provide verified audit rationale for approving or rejecting this request..."
                          className="w-full bg-slate-950 border border-slate-700 rounded-lg p-2 text-xs text-slate-200 focus:outline-none focus:border-indigo-500"
                        />
                      </div>
                      <div className="flex items-center justify-end gap-2">
                        <button
                          onClick={() => setSelectedApproval(null)}
                          disabled={deciding}
                          className="px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs"
                        >
                          Cancel
                        </button>
                        <button
                          onClick={() => handleDecideApproval(appr.id, false)}
                          disabled={deciding}
                          className="px-3 py-1.5 rounded bg-red-900/60 hover:bg-red-800 text-red-200 border border-red-700/60 text-xs font-semibold flex items-center gap-1.5"
                        >
                          <XCircle className="w-3.5 h-3.5" /> Reject Request
                        </button>
                        <button
                          onClick={() => handleDecideApproval(appr.id, true)}
                          disabled={deciding}
                          className="px-4 py-1.5 rounded bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold flex items-center gap-1.5"
                        >
                          <CheckCircle className="w-3.5 h-3.5" /> Approve Request
                        </button>
                      </div>
                    </div>
                  ) : (
                    <div className="pt-2 border-t border-slate-800/80 flex justify-end">
                      <button
                        onClick={() => {
                          setSelectedApproval(appr);
                          setDecisionReason('');
                        }}
                        className="px-4 py-1.5 rounded-lg bg-indigo-600/80 hover:bg-indigo-600 text-white text-xs font-medium transition"
                      >
                        Review & Decide
                      </button>
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Content: Decision History */}
      {activeTab === 'history' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <label className="text-xs font-medium text-slate-400">Workflow Type:</label>
              <select
                value={workflowFilter}
                onChange={(e) => setWorkflowFilter(e.target.value)}
                className="bg-slate-800 border border-slate-700 rounded text-xs px-2.5 py-1 text-slate-200"
              >
                <option value="ALL">All Workflows</option>
                <option value="SCOPE_AUTHORIZATION">Scope Authorization</option>
                <option value="SECURITY_DECISION">Security Decision</option>
                <option value="REMEDIATION_CHANGE">Remediation Change</option>
                <option value="RISK_ACCEPTANCE">Risk Acceptance</option>
                <option value="MODEL_PROMOTION">Model Promotion</option>
                <option value="DATA_PURGE">Data Purge</option>
              </select>
            </div>
          </div>

          <div className="space-y-3">
            {historyApprovals.map((appr) => (
              <div
                key={appr.id}
                className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-2 text-xs"
              >
                <div className="flex items-start justify-between gap-4">
                  <div>
                    <div className="flex items-center gap-2 mb-1">
                      <span className="px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-slate-800 text-slate-300">
                        {appr.workflow_type}
                      </span>
                      {getStatusBadge(appr.status)}
                    </div>
                    <div className="text-sm font-semibold text-slate-200">{appr.title}</div>
                  </div>
                  <div className="text-right text-[11px] text-slate-500 font-mono">
                    <div>Decided: {appr.decided_at ? new Date(appr.decided_at).toLocaleString() : 'N/A'}</div>
                    {appr.executed_at && (
                      <div className="text-blue-400">Executed: {new Date(appr.executed_at).toLocaleString()}</div>
                    )}
                  </div>
                </div>

                {appr.decision_reason && (
                  <div className="p-2.5 rounded bg-slate-950/60 border border-slate-800 text-slate-300">
                    <span className="text-slate-500 font-semibold">Decision Rationale: </span>
                    {appr.decision_reason}
                  </div>
                )}

                {appr.invalidation_reason && (
                  <div className="p-2.5 rounded bg-amber-950/40 border border-amber-900/60 text-amber-300">
                    <span className="text-amber-400 font-semibold flex items-center gap-1 mb-0.5">
                      <AlertTriangle className="w-3.5 h-3.5" /> Parameter Drift Detected:
                    </span>
                    {appr.invalidation_reason}
                  </div>
                )}

                <div className="text-[11px] font-mono text-slate-500 flex items-center justify-between pt-1">
                  <div>Hash: {appr.parameter_hash.slice(0, 24)}...</div>
                  <div>Policy: {appr.policy_version}</div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Content: Permission Matrix */}
      {activeTab === 'matrix' && matrixData && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-6">
          <div className="flex items-center justify-between pb-4 border-b border-slate-800">
            <div>
              <h2 className="text-lg font-semibold text-slate-100 flex items-center gap-2">
                <Layers className="w-5 h-5 text-indigo-400" />
                System & Workspace RBAC Permission Matrix
              </h2>
              <p className="text-xs text-slate-400 mt-0.5">
                Formal capability matrix defining authorized operations across global and workspace roles.
              </p>
            </div>
            <div className="text-xs font-mono text-slate-500">
              Version: {matrixData.version}
            </div>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="border-b border-slate-800 text-slate-400 font-semibold uppercase tracking-wider">
                  <th className="py-3 px-4">Resource Domain</th>
                  <th className="py-3 px-4">Action</th>
                  <th className="py-3 px-4">Authorized Roles</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {matrixData.matrix.map((row, idx) =>
                  Object.entries(row.actions).map(([actionName, roles], subIdx) => (
                    <tr key={`${idx}-${subIdx}`} className="hover:bg-slate-800/30 transition">
                      {subIdx === 0 ? (
                        <td
                          rowSpan={Object.keys(row.actions).length}
                          className="py-3 px-4 font-semibold text-slate-200 border-r border-slate-800/80 align-top"
                        >
                          {row.resource}
                        </td>
                      ) : null}
                      <td className="py-3 px-4 font-mono text-indigo-300">{actionName}</td>
                      <td className="py-3 px-4">
                        <div className="flex flex-wrap gap-1.5">
                          {roles.map((r) => (
                            <span
                              key={r}
                              className={`px-2 py-0.5 rounded text-[10px] font-semibold font-mono ${
                                r === 'ADMIN'
                                  ? 'bg-red-950/60 text-red-300 border border-red-800/60'
                                  : r === 'LEAD' || r === 'SECURITY_LEAD'
                                  ? 'bg-indigo-950/60 text-indigo-300 border border-indigo-800/60'
                                  : r === 'TESTER' || r === 'SECURITY_TESTER'
                                  ? 'bg-blue-950/60 text-blue-300 border border-blue-800/60'
                                  : 'bg-slate-800 text-slate-400 border border-slate-700/60'
                              }`}
                            >
                              {r}
                            </span>
                          ))}
                        </div>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
};
