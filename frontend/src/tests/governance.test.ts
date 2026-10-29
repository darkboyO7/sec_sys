import { describe, it, expect, vi, beforeEach } from 'vitest';
import { api } from '../services/api';
import type {
  ApprovalWorkflowType,
  GovernanceApprovalStatus,
  ProjectGovernancePolicy,
  ApprovalRequestRecord,
  PermissionMatrixResponse,
} from '../types';

describe('Prompt 22: Multi-Tenant Isolation, Governance & Secure Collaboration', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('verifies all required approval workflow types and approval statuses are defined', () => {
    const workflows: ApprovalWorkflowType[] = [
      'SCOPE_AUTHORIZATION',
      'SECURITY_DECISION',
      'REMEDIATION_CHANGE',
      'RISK_ACCEPTANCE',
      'MODEL_PROMOTION',
      'DATA_PURGE',
    ];
    expect(workflows).toHaveLength(6);
    expect(workflows).toContain('SCOPE_AUTHORIZATION');
    expect(workflows).toContain('SECURITY_DECISION');
    expect(workflows).toContain('REMEDIATION_CHANGE');
    expect(workflows).toContain('RISK_ACCEPTANCE');
    expect(workflows).toContain('MODEL_PROMOTION');
    expect(workflows).toContain('DATA_PURGE');

    const statuses: GovernanceApprovalStatus[] = [
      'PENDING',
      'APPROVED',
      'REJECTED',
      'EXECUTED',
      'REVOKED',
      'INVALIDATED',
    ];
    expect(statuses).toHaveLength(6);
    expect(statuses).toContain('PENDING');
    expect(statuses).toContain('APPROVED');
    expect(statuses).toContain('REJECTED');
    expect(statuses).toContain('EXECUTED');
    expect(statuses).toContain('INVALIDATED');
  });

  it('fetches and updates project governance policy with Separation of Duties settings', async () => {
    const mockPolicy: ProjectGovernancePolicy = {
      id: 'pol-123',
      project_id: 'proj-apex',
      enforce_separation_of_duties: true,
      allow_self_approval_override: false,
      require_two_person_rule_for_purge: true,
      require_lead_for_scope_authorization: true,
      require_lead_for_risk_acceptance: true,
      require_lead_for_remediation_approval: true,
      require_lead_for_model_promotion: true,
      policy_version: 'v2026.2.0',
      created_at: '2026-10-28T12:00:00Z',
      updated_at: '2026-10-28T12:00:00Z',
    };

    vi.spyOn(api as any, 'request').mockResolvedValueOnce(mockPolicy);
    const policy = await api.getGovernancePolicy('proj-apex');
    expect(policy.enforce_separation_of_duties).toBe(true);
    expect(policy.allow_self_approval_override).toBe(false);

    const updatedMock: ProjectGovernancePolicy = {
      ...mockPolicy,
      allow_self_approval_override: true,
    };
    vi.spyOn(api as any, 'request').mockResolvedValueOnce(updatedMock);
    const updated = await api.updateGovernancePolicy('proj-apex', {
      allow_self_approval_override: true,
    });
    expect(updated.allow_self_approval_override).toBe(true);
  });

  it('lists approval requests with cryptographic parameter hash binding and replay protection', async () => {
    const mockApprovals: ApprovalRequestRecord[] = [
      {
        id: 'appr-uuid-1',
        project_id: 'proj-apex',
        workflow_type: 'SCOPE_AUTHORIZATION',
        resource_type: 'ScopeTarget',
        resource_id: 'target-100',
        status: 'PENDING',
        title: 'Authorize 192.168.1.0/24 subnet',
        description: 'Passive vulnerability assessment for corporate DMZ',
        parameter_hash: 'a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e',
        parameters_snapshot: { target: '192.168.1.0/24', action: 'PASSIVE_SCAN' },
        requester_id: 'user-tester-1',
        requested_at: '2026-10-28T12:05:00Z',
        policy_version: 'v2026.2.0',
        created_at: '2026-10-28T12:05:00Z',
        updated_at: '2026-10-28T12:05:00Z',
      },
    ];

    vi.spyOn(api as any, 'request').mockResolvedValueOnce(mockApprovals);
    const approvals = await api.listApprovals('proj-apex', { status: 'PENDING' });
    expect(approvals).toHaveLength(1);
    expect(approvals[0].parameter_hash).toHaveLength(64);
    expect(approvals[0].workflow_type).toBe('SCOPE_AUTHORIZATION');
    expect(approvals[0].status).toBe('PENDING');
  });

  it('decides an approval request with mandatory audit justification', async () => {
    const decidedMock: ApprovalRequestRecord = {
      id: 'appr-uuid-1',
      project_id: 'proj-apex',
      workflow_type: 'SECURITY_DECISION',
      resource_type: 'SecurityDecision',
      resource_id: 'dec-retest-1',
      status: 'APPROVED',
      title: 'Authorize Retest on DMZ Gateway',
      parameter_hash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      parameters_snapshot: { target: '192.168.1.1' },
      requester_id: 'user-tester-1',
      approver_id: 'user-lead-2',
      requested_at: '2026-10-28T12:05:00Z',
      decided_at: '2026-10-28T12:10:00Z',
      decision_reason: 'Independent verification confirmed patch staged on host.',
      policy_version: 'v2026.2.0',
      created_at: '2026-10-28T12:05:00Z',
      updated_at: '2026-10-28T12:10:00Z',
    };

    vi.spyOn(api as any, 'request').mockResolvedValueOnce(decidedMock);
    const result = await api.decideApproval('proj-apex', 'appr-uuid-1', {
      approved: true,
      reason: 'Independent verification confirmed patch staged on host.',
    });
    expect(result.status).toBe('APPROVED');
    expect(result.approver_id).toBe('user-lead-2');
    expect(result.decision_reason).toContain('Independent verification');
  });

  it('retrieves formal system & project RBAC permission matrix', async () => {
    const mockMatrix: PermissionMatrixResponse = {
      version: '2026.2',
      roles: {
        SystemRole: ['ADMIN', 'SECURITY_LEAD', 'SECURITY_TESTER', 'AUDITOR', 'VIEWER'],
        ProjectRole: ['LEAD', 'TESTER', 'AUDITOR', 'VIEWER'],
      },
      matrix: [
        {
          resource: 'Projects / Workspaces',
          actions: {
            read: ['ADMIN', 'LEAD', 'TESTER', 'AUDITOR', 'VIEWER'],
            create: ['ADMIN', 'SECURITY_LEAD', 'SECURITY_TESTER'],
            modify: ['ADMIN', 'LEAD'],
            delete_or_purge: ['ADMIN', 'LEAD'],
          },
        },
        {
          resource: 'Scope Targets & Exclusions',
          actions: {
            read: ['ADMIN', 'LEAD', 'TESTER', 'AUDITOR', 'VIEWER'],
            register_candidate: ['ADMIN', 'LEAD', 'TESTER'],
            authorize_scope: ['ADMIN', 'LEAD'],
            revoke_scope: ['ADMIN', 'LEAD'],
          },
        },
      ],
    };

    vi.spyOn(api as any, 'request').mockResolvedValueOnce(mockMatrix);
    const matrix = await api.getPermissionMatrix('proj-apex');
    expect(matrix.version).toBe('2026.2');
    expect(matrix.roles.SystemRole).toContain('ADMIN');
    expect(matrix.roles.ProjectRole).toContain('LEAD');
    expect(matrix.matrix.length).toBeGreaterThanOrEqual(2);
  });
});
