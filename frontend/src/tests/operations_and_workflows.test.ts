import { describe, it, expect, beforeEach, vi } from 'vitest';

// Polyfill localStorage in node test environment
const storageMock: Record<string, string> = {};
const localStorageMock = {
  getItem: (key: string) => storageMock[key] ?? null,
  setItem: (key: string, value: string) => {
    storageMock[key] = value;
  },
  removeItem: (key: string) => {
    delete storageMock[key];
  },
  clear: () => {
    for (const k of Object.keys(storageMock)) {
      delete storageMock[k];
    }
  },
};
(globalThis as any).localStorage = localStorageMock;

import { api } from '../services/api';

describe('Frontend Operations & Workflows Contract Validation', () => {
  beforeEach(() => {
    localStorageMock.clear();
    api.setToken(null);
    vi.restoreAllMocks();
  });

  // 1. Authentication & Permission-Dependent Headers
  it('attaches Bearer token to authenticated requests and clears on logout', async () => {
    api.setToken('valid-jwt-token-xyz');
    expect(api.getToken()).toBe('valid-jwt-token-xyz');

    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({ id: 'usr-1', email: 'lead@bank.corp', system_role: 'SECURITY_LEAD' }),
      })
    );

    const user = await api.getMe();
    expect(user.email).toBe('lead@bank.corp');
    expect(fetch).toHaveBeenCalledWith(
      '/api/v1/auth/me',
      expect.objectContaining({
        headers: expect.objectContaining({
          Authorization: 'Bearer valid-jwt-token-xyz',
        }),
      })
    );

    api.logout();
    expect(api.getToken()).toBeNull();
  });

  // 2. Scope Authorization and Exclusions
  it('handles scope validation query and identifies excluded targets', async () => {
    const mockExcluded = {
      target: '10.0.0.1',
      normalized_target: '10.0.0.1',
      is_authorized: false,
      status: 'EXCLUDED',
      reason: 'Target is strictly excluded: Internal gateway',
      matched_rule: null,
      matched_exclusion: { id: 'excl-99', target_type: 'IP_ADDRESS', target_value: '10.0.0.1', reason: 'Internal gateway' },
    };

    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => mockExcluded,
      })
    );

    const res = await api.validateTarget('proj-1', '10.0.0.1');
    expect(res.is_authorized).toBe(false);
    expect(res.status).toBe('EXCLUDED');
    expect(res.reason).toContain('Internal gateway');
  });

  // 3. Assessment Lifecycle and Partial Failures
  it('tracks assessment jobs and propagates error on preflight denial', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({
        ok: false,
        status: 400,
        json: async () => ({
          detail: 'Preflight execution boundary denial: Target is not within registered scope',
        }),
      })
    );

    await expect(
      api.createAssessment('proj-1', {
        target_input: 'out-of-scope.target.com',
        fixture_profile: 'WEB_APPLICATION_BASELINE',
      })
    ).rejects.toThrow('Preflight execution boundary denial');
  });

  // 4. Finding Evidence & Optimistic Concurrency Conflict (HTTP 409)
  it('handles optimistic concurrency conflict (409) when finding state changed', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({
        ok: false,
        status: 409,
        json: async () => ({
          detail: "Concurrent transition conflict: Expected finding status 'DETECTED' but current status is 'ACCEPTED_RISK'.",
        }),
      })
    );

    await expect(
      api.transitionFinding('proj-1', 'f-100', {
        to_status: 'REMEDIATION_PROPOSED' as any,
        reason: 'Attempting transition on stale cached state',
      })
    ).rejects.toThrow('Concurrent transition conflict');
  });

  // 5. Contextual Risk & Attack Path Uncertainty
  it('parses contextual risk and attack path uncertainty ratings correctly', async () => {
    const mockAttackPaths = {
      project_id: 'proj-1',
      total_paths_found: 1,
      max_depth_evaluated: 3,
      paths: [
        {
          path_id: 'path-1',
          step_count: 2,
          path_verification_status: 'STALE',
          cumulative_confidence: 0.85,
          missing_evidence: ["Relationship 'Web Server' --[CAN_ACCESS]--> 'Database' is STALE."],
          relationships: [{ id: 'rel-1', relationship_type: 'CAN_ACCESS', status: 'STALE', confidence: 0.85 }],
          nodes: [{ id: 'n-1', label: 'Web Server' }, { id: 'n-2', label: 'Database' }],
        },
      ],
      chokepoints: [{ element_type: 'RELATIONSHIP', id: 'rel-1', paths_intersected: 1, remediation_leverage: 1.0 }],
      methodology_disclaimer: 'Attack path analysis represents relational topology and potential exposure chains.',
    };

    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => mockAttackPaths,
      })
    );

    const result = await api.analyzeAttackPaths('proj-1', { max_depth: 3, max_paths: 5 });
    expect(result.total_paths_found).toBe(1);
    expect(result.paths[0].path_verification_status).toBe('STALE');
    expect(result.paths[0].missing_evidence).toHaveLength(1);
    expect(result.methodology_disclaimer).toContain('relational topology');
  });

  // 6. Remediation Approval and Independent Retest
  it('handles independent retest verification outcome correctly', async () => {
    const mockVerification = {
      id: 'verif-1',
      finding_id: 'f-101',
      outcome: 'VERIFIED_FIXED',
      is_resolved: true,
      verification_evidence_summary: 'Target host no longer responds to exploit payload.',
      verified_at: '2026-10-28T12:00:00Z',
    };

    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => mockVerification,
      })
    );

    const res = await api.verifyFinding('proj-1', 'f-101', {
      outcome: 'VERIFIED_FIXED',
      verification_method: 'AUTOMATED_PROBE',
      verification_criteria: 'Exploit payload fails',
      verification_evidence_summary: 'Target host no longer responds to exploit payload.',
    });
    expect(res.outcome).toBe('VERIFIED_FIXED');
    expect(res.is_resolved).toBe(true);
    expect(fetch).toHaveBeenCalledWith(
      '/api/v1/projects/proj-1/findings/f-101/verify',
      expect.objectContaining({ method: 'POST' })
    );
  });

  // 7. Diagnostics Run & Controlled Recovery Actions
  it('triggers project diagnostics sweep and executes recovery with two-phase verification', async () => {
    const mockRun = {
      run_id: 'run-99',
      project_id: 'proj-1',
      timestamp: '2026-10-28T12:30:00Z',
      total_checks: 10,
      passed_checks: 9,
      warning_checks: 0,
      failed_checks: 1,
      summary: '1 defect detected: Stuck assessment job',
      findings: [
        {
          check_id: 'DIAG_STUCK_JOBS',
          category: 'WORKER_EXECUTION',
          severity: 'HIGH',
          confidence: 'CONFIRMED',
          message: 'Job job-55 running past threshold',
          recovery_action_available: 'RECOVER_STUCK_JOB',
        },
      ],
    };

    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => mockRun,
      })
    );

    const runRes = await api.runProjectDiagnostics('proj-1');
    expect(runRes.total_checks).toBe(10);
    expect(runRes.findings[0].recovery_action_available).toBe('RECOVER_STUCK_JOB');

    // Recovery action execution
    const mockRecovery = {
      recovery_id: 'rec-act-1',
      project_id: 'proj-1',
      action_type: 'RECOVER_STUCK_JOB',
      outcome: 'SUCCESS',
      pre_condition: { job_id: 'job-55', status: 'RUNNING' },
      post_condition: { job_id: 'job-55', status: 'CANCELLED' },
      verification_notes: 'Job transitioned to CANCELLED; worker slot freed.',
    };

    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => mockRecovery,
      })
    );

    const recRes = await api.executeRecoveryAction(
      'proj-1',
      'RECOVER_STUCK_JOB',
      'assessment_job',
      'job-55',
      null,
      'Operator recovering crashed worker'
    );
    expect(recRes.outcome).toBe('SUCCESS');
    expect(recRes.post_condition.status).toBe('CANCELLED');
  });

  // 8. Graceful Network & API Failure Handling
  it('throws descriptive error on HTTP 500 or unreachable backend', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockRejectedValue(new Error('Failed to fetch'))
    );

    await expect(api.getSystemHealth()).rejects.toThrow('Failed to fetch');
  });
});
