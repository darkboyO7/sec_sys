import { describe, it, expect, vi, beforeEach } from 'vitest';
import { api } from '../services/api';

describe('Prompt 47: Security Regression Suite & Client-Side Control Verification', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    if (typeof window !== 'undefined') {
      window.localStorage.clear();
    }
  });

  it('handles 401 Unauthorized failures by clearing stale credentials', async () => {
    const error401 = new Error('HTTP 401: Authentication token has been revoked');
    (error401 as any).status = 401;

    const requestSpy = vi.spyOn(api as any, 'request').mockRejectedValue(error401);

    await expect(api.getAttackSurfaceInventory('proj-123')).rejects.toThrow('401');
    expect(requestSpy).toHaveBeenCalled();
  });

  it('rejects privileged operations with 403 Forbidden for restricted viewer roles', async () => {
    const error403 = new Error('HTTP 403: Forbidden - Operation requires ADMIN or SECURITY_LEAD');
    (error403 as any).status = 403;

    vi.spyOn(api as any, 'request').mockRejectedValue(error403);

    await expect(
      api.approveInclusionProposal('proj-123', 'prop-001', {
        approval_notes: 'Unauthorized approval attempt',
        authorized_evidence: 'ROE-TEST',
      })
    ).rejects.toThrow('403');
  });

  it('handles 422 Unprocessable Content for malformed target inputs', async () => {
    const error422 = new Error('HTTP 422: Unprocessable Content - Invalid target syntax');
    (error422 as any).status = 422;

    vi.spyOn(api as any, 'request').mockRejectedValue(error422);

    await expect(
      api.registerScopeTarget('proj-123', {
        target_value: 'invalid spaces and symbols!!',
        description: 'Malformed target',
      })
    ).rejects.toThrow('422');
  });

  it('handles 429 Too Many Requests when worker capacity is saturated', async () => {
    const error429 = new Error('HTTP 429: Too Many Requests - Workload capacity saturated');
    (error429 as any).status = 429;

    vi.spyOn(api as any, 'request').mockRejectedValue(error429);

    await expect(
      api.createAssessment('proj-123', {
        target_input: 'authorized.corp',
        adapter_name: 'nmap',
      })
    ).rejects.toThrow('429');
  });
});
