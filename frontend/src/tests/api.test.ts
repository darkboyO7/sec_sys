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

describe('ApiService', () => {
  beforeEach(() => {
    localStorageMock.clear();
    api.setToken(null);
  });

  it('manages authorization tokens correctly in storage', () => {
    expect(api.getToken()).toBeNull();
    api.setToken('test-jwt-token-123');
    expect(api.getToken()).toBe('test-jwt-token-123');
    expect(localStorageMock.getItem('vapt_auth_token')).toBe('test-jwt-token-123');

    api.logout();
    expect(api.getToken()).toBeNull();
    expect(localStorageMock.getItem('vapt_auth_token')).toBeNull();
  });

  it('handles health check response formatting', async () => {
    const mockHealth = {
      status: 'ok',
      version: '1.0.0',
      environment: 'development',
      timestamp: '2026-10-25T00:00:00Z',
    };

    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => mockHealth,
      })
    );

    const health = await api.getHealth();
    expect(health.status).toBe('ok');
    expect(health.version).toBe('1.0.0');
    expect(fetch).toHaveBeenCalledWith('/api/v1/health', expect.any(Object));
  });

  it('passes scope validation queries to /api/v1/projects/:id/validate', async () => {
    const mockValidation = {
      target: '192.168.1.1',
      normalized_target: '192.168.1.1',
      is_authorized: false,
      status: 'EXCLUDED',
      reason: 'Gateway excluded',
      matched_rule: null,
      matched_exclusion: { id: 'excl-1', target_value: '192.168.1.1', reason: 'Gateway' },
      evaluated_at: '2026-10-25T00:00:00Z',
    };

    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => mockValidation,
      })
    );

    const res = await api.validateTarget('proj-123', '192.168.1.1');
    expect(res.is_authorized).toBe(false);
    expect(res.status).toBe('EXCLUDED');
    expect(fetch).toHaveBeenCalledWith(
      '/api/v1/projects/proj-123/validate',
      expect.objectContaining({
        method: 'POST',
        body: JSON.stringify({ target: '192.168.1.1' }),
      })
    );
  });

  it('handles assessment orchestration API endpoints correctly', async () => {
    const mockJob = {
      id: 'job-999',
      project_id: 'proj-123',
      target_input: 'api.bank.corp',
      adapter_name: 'local_fixture_adapter',
      status: 'COMPLETED',
      is_simulated: true,
      findings_count: 2,
    };

    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => mockJob,
      })
    );

    const createdJob = await api.createAssessment('proj-123', {
      target_input: 'api.bank.corp',
      fixture_profile: 'WEB_APPLICATION_BASELINE',
    });

    expect(createdJob.id).toBe('job-999');
    expect(createdJob.status).toBe('COMPLETED');
    expect(fetch).toHaveBeenCalledWith(
      '/api/v1/projects/proj-123/assessments/',
      expect.objectContaining({
        method: 'POST',
        body: JSON.stringify({
          target_input: 'api.bank.corp',
          fixture_profile: 'WEB_APPLICATION_BASELINE',
        }),
      })
    );
  });

  it('queries finding lifecycle and deduplication endpoints', async () => {
    const mockStats = {
      total: 5,
      by_status: { CONFIRMED: 2, DETECTED: 3 },
      by_severity: { HIGH: 2, MEDIUM: 3 },
      unresolved_count: 5,
      reopened_count: 0,
      accepted_risk_count: 0,
      contradiction_count: 1,
    };

    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => mockStats,
      })
    );

    const stats = await api.getFindingStats('proj-123');
    expect(stats.total).toBe(5);
    expect(stats.contradiction_count).toBe(1);
    expect(fetch).toHaveBeenCalledWith('/api/v1/projects/proj-123/findings/stats', expect.any(Object));
  });

  it('dispatches finding state machine transition requests correctly', async () => {
    const mockTransitioned = {
      id: 'finding-001',
      status: 'CONFIRMED',
      transitions: [
        {
          id: 'trans-1',
          from_status: 'DETECTED',
          to_status: 'CONFIRMED',
          reason: 'Verified in lab reproduction',
        },
      ],
    };

    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => mockTransitioned,
      })
    );

    const res = await api.transitionFinding('proj-123', 'finding-001', {
      to_status: 'CONFIRMED',
      reason: 'Verified in lab reproduction',
    });

    expect(res.id).toBe('finding-001');
    expect(res.status).toBe('CONFIRMED');
    expect(fetch).toHaveBeenCalledWith(
      '/api/v1/projects/proj-123/findings/finding-001/transition',
      expect.objectContaining({
        method: 'POST',
        body: JSON.stringify({
          to_status: 'CONFIRMED',
          reason: 'Verified in lab reproduction',
        }),
      })
    );
  });
});
