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

  it('handles persistent prediction ledger API endpoints correctly', async () => {
    const mockPrediction = {
      id: 'pred-101',
      project_id: 'proj-123',
      target_entity_type: 'finding',
      target_entity_id: 'f-101',
      prediction_type: 'FALSE_POSITIVE_LIKELIHOOD',
      predicted_outcome: 'FALSE_POSITIVE',
      confidence_score: 0.92,
      evaluation_status: 'PENDING',
    };

    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => [mockPrediction],
      })
    );

    const list = await api.listPredictions('proj-123', { target_entity_type: 'finding' });
    expect(list).toHaveLength(1);
    expect(list[0].id).toBe('pred-101');
    expect(fetch).toHaveBeenCalledWith(
      '/api/v1/projects/proj-123/learning/predictions?limit=50&target_entity_type=finding',
      expect.any(Object)
    );

    // Evaluate prediction
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({ ...mockPrediction, evaluation_status: 'VERIFIED_ACCURATE', actual_outcome: 'FALSE_POSITIVE' }),
      })
    );

    const evaluated = await api.evaluatePrediction('proj-123', 'pred-101', {
      actual_outcome: 'FALSE_POSITIVE',
    });
    expect(evaluated.evaluation_status).toBe('VERIFIED_ACCURATE');
    expect(fetch).toHaveBeenCalledWith(
      '/api/v1/projects/proj-123/learning/predictions/pred-101/evaluate',
      expect.objectContaining({
        method: 'POST',
        body: JSON.stringify({ actual_outcome: 'FALSE_POSITIVE' }),
      })
    );
  });

  it('handles enterprise integration API endpoints correctly', async () => {
    const mockIntegrations = [
      { name: 'CISA KEV Feed Adapter', version: '1.0.0', status: 'CONFIGURED' },
      { name: 'Webhook Notifier Adapter', version: '1.0.0', status: 'CONFIGURED' },
      { name: 'SIEM Audit Exporter Adapter', version: '1.0.0', status: 'CONFIGURED' },
    ];

    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => mockIntegrations,
      })
    );

    const statusList = await api.getIntegrationsStatus('proj-123');
    expect(statusList).toHaveLength(3);
    expect(statusList[0].name).toBe('CISA KEV Feed Adapter');
    expect(fetch).toHaveBeenCalledWith('/api/v1/projects/proj-123/integrations/status', expect.any(Object));

    // Test CISA KEV lookup
    const mockKev = { cve_id: 'CVE-2021-44228', product: 'Log4j', known_ransomware_campaign_use: true };
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => mockKev,
      })
    );

    const kevData = await api.lookupCveKev('proj-123', 'CVE-2021-44228');
    expect(kevData.cve_id).toBe('CVE-2021-44228');
    expect(kevData.known_ransomware_campaign_use).toBe(true);
    expect(fetch).toHaveBeenCalledWith(
      '/api/v1/projects/proj-123/integrations/kev/lookup?cve_id=CVE-2021-44228',
      expect.any(Object)
    );
  });
});
