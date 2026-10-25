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

    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => mockHealth,
    }));

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

    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => mockValidation,
    }));

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
});
