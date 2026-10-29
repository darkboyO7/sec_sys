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

describe('Prompt 18: End-to-End Acceptance & Release Qualification UI Contract Tests', () => {
  beforeEach(() => {
    localStorageMock.clear();
    api.setToken(null);
    vi.restoreAllMocks();
  });

  it('1. Authoritative health status reflects HEALTHY when live and ready', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (url: any) => {
      if (String(url).includes('/health')) {
        return {
          ok: true,
          status: 200,
          json: async () => ({ status: 'healthy', version: '1.0.0', environment: 'production', timestamp: '2026-10-28T12:00:00Z' }),
        } as any;
      }
      if (String(url).includes('/ready')) {
        return {
          ok: true,
          status: 200,
          json: async () => ({ status: 'ready', checks: { database: 'ok' } }),
        } as any;
      }
      return { ok: false, status: 404 } as any;
    });

    const health = await api.getHealth();
    const ready = await api.getReadiness();

    expect(health.status).toBe('healthy');
    expect(ready.status).toBe('ready');
  });

  it('2. Authoritative health status reflects DEGRADED or UNAVAILABLE on check failure', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce({
      ok: false,
      status: 503,
      json: async () => ({
        detail: {
          status: 'degraded',
          reason: 'Database pool latency high',
          checks: { database: 'degraded' },
        },
      }),
    } as any);

    await expect(api.getReadiness()).rejects.toThrow();
  });

  it('3. Direct API bypass without token triggers 401 unauthenticated rejection', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce({
      ok: false,
      status: 401,
      json: async () => ({ detail: 'Not authenticated' }),
    } as any);

    await expect(api.listProjects()).rejects.toThrow('Not authenticated');
  });

  it('4. Insufficient role permissions trigger 403 Forbidden rejection', async () => {
    api.setToken('viewer_token');

    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce({
      ok: false,
      status: 403,
      json: async () => ({ detail: 'Viewers have read-only permissions and cannot alter finding lifecycle states.' }),
    } as any);

    await expect(
      api.transitionFinding('proj-1', 'find-1', {
        to_status: 'FALSE_POSITIVE' as any,
        reason: 'Attempted viewer override',
      })
    ).rejects.toThrow('Viewers have read-only permissions');
  });

  it('5. Simulated assessment findings are explicitly identified and labeled', async () => {
    api.setToken('admin_token');

    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: async () => [
        {
          id: 'find-sim-1',
          title: 'Simulated Insecure Header Observation',
          is_simulated: true,
          severity: 'LOW',
          status: 'DETECTED',
        },
        {
          id: 'find-real-2',
          title: 'Live Target HSTS Missing',
          is_simulated: false,
          severity: 'HIGH',
          status: 'CONFIRMED',
        },
      ],
    } as any);

    const findings = await api.listFindings('proj-1');
    expect(findings).toHaveLength(2);
    expect(findings[0].is_simulated).toBe(true);
    expect(findings[1].is_simulated).toBe(false);
  });

  it('6. Audit log chain verification returns valid status and unbroken link count', async () => {
    api.setToken('admin_token');

    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: async () => ({
        total: 42,
        items: [
          {
            id: 'evt-1',
            action: 'TARGET_REGISTERED',
            event_hash: '3f7b2c...889e',
            prev_event_hash: 'GENESIS',
          },
        ],
      }),
    } as any);

    const ledger = await api.getAuditLedger({ projectId: 'proj-1' });
    expect(ledger.total).toBe(42);
    expect(ledger.items[0].prev_event_hash).toBe('GENESIS');
  });

  it('7. Workflow suspension handles server error correctly', async () => {
    api.setToken('admin_token');

    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce({
      ok: false,
      status: 409,
      json: async () => ({
        detail: 'Workflow lease locked by worker-active-01 until 2026-10-28T12:05:00Z',
      }),
    } as any);

    await expect(api.suspendOrchestrationWorkflow('proj-1', 'wf-1', 'Manual intervention')).rejects.toThrow('Workflow lease locked');
  });

  it('8. Remediation retest verification records outcome and updates finding', async () => {
    api.setToken('lead_token');

    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: async () => ({
        id: 'verif-1',
        outcome: 'VERIFIED_FIXED',
        finding_id: 'find-1',
        finding_status: 'VERIFIED_CLOSED',
        notes: 'Independent retest verified HSTS header is active.',
      }),
    } as any);

    const res = await api.verifyFinding('proj-1', 'find-1', {
      outcome: 'VERIFIED_FIXED',
      verification_method: 'PASSIVE_SCAN',
      verification_criteria: 'HSTS max-age >= 31536000 must be present',
      verification_evidence_summary: 'Automated probe verified HSTS is present and valid.',
      notes: 'Independent retest verified HSTS header is active.',
    });

    expect(res.outcome).toBe('VERIFIED_FIXED');
    expect(res.finding_status).toBe('VERIFIED_CLOSED');
  });
});
