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

describe('Autonomous Security Orchestration Control Plane Contract Tests (Prompt 15)', () => {
  beforeEach(() => {
    localStorageMock.clear();
    api.setToken(null);
    vi.restoreAllMocks();
  });

  it('1. getOrchestrationDashboard requests /orchestration/:projectId/dashboard', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce({
      ok: true,
      json: async () => ({
        project_id: 'proj-123',
        summary: { total_workflows: 5, active_workflows: 2 },
        active_workflows: [],
        recent_events: [],
        pending_approvals: [],
      }),
    } as any);

    const result = await api.getOrchestrationDashboard('proj-123');
    expect(fetchSpy).toHaveBeenCalledWith(
      '/api/v1/orchestration/proj-123/dashboard',
      expect.anything()
    );
    expect(result.summary.total_workflows).toBe(5);
  });

  it('2. listOrchestrationWorkflows applies state filter', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce({
      ok: true,
      json: async () => [],
    } as any);

    await api.listOrchestrationWorkflows('proj-123', 'AWAITING_APPROVAL', 15);
    expect(fetchSpy).toHaveBeenCalledWith(
      '/api/v1/orchestration/proj-123/workflows?state=AWAITING_APPROVAL&limit=15',
      expect.anything()
    );
  });

  it('3. ingestOrchestrationEvent posts event payload', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce({
      ok: true,
      json: async () => ({ id: 'ev-1', status: 'RECEIVED' }),
    } as any);

    const res = await api.ingestOrchestrationEvent(
      'proj-123',
      'CONFIG_CHANGED',
      '192.168.1.50',
      { port: 8080 }
    );

    expect(fetchSpy).toHaveBeenCalledWith(
      '/api/v1/orchestration/proj-123/events',
      expect.objectContaining({
        method: 'POST',
        body: JSON.stringify({
          event_type: 'CONFIG_CHANGED',
          target_resource: '192.168.1.50',
          payload: { port: 8080 },
          event_source: 'OPERATOR',
        }),
      })
    );
    expect(res.id).toBe('ev-1');
  });

  it('4. approveOrchestrationWorkflow posts approval notes', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce({
      ok: true,
      json: async () => ({ workflow_id: 'wf-1', state: 'ACTION_QUEUED', message: 'Approved' }),
    } as any);

    const res = await api.approveOrchestrationWorkflow('proj-123', 'wf-1', 'Lead Approved');
    expect(fetchSpy).toHaveBeenCalledWith(
      '/api/v1/orchestration/proj-123/workflows/wf-1/approve',
      expect.objectContaining({
        method: 'POST',
        body: JSON.stringify({ notes: 'Lead Approved' }),
      })
    );
    expect(res.state).toBe('ACTION_QUEUED');
  });

  it('5. rejectOrchestrationWorkflow posts rejection', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce({
      ok: true,
      json: async () => ({ workflow_id: 'wf-1', state: 'COMPLETED', message: 'Rejected' }),
    } as any);

    const res = await api.rejectOrchestrationWorkflow('proj-123', 'wf-1', 'Too risky');
    expect(fetchSpy).toHaveBeenCalledWith(
      '/api/v1/orchestration/proj-123/workflows/wf-1/reject',
      expect.objectContaining({
        method: 'POST',
        body: JSON.stringify({ notes: 'Too risky' }),
      })
    );
    expect(res.state).toBe('COMPLETED');
  });

  it('6. suspend, resume, and retry endpoints trigger correct paths', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce({ ok: true, json: async () => ({ state: 'SUSPENDED' }) } as any)
      .mockResolvedValueOnce({ ok: true, json: async () => ({ state: 'DECISION_PENDING' }) } as any)
      .mockResolvedValueOnce({ ok: true, json: async () => ({ state: 'ACTION_QUEUED' }) } as any);

    await api.suspendOrchestrationWorkflow('proj-123', 'wf-1', 'Maintenance');
    expect(fetchSpy).toHaveBeenNthCalledWith(
      1,
      '/api/v1/orchestration/proj-123/workflows/wf-1/suspend',
      expect.objectContaining({ method: 'POST' })
    );

    await api.resumeOrchestrationWorkflow('proj-123', 'wf-1');
    expect(fetchSpy).toHaveBeenNthCalledWith(
      2,
      '/api/v1/orchestration/proj-123/workflows/wf-1/resume',
      expect.objectContaining({ method: 'POST' })
    );

    await api.retryOrchestrationWorkflow('proj-123', 'wf-1');
    expect(fetchSpy).toHaveBeenNthCalledWith(
      3,
      '/api/v1/orchestration/proj-123/workflows/wf-1/retry',
      expect.objectContaining({ method: 'POST' })
    );
  });

  it('7. getAdaptiveOptimizations and getDependencyInvalidations fetch records', async () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce({ ok: true, json: async () => [{ id: 'opt-1' }] } as any)
      .mockResolvedValueOnce({ ok: true, json: async () => [{ id: 'inv-1' }] } as any);

    const opts = await api.getAdaptiveOptimizations('proj-123', 5);
    expect(fetchSpy).toHaveBeenNthCalledWith(
      1,
      '/api/v1/orchestration/proj-123/optimizations?limit=5',
      expect.anything()
    );
    expect(opts[0].id).toBe('opt-1');

    const invs = await api.getDependencyInvalidations('proj-123', 10);
    expect(fetchSpy).toHaveBeenNthCalledWith(
      2,
      '/api/v1/orchestration/proj-123/invalidations?limit=10',
      expect.anything()
    );
    expect(invs[0].id).toBe('inv-1');
  });
});
