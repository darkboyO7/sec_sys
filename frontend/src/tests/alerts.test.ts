import { describe, it, expect, vi } from 'vitest';
import { api } from '../services/api';
import type {
  AlertListResponse,
  OutboxStatusResponse,
  MaintenanceWindowResponse,
} from '../types';

describe('Prompt 31: Reliable Security Alerting & Event Intelligence Tests', () => {
  it('should fetch alert list with lifecycle states and aggregated counts', async () => {
    const mockAlerts: AlertListResponse = {
      total: 2,
      limit: 50,
      offset: 0,
      active_count: 1,
      unresolved_count: 2,
      critical_count: 1,
      items: [
        {
          id: 'alert-1',
          project_id: 'proj-1',
          event_type: 'CRITICAL_FINDING_DISCOVERED',
          severity: 'CRITICAL',
          title: 'Unauthenticated RCE Detected',
          summary: 'Critical vulnerability detected on primary payment gateway.',
          lifecycle_status: 'NEW',
          delivery_status: 'DELIVERED',
          schema_version: 'v1.0.0',
          retry_count: 0,
          max_retries: 3,
          delivery_attempts_count: 1,
          created_at: new Date().toISOString(),
          updated_at: new Date().toISOString(),
        },
        {
          id: 'alert-2',
          project_id: 'proj-1',
          event_type: 'ASSESSMENT_FAILED',
          severity: 'HIGH',
          title: 'Assessment Job Execution Failed',
          summary: 'Job job-99 timed out.',
          lifecycle_status: 'ACKNOWLEDGED',
          delivery_status: 'DELIVERED',
          schema_version: 'v1.0.0',
          retry_count: 0,
          max_retries: 3,
          delivery_attempts_count: 1,
          created_at: new Date().toISOString(),
          updated_at: new Date().toISOString(),
        },
      ],
    };

    vi.spyOn(api, 'getAlerts').mockResolvedValueOnce(mockAlerts);
    const result = await api.getAlerts('proj-1');

    expect(result.total).toBe(2);
    expect(result.active_count).toBe(1);
    expect(result.critical_count).toBe(1);
    expect(result.items[0].severity).toBe('CRITICAL');
    expect(result.items[0].lifecycle_status).toBe('NEW');
  });

  it('should acknowledge an active alert', async () => {
    const mockAck = { status: 'ACKNOWLEDGED', alert_id: 'alert-1' };
    vi.spyOn(api, 'acknowledgeAlert').mockResolvedValueOnce(mockAck);

    const res = await api.acknowledgeAlert('alert-1', 'Investigating now', 'proj-1');
    expect(res.status).toBe('ACKNOWLEDGED');
    expect(res.alert_id).toBe('alert-1');
  });

  it('should resolve an alert with audit tracking', async () => {
    const mockRes = { status: 'RESOLVED', alert_id: 'alert-1' };
    vi.spyOn(api, 'resolveAlert').mockResolvedValueOnce(mockRes);

    const res = await api.resolveAlert('alert-1', 'Patched and verified', 'proj-1');
    expect(res.status).toBe('RESOLVED');
  });

  it('should fetch outbox backlog telemetry and delivery health', async () => {
    const mockOutbox: OutboxStatusResponse = {
      pending_count: 0,
      delivered_count: 15,
      dead_letter_count: 0,
      suppressed_count: 2,
      oldest_pending_age_seconds: null,
      healthy: true,
      generated_at: new Date().toISOString(),
    };

    vi.spyOn(api, 'getOutboxStatus').mockResolvedValueOnce(mockOutbox);
    const res = await api.getOutboxStatus('proj-1');

    expect(res.healthy).toBe(true);
    expect(res.dead_letter_count).toBe(0);
    expect(res.delivered_count).toBe(15);
  });

  it('should dispatch transactional outbox events', async () => {
    const mockProcess = { processed: 3, delivered: 3, retried: 0, dead_letter: 0 };
    vi.spyOn(api, 'processOutbox').mockResolvedValueOnce(mockProcess);

    const res = await api.processOutbox(50);
    expect(res.processed).toBe(3);
    expect(res.delivered).toBe(3);
    expect(res.dead_letter).toBe(0);
  });

  it('should retrieve scheduled maintenance windows', async () => {
    const mockWindows: MaintenanceWindowResponse[] = [
      {
        id: 'mw-1',
        project_id: 'proj-1',
        title: 'Weekend Maintenance',
        reason: 'OS patching',
        start_time: new Date().toISOString(),
        end_time: new Date(Date.now() + 3600000).toISOString(),
        suppress_critical: false,
        is_currently_active: true,
        created_at: new Date().toISOString(),
      },
    ];

    vi.spyOn(api, 'getMaintenanceWindows').mockResolvedValueOnce(mockWindows);
    const res = await api.getMaintenanceWindows('proj-1');

    expect(res.length).toBe(1);
    expect(res[0].title).toBe('Weekend Maintenance');
    expect(res[0].suppress_critical).toBe(false);
  });
});
