import { describe, it, expect, vi, beforeEach } from 'vitest';
import { api } from '../services/api';
import type {
  BackupSchedule,
  BackupScheduleCreate,
  BackupScheduleUpdate,
  BackupScheduleRunResult,
  DiskSpaceStatus,
} from '../types';

describe('Prompt 42: Automated Backup Scheduling & Restoration Assurance Tests', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('validates disk space inspection API schema and sufficiency check', async () => {
    const mockDiskSpace: DiskSpaceStatus = {
      storage_path: 'D:/alt/data/backups',
      total_bytes: 107374182400,
      free_bytes: 53687091200,
      used_bytes: 53687091200,
      free_gb: 50.0,
      total_gb: 100.0,
      is_sufficient_for_backup: true,
      minimum_required_bytes: 52428800,
      message: 'Sufficient storage available (50.0 GB free)',
    };

    vi.spyOn(api, 'getDiskSpaceStatus').mockResolvedValue(mockDiskSpace);

    const space = await api.getDiskSpaceStatus();
    expect(space.is_sufficient_for_backup).toBe(true);
    expect(space.free_gb).toBe(50.0);
    expect(space.storage_path).toContain('backups');
    expect(space.message).toContain('Sufficient storage available');
  });

  it('creates and lists automated backup schedules via API client', async () => {
    const newSchedulePayload: BackupScheduleCreate = {
      name: 'Production Daily Snapshot',
      interval_hours: 24,
      retention_days: 30,
      max_bundles_to_keep: 10,
      storage_location: './data/backups',
      include_evidence: true,
      auto_verify_after_backup: true,
      auto_drill_after_backup: true,
      is_active: true,
    };

    const mockSchedule: BackupSchedule = {
      id: 'sched-uuid-42001',
      name: newSchedulePayload.name,
      interval_hours: newSchedulePayload.interval_hours,
      retention_days: newSchedulePayload.retention_days,
      max_bundles_to_keep: newSchedulePayload.max_bundles_to_keep,
      storage_location: newSchedulePayload.storage_location || './data/backups',
      include_evidence: true,
      auto_verify_after_backup: true,
      auto_drill_after_backup: true,
      is_active: true,
      consecutive_failures: 0,
      last_run_at: null,
      last_run_status: null,
      next_run_at: '2026-10-30T12:00:00Z',
      created_at: '2026-10-29T12:00:00Z',
    };

    vi.spyOn(api, 'createBackupSchedule').mockResolvedValue(mockSchedule);
    vi.spyOn(api, 'listBackupSchedules').mockResolvedValue([mockSchedule]);

    const created = await api.createBackupSchedule(newSchedulePayload);
    expect(created.id).toBe('sched-uuid-42001');
    expect(created.name).toBe('Production Daily Snapshot');
    expect(created.auto_verify_after_backup).toBe(true);
    expect(created.auto_drill_after_backup).toBe(true);

    const list = await api.listBackupSchedules();
    expect(list).toHaveLength(1);
    expect(list[0].id).toBe('sched-uuid-42001');
  });

  it('triggers schedule execution and returns verification and drill assurance status', async () => {
    const mockRunResult: BackupScheduleRunResult = {
      schedule_id: 'sched-uuid-42001',
      status: 'SUCCESS',
      bundle_id: 'dr_bundle_20261029_120000_abc42',
      verification_status: 'PASSED',
      drill_status: 'SUCCESS',
      executed_at: '2026-10-29T12:00:05Z',
      error: null,
    };

    vi.spyOn(api, 'triggerBackupSchedule').mockResolvedValue(mockRunResult);

    const result = await api.triggerBackupSchedule('sched-uuid-42001', true);
    expect(result.status).toBe('SUCCESS');
    expect(result.bundle_id).toBe('dr_bundle_20261029_120000_abc42');
    expect(result.verification_status).toBe('PASSED');
    expect(result.drill_status).toBe('SUCCESS');
    expect(result.error).toBeNull();
  });

  it('polls due schedules and handles batch execution results', async () => {
    const mockBatchResults: BackupScheduleRunResult[] = [
      {
        schedule_id: 'sched-uuid-42001',
        status: 'SUCCESS',
        bundle_id: 'dr_bundle_batch_1',
        verification_status: 'PASSED',
        drill_status: 'SUCCESS',
        executed_at: '2026-10-29T13:00:00Z',
      },
      {
        schedule_id: 'sched-uuid-42002',
        status: 'SKIPPED_DISK_LOW',
        bundle_id: null,
        error: 'Insufficient storage volume',
        executed_at: '2026-10-29T13:00:01Z',
      },
    ];

    vi.spyOn(api, 'pollDueBackupSchedules').mockResolvedValue(mockBatchResults);

    const polled = await api.pollDueBackupSchedules();
    expect(polled).toHaveLength(2);
    expect(polled[0].status).toBe('SUCCESS');
    expect(polled[1].status).toBe('SKIPPED_DISK_LOW');
  });

  it('updates and deletes backup schedules cleanly', async () => {
    const updatePayload: BackupScheduleUpdate = {
      interval_hours: 12,
      retention_days: 14,
    };

    const mockUpdatedSchedule: BackupSchedule = {
      id: 'sched-uuid-42001',
      name: 'Production Daily Snapshot',
      interval_hours: 12,
      retention_days: 14,
      max_bundles_to_keep: 10,
      storage_location: './data/backups',
      include_evidence: true,
      auto_verify_after_backup: true,
      auto_drill_after_backup: false,
      is_active: true,
      consecutive_failures: 0,
      created_at: '2026-10-29T12:00:00Z',
    };

    vi.spyOn(api, 'updateBackupSchedule').mockResolvedValue(mockUpdatedSchedule);
    vi.spyOn(api, 'deleteBackupSchedule').mockResolvedValue(undefined);

    const updated = await api.updateBackupSchedule('sched-uuid-42001', updatePayload);
    expect(updated.interval_hours).toBe(12);
    expect(updated.retention_days).toBe(14);

    await expect(api.deleteBackupSchedule('sched-uuid-42001')).resolves.toBeUndefined();
  });
});
