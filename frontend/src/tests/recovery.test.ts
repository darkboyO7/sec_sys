import { describe, it, expect, vi, beforeEach } from 'vitest';
import { api } from '../services/api';
import type {
  DisasterRecoveryBundle,
  BackupVerificationResult,
  RestoreDrillResult,
  LiveRestoreResult,
  RotationResult,
  RecoveryStatusSummary,
} from '../types';

describe('Prompt 23: Disaster Recovery, Verified Restoration & Data Integrity', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('verifies all expected disaster recovery bundle and readiness statuses are valid', () => {
    const bundleStatuses: Array<DisasterRecoveryBundle['status']> = [
      'PENDING',
      'VERIFIED',
      'FAILED',
      'RESTORE_VERIFIED',
      'CORRUPTED',
    ];
    expect(bundleStatuses).toHaveLength(5);
    expect(bundleStatuses).toContain('VERIFIED');
    expect(bundleStatuses).toContain('RESTORE_VERIFIED');

    const readinessStatuses: Array<RecoveryStatusSummary['recovery_readiness']> = [
      'READY',
      'ATTENTION_REQUIRED',
      'DEGRADED',
    ];
    expect(readinessStatuses).toHaveLength(3);
    expect(readinessStatuses).toContain('READY');
  });

  it('creates a disaster recovery bundle via api.createRecoveryBundle', async () => {
    const mockBundle: DisasterRecoveryBundle = {
      bundle_id: 'dr_bundle_20261029_000001_abc12345',
      bundle_path: 'D:/alt/data/backups/dr_bundle_20261029_000001_abc12345',
      created_at: '2026-10-29T00:00:01Z',
      created_by_id: 'user-admin-1',
      manifest_sha256: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
      database_sha256: '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8',
      size_bytes: 4096000,
      status: 'PENDING',
      is_last_known_good: false,
      table_counts: { organizations: 1, projects: 2, users: 3, assessment_jobs: 5 },
      schema_revision: 'd3e4f5a6b7c8',
    };

    const spy = vi.spyOn(api as any, 'request').mockResolvedValueOnce(mockBundle);
    const result = await api.createRecoveryBundle();

    expect(spy).toHaveBeenCalledWith('/recovery/bundles', { method: 'POST' });
    expect(result.bundle_id).toBe('dr_bundle_20261029_000001_abc12345');
    expect(result.size_bytes).toBe(4096000);
    expect(result.schema_revision).toBe('d3e4f5a6b7c8');
  });

  it('retrieves recovery bundles list and details via api', async () => {
    const mockBundles: DisasterRecoveryBundle[] = [
      {
        bundle_id: 'dr_bundle_1',
        bundle_path: 'D:/alt/data/backups/dr_bundle_1',
        created_at: '2026-10-28T12:00:00Z',
        manifest_sha256: 'hash1',
        database_sha256: 'dbhash1',
        size_bytes: 2048000,
        status: 'RESTORE_VERIFIED',
        is_last_known_good: true,
      },
      {
        bundle_id: 'dr_bundle_2',
        bundle_path: 'D:/alt/data/backups/dr_bundle_2',
        created_at: '2026-10-29T00:00:00Z',
        manifest_sha256: 'hash2',
        database_sha256: 'dbhash2',
        size_bytes: 2100000,
        status: 'VERIFIED',
        is_last_known_good: false,
      },
    ];

    vi.spyOn(api as any, 'request').mockResolvedValueOnce(mockBundles);
    const bundles = await api.listRecoveryBundles();

    expect(bundles).toHaveLength(2);
    expect(bundles[0].is_last_known_good).toBe(true);
    expect(bundles[0].status).toBe('RESTORE_VERIFIED');
  });

  it('performs 7-point independent verification via api.verifyRecoveryBundle', async () => {
    const mockVerifyResult: BackupVerificationResult = {
      bundle_id: 'dr_bundle_test',
      status: 'PASSED',
      verified_at: '2026-10-29T00:05:00Z',
      checks: {
        staging_complete: { passed: true, detail: 'Clean bundle.' },
        manifest_integrity: { passed: true, detail: 'Signature verified.' },
        file_checksums: { passed: true, detail: 'All digests match.' },
        sqlite_integrity: { passed: true, detail: 'PRAGMA integrity_check ok.' },
        foreign_keys: { passed: true, detail: 'Zero foreign key violations.' },
        schema_revision: { passed: true, detail: 'Schema verified.' },
        audit_chain_continuity: { passed: true, detail: 'Audit chain continuous.' },
      },
      errors: [],
    };

    const spy = vi.spyOn(api as any, 'request').mockResolvedValueOnce(mockVerifyResult);
    const res = await api.verifyRecoveryBundle('dr_bundle_test');

    expect(spy).toHaveBeenCalledWith('/recovery/bundles/dr_bundle_test/verify', { method: 'POST' });
    expect(res.status).toBe('PASSED');
    expect(res.checks.sqlite_integrity.passed).toBe(true);
    expect(res.checks.foreign_keys.passed).toBe(true);
    expect(res.checks.audit_chain_continuity.passed).toBe(true);
  });

  it('runs isolated restore drill and captures reconciled in-flight jobs', async () => {
    const mockDrillResult: RestoreDrillResult = {
      status: 'SUCCESS',
      bundle_id: 'dr_bundle_drill_1',
      drill_type: 'ISOLATED_SANDBOX',
      sandbox_path: 'D:/alt/data/restore_drill_123',
      jobs_reconciled: [
        { job_id: 'job-run-99', prior_status: 'RUNNING', new_status: 'INTERRUPTED' },
        { job_id: 'job-pre-98', prior_status: 'PREFLIGHT', new_status: 'INTERRUPTED' },
      ],
      tables_verified: 23,
      audit_events_count: 42,
      sandbox_cleaned: true,
      duration_ms: 250.5,
      message: 'Restore drill verified 23 tables in isolated sandbox.',
    };

    const spy = vi.spyOn(api as any, 'request').mockResolvedValueOnce(mockDrillResult);
    const res = await api.runIsolatedRestoreDrill('dr_bundle_drill_1');

    expect(spy).toHaveBeenCalledWith('/recovery/bundles/dr_bundle_drill_1/restore-drill', { method: 'POST' });
    expect(res.status).toBe('SUCCESS');
    expect(res.jobs_reconciled).toHaveLength(2);
    expect(res.jobs_reconciled[0].new_status).toBe('INTERRUPTED');
    expect(res.sandbox_cleaned).toBe(true);
  });

  it('executes live restore with exact confirmation phrase and rollback snapshot', async () => {
    const confirmationPhrase = 'CONFIRM DISASTER RESTORE dr_bundle_live_1';
    const mockLiveResult: LiveRestoreResult = {
      status: 'RESTORED',
      bundle_id: 'dr_bundle_live_1',
      live_db_path: 'D:/alt/data/vapt_system.db',
      rollback_path: 'D:/alt/data/backups/prerestore_20261029.bak',
      tables_restored: 24,
      jobs_reconciled_count: 1,
      audit_events_count: 50,
      integrity_check: 'ok',
      restored_at: '2026-10-29T00:10:00Z',
    };

    const spy = vi.spyOn(api as any, 'request').mockResolvedValueOnce(mockLiveResult);
    const res = await api.liveRestoreBundle('dr_bundle_live_1', confirmationPhrase);

    expect(spy).toHaveBeenCalledWith('/recovery/bundles/dr_bundle_live_1/live-restore', {
      method: 'POST',
      body: JSON.stringify({ confirmation_phrase: confirmationPhrase }),
    });
    expect(res.status).toBe('RESTORED');
    expect(res.rollback_path).toContain('prerestore');
    expect(res.integrity_check).toBe('ok');
  });

  it('rotates backup bundles and preserves last known good', async () => {
    const mockRotation: RotationResult = {
      bundles_scanned: 10,
      bundles_retained: 5,
      bundles_pruned: 5,
      incomplete_cleaned: 1,
      last_known_good_preserved: 'dr_bundle_lkg',
      details: ['Pruned old bundle 1', 'Preserved last-known-good dr_bundle_lkg'],
    };

    const spy = vi.spyOn(api as any, 'request').mockResolvedValueOnce(mockRotation);
    const res = await api.rotateRecoveryBundles(5, true);

    expect(spy).toHaveBeenCalledWith('/recovery/rotate', {
      method: 'POST',
      body: JSON.stringify({ max_retained: 5, preserve_last_known_good: true }),
    });
    expect(res.bundles_pruned).toBe(5);
    expect(res.last_known_good_preserved).toBe('dr_bundle_lkg');
  });

  it('fetches recovery readiness status summary', async () => {
    const mockStatus: RecoveryStatusSummary = {
      total_bundles: 5,
      incomplete_bundles: 0,
      last_attempt_at: '2026-10-29T00:00:00Z',
      last_verified_bundle_id: 'dr_bundle_lkg',
      last_verified_at: '2026-10-29T00:05:00Z',
      last_restore_drill_bundle_id: 'dr_bundle_lkg',
      last_restore_drill_at: '2026-10-29T00:06:00Z',
      last_known_good_bundle_id: 'dr_bundle_lkg',
      total_storage_bytes: 20480000,
      recovery_readiness: 'READY',
    };

    const spy = vi.spyOn(api as any, 'request').mockResolvedValueOnce(mockStatus);
    const res = await api.getRecoveryStatus();

    expect(spy).toHaveBeenCalledWith('/recovery/status');
    expect(res.recovery_readiness).toBe('READY');
    expect(res.total_bundles).toBe(5);
    expect(res.last_known_good_bundle_id).toBe('dr_bundle_lkg');
  });
});
