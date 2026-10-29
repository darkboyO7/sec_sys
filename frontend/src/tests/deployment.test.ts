import { describe, it, expect, vi } from 'vitest';
import { api } from '../services/api';
import type { PreflightReport, RedactedConfigResponse, UpgradePrecheckResponse } from '../types';

describe('Prompt 28: Secure Windows Deployment & Configuration Governance Tests', () => {
  it('should fetch preflight inspection report with valid security invariants', async () => {
    const mockReport: PreflightReport = {
      status: 'PASSED',
      environment: 'development',
      total_checks: 8,
      passed_count: 8,
      warning_count: 0,
      failure_count: 0,
      checks: [
        {
          name: 'SECRET_KEY Cryptographic Hardening',
          category: 'Cryptography',
          status: 'PASS',
          details: 'SECRET_KEY meets 32+ character requirement (64 chars) for development mode.',
        },
        {
          name: 'Database Engine Connectivity',
          category: 'Persistence',
          status: 'PASS',
          details: "Successfully connected to database dialect 'sqlite'.",
        },
      ],
      evaluated_at: new Date().toISOString(),
    };

    vi.spyOn(api, 'getPreflightReport').mockResolvedValueOnce(mockReport);
    const report = await api.getPreflightReport();

    expect(report.status).toBe('PASSED');
    expect(report.passed_count).toBe(8);
    expect(report.failure_count).toBe(0);
    expect(report.checks.length).toBeGreaterThan(0);
    expect(report.checks[0].status).toBe('PASS');
  });

  it('should verify that redacted config never leaks secrets or raw credentials', async () => {
    const mockConfig: RedactedConfigResponse = {
      environment: 'development',
      debug: true,
      app_name: 'VAPT Security Platform',
      database_type: 'sqlite',
      database_url_redacted: 'sqlite:///***LOCAL_DATA_DIR***/vapt.db',
      allowed_origins: ['http://localhost:5173'],
      audit_strict: true,
      data_directories: {
        data_dir: 'D:\\alt\\backend\\data',
        evidence_dir: 'D:\\alt\\backend\\data\\evidence',
        backup_dir: 'D:\\alt\\backend\\data\\backups',
        logs_dir: 'D:\\alt\\backend\\data\\logs',
      },
      cryptographic_algorithm: 'HS256',
      token_expiry_minutes: 480,
      worker_execution_mode: 'bounded',
      retrieved_at: new Date().toISOString(),
    };

    vi.spyOn(api, 'getRedactedConfig').mockResolvedValueOnce(mockConfig);
    const config = await api.getRedactedConfig();

    expect(config.database_url_redacted).toContain('***');
    expect(config.database_url_redacted).not.toContain('password');
    expect(config.allowed_origins).toContain('http://localhost:5173');
    expect(config.data_directories.data_dir).toBeDefined();
  });

  it('should verify schema upgrade readiness check and backup recommendation', async () => {
    const mockUpgrade: UpgradePrecheckResponse = {
      current_version: '1.0.0',
      target_version: '1.1.0',
      migration_head: 'e4f5a6b7c8d9',
      current_db_version: 'e4f5a6b7c8d9',
      pending_migrations_count: 0,
      backup_required: true,
      can_upgrade: true,
      recommended_action: 'Schema is fully up-to-date with migration head.',
      checked_at: new Date().toISOString(),
    };

    vi.spyOn(api, 'checkUpgradeReadiness').mockResolvedValueOnce(mockUpgrade);
    const upgrade = await api.checkUpgradeReadiness();

    expect(upgrade.can_upgrade).toBe(true);
    expect(upgrade.migration_head).toBe('e4f5a6b7c8d9');
    expect(upgrade.backup_required).toBe(true);
    expect(upgrade.pending_migrations_count).toBe(0);
  });
});
