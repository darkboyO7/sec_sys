import { describe, it, expect, vi, beforeEach } from 'vitest';
import { api } from '../services/api';
import type { ConfigDiagnosticResponse, ConnectorConfigRead } from '../types';

describe('Prompt 45: Secrets Management, Configuration Diagnostics & Credential Lifecycle', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    if (typeof window !== 'undefined') {
      window.localStorage.clear();
    }
  });

  it('retrieves configuration diagnostics with non-secret posture ratings and masked tokens', async () => {
    const mockResponse: ConfigDiagnosticResponse = {
      environment: 'production',
      total_settings: 8,
      passed_count: 7,
      warning_count: 1,
      failure_count: 0,
      items: [
        {
          key: 'SECRET_KEY',
          is_secret: true,
          configured: true,
          status: 'PASS',
          strength: 'STRONG',
          redacted_value: 'c8f****c8d7',
          message: 'Cryptographically strong secret key (64 chars, sufficient entropy).',
        },
        {
          key: 'DATABASE_URL',
          is_secret: true,
          configured: true,
          status: 'PASS',
          strength: 'STRONG',
          redacted_value: 'postgresql://vapt_app:***REDACTED***@db.corp:5432/vapt',
          message: 'Enterprise PostgreSQL engine configured.',
        },
        {
          key: 'AUDIT_LOG_STRICT',
          is_secret: false,
          configured: true,
          status: 'PASS',
          strength: 'NOT_APPLICABLE',
          redacted_value: 'true',
          message: 'Immutable audit hash-chaining strictly enforced.',
        },
      ],
      evaluated_at: '2026-10-30T00:00:00Z',
    };

    const requestSpy = vi.spyOn(api as any, 'request').mockResolvedValue(mockResponse);

    const diags = await api.getConfigDiagnostics();

    expect(requestSpy).toHaveBeenCalledWith('/system/deployment/config/diagnostic');
    expect(diags.total_settings).toBe(8);
    expect(diags.passed_count).toBe(7);

    // Verify secret masking: No raw secret in redacted_value
    const secretKeyItem = diags.items.find(i => i.key === 'SECRET_KEY');
    expect(secretKeyItem?.is_secret).toBe(true);
    expect(secretKeyItem?.redacted_value).toContain('****');
    expect(secretKeyItem?.redacted_value).not.toContain('super_secret_raw_key');

    const dbUrlItem = diags.items.find(i => i.key === 'DATABASE_URL');
    expect(dbUrlItem?.redacted_value).toContain('***REDACTED***');
    expect(dbUrlItem?.redacted_value).not.toContain('password');
  });

  it('rotates connector credentials without leaking plaintext tokens in response', async () => {
    const mockRotatedConnector: ConnectorConfigRead = {
      id: 'conn-12345',
      project_id: 'proj-999',
      name: 'Production Threat Intel',
      provider_type: 'CISA_KEV',
      version: '1.0.0',
      enabled: true,
      capabilities: ['PULL_THREAT_INTEL', 'TEST_CONNECTIVITY'],
      config_schema_version: '1.0.0',
      settings_masked: {
        api_token: 'new****456',
        api_endpoint: 'https://cisa.gov/api/v1',
      },
      rate_limit_per_minute: 60,
      timeout_seconds: 10.0,
      max_retries: 3,
      max_response_size_kb: 10240,
      last_health_status: 'HEALTHY',
      consecutive_failures: 0,
      created_at: '2026-10-30T00:00:00Z',
      updated_at: '2026-10-30T00:05:00Z',
    };

    const requestSpy = vi.spyOn(api as any, 'request').mockResolvedValue(mockRotatedConnector);

    const rotated = await api.rotateConnectorCredentials('proj-999', 'conn-12345', {
      api_token: 'new_rotated_raw_token_123456',
      api_endpoint: 'https://cisa.gov/api/v1',
    });

    expect(requestSpy).toHaveBeenCalledWith(
      '/projects/proj-999/connectors/conn-12345/rotate-credentials',
      expect.objectContaining({
        method: 'POST',
      })
    );
    expect(rotated.id).toBe('conn-12345');
    expect(rotated.settings_masked.api_token).toBe('new****456');
    expect(JSON.stringify(rotated)).not.toContain('new_rotated_raw_token_123456');
  });

  it('verifies that no VITE_* environment variables expose backend secrets in build context', () => {
    const envKeys = Object.keys(import.meta.env || {});
    const dangerousKeywords = ['SECRET', 'PASSWORD', 'PRIVATE_KEY', 'TOKEN', 'CREDENTIAL'];

    for (const key of envKeys) {
      if (key.startsWith('VITE_')) {
        for (const kw of dangerousKeywords) {
          expect(key.toUpperCase()).not.toContain(kw);
        }
      }
    }
  });
});
