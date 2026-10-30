import { describe, it, expect, afterEach, vi } from 'vitest';
import { getFrontendEnvironment } from '../config/environment';

describe('Prompt 49: Frontend Environment Profiles and Runtime Configuration', () => {

  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it('correctly resolves default development profile', () => {
    vi.stubEnv('VITE_APP_PROFILE', 'development');
    vi.stubEnv('VITE_API_URL', 'http://localhost:8000/api/v1');

    const config = getFrontendEnvironment();
    expect(config.profile).toBe('development');
    expect(config.isDevelopment).toBe(true);
    expect(config.isProduction).toBe(false);
    expect(config.isStaging).toBe(false);
    expect(config.isTesting).toBe(false);
    expect(config.apiBaseUrl).toBe('http://localhost:8000/api/v1');
    expect(config.features.debugPanel).toBe(true);
  });

  it('correctly resolves staging profile with relative API endpoint', () => {
    vi.stubEnv('VITE_APP_PROFILE', 'staging');
    vi.stubEnv('VITE_API_URL', '/api/v1');

    const config = getFrontendEnvironment();
    expect(config.profile).toBe('staging');
    expect(config.isStaging).toBe(true);
    expect(config.isProduction).toBe(false);
    expect(config.isDevelopment).toBe(false);
    expect(config.apiBaseUrl).toBe('/api/v1');
    expect(config.features.debugPanel).toBe(false);
  });

  it('correctly resolves production profile and enables strict security flags', () => {
    vi.stubEnv('VITE_APP_PROFILE', 'production');
    vi.stubEnv('VITE_API_URL', '/api/v1');

    const config = getFrontendEnvironment();
    expect(config.profile).toBe('production');
    expect(config.isProduction).toBe(true);
    expect(config.isStaging).toBe(false);
    expect(config.isDevelopment).toBe(false);
    expect(config.apiBaseUrl).toBe('/api/v1');
    expect(config.features.debugPanel).toBe(false);
    expect(config.features.mockDataShortcuts).toBe(false);
  });

  it('guards against localhost API URL in production and falls back safely', () => {
    vi.stubEnv('VITE_APP_PROFILE', 'production');
    vi.stubEnv('VITE_API_URL', 'http://localhost:8000/api/v1');

    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const config = getFrontendEnvironment();

    expect(config.profile).toBe('production');
    expect(config.apiBaseUrl).toBe('/api/v1');
    expect(warnSpy).toHaveBeenCalledWith(
      expect.stringContaining('[SECURITY] Production profile cannot use localhost API base URL')
    );
    warnSpy.mockRestore();
  });

  it('normalizes testing profile variations', () => {
    vi.stubEnv('VITE_APP_PROFILE', 'TEST');

    const config = getFrontendEnvironment();
    expect(config.profile).toBe('testing');
    expect(config.isTesting).toBe(true);
    expect(config.isProduction).toBe(false);
  });

  it('ensures zero backend private secrets are exposed in import.meta.env', () => {
    const envKeys = Object.keys(import.meta.env);
    const forbiddenKeys = ['SECRET_KEY', 'DATABASE_URL', 'POSTGRES_PASSWORD', 'CREDENTIAL_ENCRYPTION_KEY'];

    for (const key of envKeys) {
      for (const forbidden of forbiddenKeys) {
        expect(key.toUpperCase()).not.toContain(forbidden);
      }
    }
  });
});
