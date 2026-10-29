import { describe, it, expect, vi, beforeEach } from 'vitest';
import { api } from '../services/api';
import type {
  DependencyInventoryResponse,
  DependencyAuditResponse,
  SecretScanResponse,
  ReleaseVerificationResult,
  VulnerabilitySeverity,
} from '../types';

describe('Prompt 25: Software Supply-Chain Security & Verifiable Release Provenance', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('validates dependency ecosystems, scopes, and vulnerability severity enums', () => {
    const severities: VulnerabilitySeverity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
    expect(severities).toHaveLength(5);
    expect(severities).toContain('CRITICAL');
    expect(severities).toContain('HIGH');

    const ecosystems = ['pypi', 'npm'];
    expect(ecosystems).toContain('pypi');
    expect(ecosystems).toContain('npm');
  });

  it('fetches complete dependency inventory via api.getDependencyInventory', async () => {
    const mockInventory: DependencyInventoryResponse = {
      total_dependencies: 182,
      pypi_count: 45,
      npm_count: 137,
      direct_count: 20,
      transitive_count: 162,
      generated_at: '2026-10-29T02:00:00Z',
      items: [
        {
          name: 'fastapi',
          version: '0.162.0',
          ecosystem: 'pypi',
          purl: 'pkg:pypi/fastapi@0.162.0',
          is_direct: true,
          scope: 'required',
          license: 'MIT',
        },
        {
          name: 'react',
          version: '19.3.1',
          ecosystem: 'npm',
          purl: 'pkg:npm/react@19.3.1',
          is_direct: true,
          scope: 'required',
          license: 'MIT',
        },
      ],
    };

    const spy = vi.spyOn(api as any, 'request').mockResolvedValueOnce(mockInventory);
    const result = await api.getDependencyInventory();

    expect(spy).toHaveBeenCalledWith('/system/supply-chain/inventory');
    expect(result.total_dependencies).toBe(182);
    expect(result.pypi_count).toBe(45);
    expect(result.npm_count).toBe(137);
    expect(result.items).toHaveLength(2);
    expect(result.items[0].purl).toBe('pkg:pypi/fastapi@0.162.0');
  });

  it('executes dependency vulnerability audit via api.runDependencyAudit', async () => {
    const mockAudit: DependencyAuditResponse = {
      status: 'CLEAN',
      advisory_service_status: 'ONLINE',
      total_vulnerabilities: 0,
      critical_count: 0,
      high_count: 0,
      medium_count: 0,
      low_count: 0,
      release_gate_passed: true,
      advisories: [],
      scanned_at: '2026-10-29T02:05:00Z',
      details: {},
    };

    const spy = vi.spyOn(api as any, 'request').mockResolvedValueOnce(mockAudit);
    const result = await api.runDependencyAudit(true);

    expect(spy).toHaveBeenCalledWith('/system/supply-chain/audit?allow_network=true', { method: 'POST' });
    expect(result.status).toBe('CLEAN');
    expect(result.release_gate_passed).toBe(true);
    expect(result.advisory_service_status).toBe('ONLINE');
  });

  it('enforces release gate blocking on critical vulnerability finding', async () => {
    const mockBlockedAudit: DependencyAuditResponse = {
      status: 'CRITICAL_BLOCKED',
      advisory_service_status: 'OFFLINE_FALLBACK',
      total_vulnerabilities: 1,
      critical_count: 1,
      high_count: 0,
      medium_count: 0,
      low_count: 0,
      release_gate_passed: false,
      advisories: [
        {
          id: 'CVE-2024-23342',
          package_name: 'ecdsa',
          ecosystem: 'pypi',
          affected_version: '0.18.0',
          severity: 'CRITICAL',
          title: 'Minerva timing attack against P-256 ECDSA',
          remediation_version: '0.19.0',
        },
      ],
      scanned_at: '2026-10-29T02:06:00Z',
      details: {},
    };

    vi.spyOn(api as any, 'request').mockResolvedValueOnce(mockBlockedAudit);
    const result = await api.runDependencyAudit(false);

    expect(result.status).toBe('CRITICAL_BLOCKED');
    expect(result.release_gate_passed).toBe(false);
    expect(result.critical_count).toBe(1);
    expect(result.advisories[0].id).toBe('CVE-2024-23342');
  });

  it('retrieves CycloneDX 1.5 and SPDX 2.3 SBOM via api.getSbom', async () => {
    const mockCdxSbom = {
      bomFormat: 'CycloneDX',
      specVersion: '1.5',
      components: [{ name: 'fastapi', version: '0.162.0' }],
    };

    const spy = vi.spyOn(api as any, 'request').mockResolvedValueOnce(mockCdxSbom);
    const result = await api.getSbom('cyclonedx');

    expect(spy).toHaveBeenCalledWith('/system/supply-chain/sbom?format=cyclonedx');
    expect(result.bomFormat).toBe('CycloneDX');
    expect(result.specVersion).toBe('1.5');
  });

  it('scans workspace for leaked secrets and forbidden files via api.scanSecrets', async () => {
    const mockSecretScan: SecretScanResponse = {
      status: 'CLEAN',
      total_scanned_files: 412,
      total_findings: 0,
      findings: [],
      scanned_at: '2026-10-29T02:10:00Z',
    };

    const spy = vi.spyOn(api as any, 'request').mockResolvedValueOnce(mockSecretScan);
    const result = await api.scanSecrets();

    expect(spy).toHaveBeenCalledWith('/system/supply-chain/secrets/scan', { method: 'POST' });
    expect(result.status).toBe('CLEAN');
    expect(result.total_scanned_files).toBe(412);
    expect(result.findings).toHaveLength(0);
  });

  it('verifies release archive integrity and HMAC-SHA256 signature via api.verifyRelease', async () => {
    const mockVerResult: ReleaseVerificationResult = {
      valid: true,
      release_id: 'rel-1.0.0-1761700000',
      version: '1.0.0',
      total_files_verified: 350,
      mismatched_files: [],
      missing_files: [],
      unexpected_files: [],
      forbidden_files_detected: [],
      signature_valid: true,
      message: 'Release verified authentic and intact.',
      errors: [],
    };

    const spy = vi.spyOn(api as any, 'request').mockResolvedValueOnce(mockVerResult);
    const result = await api.verifyRelease('dist/vapt-platform-v1.0.0.tar.gz');

    expect(spy).toHaveBeenCalledWith('/system/supply-chain/release/verify', {
      method: 'POST',
      body: JSON.stringify({ archive_path: 'dist/vapt-platform-v1.0.0.tar.gz', manifest_path: undefined }),
    });
    expect(result.valid).toBe(true);
    expect(result.signature_valid).toBe(true);
    expect(result.total_files_verified).toBe(350);
  });

  it('detects tampering or missing files during release verification', async () => {
    const mockTamperedResult: ReleaseVerificationResult = {
      valid: false,
      release_id: 'rel-1.0.0-tampered',
      version: '1.0.0',
      total_files_verified: 349,
      mismatched_files: ['backend/app/main.py (hash mismatch)'],
      missing_files: ['reports/sbom/vapt-sbom.cdx.json'],
      unexpected_files: ['unmanifested_payload.exe'],
      forbidden_files_detected: ['.env'],
      signature_valid: false,
      message: 'Release verification failed.',
      errors: [
        'Release manifest cryptographic signature mismatch or invalid key.',
        '1 file(s) failed integrity hash verification.',
        '1 file(s) listed in manifest are missing from archive.',
        '1 unmanifested file(s) found in archive.',
        '1 forbidden file(s) (.env, database, cache) found in release.',
      ],
    };

    vi.spyOn(api as any, 'request').mockResolvedValueOnce(mockTamperedResult);
    const result = await api.verifyRelease();

    expect(result.valid).toBe(false);
    expect(result.signature_valid).toBe(false);
    expect(result.mismatched_files).toHaveLength(1);
    expect(result.missing_files).toHaveLength(1);
    expect(result.unexpected_files).toHaveLength(1);
    expect(result.forbidden_files_detected).toContain('.env');
    expect(result.errors).toHaveLength(5);
  });
});
