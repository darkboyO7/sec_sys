import { describe, it, expect, vi } from 'vitest';
import { api } from '../services/api';
import type {
  AssessmentReportManifest,
  ReportCoverageSummary,
  BundleVerificationResult,
} from '../types';

describe('Prompt 32: Evidence-Backed Security Reporting & Verifiable Export Tests', () => {
  it('should retrieve canonical assessment report manifest with coverage & evidence bindings', async () => {
    const mockManifest: AssessmentReportManifest = {
      schema_version: '1.0.0',
      report_id: 'rep-test-01',
      project_id: 'proj-1',
      assessment_id: 'job-1',
      title: 'Payment Gateway Security Assessment Report',
      assessment_status: 'COMPLETED',
      started_at: '2026-10-29T10:00:00Z',
      completed_at: '2026-10-29T10:05:00Z',
      generated_at: '2026-10-29T10:06:00Z',
      methodology: {
        adapter_name: 'scanner.http_header',
        scoring_system: 'CVSS_v3.1',
      },
      scope_summary: {
        target_input: 'https://pay.local/api',
      },
      coverage_summary: {
        assessment_id: 'job-1',
        target_input: 'https://pay.local/api',
        status: 'COMPLETED',
        total_targets_assessed: 1,
        total_checks_attempted: 5,
        total_checks_completed: 5,
        checks_failed_count: 0,
        skipped_checks: [],
        missing_evidence_count: 0,
        coverage_gap_identified: false,
        is_incomplete: false,
        disclaimer: 'Clean assessment results reflect absence of detected indicators.',
      },
      finding_counts_by_severity: { CRITICAL: 1, HIGH: 0, MEDIUM: 1 },
      findings: [
        {
          id: 'f-1',
          fingerprint: 'fp-pay-rce',
          title: 'Remote Code Execution in Checkout',
          description: 'Unsanitized input allows shell command execution.',
          severity: 'CRITICAL',
          confidence: 'CERTAIN',
          cvss_score: 9.8,
          target: 'https://pay.local/api/checkout',
          status: 'CONFIRMED',
          is_simulated: true,
          evidence_refs: ['ev-01'],
          has_missing_evidence: false,
          contradictory_evidence_noted: false,
        },
      ],
      assets: [
        {
          id: 'a-1',
          name: 'Payment API Gateway',
          target_value: 'https://pay.local/api',
          asset_type: 'WEB_APPLICATION',
          criticality: 'CRITICAL',
          has_active_findings: true,
          assessment_covered: true,
        },
      ],
      remediation_summary: [
        {
          id: 'rem-1',
          finding_id: 'f-1',
          title: 'Sanitize checkout endpoint arguments',
          action_type: 'CODE_PATCH',
          governance_stage: 'CHANGE_AUTHORIZED',
          status: 'APPROVED',
        },
      ],
      retest_verifications: [
        {
          id: 'ver-1',
          finding_id: 'f-1',
          outcome: 'VERIFIED_FIXED',
          verification_method: 'AUTOMATED_PROBE',
          verified_at: '2026-10-29T11:00:00Z',
        },
      ],
      evidence_manifest: [
        {
          evidence_id: 'ev-01',
          finding_id: 'f-1',
          evidence_type: 'HTTP_EXCHANGE',
          sha256_digest: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
          collected_at: '2026-10-29T10:02:00Z',
          source: 'assessment_probe:scanner.http_header',
          redacted: false,
        },
      ],
      limitations: ['Defensive posture assurance limited to evaluated endpoints.'],
      provenance_digest: '8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4',
    };

    const spy = vi.spyOn(api, 'getCanonicalReport').mockResolvedValue(mockManifest);
    const result = await api.getCanonicalReport('proj-1', 'job-1');

    expect(spy).toHaveBeenCalledWith('proj-1', 'job-1');
    expect(result.schema_version).toBe('1.0.0');
    expect(result.findings.length).toBe(1);
    expect(result.findings[0].severity).toBe('CRITICAL');
    expect(result.evidence_manifest.length).toBe(1);
    expect(result.provenance_digest).toHaveLength(64);
    spy.mockRestore();
  });

  it('should fetch coverage summary and detect incomplete status and evidence gaps', async () => {
    const mockCoverage: ReportCoverageSummary = {
      assessment_id: 'job-incomplete-2',
      target_input: 'https://admin.local',
      status: 'PARTIAL',
      total_targets_assessed: 1,
      total_checks_attempted: 10,
      total_checks_completed: 4,
      checks_failed_count: 2,
      skipped_checks: ['ssl_ciphers', 'dns_zone_transfer'],
      missing_evidence_count: 1,
      coverage_gap_identified: true,
      is_incomplete: true,
      disclaimer: 'Unassessed components are not certified secure.',
    };

    const spy = vi.spyOn(api, 'getReportCoverage').mockResolvedValue(mockCoverage);
    const coverage = await api.getReportCoverage('proj-1', 'job-incomplete-2');

    expect(coverage.is_incomplete).toBe(true);
    expect(coverage.coverage_gap_identified).toBe(true);
    expect(coverage.skipped_checks).toContain('ssl_ciphers');
    expect(coverage.missing_evidence_count).toBe(1);
    spy.mockRestore();
  });

  it('should inspect portable assessment bundle in validation-only mode', async () => {
    const mockVerification: BundleVerificationResult = {
      is_valid: true,
      manifest_version: '1.0.0',
      bundle_version: '1.0.0',
      assessment_id: 'job-1',
      project_id: 'proj-1',
      file_count: 6,
      total_decompressed_bytes: 4520,
      checked_files: ['report.json', 'findings.json', 'evidence_manifest.json', 'assets.json', 'verifications.json', 'sha256sums.txt'],
      corrupted_files: [],
      missing_files: [],
      violations: [],
      assessment_summary: {
        report_id: 'rep-test-01',
        assessment_id: 'job-1',
        status: 'COMPLETED',
        findings_count: 1,
        severity_distribution: { CRITICAL: 1 },
        coverage_gap: false,
      },
      inspection_mode: 'validation_only',
    };

    const spy = vi.spyOn(api, 'verifyBundle').mockResolvedValue(mockVerification);
    const result = await api.verifyBundle('proj-1', 'H4sIC...dummy_base64');

    expect(result.is_valid).toBe(true);
    expect(result.inspection_mode).toBe('validation_only');
    expect(result.checked_files.length).toBe(6);
    expect(result.corrupted_files).toHaveLength(0);
    expect(result.violations).toHaveLength(0);
    spy.mockRestore();
  });

  it('should flag tampered or corrupted bundles during verification', async () => {
    const mockCorrupted: BundleVerificationResult = {
      is_valid: false,
      manifest_version: '1.0.0',
      bundle_version: '1.0.0',
      assessment_id: 'job-corrupt-3',
      project_id: 'proj-1',
      file_count: 6,
      total_decompressed_bytes: 4520,
      checked_files: ['report.json', 'findings.json'],
      corrupted_files: ['findings.json'],
      missing_files: [],
      violations: ['SHA-256 digest mismatch detected for member: findings.json'],
      assessment_summary: null,
      inspection_mode: 'validation_only',
    };

    const spy = vi.spyOn(api, 'verifyBundle').mockResolvedValue(mockCorrupted);
    const result = await api.verifyBundle('proj-1', 'corrupted_bytes');

    expect(result.is_valid).toBe(false);
    expect(result.corrupted_files).toContain('findings.json');
    expect(result.violations[0]).toContain('digest mismatch');
    spy.mockRestore();
  });

  it('should generate assessment-specific canonical report artifacts', async () => {
    const mockResponse = {
      record: {
        id: 'rep-rec-99',
        project_id: 'proj-1',
        assessment_id: 'job-1',
        report_type: 'ASSESSMENT_CANONICAL',
        report_format: 'BUNDLE',
        title: 'Verifiable Assessment Export',
        report_sha256: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
        item_count: 5,
        content_bytes: 8192,
        generated_at: new Date().toISOString(),
      },
      content: 'H4sIC...',
      mime_type: 'application/gzip',
      filename: 'assessment_report_job-1.tar.gz',
    };

    const spy = vi.spyOn(api, 'generateReport').mockResolvedValue(mockResponse);
    const result = await api.generateReport('proj-1', {
      report_type: 'ASSESSMENT_CANONICAL',
      report_format: 'BUNDLE',
      title: 'Verifiable Assessment Export',
      assessment_id: 'job-1',
    });

    expect(result.record.report_format).toBe('BUNDLE');
    expect(result.mime_type).toBe('application/gzip');
    expect(result.filename).toContain('.tar.gz');
    spy.mockRestore();
  });
});
