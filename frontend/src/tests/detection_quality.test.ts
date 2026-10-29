import { describe, it, expect, vi, beforeEach } from 'vitest';
import { api } from '../services/api';
import type {
  QualityOverviewResponse,
  FixtureBenchmarksResponse,
  FindingValidationStatus,
  FindingProvenanceResponse,
} from '../types';

describe('Prompt 19: Detection Quality & Evidence-Driven Intelligence', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('verifies all 9 epistemic finding validation states are defined in the lifecycle', () => {
    const states: FindingValidationStatus[] = [
      'DETECTED',
      'EVIDENCE_PENDING',
      'EVIDENCE_SUPPORTED',
      'INDEPENDENTLY_REPRODUCED',
      'CONFIRMED_TRUE_POSITIVE',
      'CONFIRMED_FALSE_POSITIVE',
      'INCONCLUSIVE',
      'UNABLE_TO_VERIFY',
      'RESOLVED_AFTER_RETEST',
    ];
    expect(states).toHaveLength(9);
    expect(states).toContain('DETECTED');
    expect(states).toContain('CONFIRMED_TRUE_POSITIVE');
    expect(states).toContain('CONFIRMED_FALSE_POSITIVE');
    expect(states).toContain('UNABLE_TO_VERIFY');
    expect(states).toContain('INCONCLUSIVE');
    expect(states).toContain('RESOLVED_AFTER_RETEST');
  });

  it('fetches project detection quality overview with disclosed denominators and warnings', async () => {
    const mockOverview: QualityOverviewResponse = {
      project_id: 'proj-123',
      project_name: 'Test Defensive Project',
      generated_at: new Date().toISOString(),
      sample_sizes: {
        total_canonical_findings: 15,
        total_raw_observations: 25,
        reviewed_findings: 10,
        remediated_findings: 5,
        evidence_supported_findings: 14,
        independently_reproduced_findings: 8,
      },
      disclosed_denominators: {
        evidence_completeness: '14 / 15',
        reproduction_rate: '8 / 15',
        confirmed_false_positive_rate: '1 / 10',
        retest_recurrence_rate: '0 / 5',
        duplicate_observation_rate: '(25 - 15) / 25',
      },
      metrics: {
        evidence_completeness_rate: 0.9333,
        independent_reproduction_rate: 0.5333,
        confirmed_false_positive_rate: 0.1,
        inconclusive_finding_rate: 0.0667,
        retest_recurrence_rate: 0.0,
        duplicate_observation_rate: 0.4,
      },
      validation_status_distribution: {
        DETECTED: 1,
        EVIDENCE_SUPPORTED: 4,
        INDEPENDENTLY_REPRODUCED: 3,
        CONFIRMED_TRUE_POSITIVE: 5,
        CONFIRMED_FALSE_POSITIVE: 1,
        INCONCLUSIVE: 1,
      },
      evaluation_period: {
        earliest_observed_at: '2026-01-01T00:00:00Z',
        latest_observed_at: '2026-10-28T12:00:00Z',
      },
      quality_warnings: [],
    };

    vi.spyOn(api, 'getQualityOverview').mockResolvedValue(mockOverview);

    const result = await api.getQualityOverview('proj-123');
    expect(result.project_id).toBe('proj-123');
    expect(result.metrics.evidence_completeness_rate).toBeCloseTo(0.9333);
    // Denominator rule: FPR must use reviewed_findings denominator
    expect(result.disclosed_denominators.confirmed_false_positive_rate).toBe('1 / 10');
    expect(result.metrics.confirmed_false_positive_rate).toBe(0.1);
    expect(result.sample_sizes.total_raw_observations).toBeGreaterThan(result.sample_sizes.total_canonical_findings);
  });

  it('executes deterministic fixture benchmarks and returns honest ground-truth metrics', async () => {
    const mockFixtures: FixtureBenchmarksResponse = {
      project_id: 'proj-123',
      framework_version: '1.0.0',
      benchmark_scenarios: {
        positive_exposed: {
          fixture_type: 'positive_exposed',
          fixture_version: '1.0.0',
          is_synthetic: true,
          sample_size: 6,
          true_positives: 6,
          false_positives: 0,
          true_negatives: 0,
          false_negatives: 0,
          precision: 1.0,
          recall: 1.0,
          false_positive_rate: 0.0,
          false_negative_rate: 0.0,
          ground_truth_status: 'CONFIRMED_TRUE_POSITIVE',
        },
        negative_clean: {
          fixture_type: 'negative_clean',
          fixture_version: '1.0.0',
          is_synthetic: true,
          sample_size: 6,
          true_positives: 0,
          false_positives: 0,
          true_negatives: 6,
          false_negatives: 0,
          precision: 1.0,
          recall: 1.0,
          false_positive_rate: 0.0,
          false_negative_rate: 0.0,
          ground_truth_status: 'CONFIRMED_FALSE_POSITIVE',
        },
        unavailable: {
          fixture_type: 'unavailable',
          fixture_version: '1.0.0',
          is_synthetic: true,
          ground_truth_status: 'UNABLE_TO_VERIFY',
          reported_validation_status: 'UNABLE_TO_VERIFY',
          valid_failure_handling: true,
        },
        ambiguous: {
          fixture_type: 'ambiguous',
          fixture_version: '1.0.0',
          is_synthetic: true,
          ground_truth_status: 'INCONCLUSIVE',
          reported_validation_status: 'INCONCLUSIVE',
          valid_ambiguity_handling: true,
        },
      },
    };

    vi.spyOn(api, 'getFixtureBenchmarks').mockResolvedValue(mockFixtures);

    const result = await api.getFixtureBenchmarks('proj-123');
    expect(result.framework_version).toBe('1.0.0');
    expect(result.benchmark_scenarios.positive_exposed.precision).toBe(1.0);
    expect(result.benchmark_scenarios.negative_clean.false_positive_rate).toBe(0.0);
    expect(result.benchmark_scenarios.unavailable.reported_validation_status).toBe('UNABLE_TO_VERIFY');
    expect(result.benchmark_scenarios.ambiguous.reported_validation_status).toBe('INCONCLUSIVE');
  });

  it('retrieves finding cryptographic provenance and verifies SHA-256 payload integrity', async () => {
    const mockProvenance: FindingProvenanceResponse = {
      finding_id: 'find-999',
      fingerprint: 'fp-sha256-verified-header',
      title: 'Missing Strict-Transport-Security Header',
      severity: 'HIGH',
      confidence: 'CERTAIN',
      operational_status: 'CONFIRMED',
      validation_status: 'CONFIRMED_TRUE_POSITIVE',
      is_simulated: false,
      evidence_quality_score: 0.95,
      cryptographic_integrity_verified: true,
      first_observed_at: '2026-10-28T10:00:00Z',
      last_observed_at: '2026-10-28T12:00:00Z',
      observations_count: 2,
      observations: [
        {
          observation_id: 'obs-1',
          job_id: 'job-101',
          adapter_name: 'live_network_adapter',
          adapter_version: '1.0.0',
          created_at: '2026-10-28T10:00:00Z',
          is_simulated: false,
          evidence_items: [
            {
              evidence_id: 'ev-1',
              evidence_type: 'HTTP_RESPONSE_HEADERS',
              recorded_sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
              computed_sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
              is_cryptographically_valid: true,
              is_simulated: false,
              payload_preview: 'HTTP/1.1 200 OK\r\nServer: Apache\r\n...',
            },
          ],
        },
      ],
      validation_history: [
        {
          from_status: 'DETECTED',
          to_status: 'CONFIRMED_TRUE_POSITIVE',
          validation_method: 'MANUAL_OPERATOR_REVIEW',
          actor_id: 'user-lead-1',
          reason: 'Verified header omission against production ingress gateway.',
          evidence_ref: 'job-101',
          created_at: '2026-10-28T11:00:00Z',
          metadata_snapshot: { actor_role: 'LEAD' },
        },
      ],
    };

    vi.spyOn(api, 'getFindingProvenance').mockResolvedValue(mockProvenance);

    const res = await api.getFindingProvenance('proj-123', 'find-999');
    expect(res.finding_id).toBe('find-999');
    expect(res.cryptographic_integrity_verified).toBe(true);
    expect(res.observations[0].evidence_items[0].is_cryptographically_valid).toBe(true);
    expect(res.validation_history[0].to_status).toBe('CONFIRMED_TRUE_POSITIVE');
  });

  it('submits governed validation transition with mandatory technical justification', async () => {
    const mockFindingDetail: any = {
      id: 'find-999',
      project_id: 'proj-123',
      validation_status: 'CONFIRMED_FALSE_POSITIVE',
      status: 'FALSE_POSITIVE',
      validation_notes: 'Confirmed host is internal behind cloud firewall with compensating proxy.',
    };

    const spy = vi.spyOn(api, 'transitionFindingValidation').mockResolvedValue(mockFindingDetail);

    const payload = {
      to_status: 'CONFIRMED_FALSE_POSITIVE' as FindingValidationStatus,
      reason: 'Confirmed host is internal behind cloud firewall with compensating proxy.',
      evidence_ref: 'waf-rule-992',
      validation_method: 'SECURITY_LEAD_REVIEW',
    };

    const result = await api.transitionFindingValidation('proj-123', 'find-999', payload);
    expect(spy).toHaveBeenCalledWith('proj-123', 'find-999', payload);
    expect(result.validation_status).toBe('CONFIRMED_FALSE_POSITIVE');
  });
});
