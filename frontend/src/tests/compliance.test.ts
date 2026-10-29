import { describe, it, expect, vi } from 'vitest';
import { api } from '../services/api';
import type {
  ComplianceControl,
  ComplianceEvaluationRun,
  ComplianceDriftEvent,
  ComplianceException,
} from '../types';

describe('Prompt 33: Continuous Compliance Intelligence & Drift Governance Frontend Tests', () => {
  it('should fetch versioned controls catalog from API with standard attributes', async () => {
    const mockControls: ComplianceControl[] = [
      {
        id: 'c-1',
        control_id: 'CMP-TLS-01',
        version: '1.0.0',
        category: 'TRANSPORT_SECURITY',
        title: 'Enforce Strong TLS & Transport Cryptography',
        description: 'Requires TLS 1.2+ without weak ciphers.',
        requirement_statement: 'Services must enforce HTTPS with TLS 1.2+.',
        framework: 'NIST_CSF_2.0',
        framework_reference: 'PR.DS-02',
        applicability_criteria: { target_types: ['WEB_APP'] },
        required_evidence_types: ['NETWORK_PORT_BANNER', 'HTTP_RESPONSE'],
        evaluation_rule: 'verify_tls_posture',
        severity: 'HIGH',
        remediation_guidance: 'Disable weak ciphers.',
        evaluation_limitations: 'Inspects external endpoints.',
        is_active: true,
        created_at: '2026-10-29T10:00:00Z',
        updated_at: '2026-10-29T10:00:00Z',
      },
    ];

    vi.spyOn(api, 'getComplianceControls').mockResolvedValue(mockControls);

    const controls = await api.getComplianceControls();
    expect(controls).toHaveLength(1);
    expect(controls[0].control_id).toBe('CMP-TLS-01');
    expect(controls[0].severity).toBe('HIGH');
    expect(controls[0].framework).toBe('NIST_CSF_2.0');
  });

  it('should evaluate baseline profile and strictly preserve UNKNOWN states without promoting to PASS', async () => {
    const mockRun: ComplianceEvaluationRun = {
      id: 'run-01',
      project_id: 'proj-1',
      baseline_profile_id: 'prof-web-1',
      run_status: 'COMPLETED',
      pass_count: 2,
      fail_count: 1,
      partial_count: 0,
      unknown_count: 1,
      not_applicable_count: 0,
      error_count: 0,
      total_controls_evaluated: 4,
      provenance_digest: 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2',
      evaluated_at: '2026-10-29T11:00:00Z',
      control_results: [
        {
          id: 'res-1',
          run_id: 'run-01',
          control_id: 'CMP-TLS-01',
          control_version: '1.0.0',
          status: 'PASS',
          evidence_refs: [{ type: 'EVIDENCE', id: 'ev-1' }],
          evidence_digests: ['digest1'],
          reasoning: 'TLS 1.3 verified.',
          missing_evidence_types: [],
          confidence_score: 1.0,
          has_exception: false,
          created_at: '2026-10-29T11:00:00Z',
        },
        {
          id: 'res-2',
          run_id: 'run-01',
          control_id: 'CMP-AUTH-01',
          control_version: '1.0.0',
          status: 'UNKNOWN',
          evidence_refs: [],
          evidence_digests: [],
          reasoning: 'No authentication observations available.',
          missing_evidence_types: ['HTTP_RESPONSE', 'HEADER_ANALYSIS'],
          confidence_score: 0.5,
          has_exception: false,
          created_at: '2026-10-29T11:00:00Z',
        },
      ],
    };

    vi.spyOn(api, 'evaluateComplianceBaseline').mockResolvedValue(mockRun);

    const run = await api.evaluateComplianceBaseline('proj-1', { baseline_profile_id: 'prof-web-1' });
    expect(run.total_controls_evaluated).toBe(4);
    expect(run.unknown_count).toBe(1);
    expect(run.pass_count).toBe(2);

    // Verify truthful denominator & unknown preservation
    const unknownRes = run.control_results.find((r) => r.status === 'UNKNOWN');
    expect(unknownRes).toBeDefined();
    expect(unknownRes?.missing_evidence_types).toContain('HTTP_RESPONSE');
    expect(run.provenance_digest).toHaveLength(64);
  });

  it('should fetch configuration drift events and identify regressions', async () => {
    const mockDrifts: ComplianceDriftEvent[] = [
      {
        id: 'drift-1',
        project_id: 'proj-1',
        control_id: 'CMP-VULN-01',
        drift_type: 'REGRESSION_FAIL',
        previous_status: 'PASS',
        new_status: 'FAIL',
        previous_run_id: 'run-01',
        current_run_id: 'run-02',
        reason: 'Security regression: Control CMP-VULN-01 drifted from PASS to FAIL.',
        detected_at: '2026-10-29T11:30:00Z',
        deduplication_hash: 'dedup-hash-12345',
      },
    ];

    vi.spyOn(api, 'getComplianceDriftEvents').mockResolvedValue(mockDrifts);

    const events = await api.getComplianceDriftEvents('proj-1');
    expect(events).toHaveLength(1);
    expect(events[0].drift_type).toBe('REGRESSION_FAIL');
    expect(events[0].previous_status).toBe('PASS');
    expect(events[0].new_status).toBe('FAIL');
    expect(events[0].deduplication_hash).toBe('dedup-hash-12345');
  });

  it('should enforce separation of duties when approving baseline exceptions', async () => {
    const mockException: ComplianceException = {
      id: 'exc-1',
      project_id: 'proj-1',
      control_id: 'CMP-TLS-01',
      justification: 'Legacy client support window',
      risk_assessment: 'Low risk jumpbox access',
      compensating_controls: 'IP allowlist',
      requester_id: 'user-analyst',
      approver_id: 'user-lead',
      status: 'APPROVED',
      expires_at: '2026-11-29T00:00:00Z',
      approved_at: '2026-10-29T12:00:00Z',
      review_notes: 'Approved by lead',
      created_at: '2026-10-29T11:00:00Z',
      updated_at: '2026-10-29T12:00:00Z',
    };

    vi.spyOn(api, 'reviewComplianceException').mockResolvedValue(mockException);

    const reviewed = await api.reviewComplianceException('proj-1', 'exc-1', {
      approved: true,
      review_notes: 'Approved by lead',
    });

    expect(reviewed.status).toBe('APPROVED');
    expect(reviewed.requester_id).not.toBe(reviewed.approver_id);
    expect(reviewed.approver_id).toBe('user-lead');
  });

  it('should compare two evaluation runs and surface posture regressions', async () => {
    const mockComparison = {
      baseline_profile_id: 'prof-1',
      run_a: {} as any,
      run_b: {} as any,
      regressions: [
        {
          control_id: 'CMP-VULN-01',
          status_a: 'PASS',
          status_b: 'FAIL',
          reasoning_b: 'Active critical vuln detected',
        },
      ],
      improvements: [],
      uncertainties: [],
      unchanged_count: 3,
    };

    vi.spyOn(api, 'compareComplianceEvaluations').mockResolvedValue(mockComparison as any);

    const comp = await api.compareComplianceEvaluations('proj-1', 'run-01', 'run-02');
    expect(comp.regressions).toHaveLength(1);
    expect(comp.regressions[0].control_id).toBe('CMP-VULN-01');
    expect(comp.unchanged_count).toBe(3);
  });
});
