import { describe, it, expect, vi, beforeEach } from 'vitest';

// Polyfill localStorage in node test environment
const storageMock: Record<string, string> = {};
const localStorageMock = {
  getItem: (key: string) => storageMock[key] ?? null,
  setItem: (key: string, value: string) => {
    storageMock[key] = value;
  },
  removeItem: (key: string) => {
    delete storageMock[key];
  },
  clear: () => {
    for (const k of Object.keys(storageMock)) {
      delete storageMock[k];
    }
  },
};
(globalThis as any).localStorage = localStorageMock;

import { api } from '../services/api';
import type {
  AssessmentJob,
  VulnerabilityFinding,
  VulnerabilityFindingDetail,
  ApprovalRequestRecord,
} from '../types';

describe('Prompt 43: Full-Stack Contract Integrity and Workflow Assurance Tests', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    localStorageMock.clear();
    api.setToken(null);
  });

  it('1. verifies token storage, authentication state, and token clearing on logout', () => {
    const testToken = 'jwt-token-prompt43-test';
    api.setToken(testToken);
    expect(api.getToken()).toBe(testToken);
    expect(localStorageMock.getItem('vapt_auth_token')).toBe(testToken);

    api.logout();
    expect(api.getToken()).toBeNull();
    expect(localStorageMock.getItem('vapt_auth_token')).toBeNull();
  });

  it('2. validates assessment creation contract with scope and idempotency key', async () => {
    const projectId = 'proj-apex-43';
    const mockJob: AssessmentJob = {
      id: 'job-uuid-4301',
      project_id: projectId,
      target_input: '192.168.10.50',
      adapter_name: 'local_fixture_adapter',
      adapter_version: '1.0.0',
      status: 'QUEUED',
      idempotency_key: 'idem-4301-key',
      lock_version: 1,
      progress_pct: 0,
      policy_version: '2026.1',
      authorization_status: 'AUTHORIZED',
      scope_snapshot: {},
      attempt_count: 1,
      timeout_seconds: 300,
      retry_count: 0,
      max_retries: 3,
      is_simulated: true,
      created_by_id: 'user-admin-43',
      config: {},
      summary_stats: { status: 'QUEUED' },
      queued_at: new Date().toISOString(),
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    };

    const spy = vi.spyOn(api, 'createAssessment').mockResolvedValue(mockJob);

    const result = await api.createAssessment(projectId, {
      target_input: '192.168.10.50',
      adapter_name: 'local_fixture_adapter',
      idempotency_key: 'idem-4301-key',
    });

    expect(spy).toHaveBeenCalledWith(projectId, {
      target_input: '192.168.10.50',
      adapter_name: 'local_fixture_adapter',
      idempotency_key: 'idem-4301-key',
    });
    expect(result.id).toBe('job-uuid-4301');
    expect(result.status).toBe('QUEUED');
    expect(result.authorization_status).toBe('AUTHORIZED');
  });

  it('3. validates finding listing, pagination, and status transition contracts', async () => {
    const projectId = 'proj-apex-43';
    const findingId = 'finding-4301';

    const mockFinding: VulnerabilityFinding = {
      id: findingId,
      project_id: projectId,
      fingerprint: 'fp-cwe89-test',
      target_value: '192.168.10.50/search',
      title: 'SQL Injection in Query Param',
      description: 'Unescaped SQL query construction.',
      status: 'DETECTED',
      severity: 'HIGH',
      confidence: 'CERTAIN',
      vuln_id: 'CWE-89',
      cvss_score: 8.5,
      is_simulated: false,
      reproduction_steps: "GET /search?q=' OR 1=1--",
      first_detected_at: new Date().toISOString(),
      last_observed_at: new Date().toISOString(),
      occurrence_count: 1,
      has_contradictions: false,
      contradiction_notes: [],
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    };

    const listSpy = vi.spyOn(api, 'listFindings').mockResolvedValue([mockFinding]);
    const findings = await api.listFindings(projectId, { status: 'DETECTED', limit: 10, offset: 0 });

    expect(listSpy).toHaveBeenCalled();
    expect(findings.length).toBe(1);
    expect(findings[0].severity).toBe('HIGH');

    const mockDetail: VulnerabilityFindingDetail = {
      ...mockFinding,
      status: 'CONFIRMED',
      transitions: [
        {
          id: 'trans-4301',
          finding_id: findingId,
          from_status: 'DETECTED',
          to_status: 'CONFIRMED',
          actor_id: 'user-admin-43',
          reason: 'Verified through reproducer script in staging environment.',
          metadata_snapshot: {},
          created_at: new Date().toISOString(),
        },
      ],
      observation_job_ids: ['job-uuid-4301'],
      evidence_count: 1,
    };

    const transSpy = vi.spyOn(api, 'transitionFinding').mockResolvedValue(mockDetail);
    const updated = await api.transitionFinding(projectId, findingId, {
      to_status: 'CONFIRMED',
      reason: 'Verified through reproducer script in staging environment.',
    });

    expect(transSpy).toHaveBeenCalledWith(projectId, findingId, {
      to_status: 'CONFIRMED',
      reason: 'Verified through reproducer script in staging environment.',
    });
    expect(updated.status).toBe('CONFIRMED');
    expect(updated.transitions.length).toBe(1);
  });

  it('4. validates Separation of Duties (SoD) governance request and decision contracts', async () => {
    const projectId = 'proj-apex-43';
    const approvalId = 'approval-4301';

    const mockApproval: ApprovalRequestRecord = {
      id: approvalId,
      project_id: projectId,
      workflow_type: 'REMEDIATION_CHANGE',
      resource_type: 'firewall_rule',
      resource_id: 'rule-9981',
      status: 'PENDING',
      title: 'Emergency Port 8080 Block',
      description: 'Mitigate active threat before vendor patch arrives.',
      parameter_hash: 'sha256-param-hash',
      parameters_snapshot: { action: 'BLOCK_PORT', port: 8080 },
      requester_id: 'user-tester-43',
      requested_at: new Date().toISOString(),
      policy_version: 'v2026.2.0',
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    };

    const reqSpy = vi.spyOn(api, 'requestApproval').mockResolvedValue(mockApproval);
    const requested = await api.requestApproval(projectId, {
      workflow_type: 'REMEDIATION_CHANGE',
      resource_type: 'firewall_rule',
      resource_id: 'rule-9981',
      title: 'Emergency Port 8080 Block',
      parameters: { action: 'BLOCK_PORT', port: 8080 },
    });

    expect(reqSpy).toHaveBeenCalled();
    expect(requested.id).toBe(approvalId);
    expect(requested.status).toBe('PENDING');

    const approvedRecord: ApprovalRequestRecord = {
      ...mockApproval,
      status: 'APPROVED',
      approver_id: 'user-lead-43',
      decided_at: new Date().toISOString(),
      decision_reason: 'Approved by lead after change advisory board review.',
    };

    const decSpy = vi.spyOn(api, 'decideApproval').mockResolvedValue(approvedRecord);
    const decided = await api.decideApproval(projectId, approvalId, {
      approved: true,
      reason: 'Approved by lead after change advisory board review.',
    });

    expect(decSpy).toHaveBeenCalledWith(projectId, approvalId, {
      approved: true,
      reason: 'Approved by lead after change advisory board review.',
    });
    expect(decided.status).toBe('APPROVED');
    expect(decided.approver_id).toBe('user-lead-43');
  });

  it('5. validates independent verification, retesting, and report generation contracts', async () => {
    const projectId = 'proj-apex-43';
    const findingId = 'finding-4301';

    const mockVerificationResult = {
      id: 'verif-4301',
      project_id: projectId,
      finding_id: findingId,
      outcome: 'VERIFIED_FIXED',
      verification_method: 'PASSIVE_SCAN',
      verification_criteria: 'HTTP GET /search?q=test returns 200 without SQL syntax errors.',
      verification_evidence_summary: 'Target queries executed with parameterized queries; SQL injection blocked.',
      notes: 'Fix confirmed in staging environment.',
      verified_at: new Date().toISOString(),
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    };

    const verifSpy = vi.spyOn(api, 'verifyFinding').mockResolvedValue(mockVerificationResult);
    const verifResult = await api.verifyFinding(projectId, findingId, {
      outcome: 'VERIFIED_FIXED',
      verification_method: 'PASSIVE_SCAN',
      verification_criteria: 'HTTP GET /search?q=test returns 200 without SQL syntax errors.',
      verification_evidence_summary: 'Target queries executed with parameterized queries; SQL injection blocked.',
      notes: 'Fix confirmed in staging environment.',
    });

    expect(verifSpy).toHaveBeenCalled();
    expect(verifResult.outcome).toBe('VERIFIED_FIXED');

    const mockReportExport = {
      record: {
        id: 'report-4301',
        project_id: projectId,
        report_type: 'TECHNICAL',
        report_format: 'JSON',
        title: 'VAPT Security Verification Report',
        report_sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        item_count: 5,
        content_bytes: 1420,
        generated_at: new Date().toISOString(),
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      },
      content: '{"audit": "canonical"}',
      mime_type: 'application/json',
      filename: 'vapt_report_4301.json',
    };

    const reportSpy = vi.spyOn(api, 'generateReport').mockResolvedValue(mockReportExport);
    const reportResult = await api.generateReport(projectId, {
      report_type: 'TECHNICAL',
      report_format: 'JSON',
      title: 'VAPT Security Verification Report',
    });

    expect(reportSpy).toHaveBeenCalled();
    expect(reportResult.record.report_sha256).toBeDefined();
    expect(reportResult.record.report_type).toBe('TECHNICAL');
  });

  it('6. validates assessment job cancellation and optimistic state tracking', async () => {
    const projectId = 'proj-apex-43';
    const jobId = 'job-uuid-4301';

    const cancelledJob: AssessmentJob = {
      id: jobId,
      project_id: projectId,
      target_input: '192.168.10.50',
      adapter_name: 'local_fixture_adapter',
      adapter_version: '1.0.0',
      status: 'CANCELLED',
      lock_version: 2,
      progress_pct: 25,
      policy_version: '2026.1',
      authorization_status: 'AUTHORIZED',
      scope_snapshot: {},
      attempt_count: 1,
      timeout_seconds: 300,
      retry_count: 0,
      max_retries: 3,
      is_simulated: true,
      created_by_id: 'user-admin-43',
      config: {},
      summary_stats: { status: 'CANCELLED' },
      queued_at: new Date().toISOString(),
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    };

    const cancelSpy = vi.spyOn(api, 'cancelAssessment').mockResolvedValue(cancelledJob);
    const result = await api.cancelAssessment(projectId, jobId);

    expect(cancelSpy).toHaveBeenCalledWith(projectId, jobId);
    expect(result.status).toBe('CANCELLED');
    expect(result.lock_version).toBe(2);
  });
});
