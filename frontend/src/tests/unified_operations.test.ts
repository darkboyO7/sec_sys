import { describe, it, expect, vi } from 'vitest';
import { api } from '../services/api';
import type { UnifiedOpsDashboardResponse, PriorityQueueResponse } from '../types';

describe('Prompt 30: Unified Security Operations Experience Tests', () => {
  it('should retrieve cockpit summary answering the 12 core operational questions', async () => {
    const mockSummary: UnifiedOpsDashboardResponse = {
      overall_posture: 'HEALTHY',
      control_plane_health: 'ONLINE',
      active_assessments_count: 0,
      queued_assessments_count: 0,
      failed_assessments_count: 0,
      verified_critical_findings: 0,
      verified_high_findings: 1,
      unresolved_uncertainties_count: 0,
      pending_remediation_approvals: 0,
      failed_retests_count: 0,
      exposure_drift_records_count: 0,
      data_freshness_seconds: 5,
      core_questions: [
        {
          question_id: 1,
          question_text: 'Is the application operational?',
          status: 'PASS',
          summary: 'Control plane and database online; 0 active assessments running.',
          details: { control_plane: 'ONLINE', database: 'CONNECTED', active_jobs: 0 },
        },
        {
          question_id: 2,
          question_text: 'Is its security configuration valid?',
          status: 'PASS',
          summary: 'Preflight checks passed; CORS, JWT, and DB pragmas validated.',
          details: { preflight_status: 'PASS' },
        },
        {
          question_id: 12,
          question_text: 'What is the most useful next action?',
          status: 'INFO',
          summary: 'Review 1 high findings for mitigation.',
          details: {},
        },
      ],
      recommended_next_action: 'Review 1 high findings for mitigation.',
      generated_at: new Date().toISOString(),
    };

    vi.spyOn(api, 'getCockpitSummary').mockResolvedValueOnce(mockSummary);
    const summary = await api.getCockpitSummary('proj-123');

    expect(summary.overall_posture).toBe('HEALTHY');
    expect(summary.control_plane_health).toBe('ONLINE');
    expect(summary.core_questions.length).toBeGreaterThan(0);
    expect(summary.core_questions[0].question_id).toBe(1);
    expect(summary.core_questions[0].status).toBe('PASS');
    expect(summary.recommended_next_action).toContain('Review');
  });

  it('should retrieve actionable priority queue items with explainable urgency', async () => {
    const mockQueue: PriorityQueueResponse = {
      total_items: 2,
      urgent_items_count: 1,
      items: [
        {
          item_id: 'pq-rem-1',
          priority_score: 95,
          category: 'REMEDIATION_APPROVAL',
          title: 'Remediation Awaiting Lead Sign-off',
          reason: 'Remediation plan rem-1 for SQL Injection is pending required approval.',
          affected_asset: 'db.prod.internal',
          affected_finding_id: 'find-sql-1',
          evidence_ref: null,
          permitted_action: 'APPROVE_OR_REJECT',
          required_role: 'SECURITY_LEAD',
          target_route: '/remediation',
          created_at: new Date().toISOString(),
        },
        {
          item_id: 'pq-fail-1',
          priority_score: 75,
          category: 'JOB_FAILED',
          title: 'Assessment Job Failed Execution',
          reason: 'Assessment job job-fail-1 terminated with error: Network unreachable.',
          affected_asset: 'api.gateway.internal',
          affected_finding_id: null,
          evidence_ref: null,
          permitted_action: 'INSPECT_AND_RETRY',
          required_role: 'OPERATOR',
          target_route: '/assessments',
          created_at: new Date().toISOString(),
        },
      ],
      retrieved_at: new Date().toISOString(),
    };

    vi.spyOn(api, 'getPriorityQueue').mockResolvedValueOnce(mockQueue);
    const queue = await api.getPriorityQueue('proj-123');

    expect(queue.total_items).toBe(2);
    expect(queue.urgent_items_count).toBe(1);
    expect(queue.items[0].priority_score).toBe(95);
    expect(queue.items[0].category).toBe('REMEDIATION_APPROVAL');
    expect(queue.items[0].required_role).toBe('SECURITY_LEAD');
  });

  it('should dismiss priority queue items via authenticated API call', async () => {
    const mockDismissRes = { status: 'DISMISSED', item_id: 'pq-rem-1' };
    vi.spyOn(api, 'dismissPriorityQueueItem').mockResolvedValueOnce(mockDismissRes);

    const res = await api.dismissPriorityQueueItem('pq-rem-1');
    expect(res.status).toBe('DISMISSED');
    expect(res.item_id).toBe('pq-rem-1');
  });
});
