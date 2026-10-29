import { describe, it, expect, vi } from 'vitest';
import { api } from '../services/api';
import type {
  AssessmentQueueItem,
  QueueItemPreviewResponse,
  SchedulerCapacity,
  DispatchResultResponse,
  LeaseRecoveryResponse,
} from '../types';

describe('Prompt 34: Intelligent Assessment Scheduling & Orchestration Frontend Tests', () => {
  it('should preview scheduling priority and eligibility without state changes', async () => {
    const mockPreview: QueueItemPreviewResponse = {
      target_input: 'https://staging.internal.corp',
      adapter_name: 'local_fixture_adapter',
      is_eligible: true,
      eligibility_status: 'ELIGIBLE',
      eligibility_reasons: ['Target satisfies all defensive boundaries and scope inclusions.'],
      computed_priority: 75.0,
      priority_band: 'HIGH',
      priority_explanation: 'Base: 20 + Criticality: 20 + Freshness: 20 + Findings: 15',
      priority_factors: {
        base_score: { value: 20, contribution: 20 },
        asset_criticality: { raw_value: 'HIGH', contribution: 20 },
        evidence_staleness: { raw_value: 'COVERAGE_GAP_NO_PRIOR_SCAN', contribution: 20 },
        finding_severity: { raw_value: 'HIGH', contribution: 15 },
      },
      policy_version: 'scheduling_v1.0',
    };

    vi.spyOn(api, 'previewScheduling').mockResolvedValue(mockPreview);

    const res = await api.previewScheduling('proj-123', {
      target_input: 'https://staging.internal.corp',
      adapter_name: 'local_fixture_adapter',
    });

    expect(res.is_eligible).toBe(true);
    expect(res.computed_priority).toBe(75.0);
    expect(res.priority_band).toBe('HIGH');
    expect(res.priority_factors.asset_criticality.contribution).toBe(20);
  });

  it('should list queue items with deterministic priority scores and status badges', async () => {
    const mockItems: AssessmentQueueItem[] = [
      {
        id: 'q-item-1',
        project_id: 'proj-123',
        schedule_name: 'High-Priority Reassessment',
        target_input: 'https://api.internal.corp',
        adapter_name: 'local_fixture_adapter',
        adapter_version: '1.0.0',
        status: 'SCHEDULED',
        priority_score: 85.0,
        priority_band: 'CRITICAL',
        priority_explanation: 'Priority 85.0 (CRITICAL) computed with active critical findings.',
        priority_factors: { base_score: { contribution: 20 } },
        policy_version: 'scheduling_v1.0',
        eligibility_status: 'ELIGIBLE',
        eligibility_reasons: ['Permitted'],
        concurrency_key: 'a1b2c3d4e5f6g7h8',
        attempt_count: 0,
        retry_count: 0,
        max_retries: 3,
        backoff_seconds: 30,
        next_eligible_at: '2026-10-29T12:00:00Z',
        execution_budget_seconds: 600,
        created_by_id: 'usr-1',
        created_at: '2026-10-29T11:50:00Z',
        updated_at: '2026-10-29T11:50:00Z',
      },
    ];

    vi.spyOn(api, 'listQueueItems').mockResolvedValue(mockItems);

    const items = await api.listQueueItems('proj-123', { status: 'SCHEDULED' });
    expect(items).toHaveLength(1);
    expect(items[0].priority_score).toBe(85.0);
    expect(items[0].priority_band).toBe('CRITICAL');
    expect(items[0].status).toBe('SCHEDULED');
  });

  it('should retrieve scheduler capacity and active slot allocations', async () => {
    const mockCapacity: SchedulerCapacity = {
      project_id: 'proj-123',
      max_concurrent_assessments: 5,
      current_running_assessments: 2,
      available_capacity: 3,
      total_queued_items: 4,
      active_by_target: { 'https://api.internal.corp': 1, 'https://auth.internal.corp': 1 },
      active_by_adapter: { local_fixture_adapter: 2 },
      queue_utilization_pct: 4.0,
      stale_unclaimed_leases: 0,
    };

    vi.spyOn(api, 'getSchedulerCapacity').mockResolvedValue(mockCapacity);

    const cap = await api.getSchedulerCapacity('proj-123');
    expect(cap.max_concurrent_assessments).toBe(5);
    expect(cap.current_running_assessments).toBe(2);
    expect(cap.available_capacity).toBe(3);
    expect(cap.active_by_target['https://api.internal.corp']).toBe(1);
  });

  it('should dispatch next eligible job with worker lease expiration metadata', async () => {
    const mockDispatch: DispatchResultResponse = {
      dispatched: true,
      message: 'Job dispatched successfully',
      job_id: 'job-789',
      queue_item: {
        id: 'q-item-1',
        project_id: 'proj-123',
        schedule_name: 'Ad-Hoc Assessment',
        target_input: 'https://api.internal.corp',
        adapter_name: 'local_fixture_adapter',
        adapter_version: '1.0.0',
        status: 'DISPATCHED',
        priority_score: 70.0,
        priority_band: 'HIGH',
        priority_explanation: 'High priority dispatch',
        priority_factors: {},
        policy_version: 'scheduling_v1.0',
        eligibility_status: 'ELIGIBLE',
        eligibility_reasons: [],
        concurrency_key: 'hash123',
        worker_claim_id: 'worker-local-01',
        claimed_at: '2026-10-29T12:00:00Z',
        lease_expires_at: '2026-10-29T12:02:00Z',
        attempt_count: 1,
        retry_count: 0,
        max_retries: 3,
        backoff_seconds: 30,
        next_eligible_at: '2026-10-29T12:00:00Z',
        execution_budget_seconds: 600,
        job_id: 'job-789',
        created_by_id: 'usr-1',
        created_at: '2026-10-29T11:55:00Z',
        updated_at: '2026-10-29T12:00:00Z',
      },
    };

    vi.spyOn(api, 'dispatchNextJob').mockResolvedValue(mockDispatch);

    const res = await api.dispatchNextJob('proj-123', 'worker-local-01');
    expect(res.dispatched).toBe(true);
    expect(res.job_id).toBe('job-789');
    expect(res.queue_item?.worker_claim_id).toBe('worker-local-01');
    expect(res.queue_item?.status).toBe('DISPATCHED');
  });

  it('should recover stale leases and report recovered and dead-letter counts', async () => {
    const mockRecovery: LeaseRecoveryResponse = {
      recovered_count: 2,
      dead_letter_count: 1,
      recovered_ids: ['q-1', 'q-2'],
      dead_letter_ids: ['q-3'],
    };

    vi.spyOn(api, 'recoverStaleLeases').mockResolvedValue(mockRecovery);

    const res = await api.recoverStaleLeases('proj-123');
    expect(res.recovered_count).toBe(2);
    expect(res.dead_letter_count).toBe(1);
    expect(res.recovered_ids).toContain('q-1');
  });

  it('should cancel active or scheduled queue item and reflect cancellation status', async () => {
    const mockCancelled: AssessmentQueueItem = {
      id: 'q-item-1',
      project_id: 'proj-123',
      schedule_name: 'Ad-Hoc Assessment',
      target_input: 'https://api.internal.corp',
      adapter_name: 'local_fixture_adapter',
      adapter_version: '1.0.0',
      status: 'CANCELLED',
      priority_score: 50.0,
      priority_band: 'MEDIUM',
      priority_explanation: 'Standard priority',
      priority_factors: {},
      policy_version: 'scheduling_v1.0',
      eligibility_status: 'ELIGIBLE',
      eligibility_reasons: [],
      concurrency_key: 'hash123',
      attempt_count: 0,
      retry_count: 0,
      max_retries: 3,
      backoff_seconds: 30,
      next_eligible_at: '2026-10-29T12:00:00Z',
      execution_budget_seconds: 600,
      cancellation_requested_at: '2026-10-29T12:05:00Z',
      cancellation_reason: 'Operator cancelled',
      cancelled_at: '2026-10-29T12:05:00Z',
      created_by_id: 'usr-1',
      created_at: '2026-10-29T12:00:00Z',
      updated_at: '2026-10-29T12:05:00Z',
    };

    vi.spyOn(api, 'cancelQueueItem').mockResolvedValue(mockCancelled);

    const res = await api.cancelQueueItem('proj-123', 'q-item-1', 'Operator cancelled');
    expect(res.status).toBe('CANCELLED');
    expect(res.cancellation_reason).toBe('Operator cancelled');
    expect(res.cancelled_at).not.toBeNull();
  });
});
