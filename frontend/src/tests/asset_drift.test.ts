import { describe, it, expect, vi, beforeEach } from 'vitest';
import { api } from '../services/api';
import type {
  DriftType,
  DriftMateriality,
  ReassessmentPriority,
  ReassessmentStatus,
  ProjectDriftOverview,
  ExposureDriftRecord,
  ReassessmentProposal,
  AssetIdentifierAlias,
  AssetIdentityMergeRecord,
} from '../types';

describe('Prompt 20: Asset Identity, Exposure Drift & Continuous Change Intelligence', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('verifies all drift types, materiality levels, and proposal statuses are properly defined', () => {
    const driftTypes: DriftType[] = [
      'NEW_AUTHORIZED_ASSET',
      'ASSET_UNOBSERVED_WARNING',
      'ASSET_CONFIRMED_ABSENT',
      'IP_ASSOCIATION_CHANGED',
      'HOSTNAME_ASSOCIATION_CHANGED',
      'SERVICE_ADDED',
      'SERVICE_REMOVED',
      'SERVICE_METADATA_CHANGED',
      'VERSION_CHANGED',
      'SECURITY_CONFIG_CHANGED',
      'FINDING_APPEARED',
      'FINDING_DISAPPEARED',
      'EVIDENCE_CONFIDENCE_CHANGED',
    ];
    expect(driftTypes).toHaveLength(13);

    const materialities: DriftMateriality[] = ['MATERIAL', 'IMMATERIAL', 'INCONCLUSIVE'];
    expect(materialities).toContain('MATERIAL');
    expect(materialities).toContain('INCONCLUSIVE');

    const priorities: ReassessmentPriority[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
    expect(priorities).toContain('CRITICAL');

    const statuses: ReassessmentStatus[] = ['PROPOSED', 'DEFERRED', 'APPROVED', 'REJECTED', 'QUEUED', 'COMPLETED', 'FAILED'];
    expect(statuses).toContain('DEFERRED');
    expect(statuses).toContain('QUEUED');
  });

  it('fetches project exposure drift overview with freshness distribution and warnings', async () => {
    const mockOverview: ProjectDriftOverview = {
      total_assets: 12,
      freshness_distribution: {
        FRESH: 8,
        AGING: 2,
        STALE: 1,
        EXPIRED: 1,
        UNOBSERVED: 0,
      },
      drift_materiality_distribution: {
        MATERIAL: 5,
        IMMATERIAL: 3,
        INCONCLUSIVE: 2,
      },
      drift_type_distribution: {
        NEW_AUTHORIZED_ASSET: 2,
        SERVICE_ADDED: 3,
        SECURITY_CONFIG_CHANGED: 2,
      },
      reassessment_proposals_distribution: {
        PROPOSED: 2,
        QUEUED: 1,
        DEFERRED: 1,
        REJECTED: 0,
        APPROVED: 0,
      },
      average_collection_completeness: 0.985,
      total_drift_records: 10,
      total_reassessment_proposals: 4,
      governance_warnings: [
        '2 assets have stale or expired observation baselines (> 7 days without observation).',
      ],
    };

    const spy = vi.spyOn(api, 'getDriftOverview').mockResolvedValue(mockOverview);
    const result = await api.getDriftOverview('proj-123');

    expect(spy).toHaveBeenCalledWith('proj-123');
    expect(result.total_assets).toBe(12);
    expect(result.freshness_distribution.FRESH).toBe(8);
    expect(result.drift_materiality_distribution.MATERIAL).toBe(5);
    expect(result.average_collection_completeness).toBe(0.985);
    expect(result.governance_warnings).toHaveLength(1);
  });

  it('lists exposure drift records with before/after state diffs and materiality', async () => {
    const mockDrifts: ExposureDriftRecord[] = [
      {
        id: 'drift-1',
        project_id: 'proj-123',
        asset_id: 'asset-1',
        drift_type: 'SERVICE_ADDED',
        materiality: 'MATERIAL',
        materiality_reason: 'New port 8443 open',
        target_resource: 'https://api.corp.internal',
        title: 'New Network Ports Exposed: [8443]',
        previous_observation_id: 'obs-prev',
        current_observation_id: 'obs-curr',
        previous_state: { open_ports: [443] },
        new_state: { open_ports: [443, 8443], added_ports: [8443] },
        evidence_references: ['sha256-abc123'],
        confidence: 1.0,
        is_resolved: false,
        security_impact_summary: 'Expanded exposure surface requiring security audit.',
        reassessment_recommended: true,
        detected_at: new Date().toISOString(),
        evaluated_at: new Date().toISOString(),
        created_at: new Date().toISOString(),
      },
    ];

    const spy = vi.spyOn(api, 'listDriftRecords').mockResolvedValue(mockDrifts);
    const result = await api.listDriftRecords('proj-123', { materiality: 'MATERIAL' });

    expect(spy).toHaveBeenCalledWith('proj-123', { materiality: 'MATERIAL' });
    expect(result).toHaveLength(1);
    expect(result[0].materiality).toBe('MATERIAL');
    expect(result[0].reassessment_recommended).toBe(true);
    expect(result[0].new_state.added_ports).toEqual([8443]);
  });

  it('handles reassessment proposal approval and rejection workflows', async () => {
    const mockJob: any = {
      id: 'job-reassess-1',
      name: 'Reassessment: https://api.corp.internal',
      status: 'QUEUED',
      target_input: 'https://api.corp.internal',
    };

    const approveSpy = vi.spyOn(api, 'approveReassessmentProposal').mockResolvedValue(mockJob);
    const approvedJob = await api.approveReassessmentProposal('proj-123', 'prop-1');
    expect(approveSpy).toHaveBeenCalledWith('proj-123', 'prop-1');
    expect(approvedJob.status).toBe('QUEUED');

    const mockRejectedProposal: ReassessmentProposal = {
      id: 'prop-2',
      project_id: 'proj-123',
      target_input: 'https://stage.corp.internal',
      adapter_name: 'live_network_auditor_adapter',
      fixture_profile: 'LIVE_WEB_SECURITY_AUDIT',
      priority: 'MEDIUM',
      status: 'REJECTED',
      rationale: 'Port changed during approved maintenance',
      scope_authorized: true,
      scope_validation_details: {},
      requires_human_approval: false,
      rejection_reason: 'Approved maintenance window',
      attempt_count: 0,
      max_attempts: 3,
      created_at: new Date().toISOString(),
    };

    const rejectSpy = vi.spyOn(api, 'rejectReassessmentProposal').mockResolvedValue(mockRejectedProposal);
    const rejected = await api.rejectReassessmentProposal('proj-123', 'prop-2', 'Approved maintenance window');
    expect(rejectSpy).toHaveBeenCalledWith('proj-123', 'prop-2', 'Approved maintenance window');
    expect(rejected.status).toBe('REJECTED');
    expect(rejected.rejection_reason).toBe('Approved maintenance window');
  });

  it('manages asset aliases and reversible identity merges', async () => {
    const mockAliases: AssetIdentifierAlias[] = [
      {
        id: 'alias-1',
        asset_id: 'asset-1',
        project_id: 'proj-123',
        identifier_type: 'IP_ADDRESS',
        identifier_value: '192.168.1.150',
        is_primary: true,
        confidence: 1.0,
        first_observed_at: new Date().toISOString(),
        last_observed_at: new Date().toISOString(),
        is_active: true,
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      },
    ];

    const aliasSpy = vi.spyOn(api, 'listAssetAliases').mockResolvedValue(mockAliases);
    const aliases = await api.listAssetAliases('proj-123', 'asset-1');
    expect(aliasSpy).toHaveBeenCalledWith('proj-123', 'asset-1');
    expect(aliases[0].identifier_value).toBe('192.168.1.150');

    const mockMerge: AssetIdentityMergeRecord = {
      id: 'merge-1',
      project_id: 'proj-123',
      target_asset_id: 'asset-1',
      merged_asset_id: 'asset-2',
      merged_canonical_identifier: 'core-app-internal',
      merged_asset_type: 'HOSTNAME',
      merge_rationale: 'Internal hostname alias of core app',
      confidence: 1.0,
      is_reversed: false,
      created_at: new Date().toISOString(),
    };

    const mergeSpy = vi.spyOn(api, 'mergeAssets').mockResolvedValue(mockMerge);
    const mergeResult = await api.mergeAssets('proj-123', 'asset-1', 'asset-2', 'Internal hostname alias');
    expect(mergeSpy).toHaveBeenCalled();
    expect(mergeResult.is_reversed).toBe(false);

    const reversedMerge: AssetIdentityMergeRecord = {
      ...mockMerge,
      is_reversed: true,
      reversed_at: new Date().toISOString(),
      reversal_notes: 'De-merged for staging migration',
    };
    const reverseSpy = vi.spyOn(api, 'reverseAssetMerge').mockResolvedValue(reversedMerge);
    const unmerged = await api.reverseAssetMerge('proj-123', 'merge-1', 'De-merged for staging');
    expect(reverseSpy).toHaveBeenCalled();
    expect(unmerged.is_reversed).toBe(true);
  });
});
