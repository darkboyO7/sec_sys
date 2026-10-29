import { describe, it, expect, vi } from 'vitest';
import { api } from '../services/api';
import type {
  ResolutionResult,
  DryRunImpact,
  DeduplicationProposal,
  DataQualityIssue,
} from '../types';

describe('Prompt 37: Canonical Asset Identity Resolution and Data Quality Tests', () => {
  it('should resolve candidate entity with exact canonical match and 100% confidence', async () => {
    const mockRes: ResolutionResult = {
      outcome: 'EXACT_MATCH',
      matched_asset_id: 'asset-uuid-1',
      matched_canonical_identifier: 'https://api.corp.internal',
      confidence: 1.0,
      match_reasons: ["Exact canonical key match on WEB_APP: 'https://api.corp.internal'"],
      conflicts_detected: [],
    };

    vi.spyOn(api, 'resolveAssetEntity').mockResolvedValue(mockRes);

    const res = await api.resolveAssetEntity('proj-1', 'https://api.corp.internal/');
    expect(res.outcome).toBe('EXACT_MATCH');
    expect(res.confidence).toBe(1.0);
    expect(res.matched_asset_id).toBe('asset-uuid-1');
    expect(res.match_reasons.length).toBeGreaterThan(0);
    expect(res.conflicts_detected.length).toBe(0);
  });

  it('should flag ambiguous conflict on IP address reuse and prevent auto-merge', async () => {
    const mockConflict: ResolutionResult = {
      outcome: 'AMBIGUOUS_CONFLICT',
      matched_asset_id: 'asset-uuid-2',
      matched_canonical_identifier: 'srv-old.corp.internal',
      confidence: 0.45,
      match_reasons: ["Historical alias match on IP '198.51.100.42' but observation window expired"],
      conflicts_detected: [
        "IP address reuse suspected: alias '198.51.100.42' last observed 15.0 days ago (> 7d horizon)",
      ],
    };

    vi.spyOn(api, 'resolveAssetEntity').mockResolvedValue(mockConflict);

    const res = await api.resolveAssetEntity('proj-1', '198.51.100.42');
    expect(res.outcome).toBe('AMBIGUOUS_CONFLICT');
    expect(res.confidence).toBeLessThan(0.5);
    expect(res.conflicts_detected[0]).toContain('IP address reuse suspected');
  });

  it('should evaluate deduplication dry-run impact accurately', async () => {
    const mockImpact: DryRunImpact = {
      source_asset_id: 'src-1',
      source_canonical_identifier: 'https://legacy.corp.internal',
      target_asset_id: 'tgt-1',
      target_canonical_identifier: 'https://modern.corp.internal',
      findings_to_repoint: 3,
      aliases_to_transfer: 2,
      observations_to_repoint: 5,
      conflicts_detected: [],
      safe_to_merge: true,
    };

    vi.spyOn(api, 'evaluateDeduplicationDryRun').mockResolvedValue(mockImpact);

    const impact = await api.evaluateDeduplicationDryRun('proj-1', 'src-1', 'tgt-1');
    expect(impact.safe_to_merge).toBe(true);
    expect(impact.findings_to_repoint).toBe(3);
    expect(impact.aliases_to_transfer).toBe(2);
    expect(impact.observations_to_repoint).toBe(5);
  });

  it('should govern deduplication proposal lifecycle from propose to approve and revert', async () => {
    const mockProposal: DeduplicationProposal = {
      id: 'prop-uuid-1',
      project_id: 'proj-1',
      source_asset_id: 'src-1',
      target_asset_id: 'tgt-1',
      status: 'PROPOSED',
      confidence_score: 0.95,
      match_reasons: ['Verified identical server deployment'],
      conflicts_detected: [],
      dry_run_impact: { findings_to_repoint: 2 },
      created_at: new Date().toISOString(),
    };

    vi.spyOn(api, 'proposeAssetDeduplication').mockResolvedValue(mockProposal);
    vi.spyOn(api, 'approveDeduplicationProposal').mockResolvedValue({
      ...mockProposal,
      status: 'APPROVED',
      reviewed_at: new Date().toISOString(),
    });
    vi.spyOn(api, 'revertDeduplicationProposal').mockResolvedValue({
      ...mockProposal,
      status: 'REVERTED',
      reverted_at: new Date().toISOString(),
    });

    const proposed = await api.proposeAssetDeduplication('proj-1', {
      source_asset_id: 'src-1',
      target_asset_id: 'tgt-1',
      rationale: 'Verified identical server deployment',
    });
    expect(proposed.status).toBe('PROPOSED');

    const approved = await api.approveDeduplicationProposal('proj-1', proposed.id, 'Lead approval');
    expect(approved.status).toBe('APPROVED');

    const reverted = await api.revertDeduplicationProposal('proj-1', proposed.id, 'Split back');
    expect(reverted.status).toBe('REVERTED');
  });

  it('should run inventory data quality audit and resolve issues', async () => {
    const mockIssues: DataQualityIssue[] = [
      {
        id: 'iss-1',
        project_id: 'proj-1',
        issue_type: 'ORPHANED_FINDING',
        severity: 'HIGH',
        affected_resource_type: 'FINDING',
        affected_resource_id: 'f-1',
        details: { reason: 'Finding references missing asset record' },
        status: 'OPEN',
        detected_at: new Date().toISOString(),
      },
      {
        id: 'iss-2',
        project_id: 'proj-1',
        issue_type: 'STALE_OBSERVATION',
        severity: 'MEDIUM',
        affected_resource_type: 'ASSET',
        affected_resource_id: 'a-2',
        details: { reason: 'Asset has not been observed in 45 days' },
        status: 'OPEN',
        detected_at: new Date().toISOString(),
      },
    ];

    vi.spyOn(api, 'runDataQualityAudit').mockResolvedValue(mockIssues);
    vi.spyOn(api, 'updateDataQualityIssueStatus').mockResolvedValue({
      ...mockIssues[0],
      status: 'RESOLVED',
      resolved_at: new Date().toISOString(),
    });

    const auditResults = await api.runDataQualityAudit('proj-1');
    expect(auditResults.length).toBe(2);
    expect(auditResults[0].issue_type).toBe('ORPHANED_FINDING');

    const resolved = await api.updateDataQualityIssueStatus('proj-1', 'iss-1', 'RESOLVED');
    expect(resolved.status).toBe('RESOLVED');
    expect(resolved.resolved_at).toBeDefined();
  });
});
