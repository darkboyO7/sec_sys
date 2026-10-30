import { describe, it, expect, vi, beforeEach } from 'vitest';
import { api } from '../services/api';
import type {
  AttackSurfaceExposure,
  AssetInclusionProposal,
  AttackSurfaceTimelineEvent,
  AttackSurfaceEvidenceSummary,
} from '../types';

describe('Prompt 46: Authorized Attack-Surface Inventory and Exposure Governance', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    if (typeof window !== 'undefined') {
      window.localStorage.clear();
    }
  });

  it('fetches authorized attack surface inventory with freshness and classification filters', async () => {
    const mockExposures: AttackSurfaceExposure[] = [
      {
        id: 'exp-001',
        project_id: 'proj-123',
        asset_id: 'asset-456',
        canonical_identifier: 'api.authorized.corp',
        service_name: 'https',
        port: 443,
        protocol: 'tcp',
        transport_security: 'TLS_1_3',
        exposure_classification: 'INTERNET_FACING',
        provenance_type: 'VERIFIED_OBSERVATION',
        freshness: 'FRESH',
        certificate_details: {
          subject: 'CN=api.authorized.corp',
          issuer: 'Let\'s Encrypt Authority X3',
          fingerprint_sha256: 'aaaa1111bbbb2222',
        },
        relevant_hostnames: ['api.authorized.corp'],
        evidence_hashes: ['sha256_hash_1', 'sha256_hash_2'],
        attributes: { banner: 'nginx/1.24.0' },
        observation_count: 5,
        consecutive_absences: 0,
        is_simulated: false,
        first_observed_at: '2026-10-30T00:00:00Z',
        last_observed_at: '2026-10-30T01:00:00Z',
        created_at: '2026-10-30T00:00:00Z',
        updated_at: '2026-10-30T01:00:00Z',
      },
    ];

    const requestSpy = vi.spyOn(api as any, 'request').mockResolvedValue(mockExposures);

    const inventory = await api.getAttackSurfaceInventory('proj-123', {
      freshness: 'FRESH',
      classification: 'INTERNET_FACING',
      provenance: 'VERIFIED_OBSERVATION',
    });

    expect(requestSpy).toHaveBeenCalledWith(
      '/projects/proj-123/attack-surface/inventory?freshness=FRESH&classification=INTERNET_FACING&provenance=VERIFIED_OBSERVATION'
    );
    expect(inventory).toHaveLength(1);
    expect(inventory[0].port).toBe(443);
    expect(inventory[0].transport_security).toBe('TLS_1_3');
    expect(inventory[0].provenance_type).toBe('VERIFIED_OBSERVATION');
  });

  it('queries asset exposure evidence breakdown and historical timeline events', async () => {
    const mockEvidence: AttackSurfaceEvidenceSummary = {
      asset_id: 'asset-456',
      canonical_identifier: 'api.authorized.corp',
      total_exposures: 2,
      exposures: [],
      distinct_evidence_hashes: ['sha256_hash_1', 'sha256_hash_2'],
    };

    const mockTimeline: AttackSurfaceTimelineEvent[] = [
      {
        timestamp: '2026-10-30T00:00:00Z',
        event_type: 'SERVICE_FIRST_OBSERVED',
        description: 'First observed https on 443/tcp',
        port: 443,
        protocol: 'tcp',
      },
      {
        timestamp: '2026-10-30T01:00:00Z',
        event_type: 'CERTIFICATE_RENEWAL',
        description: 'TLS certificate renewed',
        port: 443,
        protocol: 'tcp',
      },
    ];

    const requestSpy = vi
      .spyOn(api as any, 'request')
      .mockResolvedValueOnce(mockEvidence)
      .mockResolvedValueOnce(mockTimeline);

    const evidence = await api.getAssetExposureEvidence('proj-123', 'asset-456');
    const timeline = await api.getAttackSurfaceTimeline('proj-123', 25);

    expect(requestSpy).toHaveBeenNthCalledWith(
      1,
      '/projects/proj-123/attack-surface/assets/asset-456/evidence'
    );
    expect(requestSpy).toHaveBeenNthCalledWith(
      2,
      '/projects/proj-123/attack-surface/timeline?limit=25'
    );

    expect(evidence.distinct_evidence_hashes).toEqual(['sha256_hash_1', 'sha256_hash_2']);
    expect(timeline).toHaveLength(2);
    expect(timeline[1].event_type).toBe('CERTIFICATE_RENEWAL');
  });

  it('manages asset inclusion proposal lifecycle with explicit authorization approval', async () => {
    const mockProposals: AssetInclusionProposal[] = [
      {
        id: 'prop-001',
        project_id: 'proj-123',
        target_type: 'DOMAIN',
        target_value: 'discovered-subdomain.authorized.corp',
        discovery_source: 'CERTIFICATE_TRANSPARENCY',
        provenance_type: 'PASSIVE_CERTIFICATE_TRANSPARENCY',
        status: 'PENDING',
        rationale: 'Discovered from Subject Alternative Name SAN list',
        discovered_at: '2026-10-30T00:00:00Z',
        evidence_hash: 'sha256_ct_log_proof',
        is_simulated: false,
        created_at: '2026-10-30T00:00:00Z',
        updated_at: '2026-10-30T00:00:00Z',
      },
    ];

    const mockApprovalResult = {
      proposal: {
        ...mockProposals[0],
        status: 'APPROVED' as const,
        reviewed_by_id: 'user-lead-01',
        approval_notes: 'Verified ownership with cloud platform team',
      },
      scope_target_id: 'scope-tgt-888',
    };

    const requestSpy = vi
      .spyOn(api as any, 'request')
      .mockResolvedValueOnce(mockProposals)
      .mockResolvedValueOnce(mockApprovalResult);

    const pending = await api.listInclusionProposals('proj-123', 'PENDING');
    expect(pending).toHaveLength(1);
    expect(pending[0].status).toBe('PENDING');

    const approval = await api.approveInclusionProposal('proj-123', 'prop-001', {
      approval_notes: 'Verified ownership with cloud platform team',
      authorized_evidence: 'ROE-2026-SAN-INCLUSION',
    });

    expect(requestSpy).toHaveBeenNthCalledWith(
      2,
      '/projects/proj-123/attack-surface/proposals/prop-001/approve',
      expect.objectContaining({
        method: 'POST',
        body: JSON.stringify({
          approval_notes: 'Verified ownership with cloud platform team',
          authorized_evidence: 'ROE-2026-SAN-INCLUSION',
        }),
      })
    );
    expect(approval.proposal.status).toBe('APPROVED');
    expect(approval.scope_target_id).toBe('scope-tgt-888');
  });
});
