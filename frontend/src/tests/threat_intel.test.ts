import { describe, it, expect, vi } from 'vitest';
import { api } from '../services/api';
import type {
  ThreatFeed,
  ThreatFeedSyncResponse,
  ThreatIntelligenceRecord,
  ThreatCorrelation,
  ThreatCorrelationRunResponse,
  ThreatIntelSummary,
} from '../types';

describe('Prompt 35: Evidence-Grounded Threat Intelligence and Vulnerability Correlation Tests', () => {
  it('should list authoritative feeds and accurately detect fresh vs stale status', async () => {
    const mockFeeds: ThreatFeed[] = [
      {
        id: 'feed-cisa',
        feed_name: 'CISA_KEV',
        feed_url: 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
        is_authoritative: true,
        sync_status: 'SYNCED',
        record_count: 4,
        last_sync_started_at: '2026-10-28T12:00:00Z',
        last_synced_at: '2026-10-28T12:01:00Z',
        last_sync_error: null,
        stale_after_days: 7,
        is_stale: false,
        feed_checksum: 'a1b2c3d4e5f67890abcdef1234567890abcdef1234567890abcdef1234567890',
      },
      {
        id: 'feed-nvd',
        feed_name: 'NVD_CVE',
        feed_url: 'https://services.nvd.nist.gov/rest/json/cves/2.0',
        is_authoritative: true,
        sync_status: 'STALE',
        record_count: 4,
        last_sync_started_at: '2026-10-10T12:00:00Z',
        last_synced_at: '2026-10-10T12:01:00Z',
        last_sync_error: null,
        stale_after_days: 7,
        is_stale: true,
        feed_checksum: 'f6e5d4c3b2a10987abcdef1234567890abcdef1234567890abcdef1234567890',
      },
    ];

    vi.spyOn(api, 'listThreatFeeds').mockResolvedValue(mockFeeds);

    const feeds = await api.listThreatFeeds();
    expect(feeds.length).toBe(2);
    expect(feeds[0].feed_name).toBe('CISA_KEV');
    expect(feeds[0].is_stale).toBe(false);
    expect(feeds[1].feed_name).toBe('NVD_CVE');
    expect(feeds[1].is_stale).toBe(true);
  });

  it('should synchronize threat feed and return cryptographic checksum and ingest counts', async () => {
    const mockSync: ThreatFeedSyncResponse = {
      feed_name: 'CISA_KEV',
      records_ingested: 4,
      records_updated: 0,
      sync_status: 'SYNCED',
      checksum: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      message: 'Successfully synced feed CISA_KEV: 4 ingested, 0 updated',
    };

    vi.spyOn(api, 'syncThreatFeed').mockResolvedValue(mockSync);

    const res = await api.syncThreatFeed('CISA_KEV', { force_local: true });
    expect(res.feed_name).toBe('CISA_KEV');
    expect(res.records_ingested).toBe(4);
    expect(res.sync_status).toBe('SYNCED');
    expect(res.checksum).toBeDefined();
  });

  it('should search threat intelligence records by CVE ID and verify CISA KEV active status', async () => {
    const mockRecords: ThreatIntelligenceRecord[] = [
      {
        id: 'intel-cve-2024-3400',
        cve_id: 'CVE-2024-3400',
        source: 'CISA_KEV',
        title: 'Palo Alto Networks PAN-OS GlobalProtect Command Injection Vulnerability',
        description: 'Command injection vulnerability in PAN-OS GlobalProtect',
        vendor: 'Palo Alto Networks',
        product: 'PAN-OS',
        cpe: 'cpe:2.3:o:paloaltonetworks:pan-os:*:*:*:*:*:*:*:*',
        version_start_including: '10.2.0',
        version_end_excluding: '10.2.9-h1',
        version_end_including: null,
        affected_versions_list: [],
        cvss_score: 10.0,
        cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
        epss_score: 0.9412,
        epss_percentile: 0.9985,
        is_known_exploited: true,
        cisa_kev_due_date: '2024-04-19T00:00:00Z',
        cisa_kev_action: 'Apply mitigations per vendor instructions',
        published_at: '2024-04-12T00:00:00Z',
        modified_at: null,
        retrieved_at: '2026-10-28T12:00:00Z',
        confidence: 1.0,
        provenance_url: 'https://nvd.nist.gov/vuln/detail/CVE-2024-3400',
      },
    ];

    vi.spyOn(api, 'searchThreatRecords').mockResolvedValue(mockRecords);

    const res = await api.searchThreatRecords({ cve_id: 'CVE-2024-3400' });
    expect(res.length).toBe(1);
    expect(res[0].cve_id).toBe('CVE-2024-3400');
    expect(res[0].is_known_exploited).toBe(true);
    expect(res[0].product).toBe('PAN-OS');
    expect(res[0].cvss_score).toBe(10.0);
    expect(res[0].epss_score).toBe(0.9412);
  });

  it('should enforce non-destructive risk enrichment while preserving original finding severity', async () => {
    const mockCorrelations: ThreatCorrelation[] = [
      {
        id: 'corr-1',
        project_id: 'proj-123',
        finding_id: 'finding-panos-1',
        finding_title: 'Unauthenticated Command Injection in GlobalProtect',
        finding_severity: 'HIGH', // Original finding severity is preserved as HIGH!
        threat_intel_id: 'intel-cve-2024-3400',
        cve_id: 'CVE-2024-3400',
        match_classification: 'CONFIRMED_MATCH',
        confidence_score: 0.98,
        evidence_grounding: {
          matched_cve: 'CVE-2024-3400',
          intel_product: 'PAN-OS',
          version_evidence: {
            observed_version: '10.2.1',
            in_range: true,
            status: 'CONFIRMED_AFFECTED',
          },
          resemblance_check: {
            resemblance_rejected: false,
          },
        },
        enriched_risk_score: 95.0,
        risk_enrichment_factors: {
          base_finding_severity: 'HIGH',
          base_score: 60.0,
          is_known_exploited: true,
          cisa_kev_boost: 25.0,
          epss_score: 0.9412,
          epss_boost: 14.12,
          asset_criticality: 'CRITICAL',
          asset_criticality_boost: 15.0,
          match_multiplier: 1.0,
          unaltered_finding_severity: 'HIGH',
          explanation: 'Finding severity remains HIGH. Enriched risk score 95/100 incorporates active exploitation (+25).',
        },
        is_known_exploited: true,
        epss_score: 0.9412,
        correlated_at: '2026-10-28T12:00:00Z',
      },
    ];

    vi.spyOn(api, 'listProjectThreatCorrelations').mockResolvedValue(mockCorrelations);

    const corrs = await api.listProjectThreatCorrelations('proj-123');
    expect(corrs.length).toBe(1);
    expect(corrs[0].finding_severity).toBe('HIGH'); // Authoritative severity untouched
    expect(corrs[0].enriched_risk_score).toBe(95.0);
    expect(corrs[0].match_classification).toBe('CONFIRMED_MATCH');
    expect(corrs[0].is_known_exploited).toBe(true);
    expect(corrs[0].evidence_grounding.version_evidence.in_range).toBe(true);
  });

  it('should verify resemblance rejection invariant and conflicting observation classification', async () => {
    const mockCorrelations: ThreatCorrelation[] = [
      {
        id: 'corr-resemblance-rejected',
        project_id: 'proj-123',
        finding_id: 'finding-custom-lib',
        finding_title: 'Outdated custom libssl wrapper',
        finding_severity: 'LOW',
        threat_intel_id: 'intel-openssl',
        cve_id: 'CVE-2023-48795',
        match_classification: 'UNKNOWN_MATCH',
        confidence_score: 0.0,
        evidence_grounding: {
          resemblance_check: {
            observed_product: 'libssl-wrapper-custom',
            authoritative_product: 'OpenSSH',
            resemblance_rejected: true,
            resemblance_reason: 'Rejected resemblance: observed product is not an exact match',
          },
        },
        enriched_risk_score: 2.0,
        risk_enrichment_factors: {
          unaltered_finding_severity: 'LOW',
        },
        is_known_exploited: false,
        epss_score: null,
        correlated_at: '2026-10-28T12:00:00Z',
      },
      {
        id: 'corr-conflicting',
        project_id: 'proj-123',
        finding_id: 'finding-conflict-banner',
        finding_title: 'Web server banner mismatch',
        finding_severity: 'MEDIUM',
        threat_intel_id: 'intel-cve-2021-44228',
        cve_id: 'CVE-2021-44228',
        match_classification: 'CONFLICTING_DATA',
        confidence_score: 0.35,
        evidence_grounding: {
          conflict_details: ['Scanner A reported Log4j v2.14, Scanner B reported Log4j v2.17'],
        },
        enriched_risk_score: 32.0,
        risk_enrichment_factors: {
          match_multiplier: 0.40,
        },
        is_known_exploited: true,
        epss_score: 0.9754,
        correlated_at: '2026-10-28T12:00:00Z',
      },
    ];

    vi.spyOn(api, 'listProjectThreatCorrelations').mockResolvedValue(mockCorrelations);

    const corrs = await api.listProjectThreatCorrelations('proj-123');
    const rejected = corrs.find((c) => c.match_classification === 'UNKNOWN_MATCH');
    expect(rejected).toBeDefined();
    expect(rejected?.evidence_grounding.resemblance_check.resemblance_rejected).toBe(true);

    const conflicting = corrs.find((c) => c.match_classification === 'CONFLICTING_DATA');
    expect(conflicting).toBeDefined();
    expect(conflicting?.confidence_score).toBeLessThan(0.5);
  });

  it('should fetch project threat intel summary and trigger correlation run', async () => {
    const mockSummary: ThreatIntelSummary = {
      total_cves: 4,
      known_exploited_count: 3,
      active_feeds_count: 3,
      stale_feeds_count: 0,
      total_project_correlations: 2,
      confirmed_correlations_count: 1,
      possible_correlations_count: 0,
      conflicting_correlations_count: 1,
    };

    const mockRun: ThreatCorrelationRunResponse = {
      project_id: 'proj-123',
      findings_evaluated: 5,
      correlations_created: 2,
      confirmed_matches: 1,
      possible_matches: 0,
      conflicting_data: 1,
      unknown_or_rejected: 3,
      message: 'Evaluated 5 findings: 1 confirmed, 0 possible, 1 conflicting',
    };

    vi.spyOn(api, 'getThreatIntelSummary').mockResolvedValue(mockSummary);
    vi.spyOn(api, 'runProjectThreatCorrelation').mockResolvedValue(mockRun);

    const summary = await api.getThreatIntelSummary('proj-123');
    expect(summary.total_cves).toBe(4);
    expect(summary.known_exploited_count).toBe(3);

    const runRes = await api.runProjectThreatCorrelation('proj-123', { force_recorrelate: true });
    expect(runRes.findings_evaluated).toBe(5);
    expect(runRes.confirmed_matches).toBe(1);
  });
});
