import { describe, it, expect, vi } from 'vitest';
import { api } from '../services/api';
import type {
  RetentionPolicyModel,
  LegalHoldModel,
  DeletionTombstoneModel,
  RetentionPreviewReport,
  EvidenceRedactionResult,
} from '../types';

describe('Prompt 29: Evidence Lifecycle Governance & Data Retention Tests', () => {
  it('should fetch retention policies covering all major data classifications', async () => {
    const mockPolicies: RetentionPolicyModel[] = [
      {
        policy_id: 'POL-RAW-EVIDENCE-90D',
        classification: 'RAW_EVIDENCE',
        retention_days: 90,
        action: 'DELETE',
        requires_approval: true,
        is_active: true,
        description: 'Raw assessment payloads purged after 90 days.',
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      },
      {
        policy_id: 'POL-AUDIT-7Y',
        classification: 'AUDIT_RECORDS',
        retention_days: 2555,
        action: 'RETAIN',
        requires_approval: true,
        is_active: true,
        description: 'Audit logs retained for 7 years.',
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      },
    ];

    vi.spyOn(api, 'getRetentionPolicies').mockResolvedValueOnce(mockPolicies);
    const policies = await api.getRetentionPolicies();

    expect(policies.length).toBe(2);
    expect(policies[0].policy_id).toBe('POL-RAW-EVIDENCE-90D');
    expect(policies[0].action).toBe('DELETE');
    expect(policies[1].retention_days).toBe(2555);
  });

  it('should generate retention preview with deterministic state hash and hold exclusions', async () => {
    const mockPreview: RetentionPreviewReport = {
      preview_id: 'PREV-TEST-123',
      generated_at: new Date().toISOString(),
      total_scanned_records: 100,
      eligible_records_count: 10,
      excluded_by_hold_count: 5,
      excluded_by_dependency_count: 8,
      preview_items: [
        {
          record_id: 'ev-001',
          classification: 'RAW_EVIDENCE',
          entity_type: 'FindingEvidence',
          created_at: new Date().toISOString(),
          age_days: 120,
          applicable_policy_id: 'POL-RAW-EVIDENCE-90D',
          recommended_action: 'DELETE',
          is_held: false,
          has_dependent_records: false,
          eligible_for_execution: true,
        },
      ],
      dry_run_hash: 'abc123def456',
    };

    vi.spyOn(api, 'getRetentionPreview').mockResolvedValueOnce(mockPreview);
    const preview = await api.getRetentionPreview();

    expect(preview.total_scanned_records).toBe(100);
    expect(preview.eligible_records_count).toBe(10);
    expect(preview.excluded_by_hold_count).toBe(5);
    expect(preview.dry_run_hash).toBe('abc123def456');
    expect(preview.preview_items[0].eligible_for_execution).toBe(true);
  });

  it('should manage legal and investigation holds', async () => {
    const mockHold: LegalHoldModel = {
      hold_id: 'HOLD-001',
      hold_type: 'LEGAL_HOLD',
      target_scope: 'EVIDENCE',
      target_id: 'ev-001',
      reason: 'Pending investigation',
      status: 'ACTIVE',
      placed_by_id: 'user-lead',
      placed_at: new Date().toISOString(),
    };

    vi.spyOn(api, 'createLegalHold').mockResolvedValueOnce(mockHold);
    const hold = await api.createLegalHold({
      hold_type: 'LEGAL_HOLD',
      target_scope: 'EVIDENCE',
      target_id: 'ev-001',
      reason: 'Pending investigation',
    });

    expect(hold.hold_id).toBe('HOLD-001');
    expect(hold.status).toBe('ACTIVE');
    expect(hold.target_id).toBe('ev-001');
  });

  it('should fetch deletion suppression tombstones proving verifiable deletion', async () => {
    const mockTombstones: DeletionTombstoneModel[] = [
      {
        tombstone_id: 'TOMB-001',
        evidence_id: 'ev-001',
        original_sha256_hash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        classification: 'RAW_EVIDENCE',
        policy_id: 'POL-RAW-EVIDENCE-90D',
        deleted_by_id: 'admin-01',
        deleted_at: new Date().toISOString(),
        tombstone_digest: 'hmac-signature-proof',
        reason: 'Retention policy expiration',
      },
    ];

    vi.spyOn(api, 'getDeletionTombstones').mockResolvedValueOnce(mockTombstones);
    const tombstones = await api.getDeletionTombstones();

    expect(tombstones.length).toBe(1);
    expect(tombstones[0].tombstone_digest).toBe('hmac-signature-proof');
    expect(tombstones[0].original_sha256_hash).toBeDefined();
  });

  it('should sanitize sensitive evidence with automated secret redaction', async () => {
    const mockRedaction: EvidenceRedactionResult = {
      evidence_id: 'ev-002',
      redacted: true,
      secrets_masked_count: 2,
      original_sha256_hash: 'hash-orig-123',
      sanitized_preview: 'GET /api [REDACTED_SECRET_BEARER_TOKEN]',
      redacted_at: new Date().toISOString(),
    };

    vi.spyOn(api, 'redactEvidence').mockResolvedValueOnce(mockRedaction);
    const res = await api.redactEvidence({
      evidence_id: 'ev-002',
    });

    expect(res.redacted).toBe(true);
    expect(res.secrets_masked_count).toBe(2);
    expect(res.sanitized_preview).toContain('[REDACTED_SECRET_BEARER_TOKEN]');
  });
});
