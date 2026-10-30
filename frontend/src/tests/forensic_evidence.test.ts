import { describe, it, expect, vi, beforeEach } from 'vitest';
import { api } from '../services/api';
import type {
  ForensicEvidenceRecord,
  EvidenceIngestRequest,
  EvidenceNormalizeRequest,
  EvidenceContradictionRequest,
  ForensicVerificationReportItem,
  EvidenceExportBundle,
  EvidenceImportResult,
} from '../types';

describe('Prompt 48: Forensic Evidence Preservation & Chain of Custody Frontend Service', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('ingestForensicEvidence posts payload and initializes INGESTED record', async () => {
    const mockRecord: ForensicEvidenceRecord = {
      id: 'fe-001',
      project_id: 'proj-123',
      evidence_type: 'RAW_HTTP',
      raw_payload: 'GET /status HTTP/1.1\r\nHost: target.corp\r\n\r\n',
      raw_digest_sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      source_identity: 'zap-scanner',
      adapter_version: '2.14.0',
      collection_time: '2026-10-30T07:00:00Z',
      ingestion_time: '2026-10-30T07:01:00Z',
      assessment_context: { target: 'target.corp' },
      transformation_history: [],
      origin_signature: 'sig_hex_valid',
      signing_key_id: 'KEY-DEFAULT-ED25519',
      signature_algorithm: 'ED25519',
      lifecycle_state: 'INGESTED',
      last_verification_status: 'NOT_CHECKED',
      contradiction_status: 'SUPPORTING',
      classification: 'RESTRICTED',
      is_contradictory: false,
      is_redacted: false,
      is_archived: false,
      is_deleted: false,
      created_at: '2026-10-30T07:01:00Z',
      updated_at: '2026-10-30T07:01:00Z',
    };

    const requestSpy = vi.spyOn(api as any, 'request').mockResolvedValue(mockRecord);

    const req: EvidenceIngestRequest = {
      project_id: 'proj-123',
      evidence_type: 'RAW_HTTP',
      raw_payload: 'GET /status HTTP/1.1\r\nHost: target.corp\r\n\r\n',
      source_identity: 'zap-scanner',
      adapter_version: '2.14.0',
      collection_time: '2026-10-30T07:00:00Z',
    };

    const res = await api.ingestForensicEvidence(req);
    expect(requestSpy).toHaveBeenCalledWith('/forensic-evidence/records', {
      method: 'POST',
      body: JSON.stringify(req),
    });
    expect(res.id).toBe('fe-001');
    expect(res.lifecycle_state).toBe('INGESTED');
    expect(res.last_verification_status).toBe('NOT_CHECKED');
    expect(res.raw_payload).toContain('GET /status');
  });

  it('normalizeForensicEvidence stores derived representation without overwriting raw payload', async () => {
    const mockNormalized: ForensicEvidenceRecord = {
      id: 'fe-001',
      project_id: 'proj-123',
      evidence_type: 'RAW_HTTP',
      raw_payload: 'GET /status HTTP/1.1\r\nHost: target.corp\r\n\r\n',
      raw_digest_sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      normalized_payload: { method: 'GET', path: '/status', host: 'target.corp' },
      normalized_digest_sha256: 'norm_hash_123',
      source_identity: 'zap-scanner',
      adapter_version: '2.14.0',
      collection_time: '2026-10-30T07:00:00Z',
      ingestion_time: '2026-10-30T07:01:00Z',
      assessment_context: {},
      transformation_history: [
        {
          step: 'NORMALIZATION',
          transformer: 'http-parser',
          version: '1.0',
          reason: 'Extract request tokens',
          timestamp: '2026-10-30T07:02:00Z',
          actor: 'analyst@corp.com',
        },
      ],
      origin_signature: 'sig_hex_valid',
      signing_key_id: 'KEY-DEFAULT-ED25519',
      signature_algorithm: 'ED25519',
      lifecycle_state: 'NORMALIZED',
      last_verification_status: 'NOT_CHECKED',
      contradiction_status: 'SUPPORTING',
      classification: 'RESTRICTED',
      is_contradictory: false,
      is_redacted: false,
      is_archived: false,
      is_deleted: false,
      created_at: '2026-10-30T07:01:00Z',
      updated_at: '2026-10-30T07:02:00Z',
    };

    const requestSpy = vi.spyOn(api as any, 'request').mockResolvedValue(mockNormalized);

    const normReq: EvidenceNormalizeRequest = {
      normalized_payload: { method: 'GET', path: '/status', host: 'target.corp' },
      transformer_identity: 'http-parser',
      adapter_version: '1.0',
      reason: 'Extract request tokens',
    };

    const res = await api.normalizeForensicEvidence('fe-001', normReq);
    expect(requestSpy).toHaveBeenCalledWith('/forensic-evidence/records/fe-001/normalize', {
      method: 'POST',
      body: JSON.stringify(normReq),
    });
    expect(res.lifecycle_state).toBe('NORMALIZED');
    expect(res.raw_payload).toContain('GET /status');
    expect(res.normalized_payload?.method).toBe('GET');
    expect(res.transformation_history.length).toBe(1);
  });

  it('recordEvidenceContradiction attaches divergent observation with prior link', async () => {
    const mockContradiction: ForensicEvidenceRecord = {
      id: 'fe-002',
      project_id: 'proj-123',
      evidence_type: 'PORT_STATE',
      raw_payload: 'PORT 8080/tcp FILTERED',
      raw_digest_sha256: 'contra_hash_456',
      source_identity: 'scanner-run-2',
      adapter_version: '1.0',
      collection_time: '2026-10-30T07:10:00Z',
      ingestion_time: '2026-10-30T07:11:00Z',
      assessment_context: {},
      transformation_history: [],
      origin_signature: 'contra_sig_hex',
      signing_key_id: 'KEY-DEFAULT-ED25519',
      signature_algorithm: 'ED25519',
      lifecycle_state: 'INGESTED',
      last_verification_status: 'NOT_CHECKED',
      contradiction_status: 'SUPERSEDED',
      prior_evidence_id: 'fe-001',
      is_contradictory: true,
      contradiction_notes: 'Port firewalled during follow-up scan',
      classification: 'RESTRICTED',
      is_redacted: false,
      is_archived: false,
      is_deleted: false,
      created_at: '2026-10-30T07:11:00Z',
      updated_at: '2026-10-30T07:11:00Z',
    };

    const requestSpy = vi.spyOn(api as any, 'request').mockResolvedValue(mockContradiction);

    const contraReq: EvidenceContradictionRequest = {
      contradictory_payload: 'PORT 8080/tcp FILTERED',
      source_identity: 'scanner-run-2',
      adapter_version: '1.0',
      collection_time: '2026-10-30T07:10:00Z',
      notes: 'Port firewalled during follow-up scan',
      supersedes_previous: true,
    };

    const res = await api.recordEvidenceContradiction('fe-001', contraReq);
    expect(requestSpy).toHaveBeenCalledWith('/forensic-evidence/records/fe-001/contradiction', {
      method: 'POST',
      body: JSON.stringify(contraReq),
    });
    expect(res.is_contradictory).toBe(true);
    expect(res.prior_evidence_id).toBe('fe-001');
    expect(res.contradiction_status).toBe('SUPERSEDED');
  });

  it('verifyForensicEvidence returns cryptographic verification status and discrepancies', async () => {
    const mockReportItem: ForensicVerificationReportItem = {
      evidence_id: 'fe-001',
      status: 'VERIFIED',
      raw_digest_match: true,
      signature_valid: true,
      custody_chain_valid: true,
      artifacts_present: true,
      contradiction_status: 'SUPPORTING',
      discrepancies: [],
    };

    const requestSpy = vi.spyOn(api as any, 'request').mockResolvedValue(mockReportItem);

    const res = await api.verifyForensicEvidence('fe-001', {
      verify_raw_digest: true,
      verify_origin_signature: true,
      verify_custody_chain: true,
    });
    expect(requestSpy).toHaveBeenCalledWith('/forensic-evidence/records/fe-001/verify', {
      method: 'POST',
      body: JSON.stringify({
        verify_raw_digest: true,
        verify_origin_signature: true,
        verify_custody_chain: true,
      }),
    });
    expect(res.status).toBe('VERIFIED');
    expect(res.raw_digest_match).toBe(true);
    expect(res.signature_valid).toBe(true);
    expect(res.custody_chain_valid).toBe(true);
  });

  it('exportForensicEvidence and importForensicEvidence roundtrip verifiable bundles', async () => {
    const mockBundle: EvidenceExportBundle = {
      export_version: '1.0',
      exported_at: '2026-10-30T07:20:00Z',
      exported_by: 'lead@corp.com',
      record_count: 1,
      records: [{ id: 'fe-001', raw_payload: 'sample' }],
      custody_events: [{ id: 'ce-001', event_type: 'INGESTION' }],
      bundle_digest_sha256: 'bundle_hash_789',
      bundle_signature: 'bundle_sig_hex',
      signing_key_id: 'KEY-DEFAULT-ED25519',
    };

    const mockImportRes: EvidenceImportResult = {
      imported_count: 1,
      verification_passed: true,
      evidence_ids: ['fe-imported-001'],
      warnings: [],
    };

    const exportSpy = vi.spyOn(api as any, 'request').mockResolvedValue(mockBundle);
    const bundle = await api.exportForensicEvidence('proj-123');
    expect(exportSpy).toHaveBeenCalledWith('/forensic-evidence/export?project_id=proj-123', {
      method: 'POST',
    });
    expect(bundle.record_count).toBe(1);

    const importSpy = vi.spyOn(api as any, 'request').mockResolvedValue(mockImportRes);
    const impRes = await api.importForensicEvidence(bundle, 'proj-target');
    expect(importSpy).toHaveBeenCalledWith('/forensic-evidence/import', {
      method: 'POST',
      body: JSON.stringify({ bundle, target_project_id: 'proj-target' }),
    });
    expect(impRes.verification_passed).toBe(true);
    expect(impRes.imported_count).toBe(1);
  });
});
