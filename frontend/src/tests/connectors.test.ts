import { describe, it, expect, vi } from 'vitest';
import { api } from '../services/api';
import type {
  ConnectorInventoryItem,
  ConnectorConfigRead,
  ConnectorHealthRead,
  ConnectorSyncTriggerResponse,
  ConnectorSyncEventRead,
} from '../types';

describe('Prompt 40: Secure Integration Framework and Connector Contracts Frontend Tests', () => {
  it('should fetch connector inventory with truthful implementation status and capabilities', async () => {
    const mockInventory: ConnectorInventoryItem[] = [
      {
        provider_type: 'CISA_KEV',
        name: 'CISA Known Exploited Vulnerabilities',
        version: '1.0.0',
        supported_capabilities: ['PULL_THREAT_INTEL', 'TEST_CONNECTIVITY'],
        implementation_status: 'IMPLEMENTED',
        description: 'Authoritative feed of actively exploited vulnerabilities.',
        limitations: null,
        config_schema: { feed_url: 'https://www.cisa.gov/...' },
      },
      {
        provider_type: 'CLOUD_ASSET_INVENTORY',
        name: 'Cloud Asset Inventory Connector',
        version: '1.0.0',
        supported_capabilities: ['PULL_ASSETS', 'TEST_CONNECTIVITY'],
        implementation_status: 'IMPLEMENTED',
        description: 'Synchronizes compute instances without mutating scope.',
        limitations: null,
        config_schema: { cloud_provider: 'AWS' },
      },
      {
        provider_type: 'QUALYS_VM_MOCK',
        name: 'Qualys VMDR Connector',
        version: '0.9.0',
        supported_capabilities: ['PULL_FINDINGS', 'TEST_CONNECTIVITY'],
        implementation_status: 'SIMULATED',
        description: 'Simulated integration with Qualys API.',
        limitations: 'Simulated sandbox implementation.',
        config_schema: {},
      },
      {
        provider_type: 'CROWDSTRIKE_FALCON',
        name: 'CrowdStrike Falcon Host Source',
        version: '1.0.0',
        supported_capabilities: ['PULL_ASSETS', 'TEST_CONNECTIVITY'],
        implementation_status: 'DISABLED',
        description: 'Host asset inventory discovery.',
        limitations: 'Disabled by security policy.',
        config_schema: {},
      },
    ];

    vi.spyOn(api, 'getConnectorInventory').mockResolvedValue(mockInventory);

    const res = await api.getConnectorInventory('proj-1');
    expect(res.length).toBe(4);
    expect(res[0].provider_type).toBe('CISA_KEV');
    expect(res[0].implementation_status).toBe('IMPLEMENTED');
    expect(res[2].implementation_status).toBe('SIMULATED');
    expect(res[3].implementation_status).toBe('DISABLED');
  });

  it('should list and configure connectors with masked credentials', async () => {
    const mockConnector: ConnectorConfigRead = {
      id: 'conn-1',
      project_id: 'proj-1',
      name: 'AWS Production Inventory',
      provider_type: 'CLOUD_ASSET_INVENTORY',
      version: '1.0.0',
      enabled: true,
      capabilities: ['PULL_ASSETS', 'TEST_CONNECTIVITY'],
      config_schema_version: '1.0.0',
      settings_masked: {
        cloud_provider: 'AWS',
        api_endpoint: 'https://ec2.us-east-1.amazonaws.com',
        access_key_id: 'AKI****5678',
      },
      rate_limit_per_minute: 60,
      timeout_seconds: 10.0,
      max_retries: 3,
      max_response_size_kb: 10240,
      last_sync_at: null,
      last_sync_watermark: null,
      last_health_status: 'CONFIGURED',
      last_health_message: null,
      consecutive_failures: 0,
      created_at: '2026-10-29T12:00:00Z',
      updated_at: '2026-10-29T12:00:00Z',
    };

    vi.spyOn(api, 'listConnectors').mockResolvedValue([mockConnector]);

    const list = await api.listConnectors('proj-1');
    expect(list.length).toBe(1);
    expect(list[0].name).toBe('AWS Production Inventory');
    expect(list[0].settings_masked.access_key_id).toContain('****');
  });

  it('should perform connectivity check with SSRF safety verification', async () => {
    const mockHealth: ConnectorHealthRead = {
      connector_id: 'conn-webhook-1',
      name: 'SIEM Webhook',
      provider_type: 'WEBHOOK_NOTIFIER',
      status: 'HEALTHY',
      latency_ms: 18.4,
      message: 'Webhook destination verified and authorized by SSRF defense policy',
      error_category: null,
      details: { destination_url: 'https://siem.corp.internal/events' },
    };

    vi.spyOn(api, 'testConnector').mockResolvedValue(mockHealth);

    const health = await api.testConnector('proj-1', 'conn-webhook-1');
    expect(health.status).toBe('HEALTHY');
    expect(health.latency_ms).toBeGreaterThan(0);
    expect(health.message).toContain('SSRF defense policy');
  });

  it('should trigger stateful synchronization preserving scope isolation and digests', async () => {
    const mockSync: ConnectorSyncTriggerResponse = {
      sync_event_id: 'evt-sync-101',
      connector_id: 'conn-1',
      status: 'SUCCESS',
      records_pulled: 3,
      records_normalized: 3,
      records_ingested: 2,
      records_tombstoned: 1,
      raw_payload_digest: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      next_watermark: '2026-10-29T10:10:00Z',
      message: 'Sync completed successfully. 2 records updated/ingested, 1 tombstoned.',
    };

    vi.spyOn(api, 'syncConnector').mockResolvedValue(mockSync);

    const res = await api.syncConnector('proj-1', 'conn-1');
    expect(res.status).toBe('SUCCESS');
    expect(res.records_pulled).toBe(3);
    expect(res.records_ingested).toBe(2);
    expect(res.records_tombstoned).toBe(1);
    expect(res.raw_payload_digest).toHaveLength(64);
  });

  it('should retrieve sync execution history with cryptographic provenance', async () => {
    const mockHistory: ConnectorSyncEventRead[] = [
      {
        id: 'evt-1',
        connector_id: 'conn-1',
        project_id: 'proj-1',
        started_at: '2026-10-29T12:00:00Z',
        finished_at: '2026-10-29T12:00:02Z',
        status: 'SUCCESS',
        records_pulled: 3,
        records_normalized: 3,
        records_ingested: 2,
        records_tombstoned: 1,
        error_message: null,
        error_type: null,
        raw_payload_digest: 'sha256-hash-digest-1234',
        sync_watermark: '2026-10-29T10:10:00Z',
        execution_metadata: { duration_ms: 1200 },
      },
    ];

    vi.spyOn(api, 'getConnectorSyncHistory').mockResolvedValue(mockHistory);

    const history = await api.getConnectorSyncHistory('proj-1', 'conn-1');
    expect(history.length).toBe(1);
    expect(history[0].status).toBe('SUCCESS');
    expect(history[0].raw_payload_digest).toBe('sha256-hash-digest-1234');
  });
});
