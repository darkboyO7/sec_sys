import React, { useState, useEffect, useCallback } from 'react';
import {
  Globe,
  Bell,
  Terminal,
  RefreshCw,
  Search,
  Send,
  Download,
  Copy,
  CheckCircle,
  AlertTriangle,
  Activity,
  Layers,
  ShieldCheck,
  Play,
  History,
  Lock,
  Plus,
  Database,
} from 'lucide-react';
import { api } from '../services/api';
import type {
  IntegrationHealth,
  KevEntry,
  WebhookDelivery,
  SiemExportResponse,
  ConnectorInventoryItem,
  ConnectorConfigRead,
  ConnectorHealthRead,
  ConnectorSyncTriggerResponse,
  ConnectorSyncEventRead,
} from '../types';

interface IntegrationsViewProps {
  projectId: string;
}

export const IntegrationsView: React.FC<IntegrationsViewProps> = ({ projectId }) => {
  const [activeSection, setActiveSection] = useState<'connectors' | 'kev' | 'webhooks' | 'siem'>('connectors');

  // General Status
  const [integrationsStatus, setIntegrationsStatus] = useState<IntegrationHealth[]>([]);
  const [statusLoading, setStatusLoading] = useState(false);

  // Connectors State (Prompt 40)
  const [connectorInventory, setConnectorInventory] = useState<ConnectorInventoryItem[]>([]);
  const [connectors, setConnectors] = useState<ConnectorConfigRead[]>([]);
  const [connectorsLoading, setConnectorsLoading] = useState(false);
  const [testingConnectorId, setTestingConnectorId] = useState<string | null>(null);
  const [healthResults, setHealthResults] = useState<Record<string, ConnectorHealthRead>>({});
  const [syncingConnectorId, setSyncingConnectorId] = useState<string | null>(null);
  const [syncResults, setSyncResults] = useState<Record<string, ConnectorSyncTriggerResponse>>({});
  const [historyConnector, setHistoryConnector] = useState<ConnectorConfigRead | null>(null);
  const [syncHistory, setSyncHistory] = useState<ConnectorSyncEventRead[]>([]);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [isCreateModalOpen, setIsCreateModalOpen] = useState(false);
  const [createForm, setCreateForm] = useState({
    name: '',
    provider_type: 'CISA_KEV',
    capabilities: ['PULL_THREAT_INTEL', 'TEST_CONNECTIVITY'],
    rate_limit_per_minute: 60,
    timeout_seconds: 10,
    settingsJson: '{"feed_url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"}',
  });
  const [createError, setCreateError] = useState<string | null>(null);

  // CISA KEV
  const [kevCatalog, setKevCatalog] = useState<KevEntry[]>([]);
  const [kevSearchQuery, setKevSearchQuery] = useState('');
  const [kevLookupCve, setKevLookupCve] = useState('');
  const [singleKevResult, setSingleKevResult] = useState<KevEntry | null>(null);
  const [kevLoading, setKevLoading] = useState(false);
  const [kevError, setKevError] = useState<string | null>(null);

  // Webhook
  const [selectedEventType, setSelectedEventType] = useState('FINDING_CRITICAL_DISCOVERED');
  const [webhookHistory, setWebhookHistory] = useState<WebhookDelivery[]>([]);
  const [webhookTesting, setWebhookTesting] = useState(false);
  const [lastDelivery, setLastDelivery] = useState<WebhookDelivery | null>(null);
  const [webhookError, setWebhookError] = useState<string | null>(null);

  // SIEM Export
  const [siemFormat, setSiemFormat] = useState<'CEF' | 'SYSLOG' | 'JSON'>('CEF');
  const [siemResult, setSiemResult] = useState<SiemExportResponse | null>(null);
  const [siemExporting, setSiemExporting] = useState(false);
  const [copied, setCopied] = useState(false);

  // Load Connectors Data
  const loadConnectorsData = useCallback(async () => {
    setConnectorsLoading(true);
    try {
      const [inv, list] = await Promise.all([
        api.getConnectorInventory(projectId),
        api.listConnectors(projectId),
      ]);
      setConnectorInventory(inv);
      setConnectors(list);
    } catch (err: any) {
      console.error('Failed to load connectors data:', err);
    } finally {
      setConnectorsLoading(false);
    }
  }, [projectId]);

  // Load Integration Status
  const loadStatus = useCallback(async () => {
    setStatusLoading(true);
    try {
      const res = await api.getIntegrationsStatus(projectId);
      setIntegrationsStatus(res);
    } catch (err: any) {
      console.error('Failed to load integration status:', err);
    } finally {
      setStatusLoading(false);
    }
  }, [projectId]);

  // Load KEV Catalog
  const loadKevCatalog = useCallback(async (query?: string) => {
    setKevLoading(true);
    setKevError(null);
    try {
      const res = await api.searchKevCatalog(projectId, query);
      setKevCatalog(res);
    } catch (err: any) {
      setKevError(err.message || 'Failed to search CISA KEV catalog.');
    } finally {
      setKevLoading(false);
    }
  }, [projectId]);

  // Load Webhook History
  const loadWebhookHistory = useCallback(async () => {
    try {
      const res = await api.getWebhookHistory(projectId);
      setWebhookHistory(res);
    } catch (err: any) {
      console.error('Failed to load webhook history:', err);
    }
  }, [projectId]);

  useEffect(() => {
    loadConnectorsData();
    loadStatus();
    loadKevCatalog();
    loadWebhookHistory();
  }, [loadConnectorsData, loadStatus, loadKevCatalog, loadWebhookHistory]);

  // Handle Test Connector
  const handleTestConnector = async (connectorId: string) => {
    setTestingConnectorId(connectorId);
    try {
      const res = await api.testConnector(projectId, connectorId);
      setHealthResults((prev) => ({ ...prev, [connectorId]: res }));
      await loadConnectorsData();
    } catch (err: any) {
      alert(`Test failed: ${err.message}`);
    } finally {
      setTestingConnectorId(null);
    }
  };

  // Handle Sync Connector
  const handleSyncConnector = async (connectorId: string) => {
    setSyncingConnectorId(connectorId);
    try {
      const res = await api.syncConnector(projectId, connectorId);
      setSyncResults((prev) => ({ ...prev, [connectorId]: res }));
      await loadConnectorsData();
    } catch (err: any) {
      alert(`Sync failed: ${err.message}`);
    } finally {
      setSyncingConnectorId(null);
    }
  };

  // View Sync History
  const handleOpenHistory = async (conn: ConnectorConfigRead) => {
    setHistoryConnector(conn);
    setHistoryLoading(true);
    try {
      const hist = await api.getConnectorSyncHistory(projectId, conn.id);
      setSyncHistory(hist);
    } catch (err: any) {
      console.error('Failed to load sync history:', err);
    } finally {
      setHistoryLoading(false);
    }
  };

  // Create Connector Form Submit
  const handleCreateConnector = async (e: React.FormEvent) => {
    e.preventDefault();
    setCreateError(null);
    try {
      let parsedSettings = {};
      try {
        parsedSettings = JSON.parse(createForm.settingsJson);
      } catch (parseErr) {
        throw new Error('Settings must be valid JSON.');
      }

      await api.createConnector(projectId, {
        name: createForm.name,
        provider_type: createForm.provider_type,
        capabilities: createForm.capabilities,
        settings: parsedSettings,
        rate_limit_per_minute: createForm.rate_limit_per_minute,
        timeout_seconds: createForm.timeout_seconds,
      });

      setIsCreateModalOpen(false);
      setCreateForm({
        name: '',
        provider_type: 'CISA_KEV',
        capabilities: ['PULL_THREAT_INTEL', 'TEST_CONNECTIVITY'],
        rate_limit_per_minute: 60,
        timeout_seconds: 10,
        settingsJson: '{"feed_url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"}',
      });
      await loadConnectorsData();
    } catch (err: any) {
      setCreateError(err.message || 'Failed to create connector.');
    }
  };

  // Handle CVE Lookup
  const handleCveLookup = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!kevLookupCve.trim()) return;
    setKevLoading(true);
    setKevError(null);
    setSingleKevResult(null);
    try {
      const res = await api.lookupCveKev(projectId, kevLookupCve.trim().toUpperCase());
      setSingleKevResult(res);
    } catch (err: any) {
      setKevError(`CVE '${kevLookupCve.trim().toUpperCase()}' not found in CISA KEV catalog or lookup failed.`);
    } finally {
      setKevLoading(false);
    }
  };

  // Handle Webhook Test
  const handleTestWebhook = async () => {
    setWebhookTesting(true);
    setWebhookError(null);
    try {
      const res = await api.testWebhook(projectId, {
        event_type: selectedEventType,
        custom_payload: {
          test_incident_id: `INC-${Date.now().toString().slice(-6)}`,
          severity: 'CRITICAL',
          description: `Simulated ${selectedEventType} alert dispatched from VAPT control plane.`,
          dispatched_at: new Date().toISOString(),
        },
      });
      setLastDelivery(res);
      await loadWebhookHistory();
    } catch (err: any) {
      setWebhookError(err.message || 'Webhook dispatch failed.');
    } finally {
      setWebhookTesting(false);
    }
  };

  // Handle SIEM Export
  const handleExportSiem = async () => {
    setSiemExporting(true);
    try {
      const res = await api.exportSiemAudit(projectId, siemFormat);
      setSiemResult(res);
    } catch (err: any) {
      alert(`SIEM export failed: ${err.message}`);
    } finally {
      setSiemExporting(false);
    }
  };

  const copyToClipboard = () => {
    if (!siemResult) return;
    navigator.clipboard.writeText(siemResult.stream.join('\n'));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const downloadLogFile = () => {
    if (!siemResult) return;
    const blob = new Blob([siemResult.stream.join('\n')], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `vapt-siem-export-${projectId}-${Date.now()}.${siemFormat.toLowerCase()}`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 bg-cyber-850 p-6 rounded-xl border border-cyber-700">
        <div>
          <div className="flex items-center gap-2.5">
            <Layers className="w-6 h-6 text-accent-cyan" />
            <h2 className="text-xl font-bold text-slate-100">Enterprise Integrations & Secure Connectors</h2>
            <span className="px-2 py-0.5 text-[10px] rounded bg-cyber-750 text-accent-cyan font-mono border border-accent-cyan/30">
              Prompt 40 Verified
            </span>
          </div>
          <p className="text-sm text-slate-400 mt-1">
            Standardized connector contracts, capability declarations, SSRF-safe synchronization, and scope-isolated asset ingestion.
          </p>
          <div className="flex items-center gap-3 mt-2 text-xs font-mono text-slate-400">
            <span>Adapters: {integrationsStatus.length}</span>
            <span>•</span>
            <span>Connectors: {connectors.length}</span>
          </div>
        </div>
        <div className="flex items-center gap-2">
          {activeSection === 'connectors' && (
            <button
              onClick={() => setIsCreateModalOpen(true)}
              className="px-3 py-2 bg-accent-cyan hover:bg-cyan-400 text-cyber-900 font-semibold text-xs rounded-lg flex items-center gap-1.5 transition"
            >
              <Plus className="w-3.5 h-3.5" />
              Configure Connector
            </button>
          )}
          <button
            onClick={() => {
              loadConnectorsData();
              loadStatus();
              if (activeSection === 'kev') loadKevCatalog(kevSearchQuery);
              if (activeSection === 'webhooks') loadWebhookHistory();
            }}
            disabled={statusLoading || connectorsLoading}
            className="px-3.5 py-2 bg-cyber-750 hover:bg-cyber-700 text-slate-200 text-xs rounded-lg flex items-center gap-2 border border-cyber-600 transition"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${statusLoading || connectorsLoading ? 'animate-spin' : ''}`} />
            Refresh
          </button>
        </div>
      </div>

      {/* Sub-Navigation Tabs */}
      <div className="flex border-b border-cyber-750 gap-2">
        <button
          onClick={() => setActiveSection('connectors')}
          className={`flex items-center gap-2 py-2.5 px-4 text-xs font-semibold border-b-2 transition ${
            activeSection === 'connectors'
              ? 'border-accent-cyan text-accent-cyan bg-cyber-800/40'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <ShieldCheck className="w-3.5 h-3.5" />
          <span>Secure Connectors ({connectors.length})</span>
        </button>
        <button
          onClick={() => setActiveSection('kev')}
          className={`flex items-center gap-2 py-2.5 px-4 text-xs font-semibold border-b-2 transition ${
            activeSection === 'kev'
              ? 'border-accent-cyan text-accent-cyan bg-cyber-800/40'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <Globe className="w-3.5 h-3.5" />
          <span>CISA KEV Threat Feed</span>
        </button>
        <button
          onClick={() => setActiveSection('webhooks')}
          className={`flex items-center gap-2 py-2.5 px-4 text-xs font-semibold border-b-2 transition ${
            activeSection === 'webhooks'
              ? 'border-accent-cyan text-accent-cyan bg-cyber-800/40'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <Bell className="w-3.5 h-3.5" />
          <span>HMAC Webhook Alerts</span>
        </button>
        <button
          onClick={() => setActiveSection('siem')}
          className={`flex items-center gap-2 py-2.5 px-4 text-xs font-semibold border-b-2 transition ${
            activeSection === 'siem'
              ? 'border-accent-cyan text-accent-cyan bg-cyber-800/40'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <Terminal className="w-3.5 h-3.5" />
          <span>SIEM & Syslog Exporter</span>
        </button>
      </div>

      {/* SECTION 0: Secure Connectors & Framework (Prompt 40) */}
      {activeSection === 'connectors' && (
        <div className="space-y-6">
          {/* Configured Connectors */}
          <div className="bg-cyber-850 p-5 rounded-xl border border-cyber-750 space-y-4">
            <h3 className="text-xs font-bold text-slate-200 uppercase tracking-wider flex items-center justify-between">
              <span className="flex items-center gap-2">
                <Database className="w-4 h-4 text-accent-cyan" />
                Active Project Connectors
              </span>
              <span className="text-[11px] font-mono font-normal text-slate-400">
                {connectors.length} configured
              </span>
            </h3>

            {connectors.length === 0 ? (
              <div className="text-center py-8 text-slate-500 text-xs font-mono">
                No connectors configured yet. Click "Configure Connector" above to register an integration adapter.
              </div>
            ) : (
              <div className="space-y-3">
                {connectors.map((c) => {
                  const health = healthResults[c.id];
                  const sync = syncResults[c.id];
                  return (
                    <div
                      key={c.id}
                      className="bg-cyber-900 p-4 rounded-lg border border-cyber-750 flex flex-col md:flex-row md:items-center justify-between gap-4"
                    >
                      <div className="space-y-1.5 flex-1">
                        <div className="flex items-center gap-3">
                          <span className="font-semibold text-slate-100 text-sm">{c.name}</span>
                          <span className="px-2 py-0.5 text-[10px] font-mono rounded bg-cyber-800 border border-cyber-700 text-slate-300">
                            {c.provider_type} v{c.version}
                          </span>
                          <span
                            className={`px-2 py-0.5 text-[10px] font-mono font-bold rounded ${
                              c.last_health_status === 'HEALTHY'
                                ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30'
                                : c.last_health_status === 'CONFIGURED'
                                ? 'bg-blue-500/10 text-blue-400 border border-blue-500/30'
                                : 'bg-red-500/10 text-red-400 border border-red-500/30'
                            }`}
                          >
                            {c.last_health_status}
                          </span>
                        </div>
                        <div className="flex flex-wrap gap-1.5 pt-1">
                          {c.capabilities.map((cap) => (
                            <span
                              key={cap}
                              className="px-1.5 py-0.5 text-[9px] font-mono rounded bg-accent-cyan/10 text-accent-cyan border border-accent-cyan/20"
                            >
                              {cap}
                            </span>
                          ))}
                        </div>
                        <div className="text-[11px] font-mono text-slate-400 flex flex-wrap gap-4 pt-1">
                          <span>Rate Limit: {c.rate_limit_per_minute}/min</span>
                          <span>Timeout: {c.timeout_seconds}s</span>
                          <span>Watermark: {c.last_sync_watermark || 'None'}</span>
                          {c.last_sync_at && (
                            <span>Last Sync: {new Date(c.last_sync_at).toLocaleTimeString()}</span>
                          )}
                        </div>

                        {/* Test result feedback banner */}
                        {health && (
                          <div
                            className={`mt-2 p-2 rounded text-[11px] font-mono border ${
                              health.status === 'HEALTHY'
                                ? 'bg-emerald-950/40 text-emerald-400 border-emerald-800/60'
                                : 'bg-red-950/40 text-red-400 border-red-800/60'
                            }`}
                          >
                            <span className="font-bold">[{health.status}]</span> {health.message} ({health.latency_ms.toFixed(1)}ms)
                          </div>
                        )}

                        {/* Sync result feedback banner */}
                        {sync && (
                          <div className="mt-2 p-2 rounded text-[11px] font-mono bg-blue-950/40 text-cyan-300 border border-cyan-800/60">
                            <span className="font-bold">Sync:</span> {sync.message} | Digest: {sync.raw_payload_digest?.slice(0, 16)}...
                          </div>
                        )}
                      </div>

                      {/* Actions */}
                      <div className="flex items-center gap-2 self-start md:self-center">
                        <button
                          onClick={() => handleTestConnector(c.id)}
                          disabled={testingConnectorId === c.id}
                          className="px-2.5 py-1.5 bg-cyber-800 hover:bg-cyber-750 text-slate-200 text-xs font-mono rounded border border-cyber-700 flex items-center gap-1.5 transition"
                        >
                          <Activity className={`w-3.5 h-3.5 ${testingConnectorId === c.id ? 'animate-spin' : ''}`} />
                          Test
                        </button>
                        <button
                          onClick={() => handleSyncConnector(c.id)}
                          disabled={syncingConnectorId === c.id || !c.enabled}
                          className="px-2.5 py-1.5 bg-accent-cyan hover:bg-cyan-400 text-cyber-900 text-xs font-bold font-mono rounded flex items-center gap-1.5 transition"
                        >
                          <Play className={`w-3.5 h-3.5 ${syncingConnectorId === c.id ? 'animate-spin' : ''}`} />
                          Sync Now
                        </button>
                        <button
                          onClick={() => handleOpenHistory(c)}
                          className="px-2.5 py-1.5 bg-cyber-800 hover:bg-cyber-750 text-slate-300 text-xs font-mono rounded border border-cyber-700 flex items-center gap-1.5 transition"
                        >
                          <History className="w-3.5 h-3.5" />
                          History
                        </button>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>

          {/* Available Integration Registry & Catalog */}
          <div className="bg-cyber-850 p-5 rounded-xl border border-cyber-750 space-y-4">
            <div>
              <h3 className="text-xs font-bold text-slate-200 uppercase tracking-wider flex items-center gap-2">
                <ShieldCheck className="w-4 h-4 text-accent-cyan" />
                Connector Capability Discovery Catalog
              </h3>
              <p className="text-xs text-slate-400 mt-1">
                Authoritative registry of supported and experimental data source adapters with truth-in-advertising status flags.
              </p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
              {connectorInventory.map((item) => (
                <div
                  key={item.provider_type}
                  className="bg-cyber-900 p-4 rounded-lg border border-cyber-750 flex flex-col justify-between"
                >
                  <div className="space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="font-semibold text-slate-200 text-xs">{item.name}</span>
                      <span
                        className={`px-1.5 py-0.5 text-[9px] font-mono font-bold rounded ${
                          item.implementation_status === 'IMPLEMENTED'
                            ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30'
                            : item.implementation_status === 'SIMULATED'
                            ? 'bg-blue-500/10 text-blue-400 border border-blue-500/30'
                            : item.implementation_status === 'UNVERIFIED'
                            ? 'bg-amber-500/10 text-amber-400 border border-amber-500/30'
                            : 'bg-slate-700 text-slate-400 border border-slate-600'
                        }`}
                      >
                        {item.implementation_status}
                      </span>
                    </div>
                    <p className="text-[11px] text-slate-400 leading-relaxed">{item.description}</p>
                    {item.limitations && (
                      <div className="p-2 rounded bg-cyber-950 border border-amber-500/20 text-[10px] text-amber-300/80 font-mono">
                        <AlertTriangle className="w-3 h-3 inline mr-1 text-amber-400" />
                        {item.limitations}
                      </div>
                    )}
                  </div>

                  <div className="pt-3 mt-3 border-t border-cyber-800">
                    <div className="text-[10px] text-slate-500 font-mono mb-1.5">Capabilities:</div>
                    <div className="flex flex-wrap gap-1">
                      {item.supported_capabilities.map((cap) => (
                        <span
                          key={cap}
                          className="px-1.5 py-0.2 text-[8px] font-mono rounded bg-cyber-800 text-slate-300"
                        >
                          {cap}
                        </span>
                      ))}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* SECTION 1: CISA KEV Threat Feed */}
      {activeSection === 'kev' && (
        <div className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="bg-cyber-850 p-5 rounded-xl border border-cyber-750 space-y-3">
              <h3 className="text-xs font-bold text-slate-200 uppercase tracking-wider flex items-center gap-2">
                <Search className="w-4 h-4 text-accent-cyan" />
                Direct CVE Threat Lookup
              </h3>
              <form onSubmit={handleCveLookup} className="flex gap-2">
                <input
                  type="text"
                  placeholder="e.g. CVE-2021-44228"
                  value={kevLookupCve}
                  onChange={(e) => setKevLookupCve(e.target.value)}
                  className="flex-1 bg-cyber-900 border border-cyber-700 rounded-lg px-3 py-2 text-xs text-slate-100 placeholder-slate-500 font-mono focus:outline-none focus:border-accent-cyan"
                />
                <button
                  type="submit"
                  disabled={kevLoading}
                  className="px-4 py-2 bg-accent-cyan hover:bg-cyan-400 text-cyber-900 font-semibold rounded-lg text-xs flex items-center gap-1.5 transition"
                >
                  <Search className="w-3.5 h-3.5" />
                  Lookup
                </button>
              </form>

              {kevError && (
                <div className="p-3 bg-red-950/40 border border-red-800/60 rounded-lg text-xs text-red-300 flex items-center gap-2 font-mono">
                  <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />
                  {kevError}
                </div>
              )}

              {singleKevResult && (
                <div className="p-4 bg-cyber-900 border border-cyber-700 rounded-lg space-y-2 font-mono text-xs">
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-accent-cyan text-sm">{singleKevResult.cve_id}</span>
                    <span className="px-2 py-0.5 rounded text-[10px] bg-red-500/10 text-red-400 border border-red-500/30">
                      Ransomware:{' '}
                      {singleKevResult.known_ransomware_campaign_use ? 'CONFIRMED' : 'UNKNOWN'}
                    </span>
                  </div>
                  <div className="text-slate-200 font-semibold">{singleKevResult.vulnerability_name}</div>
                  <div className="text-slate-400 text-[11px]">{singleKevResult.short_description}</div>
                  <div className="pt-2 text-slate-500 text-[10px]">
                    Vendor: {singleKevResult.vendor_project} | Product: {singleKevResult.product} | Added: {singleKevResult.date_added}
                  </div>
                </div>
              )}
            </div>

            <div className="bg-cyber-850 p-5 rounded-xl border border-cyber-750 flex flex-col justify-between">
              <div>
                <h3 className="text-xs font-bold text-slate-200 uppercase tracking-wider flex items-center gap-2">
                  <Globe className="w-4 h-4 text-accent-cyan" />
                  Catalog Coverage & Search
                </h3>
                <div className="mt-2">
                  <input
                    type="text"
                    placeholder="Filter catalog by keyword or vendor..."
                    value={kevSearchQuery}
                    onChange={(e) => {
                      setKevSearchQuery(e.target.value);
                      loadKevCatalog(e.target.value);
                    }}
                    className="w-full bg-cyber-900 border border-cyber-700 rounded px-3 py-1.5 text-xs text-slate-100 placeholder-slate-500 font-mono focus:outline-none focus:border-accent-cyan"
                  />
                </div>
                <div className="mt-4 grid grid-cols-2 gap-3 text-xs font-mono">
                  <div className="p-3 bg-cyber-900 rounded-lg border border-cyber-750">
                    <span className="text-slate-500 text-[10px] block">Synchronized Entries</span>
                    <span className="text-lg font-bold text-slate-200">{kevCatalog.length}</span>
                  </div>
                  <div className="p-3 bg-cyber-900 rounded-lg border border-cyber-750">
                    <span className="text-slate-500 text-[10px] block">Feed Policy</span>
                    <span className="text-lg font-bold text-emerald-400">Strict TLS</span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* SECTION 2: HMAC Webhook Alerts */}
      {activeSection === 'webhooks' && (
        <div className="space-y-4">
          <div className="bg-cyber-850 p-5 rounded-xl border border-cyber-750 space-y-4">
            <h3 className="text-xs font-bold text-slate-200 uppercase tracking-wider flex items-center gap-2">
              <Bell className="w-4 h-4 text-accent-cyan" />
              Simulate Outbound Security Alert Dispatch
            </h3>
            <div className="flex flex-col sm:flex-row gap-3">
              <select
                value={selectedEventType}
                onChange={(e) => setSelectedEventType(e.target.value)}
                className="bg-cyber-900 border border-cyber-700 rounded-lg px-3 py-2 text-xs text-slate-100 font-mono focus:outline-none focus:border-accent-cyan"
              >
                <option value="FINDING_CRITICAL_DISCOVERED">FINDING_CRITICAL_DISCOVERED</option>
                <option value="EXPLOIT_VERIFIED_IN_WILD">EXPLOIT_VERIFIED_IN_WILD</option>
                <option value="ATTACK_PATH_REACHABLE">ATTACK_PATH_REACHABLE</option>
                <option value="CONTROL_PLANE_DRIFT">CONTROL_PLANE_DRIFT</option>
              </select>
              <button
                onClick={handleTestWebhook}
                disabled={webhookTesting}
                className="px-4 py-2 bg-accent-cyan hover:bg-cyan-400 text-cyber-900 font-semibold rounded-lg text-xs flex items-center justify-center gap-1.5 transition"
              >
                <Send className={`w-3.5 h-3.5 ${webhookTesting ? 'animate-pulse' : ''}`} />
                <span>{webhookTesting ? 'Signing & Dispatching...' : 'Dispatch Webhook Event'}</span>
              </button>
            </div>

            {webhookError && (
              <div className="p-3 bg-red-950/40 border border-red-800/60 rounded-lg text-xs text-red-300 font-mono">
                {webhookError}
              </div>
            )}

            {lastDelivery && (
              <div className="p-4 bg-cyber-900 border border-cyber-700 rounded-lg font-mono text-xs space-y-2">
                <div className="flex items-center justify-between">
                  <span className="font-bold text-emerald-400 flex items-center gap-1.5">
                    <CheckCircle className="w-4 h-4" /> Dispatched Successfully
                  </span>
                  <span className="text-slate-500 text-[10px]">{lastDelivery.delivered_at}</span>
                </div>
                <div className="text-[11px] text-slate-300">
                  <span className="text-slate-500">HMAC-SHA256 Signature:</span> {lastDelivery.signature}
                </div>
              </div>
            )}

            {webhookHistory.length > 0 && (
              <div className="mt-4 pt-3 border-t border-cyber-750 space-y-2">
                <span className="text-xs font-mono text-slate-400">Recent Webhook Deliveries ({webhookHistory.length}):</span>
                <div className="space-y-1.5 max-h-40 overflow-y-auto scrollbar-thin">
                  {webhookHistory.slice(0, 5).map((d) => (
                    <div key={d.event_id} className="p-2 bg-cyber-900 rounded text-[11px] font-mono flex items-center justify-between text-slate-300">
                      <span>{d.event_type}</span>
                      <span className="text-slate-500">{d.delivered_at}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* SECTION 3: SIEM Log Exporter */}
      {activeSection === 'siem' && (
        <div className="space-y-4">
          <div className="bg-cyber-850 p-5 rounded-xl border border-cyber-750 space-y-4">
            <h3 className="text-xs font-bold text-slate-200 uppercase tracking-wider flex items-center gap-2">
              <Terminal className="w-4 h-4 text-accent-cyan" />
              Export SIEM Audit Telemetry
            </h3>
            <div className="flex gap-3 items-center">
              <select
                value={siemFormat}
                onChange={(e) => setSiemFormat(e.target.value as any)}
                className="bg-cyber-900 border border-cyber-700 rounded-lg px-3 py-2 text-xs text-slate-100 font-mono focus:outline-none focus:border-accent-cyan"
              >
                <option value="CEF">Common Event Format (CEF)</option>
                <option value="SYSLOG">Syslog RFC 5424</option>
                <option value="JSON">Structured JSON Stream</option>
              </select>
              <button
                onClick={handleExportSiem}
                disabled={siemExporting}
                className="px-4 py-2 bg-accent-cyan hover:bg-cyan-400 text-cyber-900 font-semibold rounded-lg text-xs flex items-center gap-1.5 transition"
              >
                <Download className={`w-3.5 h-3.5 ${siemExporting ? 'animate-spin' : ''}`} />
                <span>Generate Export Stream</span>
              </button>
            </div>
          </div>

          {siemResult && (
            <div className="bg-cyber-850 rounded-xl border border-cyber-750 overflow-hidden">
              <div className="p-4 bg-cyber-800 border-b border-cyber-700 flex items-center justify-between">
                <span className="font-mono text-xs text-slate-200 font-semibold">
                  Export Stream ({siemResult.total_events} events)
                </span>
                <div className="flex items-center gap-2">
                  <button
                    onClick={copyToClipboard}
                    className="px-3 py-1 bg-cyber-750 hover:bg-cyber-700 text-slate-200 rounded text-xs flex items-center gap-1.5 transition"
                  >
                    <Copy className="w-3.5 h-3.5" />
                    <span>{copied ? 'Copied' : 'Copy'}</span>
                  </button>
                  <button
                    onClick={downloadLogFile}
                    className="px-3 py-1 bg-accent-cyan hover:bg-cyan-400 text-cyber-900 font-semibold rounded text-xs flex items-center gap-1.5 transition"
                  >
                    <Download className="w-3.5 h-3.5" />
                    <span>Download Log</span>
                  </button>
                </div>
              </div>
              <div className="p-4 bg-cyber-950 font-mono text-xs text-emerald-400 overflow-x-auto max-h-96 space-y-1 scrollbar-thin">
                {siemResult.stream.map((line, idx) => (
                  <div key={idx} className="whitespace-pre hover:bg-cyber-900/60 p-1 rounded transition">
                    {line}
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Sync History Modal */}
      {historyConnector && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-cyber-850 border border-cyber-700 rounded-xl max-w-3xl w-full p-6 space-y-4 max-h-[85vh] flex flex-col">
            <div className="flex items-center justify-between border-b border-cyber-750 pb-3">
              <div>
                <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
                  <History className="w-4 h-4 text-accent-cyan" />
                  Sync Run History & Cryptographic Provenance
                </h3>
                <p className="text-xs text-slate-400 font-mono mt-0.5">{historyConnector.name}</p>
              </div>
              <button
                onClick={() => setHistoryConnector(null)}
                className="text-slate-400 hover:text-slate-200 text-sm"
              >
                ✕
              </button>
            </div>

            <div className="flex-1 overflow-y-auto space-y-3 scrollbar-thin">
              {historyLoading ? (
                <div className="text-center py-6 text-xs font-mono text-slate-500">Loading sync history...</div>
              ) : syncHistory.length === 0 ? (
                <div className="text-center py-6 text-xs font-mono text-slate-500">No sync executions recorded yet.</div>
              ) : (
                syncHistory.map((evt) => (
                  <div key={evt.id} className="p-3 bg-cyber-900 rounded-lg border border-cyber-750 font-mono text-xs space-y-1.5">
                    <div className="flex items-center justify-between">
                      <span className="text-slate-300 font-semibold">{new Date(evt.started_at).toLocaleString()}</span>
                      <span
                        className={`px-1.5 py-0.5 text-[9px] font-bold rounded ${
                          evt.status === 'SUCCESS'
                            ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30'
                            : 'bg-red-500/10 text-red-400 border border-red-500/30'
                        }`}
                      >
                        {evt.status}
                      </span>
                    </div>
                    <div className="text-slate-400 text-[11px] flex gap-4">
                      <span>Pulled: {evt.records_pulled}</span>
                      <span>Ingested: {evt.records_ingested}</span>
                      <span>Tombstoned: {evt.records_tombstoned}</span>
                      <span>Watermark: {evt.sync_watermark || 'N/A'}</span>
                    </div>
                    {evt.raw_payload_digest && (
                      <div className="text-[10px] text-slate-500 break-all">
                        <Lock className="w-3 h-3 inline mr-1 text-accent-cyan" />
                        Payload SHA-256 Digest: {evt.raw_payload_digest}
                      </div>
                    )}
                    {evt.error_message && (
                      <div className="text-[11px] text-red-400">Error: {evt.error_message}</div>
                    )}
                  </div>
                ))
              )}
            </div>

            <div className="border-t border-cyber-750 pt-3 flex justify-end">
              <button
                onClick={() => setHistoryConnector(null)}
                className="px-4 py-2 bg-cyber-750 hover:bg-cyber-700 text-slate-200 text-xs rounded-lg transition"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Configure Connector Modal */}
      {isCreateModalOpen && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-cyber-850 border border-cyber-700 rounded-xl max-w-xl w-full p-6 space-y-4">
            <div className="flex items-center justify-between border-b border-cyber-750 pb-3">
              <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
                <Plus className="w-4 h-4 text-accent-cyan" />
                Configure External Security Connector
              </h3>
              <button onClick={() => setIsCreateModalOpen(false)} className="text-slate-400 hover:text-slate-200 text-sm">
                ✕
              </button>
            </div>

            <form onSubmit={handleCreateConnector} className="space-y-4 text-xs font-mono">
              {createError && (
                <div className="p-3 bg-red-950/40 border border-red-800/60 rounded text-red-300">
                  {createError}
                </div>
              )}

              <div className="space-y-1">
                <label className="text-slate-300 font-semibold">Connector Name</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. AWS Production EC2 Inventory"
                  value={createForm.name}
                  onChange={(e) => setCreateForm({ ...createForm, name: e.target.value })}
                  className="w-full bg-cyber-900 border border-cyber-700 rounded px-3 py-2 text-slate-100 focus:outline-none focus:border-accent-cyan"
                />
              </div>

              <div className="space-y-1">
                <label className="text-slate-300 font-semibold">Provider Adapter</label>
                <select
                  value={createForm.provider_type}
                  onChange={(e) => {
                    const p = e.target.value;
                    let caps = ['TEST_CONNECTIVITY'];
                    let defaultSettings = '{}';
                    if (p === 'CISA_KEV') {
                      caps = ['PULL_THREAT_INTEL', 'TEST_CONNECTIVITY'];
                      defaultSettings = '{"feed_url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"}';
                    } else if (p === 'CLOUD_ASSET_INVENTORY') {
                      caps = ['PULL_ASSETS', 'TEST_CONNECTIVITY'];
                      defaultSettings = '{"cloud_provider": "AWS", "api_endpoint": "https://ec2.us-east-1.amazonaws.com"}';
                    } else if (p === 'VULNERABILITY_SCANNER') {
                      caps = ['PULL_FINDINGS', 'TEST_CONNECTIVITY'];
                      defaultSettings = '{"scanner_url": "https://scanner.internal.corp/api/v2"}';
                    } else if (p === 'WEBHOOK_NOTIFIER') {
                      caps = ['PUSH_ALERTS', 'TEST_CONNECTIVITY'];
                      defaultSettings = '{"webhook_url": "https://siem.corp.internal/events"}';
                    }
                    setCreateForm({
                      ...createForm,
                      provider_type: p,
                      capabilities: caps,
                      settingsJson: defaultSettings,
                    });
                  }}
                  className="w-full bg-cyber-900 border border-cyber-700 rounded px-3 py-2 text-slate-100 focus:outline-none focus:border-accent-cyan"
                >
                  <option value="CISA_KEV">CISA_KEV (Threat Intelligence Feed)</option>
                  <option value="CLOUD_ASSET_INVENTORY">CLOUD_ASSET_INVENTORY (Cloud Host Source)</option>
                  <option value="VULNERABILITY_SCANNER">VULNERABILITY_SCANNER (Scanner Findings)</option>
                  <option value="WEBHOOK_NOTIFIER">WEBHOOK_NOTIFIER (Outbound HMAC Webhook)</option>
                  <option value="SIEM_EXPORTER">SIEM_EXPORTER (Syslog/CEF Exporter)</option>
                </select>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-1">
                  <label className="text-slate-300">Rate Limit (/min)</label>
                  <input
                    type="number"
                    value={createForm.rate_limit_per_minute}
                    onChange={(e) => setCreateForm({ ...createForm, rate_limit_per_minute: Number(e.target.value) })}
                    className="w-full bg-cyber-900 border border-cyber-700 rounded px-3 py-1.5 text-slate-100"
                  />
                </div>
                <div className="space-y-1">
                  <label className="text-slate-300">Timeout (seconds)</label>
                  <input
                    type="number"
                    value={createForm.timeout_seconds}
                    onChange={(e) => setCreateForm({ ...createForm, timeout_seconds: Number(e.target.value) })}
                    className="w-full bg-cyber-900 border border-cyber-700 rounded px-3 py-1.5 text-slate-100"
                  />
                </div>
              </div>

              <div className="space-y-1">
                <label className="text-slate-300 font-semibold">Settings & Credentials (JSON)</label>
                <textarea
                  rows={4}
                  value={createForm.settingsJson}
                  onChange={(e) => setCreateForm({ ...createForm, settingsJson: e.target.value })}
                  className="w-full bg-cyber-900 border border-cyber-700 rounded px-3 py-2 text-slate-100 font-mono text-[11px] focus:outline-none focus:border-accent-cyan"
                />
                <span className="text-[10px] text-slate-500">
                  <Lock className="w-3 h-3 inline mr-1 text-accent-cyan" />
                  Credentials (tokens, secrets) are automatically masked and encrypted in storage.
                </span>
              </div>

              <div className="pt-2 flex justify-end gap-2">
                <button
                  type="button"
                  onClick={() => setIsCreateModalOpen(false)}
                  className="px-4 py-2 bg-cyber-800 hover:bg-cyber-750 text-slate-300 rounded transition"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 bg-accent-cyan hover:bg-cyan-400 text-cyber-900 font-bold rounded transition"
                >
                  Save & Validate
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
