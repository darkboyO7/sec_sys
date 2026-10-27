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
  Shield,
  Activity,
  Layers,
} from 'lucide-react';
import { api } from '../services/api';
import type {
  IntegrationHealth,
  KevEntry,
  WebhookDelivery,
  SiemExportResponse,
} from '../types';

interface IntegrationsViewProps {
  projectId: string;
}

export const IntegrationsView: React.FC<IntegrationsViewProps> = ({ projectId }) => {
  const [activeSection, setActiveSection] = useState<'kev' | 'webhooks' | 'siem'>('kev');

  // General Status
  const [integrationsStatus, setIntegrationsStatus] = useState<IntegrationHealth[]>([]);
  const [statusLoading, setStatusLoading] = useState(false);

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
    loadStatus();
    loadKevCatalog();
    loadWebhookHistory();
  }, [loadStatus, loadKevCatalog, loadWebhookHistory]);

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
      console.error('Failed to export SIEM audit stream:', err);
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
    const blob = new Blob([siemResult.stream.join('\n')], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `siem-export-${projectId}-${siemFormat.toLowerCase()}-${Date.now()}.log`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 bg-cyber-850 p-6 rounded-xl border border-cyber-700">
        <div>
          <div className="flex items-center gap-2.5">
            <Layers className="w-6 h-6 text-accent-cyan" />
            <h2 className="text-xl font-bold text-slate-100">Enterprise Integrations & Telemetry</h2>
            <span className="px-2 py-0.5 text-[10px] rounded bg-cyber-750 text-accent-cyan font-mono border border-accent-cyan/30">
              Phase 31
            </span>
          </div>
          <p className="text-sm text-slate-400 mt-1">
            Authoritative threat feeds (CISA KEV), HMAC-SHA256 authenticated webhooks, and multi-format SIEM event streaming.
          </p>
        </div>
        <button
          onClick={() => {
            loadStatus();
            if (activeSection === 'kev') loadKevCatalog(kevSearchQuery);
            if (activeSection === 'webhooks') loadWebhookHistory();
          }}
          disabled={statusLoading}
          className="px-3.5 py-2 bg-cyber-750 hover:bg-cyber-700 text-slate-200 text-xs rounded-lg flex items-center gap-2 border border-cyber-600 transition self-start sm:self-auto"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${statusLoading ? 'animate-spin' : ''}`} />
          Refresh
        </button>
      </div>

      {/* Integration Adapter Health Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {integrationsStatus.length === 0 ? (
          <div className="col-span-3 p-4 text-center text-slate-500 text-xs font-mono">
            Loading adapter telemetry...
          </div>
        ) : (
          integrationsStatus.map((adapter) => (
            <div
              key={adapter.name}
              className="bg-cyber-850 p-4 rounded-xl border border-cyber-750 hover:border-cyber-600 transition flex flex-col justify-between"
            >
              <div>
                <div className="flex items-center justify-between mb-2">
                  <span className="font-mono text-xs font-semibold text-slate-200">{adapter.name}</span>
                  <span
                    className={`px-2 py-0.5 text-[10px] rounded font-mono font-bold ${
                      adapter.status === 'ACTIVE'
                        ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30'
                        : 'bg-amber-500/10 text-amber-400 border border-amber-500/30'
                    }`}
                  >
                    {adapter.status}
                  </span>
                </div>
                <div className="text-[11px] text-slate-400 space-y-1 font-mono">
                  <div>Version: {adapter.version}</div>
                  {adapter.details?.total_cached_entries !== undefined && (
                    <div>Catalog Entries: {adapter.details.total_cached_entries.toLocaleString()}</div>
                  )}
                  {adapter.details?.algorithm && (
                    <div>Signer: {adapter.details.algorithm}</div>
                  )}
                  {adapter.details?.supported_formats && (
                    <div>Formats: {adapter.details.supported_formats.join(', ')}</div>
                  )}
                </div>
              </div>
              <div className="mt-3 pt-2 border-t border-cyber-750/60 flex items-center gap-1.5 text-[10px] text-slate-500">
                <Activity className="w-3 h-3 text-emerald-400" />
                <span>Operational In-Memory Singleton</span>
              </div>
            </div>
          ))
        )}
      </div>

      {/* Sub-Navigation Tabs */}
      <div className="flex border-b border-cyber-750 gap-2">
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

      {/* SECTION 1: CISA KEV Threat Feed */}
      {activeSection === 'kev' && (
        <div className="space-y-4">
          {/* Search and Direct Lookup */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Direct CVE Lookup */}
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
                  disabled={kevLoading || !kevLookupCve.trim()}
                  className="px-4 py-2 bg-accent-cyan hover:bg-cyan-400 text-cyber-900 font-bold rounded-lg text-xs transition disabled:opacity-50"
                >
                  Lookup
                </button>
              </form>
            </div>

            {/* Catalog Filter */}
            <div className="bg-cyber-850 p-5 rounded-xl border border-cyber-750 space-y-3">
              <h3 className="text-xs font-bold text-slate-200 uppercase tracking-wider flex items-center gap-2">
                <Globe className="w-4 h-4 text-indigo-400" />
                Filter In-Memory Catalog
              </h3>
              <div className="flex gap-2">
                <input
                  type="text"
                  placeholder="Keyword, vendor, or product (e.g. Apache, Log4j, Microsoft)..."
                  value={kevSearchQuery}
                  onChange={(e) => setKevSearchQuery(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter') loadKevCatalog(kevSearchQuery);
                  }}
                  className="flex-1 bg-cyber-900 border border-cyber-700 rounded-lg px-3 py-2 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:border-accent-cyan"
                />
                <button
                  onClick={() => loadKevCatalog(kevSearchQuery)}
                  disabled={kevLoading}
                  className="px-4 py-2 bg-cyber-750 hover:bg-cyber-700 text-slate-200 border border-cyber-600 rounded-lg text-xs font-semibold transition"
                >
                  Filter
                </button>
              </div>
            </div>
          </div>

          {/* Single CVE Lookup Result Card */}
          {singleKevResult && (
            <div className="bg-accent-cyan/5 border border-accent-cyan/30 rounded-xl p-5 space-y-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2.5">
                  <span className="font-mono text-sm font-bold text-accent-cyan">{singleKevResult.cve_id}</span>
                  <span className="text-xs font-semibold text-slate-200">{singleKevResult.vulnerability_name}</span>
                </div>
                {singleKevResult.known_ransomware_campaign_use && (
                  <span className="px-2 py-0.5 text-[10px] rounded bg-rose-500/20 text-rose-300 border border-rose-500/30 font-bold flex items-center gap-1">
                    <AlertTriangle className="w-3 h-3" />
                    KNOWN RANSOMWARE CAMPAIGN
                  </span>
                )}
              </div>
              <p className="text-xs text-slate-300">{singleKevResult.short_description}</p>
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-[11px] font-mono text-slate-400 bg-cyber-900/60 p-3 rounded-lg border border-cyber-800">
                <div>Vendor: <span className="text-slate-200">{singleKevResult.vendor_project}</span></div>
                <div>Product: <span className="text-slate-200">{singleKevResult.product}</span></div>
                <div>Added Date: <span className="text-slate-200">{singleKevResult.date_added}</span></div>
                <div>Action: <span className="text-amber-300">{singleKevResult.required_action}</span></div>
              </div>
            </div>
          )}

          {kevError && (
            <div className="p-4 bg-rose-500/10 border border-rose-500/30 text-rose-300 rounded-lg text-xs font-mono">
              {kevError}
            </div>
          )}

          {/* Catalog Table */}
          <div className="bg-cyber-850 rounded-xl border border-cyber-700 overflow-hidden">
            <div className="px-6 py-4 border-b border-cyber-750 flex items-center justify-between">
              <span className="text-xs font-bold text-slate-200 uppercase tracking-wider">
                CISA Known Exploited Vulnerabilities ({kevCatalog.length} Entries)
              </span>
              <span className="text-[11px] text-slate-400 font-mono">
                Source: CISA KEV Catalog
              </span>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="bg-cyber-800 text-slate-400 font-mono text-[11px] uppercase border-b border-cyber-750">
                  <tr>
                    <th className="py-3 px-4">CVE ID</th>
                    <th className="py-3 px-4">Vendor & Product</th>
                    <th className="py-3 px-4">Vulnerability Summary</th>
                    <th className="py-3 px-4">Ransomware Status</th>
                    <th className="py-3 px-4">Required Action</th>
                    <th className="py-3 px-4">Date Added</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-cyber-750 text-slate-300">
                  {kevCatalog.length === 0 ? (
                    <tr>
                      <td colSpan={6} className="py-8 text-center text-slate-500">
                        {kevLoading ? 'Filtering catalog...' : 'No matching vulnerabilities found.'}
                      </td>
                    </tr>
                  ) : (
                    kevCatalog.map((entry) => (
                      <tr key={entry.cve_id} className="hover:bg-cyber-800/40 transition">
                        <td className="py-3 px-4 font-mono font-semibold text-accent-cyan whitespace-nowrap">
                          {entry.cve_id}
                        </td>
                        <td className="py-3 px-4">
                          <div className="font-semibold text-slate-200">{entry.vendor_project}</div>
                          <div className="text-[10px] text-slate-400 font-mono">{entry.product}</div>
                        </td>
                        <td className="py-3 px-4 max-w-xs">
                          <div className="truncate font-semibold text-slate-200">{entry.vulnerability_name}</div>
                          <div className="text-[10px] text-slate-400 truncate">{entry.short_description}</div>
                        </td>
                        <td className="py-3 px-4 whitespace-nowrap">
                          {entry.known_ransomware_campaign_use ? (
                            <span className="px-2 py-0.5 text-[9px] rounded bg-rose-500/20 text-rose-300 border border-rose-500/30 font-bold">
                              RANSOMWARE
                            </span>
                          ) : (
                            <span className="px-2 py-0.5 text-[9px] rounded bg-slate-700 text-slate-300 font-mono">
                              STANDARD
                            </span>
                          )}
                        </td>
                        <td className="py-3 px-4 text-[10px] text-amber-300 max-w-xs truncate">
                          {entry.required_action}
                        </td>
                        <td className="py-3 px-4 font-mono text-[10px] text-slate-400 whitespace-nowrap">
                          {entry.date_added}
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* SECTION 2: HMAC-SHA256 Webhooks */}
      {activeSection === 'webhooks' && (
        <div className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {/* Dispatcher Controls */}
            <div className="md:col-span-1 bg-cyber-850 p-5 rounded-xl border border-cyber-700 space-y-4">
              <h3 className="text-xs font-bold text-slate-200 uppercase tracking-wider flex items-center gap-2">
                <Send className="w-4 h-4 text-accent-cyan" />
                Dispatch Test Event
              </h3>
              <p className="text-xs text-slate-400">
                Dispatches a cryptographically signed HMAC-SHA256 test alert with an anti-replay timestamp.
              </p>

              <div>
                <label className="text-[11px] font-semibold text-slate-400 block mb-1.5">
                  Select Event Type
                </label>
                <select
                  value={selectedEventType}
                  onChange={(e) => setSelectedEventType(e.target.value)}
                  className="w-full bg-cyber-900 border border-cyber-700 rounded-lg px-3 py-2 text-xs text-slate-100 font-mono focus:outline-none focus:border-accent-cyan"
                >
                  <option value="FINDING_CRITICAL_DISCOVERED">FINDING_CRITICAL_DISCOVERED</option>
                  <option value="RISK_THRESHOLD_EXCEEDED">RISK_THRESHOLD_EXCEEDED</option>
                  <option value="ASSESSMENT_COMPLETED">ASSESSMENT_COMPLETED</option>
                  <option value="MORPH_LOCKDOWN_ENGAGED">MORPH_LOCKDOWN_ENGAGED</option>
                </select>
              </div>

              <div className="p-3 bg-cyber-900 rounded-lg border border-cyber-800 text-[11px] font-mono text-slate-400 space-y-1">
                <div>Endpoint: <span className="text-slate-200">https://siem-alert.internal.corp/webhook</span></div>
                <div>Algorithm: <span className="text-emerald-400">HMAC-SHA256</span></div>
                <div>Key ID: <span className="text-slate-200">vapt_webhook_secret_key_...</span></div>
              </div>

              <button
                onClick={handleTestWebhook}
                disabled={webhookTesting}
                className="w-full py-2.5 bg-accent-cyan hover:bg-cyan-400 text-cyber-900 font-bold rounded-lg text-xs flex items-center justify-center gap-2 transition disabled:opacity-50"
              >
                <Send className={`w-3.5 h-3.5 ${webhookTesting ? 'animate-pulse' : ''}`} />
                {webhookTesting ? 'Signing & Dispatching...' : 'Dispatch Test Alert'}
              </button>

              {webhookError && (
                <div className="p-3 bg-rose-500/10 border border-rose-500/30 text-rose-300 rounded-lg text-xs font-mono">
                  {webhookError}
                </div>
              )}
            </div>

            {/* Last Dispatch Signature Inspector */}
            <div className="md:col-span-2 bg-cyber-850 p-5 rounded-xl border border-cyber-700 space-y-3 flex flex-col justify-between">
              <div>
                <h3 className="text-xs font-bold text-slate-200 uppercase tracking-wider flex items-center gap-2 mb-2">
                  <Shield className="w-4 h-4 text-emerald-400" />
                  Live Cryptographic Signature Inspector
                </h3>
                {lastDelivery ? (
                  <div className="space-y-2 text-xs font-mono">
                    <div className="flex items-center gap-2 text-emerald-400 font-bold">
                      <CheckCircle className="w-4 h-4" />
                      <span>Delivery Confirmed (HTTP 200 OK)</span>
                    </div>
                    <div className="bg-cyber-900 p-3 rounded-lg border border-cyber-800 space-y-1.5 text-[11px]">
                      <div><span className="text-slate-400">Event ID:</span> <span className="text-slate-200">{lastDelivery.event_id}</span></div>
                      <div><span className="text-slate-400">Event Type:</span> <span className="text-accent-cyan">{lastDelivery.event_type}</span></div>
                      <div><span className="text-slate-400">Anti-Replay Timestamp:</span> <span className="text-slate-200">{lastDelivery.timestamp}</span></div>
                      <div><span className="text-slate-400">Payload Size:</span> <span className="text-slate-200">{lastDelivery.payload_size} bytes</span></div>
                      <div className="truncate"><span className="text-slate-400">HMAC-SHA256 Signature:</span> <span className="text-amber-400 font-bold">{lastDelivery.signature}</span></div>
                    </div>
                    <div className="text-[10px] text-slate-500">
                      Payload headers include: <code className="text-slate-400">X-VAPT-Signature</code>, <code className="text-slate-400">X-VAPT-Timestamp</code>, <code className="text-slate-400">X-VAPT-Event-ID</code>
                    </div>
                  </div>
                ) : (
                  <div className="py-12 text-center text-slate-500 text-xs font-mono">
                    Dispatch a test alert to inspect the cryptographic HMAC-SHA256 signature and sanitized wire payload.
                  </div>
                )}
              </div>

              <div className="text-[11px] text-slate-500 font-mono border-t border-cyber-850 pt-2">
                Credential Sanitization: Active (Passwords, auth tokens, and private keys automatically stripped).
              </div>
            </div>
          </div>

          {/* Delivery History Table */}
          <div className="bg-cyber-850 rounded-xl border border-cyber-700 overflow-hidden">
            <div className="px-6 py-4 border-b border-cyber-750 font-semibold text-xs text-slate-200 uppercase tracking-wider">
              Webhook Delivery History ({webhookHistory.length} Recorded)
            </div>
            <div className="divide-y divide-cyber-750">
              {webhookHistory.length === 0 ? (
                <div className="p-8 text-center text-slate-500 text-xs font-mono">
                  No webhook events recorded in this session.
                </div>
              ) : (
                webhookHistory.map((item) => (
                  <div key={item.event_id} className="p-4 hover:bg-cyber-800/40 transition flex items-center justify-between text-xs">
                    <div className="space-y-1">
                      <div className="flex items-center gap-2">
                        <span className="font-mono font-bold text-accent-cyan">{item.event_id}</span>
                        <span className="px-2 py-0.5 text-[10px] rounded bg-cyber-750 text-slate-300 font-mono">
                          {item.event_type}
                        </span>
                        <span className="px-2 py-0.5 text-[9px] rounded bg-emerald-500/20 text-emerald-400 font-mono font-bold">
                          DELIVERED
                        </span>
                      </div>
                      <div className="text-[10px] font-mono text-slate-500 truncate max-w-xl">
                        Sig: {item.signature} · {new Date(item.delivered_at).toLocaleString()}
                      </div>
                    </div>
                    <span className="text-[10px] font-mono text-slate-400">{item.payload_size} bytes</span>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      )}

      {/* SECTION 3: SIEM & Syslog Exporter */}
      {activeSection === 'siem' && (
        <div className="space-y-4">
          {/* Export Controls */}
          <div className="bg-cyber-850 p-6 rounded-xl border border-cyber-700 space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
              <div>
                <h3 className="text-sm font-bold text-slate-200 flex items-center gap-2">
                  <Terminal className="w-4 h-4 text-accent-cyan" />
                  Audit Event Stream Exporter
                </h3>
                <p className="text-xs text-slate-400 mt-1">
                  Exports project audit trails formatted for enterprise Security Information and Event Management (SIEM) ingestion.
                </p>
              </div>

              <div className="flex items-center gap-2 self-start sm:self-auto">
                <span className="text-xs font-semibold text-slate-400">Format:</span>
                {(['CEF', 'SYSLOG', 'JSON'] as const).map((fmt) => (
                  <button
                    key={fmt}
                    onClick={() => setSiemFormat(fmt)}
                    className={`px-3 py-1.5 text-xs font-mono font-bold rounded-lg border transition ${
                      siemFormat === fmt
                        ? 'bg-accent-cyan text-cyber-900 border-accent-cyan'
                        : 'bg-cyber-900 text-slate-400 border-cyber-700 hover:text-slate-200'
                    }`}
                  >
                    {fmt}
                  </button>
                ))}
              </div>
            </div>

            <div className="flex justify-end gap-3 pt-2">
              <button
                onClick={handleExportSiem}
                disabled={siemExporting}
                className="px-5 py-2 bg-accent-cyan hover:bg-cyan-400 text-cyber-900 font-bold rounded-lg text-xs flex items-center gap-2 transition disabled:opacity-50"
              >
                <Terminal className={`w-3.5 h-3.5 ${siemExporting ? 'animate-pulse' : ''}`} />
                {siemExporting ? 'Exporting Stream...' : `Export Audit Events (${siemFormat})`}
              </button>
            </div>
          </div>

          {/* Export Results Stream Container */}
          {siemResult && (
            <div className="bg-cyber-850 rounded-xl border border-cyber-700 overflow-hidden">
              <div className="px-6 py-3 border-b border-cyber-750 flex items-center justify-between bg-cyber-800">
                <div className="flex items-center gap-3">
                  <span className="text-xs font-mono font-bold text-slate-200">
                    {siemResult.format} Stream ({siemResult.total_events} Events)
                  </span>
                  <span className="text-[10px] text-slate-400 font-mono">
                    Exported: {new Date(siemResult.exported_at).toLocaleTimeString()}
                  </span>
                </div>
                <div className="flex items-center gap-2">
                  <button
                    onClick={copyToClipboard}
                    className="px-3 py-1 bg-cyber-750 hover:bg-cyber-700 text-slate-200 border border-cyber-600 rounded text-xs flex items-center gap-1.5 transition"
                  >
                    {copied ? <CheckCircle className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                    <span>{copied ? 'Copied!' : 'Copy'}</span>
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
    </div>
  );
};
