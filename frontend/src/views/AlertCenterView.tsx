import React, { useState, useEffect, useCallback } from 'react';
import {
  Bell,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  RefreshCw,
  Send,
  RotateCcw,
  ShieldAlert,
  Calendar,
  Layers,
  Search,
  Check,
  UserCheck,
} from 'lucide-react';
import { api } from '../services/api';
import type {
  AlertResponse,
  AlertListResponse,
  OutboxStatusResponse,
  MaintenanceWindowResponse,
  AlertLifecycleStatus,
} from '../types';

interface AlertCenterViewProps {
  projectId: string;
}

export const AlertCenterView: React.FC<AlertCenterViewProps> = ({ projectId }) => {
  const [activeTab, setActiveTab] = useState<'alerts' | 'outbox' | 'maintenance'>('alerts');
  const [alertsData, setAlertsData] = useState<AlertListResponse | null>(null);
  const [outboxData, setOutboxData] = useState<OutboxStatusResponse | null>(null);
  const [maintenanceWindows, setMaintenanceWindows] = useState<MaintenanceWindowResponse[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [statusFilter, setStatusFilter] = useState<string>('ALL');
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [selectedAlert, setSelectedAlert] = useState<AlertResponse | null>(null);
  const [actionInProgress, setActionInProgress] = useState<string | null>(null);

  // New Maintenance Window Form State
  const [mwTitle, setMwTitle] = useState('');
  const [mwReason, setMwReason] = useState('');
  const [mwStart, setMwStart] = useState('');
  const [mwEnd, setMwEnd] = useState('');
  const [mwSuppressCrit, setMwSuppressCrit] = useState(false);
  const [showMwModal, setShowMwModal] = useState(false);

  const fetchAlerts = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const [alertsRes, outboxRes, mwRes] = await Promise.all([
        api.getAlerts(projectId, statusFilter, severityFilter),
        api.getOutboxStatus(projectId),
        api.getMaintenanceWindows(projectId),
      ]);
      setAlertsData(alertsRes);
      setOutboxData(outboxRes);
      setMaintenanceWindows(mwRes);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Failed to fetch alerts telemetry';
      setError(msg);
    } finally {
      setLoading(false);
    }
  }, [projectId, statusFilter, severityFilter]);

  useEffect(() => {
    fetchAlerts();
  }, [fetchAlerts]);

  const handleAcknowledge = async (alertId: string) => {
    try {
      setActionInProgress(alertId);
      await api.acknowledgeAlert(alertId, 'Acknowledged by operator', projectId);
      await fetchAlerts();
      if (selectedAlert?.id === alertId) {
        const updated = await api.getAlert(alertId, projectId);
        setSelectedAlert(updated);
      }
    } catch (err: unknown) {
      alert(`Error acknowledging: ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setActionInProgress(null);
    }
  };

  const handleResolve = async (alertId: string) => {
    try {
      setActionInProgress(alertId);
      await api.resolveAlert(alertId, 'Resolved by operator', projectId);
      await fetchAlerts();
      if (selectedAlert?.id === alertId) {
        const updated = await api.getAlert(alertId, projectId);
        setSelectedAlert(updated);
      }
    } catch (err: unknown) {
      alert(`Error resolving: ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setActionInProgress(null);
    }
  };

  const handleReopen = async (alertId: string) => {
    try {
      setActionInProgress(alertId);
      await api.reopenAlert(alertId, 'Reopened by operator for reassessment', projectId);
      await fetchAlerts();
      if (selectedAlert?.id === alertId) {
        const updated = await api.getAlert(alertId, projectId);
        setSelectedAlert(updated);
      }
    } catch (err: unknown) {
      alert(`Error reopening: ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setActionInProgress(null);
    }
  };

  const handleProcessOutbox = async () => {
    try {
      setActionInProgress('outbox-process');
      const res = await api.processOutbox(50);
      alert(`Processed ${res.processed} outbox events (${res.delivered} delivered, ${res.dead_letter} dead-letter).`);
      await fetchAlerts();
    } catch (err: unknown) {
      alert(`Error processing outbox: ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setActionInProgress(null);
    }
  };

  const handleCreateMaintenanceWindow = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await api.createMaintenanceWindow(projectId, {
        title: mwTitle,
        reason: mwReason,
        start_time: new Date(mwStart).toISOString(),
        end_time: new Date(mwEnd).toISOString(),
        suppress_critical: mwSuppressCrit,
      });
      setShowMwModal(false);
      setMwTitle('');
      setMwReason('');
      setMwStart('');
      setMwEnd('');
      await fetchAlerts();
    } catch (err: unknown) {
      alert(`Error creating maintenance window: ${err instanceof Error ? err.message : String(err)}`);
    }
  };

  const getSeverityBadge = (sev: string) => {
    switch (sev) {
      case 'CRITICAL':
        return 'bg-rose-500/20 text-rose-300 border-rose-500/40';
      case 'HIGH':
        return 'bg-amber-500/20 text-amber-300 border-amber-500/40';
      case 'MEDIUM':
        return 'bg-yellow-500/20 text-yellow-300 border-yellow-500/40';
      case 'LOW':
        return 'bg-blue-500/20 text-blue-300 border-blue-500/40';
      default:
        return 'bg-slate-500/20 text-slate-300 border-slate-500/40';
    }
  };

  const getLifecycleBadge = (status: AlertLifecycleStatus) => {
    switch (status) {
      case 'NEW':
        return 'bg-cyan-500/20 text-cyan-300 border-cyan-500/40';
      case 'ACTIVE':
        return 'bg-amber-500/20 text-amber-300 border-amber-500/40';
      case 'ACKNOWLEDGED':
        return 'bg-indigo-500/20 text-indigo-300 border-indigo-500/40';
      case 'ASSIGNED':
        return 'bg-purple-500/20 text-purple-300 border-purple-500/40';
      case 'RESOLVED':
        return 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40';
      case 'REOPENED':
        return 'bg-rose-500/20 text-rose-300 border-rose-500/40';
      default:
        return 'bg-slate-500/20 text-slate-300 border-slate-500/40';
    }
  };

  const filteredItems = alertsData?.items.filter((item) => {
    if (!searchQuery) return true;
    const q = searchQuery.toLowerCase();
    return (
      item.title.toLowerCase().includes(q) ||
      item.summary.toLowerCase().includes(q) ||
      item.event_type.toLowerCase().includes(q)
    );
  }) || [];

  return (
    <div className="space-y-6">
      {/* 1. Top Executive Banner */}
      <div className="bg-gradient-to-r from-cyber-850 via-cyber-850 to-cyber-800 border border-cyber-750 rounded-xl p-6 shadow-md flex flex-col lg:flex-row lg:items-center justify-between gap-6">
        <div>
          <div className="flex items-center gap-2 mb-1.5">
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-accent-cyan/15 text-accent-cyan border border-accent-cyan/30 uppercase font-semibold">
              Prompt 31 Security Operations
            </span>
            <span className="text-xs text-slate-500 font-mono">Project UUID: {projectId}</span>
          </div>
          <h2 className="text-2xl font-bold text-white tracking-tight flex items-center gap-2.5">
            <Bell className="w-6 h-6 text-accent-cyan" />
            Security Alerting, Event Delivery & Escalation Center
          </h2>
          <p className="text-xs text-slate-400 mt-1 max-w-2xl leading-relaxed">
            Reliable event-driven alerting subsystem with transactional outbox, bounded exponential backoff, sliding-window deduplication, and HMAC-signed webhook delivery.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={fetchAlerts}
            disabled={loading}
            className="px-3.5 py-2 rounded-lg bg-cyber-800 hover:bg-cyber-750 border border-cyber-700 text-xs font-semibold text-slate-200 flex items-center gap-1.5 transition-colors disabled:opacity-50"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </button>
        </div>
      </div>

      {error && (
        <div className="p-4 bg-rose-500/10 border border-rose-500/30 rounded-lg text-rose-300 text-xs flex items-center gap-2">
          <XCircle className="w-4 h-4 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* 2. Key Operational KPI Tiles */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-cyber-850 border border-cyber-750 rounded-xl p-4 shadow-sm">
          <div className="flex items-center justify-between text-slate-400 text-xs mb-1">
            <span>Active Alerts</span>
            <AlertTriangle className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-amber-400">
            {alertsData?.active_count ?? 0}
          </div>
          <p className="text-[11px] text-slate-500 mt-1">Pending triage or investigation</p>
        </div>

        <div className="bg-cyber-850 border border-cyber-750 rounded-xl p-4 shadow-sm">
          <div className="flex items-center justify-between text-slate-400 text-xs mb-1">
            <span>Critical Exposure Alerts</span>
            <ShieldAlert className="w-4 h-4 text-rose-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-rose-400">
            {alertsData?.critical_count ?? 0}
          </div>
          <p className="text-[11px] text-slate-500 mt-1">Breaks through quiet periods</p>
        </div>

        <div className="bg-cyber-850 border border-cyber-750 rounded-xl p-4 shadow-sm">
          <div className="flex items-center justify-between text-slate-400 text-xs mb-1">
            <span>Transactional Outbox</span>
            <Layers className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-cyan-400">
            {outboxData?.pending_count ?? 0} PENDING
          </div>
          <p className="text-[11px] text-slate-500 mt-1">
            {outboxData?.delivered_count ?? 0} delivered · {outboxData?.dead_letter_count ?? 0} dead-letter
          </p>
        </div>

        <div className="bg-cyber-850 border border-cyber-750 rounded-xl p-4 shadow-sm">
          <div className="flex items-center justify-between text-slate-400 text-xs mb-1">
            <span>Delivery Health</span>
            {outboxData?.healthy ? (
              <CheckCircle2 className="w-4 h-4 text-emerald-400" />
            ) : (
              <AlertTriangle className="w-4 h-4 text-rose-400" />
            )}
          </div>
          <div className="text-2xl font-bold font-mono text-emerald-400">
            {outboxData?.healthy ? 'HEALTHY' : 'BACKLOG_WARN'}
          </div>
          <p className="text-[11px] text-slate-500 mt-1">
            {outboxData?.dead_letter_count === 0 ? 'Zero dead-letter events' : `${outboxData?.dead_letter_count} events need replay`}
          </p>
        </div>
      </div>

      {/* 3. Navigation Tabs */}
      <div className="border-b border-cyber-750 flex items-center justify-between">
        <div className="flex space-x-6">
          <button
            onClick={() => setActiveTab('alerts')}
            className={`pb-3 text-xs font-semibold uppercase tracking-wider transition-colors flex items-center gap-1.5 ${
              activeTab === 'alerts'
                ? 'text-accent-cyan border-b-2 border-accent-cyan'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Bell className="w-4 h-4" />
            Alert Ledger ({alertsData?.total ?? 0})
          </button>

          <button
            onClick={() => setActiveTab('outbox')}
            className={`pb-3 text-xs font-semibold uppercase tracking-wider transition-colors flex items-center gap-1.5 ${
              activeTab === 'outbox'
                ? 'text-accent-cyan border-b-2 border-accent-cyan'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Layers className="w-4 h-4" />
            Transactional Outbox & Dead-Letter
          </button>

          <button
            onClick={() => setActiveTab('maintenance')}
            className={`pb-3 text-xs font-semibold uppercase tracking-wider transition-colors flex items-center gap-1.5 ${
              activeTab === 'maintenance'
                ? 'text-accent-cyan border-b-2 border-accent-cyan'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Calendar className="w-4 h-4" />
            Maintenance Windows ({maintenanceWindows.length})
          </button>
        </div>
      </div>

      {/* 4. Tab Content */}
      {activeTab === 'alerts' && (
        <div className="space-y-4">
          {/* Filters Bar */}
          <div className="bg-cyber-850 border border-cyber-750 rounded-xl p-4 flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div className="flex items-center gap-3 flex-wrap">
              <div className="relative">
                <Search className="w-3.5 h-3.5 absolute left-3 top-2.5 text-slate-500" />
                <input
                  type="text"
                  placeholder="Search alert title or summary..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="bg-cyber-900 border border-cyber-700 text-xs text-slate-200 rounded-lg pl-8 pr-3 py-1.5 w-64"
                />
              </div>

              <div className="flex items-center gap-2">
                <label className="text-xs text-slate-400 font-mono">Status:</label>
                <select
                  value={statusFilter}
                  onChange={(e) => setStatusFilter(e.target.value)}
                  className="bg-cyber-900 border border-cyber-700 text-xs text-slate-200 rounded px-2.5 py-1"
                >
                  <option value="ALL">All Statuses</option>
                  <option value="NEW">NEW</option>
                  <option value="ACTIVE">ACTIVE</option>
                  <option value="ACKNOWLEDGED">ACKNOWLEDGED</option>
                  <option value="ASSIGNED">ASSIGNED</option>
                  <option value="RESOLVED">RESOLVED</option>
                  <option value="REOPENED">REOPENED</option>
                </select>
              </div>

              <div className="flex items-center gap-2">
                <label className="text-xs text-slate-400 font-mono">Severity:</label>
                <select
                  value={severityFilter}
                  onChange={(e) => setSeverityFilter(e.target.value)}
                  className="bg-cyber-900 border border-cyber-700 text-xs text-slate-200 rounded px-2.5 py-1"
                >
                  <option value="ALL">All Severities</option>
                  <option value="CRITICAL">CRITICAL</option>
                  <option value="HIGH">HIGH</option>
                  <option value="MEDIUM">MEDIUM</option>
                  <option value="LOW">LOW</option>
                  <option value="INFO">INFO</option>
                </select>
              </div>
            </div>

            <div className="text-xs font-mono text-slate-400">
              Showing {filteredItems.length} of {alertsData?.total ?? 0} alerts
            </div>
          </div>

          {/* Alerts List */}
          {loading && !alertsData ? (
            <div className="p-12 text-center text-xs text-slate-500 font-mono">Loading alert records...</div>
          ) : filteredItems.length === 0 ? (
            <div className="p-8 text-center text-xs text-slate-500 bg-cyber-850 rounded-xl border border-cyber-750">
              No alerts match the selected criteria.
            </div>
          ) : (
            <div className="space-y-3">
              {filteredItems.map((alertItem: AlertResponse) => (
                <div
                  key={alertItem.id}
                  className="bg-cyber-850 border border-cyber-750 hover:border-cyber-700 rounded-xl p-4 transition-all flex flex-col md:flex-row md:items-center justify-between gap-4"
                >
                  <div className="space-y-1.5 flex-1">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className={`text-[10px] font-mono px-2 py-0.5 rounded font-bold border ${getSeverityBadge(alertItem.severity)}`}>
                        {alertItem.severity}
                      </span>
                      <span className={`text-[10px] font-mono px-2 py-0.5 rounded font-bold border ${getLifecycleBadge(alertItem.lifecycle_status)}`}>
                        {alertItem.lifecycle_status}
                      </span>
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyber-900 text-slate-400 border border-cyber-800">
                        {alertItem.event_type.replace(/_/g, ' ')}
                      </span>
                      <span className="font-semibold text-slate-100 text-xs">{alertItem.title}</span>
                    </div>

                    <p className="text-xs text-slate-300 leading-relaxed">{alertItem.summary}</p>

                    <div className="flex items-center gap-4 text-[10px] font-mono text-slate-500 flex-wrap">
                      <span>ID: {alertItem.id.slice(0, 8)}</span>
                      <span>Delivery: {alertItem.delivery_status}</span>
                      {alertItem.suppression_reason && (
                        <span className="text-amber-400">Suppression: {alertItem.suppression_reason}</span>
                      )}
                      <span>Created: {new Date(alertItem.created_at).toLocaleTimeString()}</span>
                      {alertItem.acknowledged_at && <span>Acked: {new Date(alertItem.acknowledged_at).toLocaleTimeString()}</span>}
                    </div>
                  </div>

                  {/* Actions */}
                  <div className="flex items-center gap-2 shrink-0">
                    {alertItem.lifecycle_status !== 'ACKNOWLEDGED' && alertItem.lifecycle_status !== 'RESOLVED' && (
                      <button
                        onClick={() => handleAcknowledge(alertItem.id)}
                        disabled={actionInProgress === alertItem.id}
                        className="px-2.5 py-1.5 rounded bg-indigo-500/20 hover:bg-indigo-500/30 text-indigo-300 border border-indigo-500/40 text-xs font-semibold flex items-center gap-1 transition-colors disabled:opacity-50"
                      >
                        <UserCheck className="w-3.5 h-3.5" />
                        Ack
                      </button>
                    )}

                    {alertItem.lifecycle_status !== 'RESOLVED' && (
                      <button
                        onClick={() => handleResolve(alertItem.id)}
                        disabled={actionInProgress === alertItem.id}
                        className="px-2.5 py-1.5 rounded bg-emerald-500/20 hover:bg-emerald-500/30 text-emerald-300 border border-emerald-500/40 text-xs font-semibold flex items-center gap-1 transition-colors disabled:opacity-50"
                      >
                        <Check className="w-3.5 h-3.5" />
                        Resolve
                      </button>
                    )}

                    {alertItem.lifecycle_status === 'RESOLVED' && (
                      <button
                        onClick={() => handleReopen(alertItem.id)}
                        disabled={actionInProgress === alertItem.id}
                        className="px-2.5 py-1.5 rounded bg-rose-500/20 hover:bg-rose-500/30 text-rose-300 border border-rose-500/40 text-xs font-semibold flex items-center gap-1 transition-colors disabled:opacity-50"
                      >
                        <RotateCcw className="w-3.5 h-3.5" />
                        Reopen
                      </button>
                    )}

                    <button
                      onClick={() => setSelectedAlert(alertItem)}
                      className="px-2.5 py-1.5 rounded bg-cyber-800 hover:bg-cyber-750 text-slate-300 text-xs transition-colors"
                    >
                      Details
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Outbox & Dead-Letter Tab */}
      {activeTab === 'outbox' && (
        <div className="space-y-6">
          <div className="bg-cyber-850 border border-cyber-750 rounded-xl p-5 shadow-lg">
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
              <div>
                <h3 className="text-sm font-semibold text-white">Transactional Outbox Queue</h3>
                <p className="text-xs text-slate-400 mt-1">
                  Guarantees that database mutations and event publications remain atomic. Retries failed dispatches with bounded exponential backoff.
                </p>
              </div>

              <button
                onClick={handleProcessOutbox}
                disabled={actionInProgress === 'outbox-process'}
                className="px-4 py-2 rounded-lg bg-accent-blue/20 hover:bg-accent-blue/30 text-accent-blue border border-accent-blue/40 text-xs font-semibold flex items-center gap-1.5 transition-colors disabled:opacity-50"
              >
                <Send className="w-3.5 h-3.5" />
                Dispatch Outbox Batch
              </button>
            </div>

            <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mt-6 font-mono text-xs">
              <div className="p-3 bg-cyber-900 border border-cyber-800 rounded-lg">
                <span className="text-slate-500">Pending Outbox</span>
                <div className="text-xl font-bold text-cyan-400 mt-1">{outboxData?.pending_count ?? 0}</div>
              </div>
              <div className="p-3 bg-cyber-900 border border-cyber-800 rounded-lg">
                <span className="text-slate-500">Delivered</span>
                <div className="text-xl font-bold text-emerald-400 mt-1">{outboxData?.delivered_count ?? 0}</div>
              </div>
              <div className="p-3 bg-cyber-900 border border-cyber-800 rounded-lg">
                <span className="text-slate-500">Suppressed (Quiet/Dedup)</span>
                <div className="text-xl font-bold text-amber-400 mt-1">{outboxData?.suppressed_count ?? 0}</div>
              </div>
              <div className="p-3 bg-cyber-900 border border-cyber-800 rounded-lg">
                <span className="text-slate-500">Dead-Letter Queue</span>
                <div className="text-xl font-bold text-rose-400 mt-1">{outboxData?.dead_letter_count ?? 0}</div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Maintenance Windows Tab */}
      {activeTab === 'maintenance' && (
        <div className="space-y-6">
          <div className="bg-cyber-850 border border-cyber-750 rounded-xl p-5 shadow-lg">
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
              <div>
                <h3 className="text-sm font-semibold text-white">Scheduled Maintenance Windows</h3>
                <p className="text-xs text-slate-400 mt-1">
                  Defines planned quiet periods. Non-critical alerts are suppressed with explainable audit logs; critical security breaches break through automatically.
                </p>
              </div>

              <button
                onClick={() => setShowMwModal(true)}
                className="px-4 py-2 rounded-lg bg-accent-cyan/20 hover:bg-accent-cyan/30 text-accent-cyan border border-accent-cyan/40 text-xs font-semibold flex items-center gap-1.5 transition-colors"
              >
                <Calendar className="w-3.5 h-3.5" />
                Schedule Maintenance Window
              </button>
            </div>

            <div className="mt-6 space-y-3">
              {maintenanceWindows.length === 0 ? (
                <div className="p-8 text-center text-xs text-slate-500 bg-cyber-900 rounded-lg border border-cyber-800">
                  No maintenance windows configured. All security events will be delivered according to policy.
                </div>
              ) : (
                maintenanceWindows.map((mw) => (
                  <div
                    key={mw.id}
                    className="p-4 bg-cyber-900 border border-cyber-800 rounded-lg flex flex-col md:flex-row md:items-center justify-between gap-3 text-xs"
                  >
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="font-semibold text-slate-100">{mw.title}</span>
                        {mw.is_currently_active && (
                          <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-amber-500/20 text-amber-300 border border-amber-500/40 font-bold">
                            CURRENTLY ACTIVE
                          </span>
                        )}
                      </div>
                      <p className="text-[11px] text-slate-400 mt-0.5">{mw.reason}</p>
                      <div className="text-[10px] text-slate-500 font-mono mt-1">
                        Start: {new Date(mw.start_time).toLocaleString()} · End: {new Date(mw.end_time).toLocaleString()} · Suppress Critical: {mw.suppress_critical ? 'YES' : 'NO (CRITICALS DELIVERED)'}
                      </div>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      )}

      {/* Detail Modal */}
      {selectedAlert && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center p-4 z-50">
          <div className="bg-cyber-850 border border-cyber-750 rounded-xl p-6 max-w-2xl w-full shadow-2xl space-y-4">
            <div className="flex items-center justify-between border-b border-cyber-750 pb-3">
              <div className="flex items-center gap-2">
                <span className={`text-[10px] font-mono px-2 py-0.5 rounded font-bold border ${getSeverityBadge(selectedAlert.severity)}`}>
                  {selectedAlert.severity}
                </span>
                <h3 className="text-sm font-bold text-white">{selectedAlert.title}</h3>
              </div>
              <button
                onClick={() => setSelectedAlert(null)}
                className="text-slate-400 hover:text-white text-xs font-mono"
              >
                Close [x]
              </button>
            </div>

            <div className="space-y-3 text-xs">
              <div>
                <span className="text-slate-500 font-mono">Summary:</span>
                <p className="text-slate-200 mt-0.5">{selectedAlert.summary}</p>
              </div>

              <div className="grid grid-cols-2 gap-3 font-mono text-[11px] bg-cyber-900 p-3 rounded-lg border border-cyber-800">
                <div>
                  <span className="text-slate-500">Alert ID:</span>
                  <div className="text-slate-300 truncate">{selectedAlert.id}</div>
                </div>
                <div>
                  <span className="text-slate-500">Lifecycle Status:</span>
                  <div className="text-slate-300">{selectedAlert.lifecycle_status}</div>
                </div>
                <div>
                  <span className="text-slate-500">Delivery Status:</span>
                  <div className="text-slate-300">{selectedAlert.delivery_status}</div>
                </div>
                <div>
                  <span className="text-slate-500">Schema Version:</span>
                  <div className="text-slate-300">{selectedAlert.schema_version}</div>
                </div>
                {selectedAlert.suppression_reason && (
                  <div className="col-span-2">
                    <span className="text-slate-500">Suppression Reason:</span>
                    <div className="text-amber-300">{selectedAlert.suppression_reason}</div>
                  </div>
                )}
                {selectedAlert.error_message && (
                  <div className="col-span-2">
                    <span className="text-slate-500">Last Delivery Error:</span>
                    <div className="text-rose-400">{selectedAlert.error_message}</div>
                  </div>
                )}
              </div>
            </div>

            <div className="flex justify-end pt-2">
              <button
                onClick={() => setSelectedAlert(null)}
                className="px-4 py-1.5 rounded bg-cyber-800 hover:bg-cyber-700 text-slate-200 text-xs"
              >
                Dismiss View
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Schedule Maintenance Window Modal */}
      {showMwModal && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center p-4 z-50">
          <form onSubmit={handleCreateMaintenanceWindow} className="bg-cyber-850 border border-cyber-750 rounded-xl p-6 max-w-lg w-full shadow-2xl space-y-4">
            <div className="flex items-center justify-between border-b border-cyber-750 pb-3">
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <Calendar className="w-4 h-4 text-accent-cyan" />
                Schedule Maintenance Window
              </h3>
              <button
                type="button"
                onClick={() => setShowMwModal(false)}
                className="text-slate-400 hover:text-white text-xs font-mono"
              >
                Close [x]
              </button>
            </div>

            <div className="space-y-3 text-xs">
              <div>
                <label className="text-slate-400 font-mono block mb-1">Window Title:</label>
                <input
                  type="text"
                  required
                  value={mwTitle}
                  onChange={(e) => setMwTitle(e.target.value)}
                  placeholder="e.g., Q4 Production Cluster OS Upgrade"
                  className="w-full bg-cyber-900 border border-cyber-700 rounded px-3 py-1.5 text-slate-200"
                />
              </div>

              <div>
                <label className="text-slate-400 font-mono block mb-1">Reason / Change Ticket:</label>
                <textarea
                  required
                  value={mwReason}
                  onChange={(e) => setMwReason(e.target.value)}
                  placeholder="e.g., Planned maintenance window CHG-88219"
                  className="w-full bg-cyber-900 border border-cyber-700 rounded px-3 py-1.5 text-slate-200 h-20"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-slate-400 font-mono block mb-1">Start Time (Local):</label>
                  <input
                    type="datetime-local"
                    required
                    value={mwStart}
                    onChange={(e) => setMwStart(e.target.value)}
                    className="w-full bg-cyber-900 border border-cyber-700 rounded px-2.5 py-1 text-slate-200"
                  />
                </div>
                <div>
                  <label className="text-slate-400 font-mono block mb-1">End Time (Local):</label>
                  <input
                    type="datetime-local"
                    required
                    value={mwEnd}
                    onChange={(e) => setMwEnd(e.target.value)}
                    className="w-full bg-cyber-900 border border-cyber-700 rounded px-2.5 py-1 text-slate-200"
                  />
                </div>
              </div>

              <div className="flex items-center gap-2 pt-1">
                <input
                  type="checkbox"
                  id="suppressCrit"
                  checked={mwSuppressCrit}
                  onChange={(e) => setMwSuppressCrit(e.target.checked)}
                  className="rounded bg-cyber-900 border-cyber-700"
                />
                <label htmlFor="suppressCrit" className="text-slate-300">
                  Suppress Critical Alerts (Default is unchecked; criticals always notify)
                </label>
              </div>
            </div>

            <div className="flex justify-end gap-2 pt-3 border-t border-cyber-750">
              <button
                type="button"
                onClick={() => setShowMwModal(false)}
                className="px-3.5 py-1.5 rounded bg-cyber-800 hover:bg-cyber-700 text-slate-300 text-xs"
              >
                Cancel
              </button>
              <button
                type="submit"
                className="px-4 py-1.5 rounded bg-accent-cyan/20 hover:bg-accent-cyan/30 text-accent-cyan border border-accent-cyan/40 text-xs font-semibold"
              >
                Save Window
              </button>
            </div>
          </form>
        </div>
      )}
    </div>
  );
};
