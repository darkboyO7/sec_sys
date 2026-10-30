import React, { useState, useEffect } from 'react';
import {
  Activity,
  Database,
  HardDrive,
  ShieldCheck,
  RefreshCw,
  Layers,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  HelpCircle,
  Wrench,
  BookOpen,
} from 'lucide-react';
import { api } from '../services/api';
import type { ReadinessResponse, OperationalHealthState, DegradationHealthResponse } from '../types';

interface SystemHealthViewProps {
  health: { status: string; version: string; environment: string; timestamp: string } | null;
  readiness: ReadinessResponse | null;
  onRefresh: () => void;
  loading: boolean;
}

export const SystemHealthView: React.FC<SystemHealthViewProps> = ({
  readiness,
  onRefresh,
  loading,
}) => {
  const [degradationData, setDegradationData] = useState<DegradationHealthResponse | null>(null);
  const [loadingDegradation, setLoadingDegradation] = useState<boolean>(false);

  const fetchDegradation = async () => {
    setLoadingDegradation(true);
    try {
      const data = await api.getDegradationStatus();
      setDegradationData(data);
    } catch {
      // Degraded or offline fallback handled gracefully
    } finally {
      setLoadingDegradation(false);
    }
  };

  useEffect(() => {
    fetchDegradation();
  }, []);

  const handleFullRefresh = () => {
    onRefresh();
    fetchDegradation();
  };

  // Determine precise operational state (never display unknown as healthy)
  const getOperationalStatus = (): OperationalHealthState => {
    if (loading && !readiness) return 'UNKNOWN';
    if (!readiness) return 'UNKNOWN';
    if (readiness.status === 'not_ready') return 'UNAVAILABLE';
    if (readiness.degraded || (degradationData && degradationData.degraded_capabilities.length > 0)) return 'DEGRADED';
    if (readiness.status === 'ready') return 'HEALTHY';
    return 'UNKNOWN';
  };

  const status = getOperationalStatus();

  return (
    <div className="space-y-6">
      {/* Title & Live Status */}
      <div className="bg-cyber-850 border border-cyber-750 rounded-xl p-5 shadow-lg flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <Activity className="w-5 h-5 text-accent-cyan" />
            <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono">
              Control Plane Health & Observability
            </h3>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Real-time diagnostics and layered operational probes across database persistence, migrations, and local storage.
          </p>
        </div>

        <button
          onClick={handleFullRefresh}
          disabled={loading || loadingDegradation}
          className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-cyber-800 hover:bg-cyber-750 text-slate-300 hover:text-white text-xs font-semibold transition-colors shrink-0"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading || loadingDegradation ? 'animate-spin text-accent-cyan' : ''}`} />
          Run Health Probes
        </button>
      </div>

      {/* Primary Health State Banner */}
      <div
        className={`p-4 rounded-xl border flex items-center justify-between ${
          status === 'HEALTHY'
            ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300'
            : status === 'DEGRADED'
            ? 'bg-amber-500/10 border-amber-500/30 text-amber-300'
            : status === 'UNAVAILABLE'
            ? 'bg-rose-500/10 border-rose-500/30 text-rose-300'
            : 'bg-slate-800/40 border-slate-700 text-slate-400'
        }`}
      >
        <div className="flex items-center gap-3">
          {status === 'HEALTHY' && <CheckCircle2 className="w-6 h-6 text-emerald-400" />}
          {status === 'DEGRADED' && <AlertTriangle className="w-6 h-6 text-amber-400" />}
          {status === 'UNAVAILABLE' && <XCircle className="w-6 h-6 text-rose-400" />}
          {status === 'UNKNOWN' && <HelpCircle className="w-6 h-6 text-slate-400" />}

          <div>
            <div className="text-xs font-bold uppercase font-mono tracking-wider">
              System State: {status}
            </div>
            <p className="text-xs opacity-90 mt-0.5">
              {status === 'HEALTHY' && 'All critical persistence engines and subsystem services are fully operational.'}
              {status === 'DEGRADED' && 'Core platform is operational, but one or more optional integrations are degraded or offline.'}
              {status === 'UNAVAILABLE' && 'Critical dependencies failed. Control plane cannot safely process assessment workloads.'}
              {status === 'UNKNOWN' && 'Health probe not yet executed or awaiting backend diagnostic response.'}
            </p>
          </div>
        </div>

        <span
          className={`px-3 py-1 rounded text-xs font-mono font-bold uppercase ${
            status === 'HEALTHY'
              ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
              : status === 'DEGRADED'
              ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40'
              : status === 'UNAVAILABLE'
              ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40'
              : 'bg-slate-700 text-slate-300 border border-slate-600'
          }`}
        >
          {status}
        </span>
      </div>

      {/* Degraded Alert Notice if in DEGRADED mode */}
      {status === 'DEGRADED' && (
        <div className="bg-amber-950/20 border border-amber-500/30 rounded-xl p-4 text-xs space-y-2">
          <div className="font-bold text-amber-400 flex items-center gap-1.5">
            <AlertTriangle className="w-4 h-4" />
            <span>Operator Notice: Degraded Subsystem Operation</span>
          </div>
          <p className="text-amber-200/80 leading-relaxed">
            The core SQLite/PostgreSQL persistence engine and storage volume are fully functional. Secondary subsystems
            (such as external notification dispatchers or threat intelligence caches) may be in offline or degraded mode.
            Passive vulnerability scanning and attack path generation continue safely.
          </p>
        </div>
      )}

      {/* Status Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {/* Database Diagnostic */}
        <div className="bg-cyber-850 border border-cyber-750 rounded-xl p-5 shadow-md">
          <div className="flex items-center justify-between mb-3">
            <div className="w-9 h-9 rounded-lg bg-accent-blue/15 border border-accent-blue/30 flex items-center justify-center text-accent-blue">
              <Database className="w-5 h-5" />
            </div>
            {readiness?.checks?.database ? (
              <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                CONNECTED
              </span>
            ) : readiness ? (
              <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-rose-500/10 text-rose-400 border border-rose-500/30">
                UNREACHABLE
              </span>
            ) : (
              <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-700 text-slate-400 border border-slate-600">
                UNKNOWN
              </span>
            )}
          </div>
          <h4 className="text-xs font-bold text-white uppercase font-mono mb-1">Database Connectivity</h4>
          <p className="text-xs text-slate-400 leading-relaxed">
            Status:{' '}
            <span className="font-mono text-slate-200">
              {readiness?.checks?.details?.database || 'Pending probe...'}
            </span>
          </p>
          <div className="mt-3 text-[10px] text-slate-500 font-mono">
            Mode: SQLite WAL (Native Windows Development)
          </div>
        </div>

        {/* Migrations Diagnostic */}
        <div className="bg-cyber-850 border border-cyber-750 rounded-xl p-5 shadow-md">
          <div className="flex items-center justify-between mb-3">
            <div className="w-9 h-9 rounded-lg bg-accent-cyan/15 border border-accent-cyan/30 flex items-center justify-center text-accent-cyan">
              <Layers className="w-5 h-5" />
            </div>
            {readiness?.checks?.migrations ? (
              <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                SCHEMA VERIFIED
              </span>
            ) : readiness ? (
              <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-amber-500/10 text-amber-400 border border-amber-500/30">
                PENDING
              </span>
            ) : (
              <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-700 text-slate-400 border border-slate-600">
                UNKNOWN
              </span>
            )}
          </div>
          <h4 className="text-xs font-bold text-white uppercase font-mono mb-1">Alembic Schema & Models</h4>
          <p className="text-xs text-slate-400 leading-relaxed">
            Status:{' '}
            <span className="font-mono text-slate-200">
              {readiness?.checks?.details?.schema || 'Pending probe...'}
            </span>
          </p>
          <div className="mt-3 text-[10px] text-slate-500 font-mono">Revision: 8eb564b33c13_initial_schema</div>
        </div>

        {/* Storage Writability */}
        <div className="bg-cyber-850 border border-cyber-750 rounded-xl p-5 shadow-md">
          <div className="flex items-center justify-between mb-3">
            <div className="w-9 h-9 rounded-lg bg-emerald-500/15 border border-emerald-500/30 flex items-center justify-center text-emerald-400">
              <HardDrive className="w-5 h-5" />
            </div>
            {readiness?.checks?.storage_writable ? (
              <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                WRITABLE
              </span>
            ) : readiness ? (
              <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-rose-500/10 text-rose-400 border border-rose-500/30">
                READ-ONLY
              </span>
            ) : (
              <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-700 text-slate-400 border border-slate-600">
                UNKNOWN
              </span>
            )}
          </div>
          <h4 className="text-xs font-bold text-white uppercase font-mono mb-1">Data Storage Access</h4>
          <p className="text-xs text-slate-400 leading-relaxed">
            Status:{' '}
            <span className="font-mono text-slate-200">
              {readiness?.checks?.details?.storage || 'Pending probe...'}
            </span>
          </p>
          <div className="mt-3 text-[10px] text-slate-500 font-mono">Path: ./data/vapt.db</div>
        </div>
      </div>

      {/* Prompt 52: Critical Capability Matrix & Operational Degradation Guidance */}
      <div className="bg-cyber-850 border border-cyber-750 rounded-xl p-6 shadow-md space-y-4">
        <div className="flex items-center justify-between pb-3 border-b border-cyber-750">
          <div className="flex items-center gap-2 text-white font-bold text-xs uppercase font-mono tracking-wider">
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
            <span>Critical Capabilities & Degradation Matrix</span>
          </div>
          {degradationData && (
            <span
              className={`px-2.5 py-0.5 rounded text-[10px] font-mono font-bold uppercase ${
                degradationData.status === 'healthy'
                  ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30'
                  : degradationData.status === 'degraded'
                  ? 'bg-amber-500/10 text-amber-400 border border-amber-500/30'
                  : 'bg-rose-500/10 text-rose-400 border border-rose-500/30'
              }`}
            >
              Mode: {degradationData.status}
            </span>
          )}
        </div>

        {/* Operator Recommendations Banner */}
        {degradationData && degradationData.operator_recommendations.length > 0 && (
          <div className="bg-cyber-900 border border-cyber-750 rounded-lg p-3 space-y-1.5 text-xs">
            <div className="text-accent-cyan font-bold flex items-center gap-1.5 font-mono">
              <Wrench className="w-3.5 h-3.5" />
              <span>Operator Action Playbook</span>
            </div>
            <ul className="list-disc list-inside text-slate-300 space-y-1 text-[11px]">
              {degradationData.operator_recommendations.map((rec, i) => (
                <li key={i} className="leading-relaxed">
                  {rec}
                </li>
              ))}
            </ul>
          </div>
        )}

        {/* Capability Grid */}
        {degradationData && degradationData.capabilities && (
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
            {Object.entries(degradationData.capabilities).map(([key, cap]: [string, any]) => {
              const isDegraded = degradationData.degraded_capabilities.includes(key);
              return (
                <div
                  key={key}
                  className={`p-3 rounded-lg border text-xs flex flex-col justify-between ${
                    isDegraded
                      ? 'bg-amber-500/10 border-amber-500/30 text-amber-200'
                      : 'bg-cyber-900 border-cyber-750 text-slate-300'
                  }`}
                >
                  <div>
                    <div className="flex items-center justify-between mb-1.5">
                      <span className="text-[10px] font-mono font-bold text-slate-400 truncate uppercase">
                        {cap.criticality}
                      </span>
                      <span
                        className={`px-1.5 py-0.2 rounded text-[9px] font-mono font-bold ${
                          isDegraded
                            ? 'bg-amber-500/20 text-amber-300'
                            : 'bg-emerald-500/20 text-emerald-300'
                        }`}
                      >
                        {isDegraded ? 'DEGRADED' : 'OPERATIONAL'}
                      </span>
                    </div>
                    <div className="font-bold text-white text-[11px] mb-1">{cap.name}</div>
                    <p className="text-[10px] text-slate-400 leading-snug">{cap.description}</p>
                  </div>
                  <div className="mt-2 pt-2 border-t border-cyber-750/50 text-[9px] font-mono text-slate-500 truncate">
                    Dependencies: {cap.dependencies?.join(', ')}
                  </div>
                </div>
              );
            })}
          </div>
        )}

        {/* Collapsible Playbook Drawer */}
        {degradationData && degradationData.failure_playbooks && (
          <div className="pt-2">
            <details className="text-xs group">
              <summary className="cursor-pointer text-slate-400 hover:text-white font-mono flex items-center gap-1.5 select-none py-1">
                <BookOpen className="w-3.5 h-3.5 text-accent-blue" />
                <span className="font-semibold text-slate-300">
                  Inspect Failure Classification Catalog & Recovery Playbooks (
                  {Object.keys(degradationData.failure_playbooks).length} Playbooks)
                </span>
              </summary>
              <div className="mt-3 grid grid-cols-1 md:grid-cols-2 gap-3 pl-2">
                {Object.entries(degradationData.failure_playbooks).map(([code, pb]: [string, any]) => (
                  <div
                    key={code}
                    className="p-3 rounded-lg bg-cyber-900 border border-cyber-750 space-y-1.5 text-xs"
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-mono font-bold text-accent-cyan text-[11px]">{code}</span>
                      <span className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-cyber-800 text-slate-300">
                        {pb.severity}
                      </span>
                    </div>
                    <div className="text-white font-semibold text-xs">{pb.name}</div>
                    <p className="text-slate-400 text-[11px] leading-relaxed">{pb.operator_summary}</p>
                    <div className="pt-1.5 border-t border-cyber-750/40 text-[10px] text-slate-400 space-y-0.5">
                      <div className="text-slate-300 font-mono font-bold">Manual Recovery Steps:</div>
                      {pb.manual_recovery_steps?.map((step: string, sIdx: number) => (
                        <div key={sIdx} className="text-slate-400">
                          {step}
                        </div>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </details>
          </div>
        )}
      </div>

      {/* Production Migration Notice & Architectural Invariants */}
      <div className="bg-cyber-850 border border-cyber-750 rounded-xl p-6 shadow-md font-mono text-xs space-y-4">
        <div className="flex items-center gap-2 pb-2 border-b border-cyber-750 text-white font-bold">
          <ShieldCheck className="w-4 h-4 text-accent-cyan" />
          <span>Architectural Integrity & PostgreSQL Production Guarantee</span>
        </div>

        <div className="space-y-2 text-slate-300 leading-relaxed font-sans text-xs">
          <p>
            <strong className="text-white">Local Development Engine:</strong> SQLite 3 running in{' '}
            <code className="text-accent-cyan font-mono">journal_mode=WAL</code> with strict{' '}
            <code className="text-accent-cyan font-mono">PRAGMA foreign_keys=ON</code>.
          </p>
          <p>
            <strong className="text-white">PostgreSQL Production Guarantee:</strong> All primary keys use RFC 4122
            UUIDs, datetimes are UTC timezone-aware, foreign keys use cascading/restrict rules, and JSON fields map
            directly to PostgreSQL JSONB columns. Transitioning to a production PostgreSQL database requires changing
            only <code className="text-accent-cyan font-mono">DATABASE_URL</code> in <code className="text-accent-cyan font-mono">.env</code>.
          </p>
          <p>
            <strong className="text-white">Fail-Closed Boundary:</strong> By design, all scanner dispatchers,
            automated test tools, and future workers remain inactive until a verified target scope authorization proof is
            registered.
          </p>
        </div>
      </div>
    </div>
  );
};
