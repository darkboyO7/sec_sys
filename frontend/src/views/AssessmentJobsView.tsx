import React, { useState, useMemo } from 'react';
import {
  PlayCircle,
  CheckCircle2,
  AlertTriangle,
  Clock,
  Ban,
  RefreshCw,
  Plus,
  X,
  Hash,
  Shield,
  Zap,
  TestTube2,
  Search,
  Filter,
  ExternalLink,
  ChevronRight,
  ShieldCheck,
  AlertCircle,
} from 'lucide-react';
import type { Project, AssessmentJob, AssessmentFinding, ScopeTarget, FindingSeverity } from '../types';
import { api } from '../services/api';
import { EmptyState } from '../components/EmptyState';

interface AssessmentJobsViewProps {
  project: Project;
  authorizedTargets: ScopeTarget[];
  jobs: AssessmentJob[];
  onRefresh: () => void;
  loading: boolean;
  onNavigateToScopes?: () => void;
  onNavigateToFindings?: () => void;
}

export const AssessmentJobsView: React.FC<AssessmentJobsViewProps> = ({
  project,
  authorizedTargets,
  jobs,
  onRefresh,
  loading,
  onNavigateToScopes,
  onNavigateToFindings,
}) => {
  const [isLaunchModalOpen, setIsLaunchModalOpen] = useState(false);
  const [selectedJob, setSelectedJob] = useState<AssessmentJob | null>(null);
  const [jobFindings, setJobFindings] = useState<AssessmentFinding[]>([]);
  const [loadingFindings, setLoadingFindings] = useState(false);
  const [selectedFinding, setSelectedFinding] = useState<AssessmentFinding | null>(null);

  // Search & Filter state
  const [searchTerm, setSearchTerm] = useState('');
  const [statusFilter, setStatusFilter] = useState('ALL');
  const [modeFilter, setModeFilter] = useState('ALL');

  // Launch Form state
  const [targetInput, setTargetInput] = useState('');
  const [adapterName, setAdapterName] = useState('live_network_auditor_adapter');
  const [fixtureProfile, setFixtureProfile] = useState('LIVE_WEB_SECURITY_AUDIT');
  const [timeoutSeconds, setTimeoutSeconds] = useState(30);
  const [idempotencyKey, setIdempotencyKey] = useState('');
  const [launching, setLaunching] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const adapterOptions = [
    {
      id: 'live_network_auditor_adapter',
      name: 'Live Network & Web Security Auditor',
      mode: 'GENUINE_LIVE',
      description: 'Genuine non-intrusive live web security probe. Performs real HTTP/HTTPS inspection, security headers, cookie flags, security resources (security.txt/robots.txt), or TLS certificates.',
      profiles: [
        { id: 'LIVE_WEB_SECURITY_AUDIT', label: 'LIVE_WEB_SECURITY_AUDIT — Comprehensive Web Audit (Headers, Cookies, Resources & TLS)' },
        { id: 'LIVE_HTTP_HEADERS', label: 'LIVE_HTTP_HEADERS — Live Real HTTP Response Headers & Cookie Flags' },
        { id: 'LIVE_TLS_HANDSHAKE', label: 'LIVE_TLS_HANDSHAKE — Live Real TLS Handshake & Certificate Audit' },
        { id: 'LIVE_SECURITY_RESOURCES', label: 'LIVE_SECURITY_RESOURCES — Safe security.txt (RFC 9116) & robots.txt Audit' },
        { id: 'LIVE_TCP_BANNER', label: 'LIVE_TCP_BANNER — Live Real Service Banner Grab' },
      ],
    },
    {
      id: 'local_fixture_adapter',
      name: 'Local Fixture Simulator (Offline)',
      mode: 'SIMULATED',
      description: 'Deterministic offline fixture engine. Generates reproducible test findings without network traffic.',
      profiles: [
        { id: 'WEB_APPLICATION_BASELINE', label: 'WEB_APPLICATION_BASELINE — CSP, Clickjacking & Security Headers' },
        { id: 'TLS_CONFIGURATION_CHECK', label: 'TLS_CONFIGURATION_CHECK — Legacy Protocol & Cipher Weakness' },
        { id: 'HARDENED_HOST_BASELINE', label: 'HARDENED_HOST_BASELINE — Clean Host Benchmark (0 Findings)' },
        { id: 'SIMULATED_CRITICAL_EXPOSURE', label: 'SIMULATED_CRITICAL_EXPOSURE — Unauthenticated SQLi Demo' },
      ],
    },
    {
      id: 'passive_header_adapter',
      name: 'Passive Header Auditor',
      mode: 'PASSIVE',
      description: 'Passive header compliance auditor evaluating HSTS, CSP, and MIME-sniffing against OWASP standards.',
      profiles: [
        { id: 'OWASP_SECURE_HEADERS', label: 'OWASP_SECURE_HEADERS — HSTS, CSP, and X-Content-Type' },
        { id: 'STRICT_TRANSPORT_AUDIT', label: 'STRICT_TRANSPORT_AUDIT — Strict Transport & Subdomains' },
        { id: 'COOKIE_SECURITY_CHECK', label: 'COOKIE_SECURITY_CHECK — Secure & HttpOnly Cookie Flags' },
      ],
    },
    {
      id: 'ssl_cipher_adapter',
      name: 'SSL/TLS Cipher Suite Auditor',
      mode: 'PASSIVE',
      description: 'SSL/TLS cipher evaluation evaluating weak ciphers, deprecated SSLv3/TLS 1.0/1.1 protocols.',
      profiles: [
        { id: 'TLS_SECURITY_AUDIT', label: 'TLS_SECURITY_AUDIT — Comprehensive Protocol & Cipher Matrix' },
        { id: 'CIPHER_SUITE_MINIMUM_TLS12', label: 'CIPHER_SUITE_MINIMUM_TLS12 — Verify TLS 1.2+ Enforcement' },
        { id: 'CERTIFICATE_SAN_VALIDATION', label: 'CERTIFICATE_SAN_VALIDATION — Subject Alternative Name Check' },
      ],
    },
  ];

  const currentAdapter = adapterOptions.find((a) => a.id === adapterName) || adapterOptions[0];
  const currentProfiles = currentAdapter.profiles;

  // Selected target authorization check (matches exact or URL domain)
  const isSelectedTargetAuthorized = useMemo(() => {
    if (!targetInput.trim()) return false;
    const clean = targetInput.trim().toLowerCase();
    return authorizedTargets.some((t) => {
      const val = t.target_value.toLowerCase();
      if (clean === val) return true;
      try {
        const u = new URL(clean.startsWith('http') ? clean : `http://${clean}`);
        const host = u.hostname.toLowerCase();
        if (host === val || val === host) return true;
        if (val.startsWith('*.') && (host === val.slice(2) || host.endsWith('.' + val.slice(2)))) return true;
        if (val.startsWith('http') && clean.startsWith(val)) return true;
      } catch {
        // Fallback
      }
      return false;
    });
  }, [targetInput, authorizedTargets]);

  // Filtered jobs
  const filteredJobs = useMemo(() => {
    return jobs.filter((j) => {
      const matchesSearch =
        j.target_input.toLowerCase().includes(searchTerm.toLowerCase()) ||
        j.adapter_name.toLowerCase().includes(searchTerm.toLowerCase()) ||
        j.id.toLowerCase().includes(searchTerm.toLowerCase());

      const matchesStatus = statusFilter === 'ALL' || j.status === statusFilter;

      const matchesMode =
        modeFilter === 'ALL' ||
        (modeFilter === 'SIMULATED' && j.is_simulated) ||
        (modeFilter === 'GENUINE_LIVE' && !j.is_simulated);

      return matchesSearch && matchesStatus && matchesMode;
    });
  }, [jobs, searchTerm, statusFilter, modeFilter]);

  // Metric counts
  const totalJobsCount = jobs.length;
  const completedJobsCount = jobs.filter((j) => j.status === 'COMPLETED').length;
  const activeJobsCount = jobs.filter((j) => ['QUEUED', 'PREFLIGHT', 'READY', 'RUNNING'].includes(j.status)).length;
  const simulatedJobsCount = jobs.filter((j) => j.is_simulated).length;
  const liveJobsCount = jobs.filter((j) => !j.is_simulated).length;

  const handleLaunch = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!targetInput.trim()) return;

    if (!isSelectedTargetAuthorized) {
      setError('Cannot dispatch assessment: Target is not in the AUTHORIZED scope for this project.');
      return;
    }

    setLaunching(true);
    setError(null);

    try {
      await api.createAssessment(project.id, {
        target_input: targetInput.trim(),
        adapter_name: adapterName,
        fixture_profile: fixtureProfile,
        timeout_seconds: Number(timeoutSeconds),
        idempotency_key: idempotencyKey.trim() || undefined,
      });
      setIsLaunchModalOpen(false);
      setTargetInput('');
      setIdempotencyKey('');
      onRefresh();
    } catch (err: any) {
      setError(err.message || 'Failed to dispatch assessment');
    } finally {
      setLaunching(false);
    }
  };

  const handleSelectJob = async (job: AssessmentJob) => {
    setSelectedJob(job);
    setSelectedFinding(null);
    setLoadingFindings(true);
    try {
      const findings = await api.listAssessmentFindings(project.id, job.id);
      setJobFindings(findings);
    } catch (err) {
      console.error('Failed to load findings:', err);
      setJobFindings([]);
    } finally {
      setLoadingFindings(false);
    }
  };

  const handleCancelJob = async (jobId: string) => {
    if (!window.confirm('Are you sure you want to cancel this active assessment job?')) return;
    try {
      await api.cancelAssessment(project.id, jobId);
      onRefresh();
      if (selectedJob && selectedJob.id === jobId) {
        const updated = await api.getAssessment(project.id, jobId);
        setSelectedJob(updated);
      }
    } catch (err: any) {
      alert(err.message || 'Failed to cancel assessment');
    }
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'COMPLETED':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded text-[11px] font-mono font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
            <CheckCircle2 className="w-3 h-3" /> COMPLETED
          </span>
        );
      case 'READY':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded text-[11px] font-mono font-bold bg-cyan-500/10 text-cyan-400 border border-cyan-500/30">
            <CheckCircle2 className="w-3 h-3" /> READY
          </span>
        );
      case 'PREFLIGHT':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded text-[11px] font-mono font-bold bg-purple-500/10 text-purple-400 border border-purple-500/30 animate-pulse">
            <RefreshCw className="w-3 h-3 animate-spin" /> PREFLIGHT
          </span>
        );
      case 'RUNNING':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded text-[11px] font-mono font-bold bg-accent-blue/10 text-accent-blue border border-accent-blue/30 animate-pulse">
            <RefreshCw className="w-3 h-3 animate-spin" /> RUNNING
          </span>
        );
      case 'CANCELLATION_REQUESTED':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded text-[11px] font-mono font-bold bg-amber-500/10 text-amber-300 border border-amber-500/30 animate-pulse">
            <Clock className="w-3 h-3 animate-spin" /> CANCEL REQ
          </span>
        );
      case 'QUEUED':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded text-[11px] font-mono font-bold bg-amber-500/10 text-amber-400 border border-amber-500/30">
            <Clock className="w-3 h-3" /> QUEUED
          </span>
        );
      case 'PARTIAL':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded text-[11px] font-mono font-bold bg-amber-500/15 text-amber-300 border border-amber-500/30">
            <AlertTriangle className="w-3 h-3" /> PARTIAL
          </span>
        );
      case 'FAILED':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded text-[11px] font-mono font-bold bg-rose-500/10 text-rose-400 border border-rose-500/30">
            <Ban className="w-3 h-3" /> FAILED
          </span>
        );
      case 'CANCELLED':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded text-[11px] font-mono font-bold bg-slate-500/10 text-slate-400 border border-slate-500/30">
            <Ban className="w-3 h-3" /> CANCELLED
          </span>
        );
      case 'TIMED_OUT':
        return (
          <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded text-[11px] font-mono font-bold bg-rose-500/10 text-rose-300 border border-rose-500/30">
            <Clock className="w-3 h-3" /> TIMED OUT
          </span>
        );
      default:
        return <span className="font-mono text-slate-400 text-xs">{status}</span>;
    }
  };

  const getModeBadge = (isSimulated: boolean) => {
    if (isSimulated) {
      return (
        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-amber-500/10 text-amber-400 border border-amber-500/30">
          <TestTube2 className="w-3 h-3" /> SIMULATED FIXTURE
        </span>
      );
    }
    return (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
        <Zap className="w-3 h-3" /> GENUINE LIVE PROBE
      </span>
    );
  };

  const getSeverityBadge = (sev: FindingSeverity) => {
    switch (sev) {
      case 'CRITICAL':
        return (
          <span className="px-2 py-0.5 rounded text-[10px] font-bold font-mono bg-rose-500/20 text-rose-400 border border-rose-500/40">
            CRITICAL
          </span>
        );
      case 'HIGH':
        return (
          <span className="px-2 py-0.5 rounded text-[10px] font-bold font-mono bg-orange-500/20 text-orange-400 border border-orange-500/40">
            HIGH
          </span>
        );
      case 'MEDIUM':
        return (
          <span className="px-2 py-0.5 rounded text-[10px] font-bold font-mono bg-amber-500/20 text-amber-400 border border-amber-500/40">
            MEDIUM
          </span>
        );
      case 'LOW':
        return (
          <span className="px-2 py-0.5 rounded text-[10px] font-bold font-mono bg-blue-500/20 text-blue-400 border border-blue-500/40">
            LOW
          </span>
        );
      case 'INFO':
        return (
          <span className="px-2 py-0.5 rounded text-[10px] font-bold font-mono bg-slate-500/20 text-slate-300 border border-slate-500/40">
            INFO
          </span>
        );
    }
  };

  return (
    <div className="space-y-6">
      {/* 1. Header & Engine Telemetry Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <div className="bg-cyber-850 border border-cyber-750 rounded-xl p-4 shadow-sm">
          <div className="flex items-center justify-between text-slate-400 text-xs mb-1">
            <span>Total Assessment Jobs</span>
            <PlayCircle className="w-4 h-4 text-accent-cyan" />
          </div>
          <div className="text-2xl font-bold font-mono text-white">{totalJobsCount}</div>
          <p className="text-[11px] text-slate-500 mt-1">{completedJobsCount} successfully completed</p>
        </div>

        <div className="bg-cyber-850 border border-cyber-750 rounded-xl p-4 shadow-sm">
          <div className="flex items-center justify-between text-slate-400 text-xs mb-1">
            <span>Active Executions</span>
            <RefreshCw className={`w-4 h-4 ${activeJobsCount > 0 ? 'text-accent-blue animate-spin' : 'text-slate-500'}`} />
          </div>
          <div className="text-2xl font-bold font-mono text-accent-blue">{activeJobsCount}</div>
          <p className="text-[11px] text-slate-500 mt-1">Under Win32 512MB Job Object</p>
        </div>

        <div className="bg-cyber-850 border border-cyber-750 rounded-xl p-4 shadow-sm">
          <div className="flex items-center justify-between text-slate-400 text-xs mb-1">
            <span>Simulated Fixtures</span>
            <TestTube2 className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-amber-400">{simulatedJobsCount}</div>
          <p className="text-[11px] text-slate-500 mt-1">Deterministic offline validation</p>
        </div>

        <div className="bg-cyber-850 border border-cyber-750 rounded-xl p-4 shadow-sm">
          <div className="flex items-center justify-between text-slate-400 text-xs mb-1">
            <span>Genuine Live Probes</span>
            <Zap className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-emerald-400">{liveJobsCount}</div>
          <p className="text-[11px] text-slate-500 mt-1">Real non-intrusive network audits</p>
        </div>
      </div>

      {/* 2. Mode Explanation Banner */}
      <div className="bg-cyber-850/80 border border-cyber-750 rounded-xl p-4 shadow-sm flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div className="flex items-start gap-3">
          <Shield className="w-5 h-5 text-accent-cyan shrink-0 mt-0.5" />
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-xs font-bold text-white uppercase tracking-wider font-mono">
                Multi-Engine Assessment Orchestration
              </h3>
              <span className="text-[10px] px-2 py-0.5 rounded font-mono font-medium bg-cyber-800 text-emerald-400 border border-emerald-500/30">
                Fail-Closed Preflight Boundary Active
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              Target authorization is re-verified at runtime immediately before process worker dispatch. Both deterministic simulated fixtures and genuine non-intrusive network audits are supported and cryptographically distinguished.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2 shrink-0">
          <button
            onClick={onRefresh}
            disabled={loading}
            className="p-2 rounded-lg bg-cyber-800 hover:bg-cyber-750 text-slate-400 hover:text-white transition-colors"
            title="Refresh Assessments"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin text-accent-cyan' : ''}`} />
          </button>
          <button
            onClick={() => {
              setError(null);
              setIsLaunchModalOpen(true);
            }}
            className="inline-flex items-center gap-1.5 px-4 py-2 rounded-lg bg-accent-blue hover:bg-accent-blue/90 text-white text-xs font-semibold transition-colors shadow-sm"
          >
            <Plus className="w-4 h-4" />
            Launch Assessment Job
          </button>
        </div>
      </div>

      {/* 3. Search & Filter Bar */}
      <div className="flex flex-col sm:flex-row items-center justify-between gap-3 bg-cyber-850/60 p-3 rounded-xl border border-cyber-750">
        <div className="relative w-full sm:w-80">
          <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
          <input
            type="text"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="Search by target, adapter, or job ID..."
            className="w-full bg-cyber-900 border border-cyber-700 rounded-lg pl-9 pr-3 py-1.5 text-xs font-mono text-white placeholder-slate-500 focus:outline-none focus:border-accent-cyan"
          />
        </div>

        <div className="flex items-center gap-2 w-full sm:w-auto">
          <div className="flex items-center gap-1 bg-cyber-900 border border-cyber-700 rounded-lg px-2.5 py-1 text-xs">
            <Filter className="w-3.5 h-3.5 text-slate-400" />
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="bg-transparent text-slate-300 font-mono text-xs focus:outline-none cursor-pointer"
            >
              <option value="ALL">All Statuses</option>
              <option value="COMPLETED">COMPLETED</option>
              <option value="RUNNING">RUNNING</option>
              <option value="QUEUED">QUEUED</option>
              <option value="FAILED">FAILED</option>
              <option value="CANCELLED">CANCELLED</option>
            </select>
          </div>

          <div className="flex items-center gap-1 bg-cyber-900 border border-cyber-700 rounded-lg px-2.5 py-1 text-xs">
            <select
              value={modeFilter}
              onChange={(e) => setModeFilter(e.target.value)}
              className="bg-transparent text-slate-300 font-mono text-xs focus:outline-none cursor-pointer"
            >
              <option value="ALL">All Modes</option>
              <option value="SIMULATED">Simulated Fixtures</option>
              <option value="GENUINE_LIVE">Genuine Live Probes</option>
            </select>
          </div>
        </div>
      </div>

      {/* 4. Main Two-Column Workflow: Execution Table & Detail Inspector */}
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        {/* Left: Assessment Jobs Table */}
        <div className={`bg-cyber-850 border border-cyber-750 rounded-xl overflow-hidden shadow-lg ${selectedJob ? 'xl:col-span-2' : 'xl:col-span-3'}`}>
          <div className="p-4 border-b border-cyber-750 bg-cyber-900/60 flex items-center justify-between">
            <span className="text-xs font-bold text-white uppercase font-mono tracking-wider">
              Execution Job History ({filteredJobs.length})
            </span>
            {authorizedTargets.length === 0 && onNavigateToScopes && (
              <button
                onClick={onNavigateToScopes}
                className="text-xs text-amber-400 hover:underline flex items-center gap-1 font-mono"
              >
                <AlertCircle className="w-3.5 h-3.5" /> No authorized targets. Configure Scopes →
              </button>
            )}
          </div>

          {filteredJobs.length === 0 ? (
            <div className="p-12">
              <EmptyState
                icon={PlayCircle}
                title={searchTerm || statusFilter !== 'ALL' || modeFilter !== 'ALL' ? 'No Matching Assessments Found' : 'No Assessments Dispatched Yet'}
                description={
                  searchTerm || statusFilter !== 'ALL' || modeFilter !== 'ALL'
                    ? 'Adjust search keywords or clear filters to see other execution jobs.'
                    : 'Select an authorized target and launch an assessment job using the offline simulator or live network auditor.'
                }
                actionLabel="Launch Assessment Job"
                onAction={() => setIsLaunchModalOpen(true)}
              />
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse text-xs font-mono">
                <thead>
                  <tr className="border-b border-cyber-750 bg-cyber-900/40 text-slate-400 text-[11px]">
                    <th className="py-3 px-4">Target Assessment Scope</th>
                    <th className="py-3 px-4">Execution Engine</th>
                    <th className="py-3 px-4">Mode</th>
                    <th className="py-3 px-4">Status</th>
                    <th className="py-3 px-4">Findings</th>
                    <th className="py-3 px-4">Queued Time</th>
                    <th className="py-3 px-4 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-cyber-800">
                  {filteredJobs.map((j) => {
                    const isSelected = selectedJob?.id === j.id;
                    return (
                      <tr
                        key={j.id}
                        onClick={() => handleSelectJob(j)}
                        className={`cursor-pointer transition-colors ${
                          isSelected ? 'bg-cyber-800 text-white' : 'hover:bg-cyber-800/40 text-slate-300'
                        }`}
                      >
                        <td className="py-3.5 px-4 font-semibold text-slate-200">
                          <div className="text-sm font-mono text-white">{j.target_input}</div>
                          <div className="text-[10px] text-slate-500 font-mono">Job: {j.id.slice(0, 8)}...</div>
                        </td>
                        <td className="py-3.5 px-4 text-slate-300">
                          <div>{j.adapter_name}</div>
                          <div className="text-[10px] text-slate-500">v{j.adapter_version}</div>
                        </td>
                        <td className="py-3.5 px-4">{getModeBadge(j.is_simulated)}</td>
                        <td className="py-3.5 px-4">{getStatusBadge(j.status)}</td>
                        <td className="py-3.5 px-4 text-slate-200 font-bold">
                          {j.summary_stats?.findings_count ?? 0}
                        </td>
                        <td className="py-3.5 px-4 text-slate-400 text-[11px]">
                          {new Date(j.queued_at).toLocaleTimeString()}
                        </td>
                        <td className="py-3.5 px-4 text-right">
                          <div className="flex items-center justify-end gap-2">
                            {['QUEUED', 'PREFLIGHT', 'READY', 'RUNNING'].includes(j.status) && (
                              <button
                                onClick={(e) => {
                                  e.stopPropagation();
                                  handleCancelJob(j.id);
                                }}
                                className="px-2 py-1 text-[11px] rounded bg-rose-500/10 hover:bg-rose-500/20 text-rose-400 border border-rose-500/20"
                              >
                                Cancel
                              </button>
                            )}
                            <ChevronRight className="w-4 h-4 text-slate-500" />
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* Right: Job Detail Inspector */}
        {selectedJob && (
          <div className="bg-cyber-850 border border-cyber-750 rounded-xl overflow-hidden shadow-lg flex flex-col">
            <div className="p-4 border-b border-cyber-750 bg-cyber-900/60 flex items-center justify-between">
              <span className="text-xs font-bold text-white uppercase font-mono tracking-wider">
                Execution Detail & Evidence
              </span>
              <button
                onClick={() => setSelectedJob(null)}
                className="text-slate-400 hover:text-white p-1 rounded hover:bg-cyber-750"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="p-4 space-y-4 overflow-y-auto max-h-[700px] text-xs font-mono">
              <div>
                <div className="text-slate-400 text-[10px] uppercase">Target Scope</div>
                <div className="text-base font-bold text-white mt-0.5">{selectedJob.target_input}</div>
              </div>

              <div className="grid grid-cols-2 gap-2 p-3 bg-cyber-900 rounded-lg border border-cyber-800">
                <div>
                  <span className="text-slate-500 text-[10px]">Status:</span>
                  <div className="mt-0.5">{getStatusBadge(selectedJob.status)}</div>
                </div>
                <div>
                  <span className="text-slate-500 text-[10px]">Observation Mode:</span>
                  <div className="mt-0.5">{getModeBadge(selectedJob.is_simulated)}</div>
                </div>
                <div>
                  <span className="text-slate-500 text-[10px]">Scanner Engine:</span>
                  <div className="text-slate-200 mt-0.5">{selectedJob.adapter_name}</div>
                </div>
                <div>
                  <span className="text-slate-500 text-[10px]">Findings Discovered:</span>
                  <div className="text-slate-200 font-bold mt-0.5">{selectedJob.summary_stats?.findings_count ?? 0}</div>
                </div>
              </div>

              {/* Preflight Scope Snapshot */}
              {selectedJob.scope_snapshot && (
                <div className="p-3 bg-cyber-900/80 rounded-lg border border-cyber-800 space-y-1">
                  <div className="text-slate-400 font-semibold flex items-center gap-1.5 text-[11px]">
                    <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
                    Preflight Scope Authorization Proof
                  </div>
                  <div className="text-slate-300 text-[11px]">
                    Normalized: <span className="text-accent-cyan">{selectedJob.scope_snapshot.normalized_target || selectedJob.target_input}</span>
                  </div>
                  <div className="text-slate-500 text-[10px]">
                    Evaluated: {new Date(selectedJob.scope_snapshot.snapshot_at).toLocaleString()}
                  </div>
                </div>
              )}

              {/* Findings List */}
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-slate-300 font-semibold text-xs">
                    Discovered Findings ({jobFindings.length})
                  </span>
                  {onNavigateToFindings && jobFindings.length > 0 && (
                    <button
                      onClick={onNavigateToFindings}
                      className="text-[11px] text-accent-cyan hover:underline flex items-center gap-1"
                    >
                      Triage in Lifecycle <ExternalLink className="w-3 h-3" />
                    </button>
                  )}
                </div>

                {loadingFindings ? (
                  <div className="py-8 text-center text-slate-500">
                    <RefreshCw className="w-4 h-4 animate-spin mx-auto mb-1 text-accent-cyan" />
                    Loading findings...
                  </div>
                ) : jobFindings.length === 0 ? (
                  <div className="p-4 bg-cyber-900/40 border border-cyber-800 rounded text-center text-slate-500 text-xs">
                    No vulnerabilities observed during this execution.
                  </div>
                ) : (
                  <div className="space-y-2 max-h-60 overflow-y-auto">
                    {jobFindings.map((f) => (
                      <div
                        key={f.id}
                        onClick={() => setSelectedFinding(selectedFinding?.id === f.id ? null : f)}
                        className={`p-2.5 rounded-lg border cursor-pointer transition-colors ${
                          selectedFinding?.id === f.id
                            ? 'bg-cyber-800 border-accent-cyan'
                            : 'bg-cyber-900/90 border-cyber-800 hover:border-cyber-700'
                        }`}
                      >
                        <div className="flex items-center justify-between gap-2">
                          <span className="font-semibold text-slate-200 truncate">{f.title}</span>
                          {getSeverityBadge(f.severity)}
                        </div>
                        <div className="text-[10px] text-slate-400 mt-1 flex items-center justify-between">
                          <span>Vuln ID: {f.vuln_id}</span>
                          {f.cvss_score !== undefined && f.cvss_score !== null && (
                            <span className="text-amber-400">CVSS: {f.cvss_score}</span>
                          )}
                        </div>
                        {selectedFinding?.id === f.id && (
                          <p className="text-[11px] text-slate-300 mt-2 pt-2 border-t border-cyber-800">
                            {f.description}
                          </p>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Raw Process Evidence Info */}
              <div className="p-3 bg-cyber-900/60 rounded-lg border border-cyber-800 space-y-1">
                <div className="text-slate-400 text-[10px] uppercase">Cryptographic Execution Anchor</div>
                <div className="text-[10px] text-slate-500 font-mono break-all flex items-center gap-1">
                  <Hash className="w-3.5 h-3.5 text-accent-cyan shrink-0" />
                  <span>Job UUID: {selectedJob.id}</span>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* 5. Governed Launch Assessment Modal */}
      {isLaunchModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm">
          <div className="w-full max-w-xl bg-cyber-850 border border-cyber-700 rounded-xl shadow-2xl overflow-hidden animate-in fade-in zoom-in-95 duration-150">
            <div className="p-5 border-b border-cyber-750 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <PlayCircle className="w-5 h-5 text-accent-cyan" />
                <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono">
                  Dispatch Controlled Assessment Job
                </h3>
              </div>
              <button
                onClick={() => setIsLaunchModalOpen(false)}
                className="text-slate-400 hover:text-white p-1 rounded hover:bg-cyber-750"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {error && (
              <div className="m-5 p-3 bg-rose-500/10 border border-rose-500/20 rounded-lg text-xs text-rose-300 font-mono flex items-start gap-2">
                <AlertCircle className="w-4 h-4 shrink-0 mt-0.5" />
                <span>{error}</span>
              </div>
            )}

            <form onSubmit={handleLaunch} className="p-5 space-y-4">
              {/* Target Scope Selection */}
              <div>
                <div className="flex items-center justify-between mb-1">
                  <label className="text-xs font-medium text-slate-300">Target Assessment Scope *</label>
                  {onNavigateToScopes && (
                    <button
                      type="button"
                      onClick={() => {
                        setIsLaunchModalOpen(false);
                        onNavigateToScopes();
                      }}
                      className="text-[10px] text-accent-cyan hover:underline flex items-center gap-0.5 font-mono"
                    >
                      Manage Scope Rules <ExternalLink className="w-2.5 h-2.5" />
                    </button>
                  )}
                </div>

                {authorizedTargets.length > 0 && (
                  <div className="mb-2">
                    <select
                      value={targetInput}
                      onChange={(e) => setTargetInput(e.target.value)}
                      className="w-full bg-cyber-900 border border-cyber-700 rounded-lg px-3 py-2 text-xs font-mono text-white focus:outline-none focus:border-accent-cyan"
                    >
                      <option value="">-- Choose from authorized targets or enter below --</option>
                      {authorizedTargets.map((t) => (
                        <option key={t.id} value={t.target_value}>
                          {t.target_value} ({t.target_type}) — AUTHORIZED
                        </option>
                      ))}
                    </select>
                  </div>
                )}

                <input
                  type="text"
                  required
                  placeholder="Enter URL or host: https://example.com, https://target.internal, http://127.0.0.1:8000"
                  value={targetInput}
                  onChange={(e) => setTargetInput(e.target.value)}
                  className="w-full bg-cyber-900 border border-cyber-700 rounded-lg px-3 py-2 text-xs font-mono text-white placeholder-slate-500 focus:outline-none focus:border-accent-cyan"
                />

                {targetInput && isSelectedTargetAuthorized && (
                  <p className="text-[11px] text-emerald-400 mt-1.5 flex items-center gap-1.5 font-mono">
                    <CheckCircle2 className="w-3.5 h-3.5" /> Target scope verified and authorized for genuine live assessment.
                  </p>
                )}

                {targetInput.trim() && !isSelectedTargetAuthorized && (
                  <div className="mt-2.5 p-3 bg-amber-500/10 border border-amber-500/25 rounded-lg">
                    <div className="flex items-start gap-2">
                      <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
                      <div>
                        <p className="text-xs font-semibold text-amber-300 font-mono">
                          Target Scope Not Authorized
                        </p>
                        <p className="text-[11px] text-slate-300 mt-1 leading-relaxed">
                          Target <span className="font-mono text-amber-200">'{targetInput.trim()}'</span> has not been granted explicit Rules of Engagement (ROE) authorization for this project.
                          To prevent unauthorized network testing, targets must be formally registered and approved in Scopes & Governance before dispatch.
                        </p>
                        {onNavigateToScopes && (
                          <button
                            type="button"
                            onClick={() => {
                              setIsLaunchModalOpen(false);
                              onNavigateToScopes();
                            }}
                            className="mt-2 inline-flex items-center gap-1.5 px-3 py-1 bg-amber-500/20 hover:bg-amber-500/30 text-amber-300 border border-amber-500/40 rounded text-xs font-mono font-medium transition-colors"
                          >
                            <span>Open Scopes & ROE Governance</span>
                            <ExternalLink className="w-3 h-3" />
                          </button>
                        )}
                      </div>
                    </div>
                  </div>
                )}
              </div>

              {/* Scanner Engine Selector */}
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">Scanner Engine *</label>
                <select
                  value={adapterName}
                  onChange={(e) => {
                    const nextAdapter = e.target.value;
                    setAdapterName(nextAdapter);
                    const opt = adapterOptions.find((a) => a.id === nextAdapter);
                    if (opt && opt.profiles.length > 0) {
                      setFixtureProfile(opt.profiles[0].id);
                    }
                  }}
                  className="w-full bg-cyber-900 border border-cyber-700 rounded-lg px-3 py-2 text-xs font-mono text-white focus:outline-none focus:border-accent-cyan"
                >
                  {adapterOptions.map((a) => (
                    <option key={a.id} value={a.id}>
                      {a.name} ({a.mode === 'GENUINE_LIVE' ? 'LIVE NETWORK PROBE' : 'SIMULATED'})
                    </option>
                  ))}
                </select>
                <p className="text-[11px] text-slate-400 mt-1 font-mono">{currentAdapter.description}</p>
              </div>

              {/* Assessment Profile */}
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">Assessment Profile *</label>
                <select
                  value={fixtureProfile}
                  onChange={(e) => setFixtureProfile(e.target.value)}
                  className="w-full bg-cyber-900 border border-cyber-700 rounded-lg px-3 py-2 text-xs font-mono text-white focus:outline-none focus:border-accent-cyan"
                >
                  {currentProfiles.map((p) => (
                    <option key={p.id} value={p.id}>
                      {p.label}
                    </option>
                  ))}
                </select>
              </div>

              {/* Timeout & Idempotency Key */}
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs font-medium text-slate-300 mb-1">Timeout (Seconds)</label>
                  <input
                    type="number"
                    min={10}
                    max={3600}
                    value={timeoutSeconds}
                    onChange={(e) => setTimeoutSeconds(Number(e.target.value))}
                    className="w-full bg-cyber-900 border border-cyber-700 rounded-lg px-3 py-2 text-xs font-mono text-white focus:outline-none focus:border-accent-cyan"
                  />
                </div>
                <div>
                  <label className="block text-xs font-medium text-slate-300 mb-1">Idempotency Key (Optional)</label>
                  <input
                    type="text"
                    value={idempotencyKey}
                    onChange={(e) => setIdempotencyKey(e.target.value)}
                    placeholder="e.g. audit-q4-run-01"
                    className="w-full bg-cyber-900 border border-cyber-700 rounded-lg px-3 py-2 text-xs font-mono text-white placeholder-slate-500 focus:outline-none focus:border-accent-cyan"
                  />
                </div>
              </div>

              <div className="pt-2 flex items-center justify-end gap-3 border-t border-cyber-750">
                <button
                  type="button"
                  onClick={() => setIsLaunchModalOpen(false)}
                  className="px-4 py-2 rounded-lg text-xs font-semibold text-slate-400 hover:text-white hover:bg-cyber-800 transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={launching || !isSelectedTargetAuthorized}
                  className="px-5 py-2 rounded-lg bg-accent-blue hover:bg-accent-blue/90 disabled:bg-cyber-750 disabled:text-slate-500 text-white text-xs font-semibold transition-colors flex items-center gap-1.5 shadow-sm"
                >
                  <PlayCircle className="w-4 h-4" />
                  {launching ? 'Dispatching...' : 'Dispatch Assessment Job'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
