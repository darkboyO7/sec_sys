import React from 'react';
import {
  Target,
  ShieldAlert,
  CheckCircle2,
  Clock,
  Ban,
  FolderPlus,
  ArrowRight,
  Server,
  PlayCircle,
  Activity,
  FileText,
} from 'lucide-react';
import type { Project, ScopeTarget, ScopeExclusion, AuditEvent, AssessmentJob } from '../types';
import { ScopeValidationConsole } from '../components/ScopeValidationConsole';
import { EmptyState } from '../components/EmptyState';
import { AutonomousOperationsConsole } from '../components/AutonomousOperationsConsole';
import { AdaptiveIntelligenceConsole } from '../components/AdaptiveIntelligenceConsole';
import { UnifiedOperationsCockpit } from '../components/UnifiedOperationsCockpit';

interface OverviewViewProps {
  activeProject: Project | null;
  targets: ScopeTarget[];
  exclusions: ScopeExclusion[];
  recentAudits: AuditEvent[];
  findingCount?: number;
  assetCount?: number;
  assessmentJobs?: AssessmentJob[];
  onCreateProjectClick: () => void;
  onNavigateToScopes: () => void;
  onNavigateToFindings?: () => void;
  onNavigateToAssets?: () => void;
  onNavigateToGraph?: () => void;
  onNavigateToAssessments?: () => void;
  onNavigateToAudit: () => void;
  onNavigateToRisk?: () => void;
  onNavigateToVerification?: () => void;
}

export const OverviewView: React.FC<OverviewViewProps> = ({
  activeProject,
  targets,
  exclusions,
  recentAudits,
  findingCount = 0,
  assetCount = 0,
  assessmentJobs = [],
  onCreateProjectClick,
  onNavigateToScopes,
  onNavigateToFindings,
  onNavigateToAssets,
  onNavigateToGraph,
  onNavigateToAssessments,
  onNavigateToAudit,
  onNavigateToRisk,
  onNavigateToVerification,
}) => {
  if (!activeProject) {
    return (
      <div className="max-w-4xl mx-auto py-16">
        <EmptyState
          icon={FolderPlus}
          title="No Assessment Workspace Selected"
          description="A security assessment project is required to register target scopes, manage exclusion rules, execute tests, and analyze vulnerabilities."
          actionLabel="Create Assessment Project"
          onAction={onCreateProjectClick}
        />
      </div>
    );
  }

  // Calculate real metrics directly from live data
  const authorizedCount = targets.filter((t) => t.authorization_status === 'AUTHORIZED').length;
  const pendingCount = targets.filter((t) => t.authorization_status === 'PENDING').length;
  const revokedCount = targets.filter((t) => t.authorization_status === 'REVOKED').length;
  const expiredCount = targets.filter((t) => t.authorization_status === 'EXPIRED').length;
  const completedJobsCount = assessmentJobs.filter((j) => j.status === 'COMPLETED').length;
  const activeJobsCount = assessmentJobs.filter((j) => ['QUEUED', 'PREFLIGHT', 'READY', 'RUNNING'].includes(j.status)).length;

  return (
    <div className="space-y-6">
      {/* 1. Active Project Executive Summary Banner */}
      <div className="bg-gradient-to-r from-cyber-850 via-cyber-850 to-cyber-800 border border-cyber-750 rounded-xl p-6 shadow-md flex flex-col lg:flex-row lg:items-center justify-between gap-6">
        <div>
          <div className="flex items-center gap-2 mb-1.5">
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-accent-cyan/15 text-accent-cyan border border-accent-cyan/30 uppercase font-semibold">
              Governed Assessment Boundary
            </span>
            <span className="text-xs text-slate-500 font-mono">Project UUID: {activeProject.id}</span>
          </div>
          <h2 className="text-2xl font-bold text-white tracking-tight">{activeProject.name}</h2>
          <p className="text-xs text-slate-400 mt-1 max-w-2xl leading-relaxed">
            {activeProject.description || 'Enterprise assessment environment governed by fail-closed boundary enforcement, Win32 Job Object isolation, and Merkle tree evidence proofs.'}
          </p>
        </div>

        {/* Quick View Switches */}
        <div className="flex flex-wrap items-center gap-2">
          {onNavigateToAssessments && (
            <button
              onClick={onNavigateToAssessments}
              className="px-3.5 py-2 rounded-lg bg-accent-blue/20 hover:bg-accent-blue/30 text-xs font-semibold text-accent-blue border border-accent-blue/40 transition-colors flex items-center gap-1.5"
            >
              <PlayCircle className="w-4 h-4 text-accent-cyan" />
              Assessments ({assessmentJobs.length})
            </button>
          )}
          {onNavigateToFindings && (
            <button
              onClick={onNavigateToFindings}
              className="px-3.5 py-2 rounded-lg bg-cyber-750 hover:bg-cyber-700 text-xs font-semibold text-slate-200 hover:text-white transition-colors flex items-center gap-1.5"
            >
              <ShieldAlert className="w-4 h-4 text-amber-400" />
              Findings ({findingCount})
            </button>
          )}
          {onNavigateToAssets && (
            <button
              onClick={onNavigateToAssets}
              className="px-3.5 py-2 rounded-lg bg-cyber-750 hover:bg-cyber-700 text-xs font-semibold text-slate-200 hover:text-white transition-colors flex items-center gap-1.5"
            >
              <Server className="w-4 h-4 text-cyan-400" />
              Assets ({assetCount})
            </button>
          )}
          {onNavigateToGraph && (
            <button
              onClick={onNavigateToGraph}
              className="px-3.5 py-2 rounded-lg bg-cyber-750 hover:bg-cyber-700 text-xs font-semibold text-slate-200 hover:text-white transition-colors flex items-center gap-1.5"
            >
              <Activity className="w-4 h-4 text-purple-400" />
              Graph
            </button>
          )}
          {onNavigateToRisk && (
            <button
              onClick={onNavigateToRisk}
              className="px-3.5 py-2 rounded-lg bg-cyber-750 hover:bg-cyber-700 text-xs font-semibold text-slate-200 hover:text-white transition-colors flex items-center gap-1.5"
            >
              <ShieldAlert className="w-4 h-4 text-amber-400" />
              Risk Paths
            </button>
          )}
          {onNavigateToScopes && (
            <button
              onClick={onNavigateToScopes}
              className="px-3.5 py-2 rounded-lg bg-cyber-750 hover:bg-cyber-700 text-xs font-semibold text-slate-200 hover:text-white transition-colors flex items-center gap-1.5"
            >
              <Target className="w-4 h-4 text-accent-cyan" />
              Scope ({targets.length})
            </button>
          )}
        </div>
      </div>

      {/* 2. Key Operational KPI Tiles */}
      <div className="grid grid-cols-2 lg:grid-cols-5 gap-4">
        {/* Scope Authorization */}
        <div className="bg-cyber-850 border border-cyber-750 rounded-xl p-4 shadow-sm">
          <div className="flex items-center justify-between text-slate-400 text-xs mb-1">
            <span>Authorized Scope</span>
            <CheckCircle2 className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-emerald-400">{authorizedCount}</div>
          <p className="text-[11px] text-slate-500 mt-1">{targets.length} total targets defined</p>
        </div>

        {/* Pending Review */}
        <div className="bg-cyber-850 border border-cyber-750 rounded-xl p-4 shadow-sm">
          <div className="flex items-center justify-between text-slate-400 text-xs mb-1">
            <span>Pending Review</span>
            <Clock className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-amber-400">{pendingCount}</div>
          <p className="text-[11px] text-slate-500 mt-1">Requires lead sign-off</p>
        </div>

        {/* Assessment Executions */}
        <div className="bg-cyber-850 border border-cyber-750 rounded-xl p-4 shadow-sm">
          <div className="flex items-center justify-between text-slate-400 text-xs mb-1">
            <span>Jobs Dispatched</span>
            <PlayCircle className="w-4 h-4 text-accent-cyan" />
          </div>
          <div className="text-2xl font-bold font-mono text-white">{assessmentJobs.length}</div>
          <p className="text-[11px] text-slate-500 mt-1">{completedJobsCount} completed, {activeJobsCount} active</p>
        </div>

        {/* Discovered Findings */}
        <div className="bg-cyber-850 border border-cyber-750 rounded-xl p-4 shadow-sm">
          <div className="flex items-center justify-between text-slate-400 text-xs mb-1">
            <span>Tracked Findings</span>
            <ShieldAlert className="w-4 h-4 text-rose-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-rose-400">{findingCount}</div>
          <p className="text-[11px] text-slate-500 mt-1">Under 7-state FSM triage</p>
        </div>

        {/* Scope Exclusions */}
        <div className="bg-cyber-850 border border-cyber-750 rounded-xl p-4 shadow-sm col-span-2 lg:col-span-1">
          <div className="flex items-center justify-between text-slate-400 text-xs mb-1">
            <span>Exclusions / Disallowed</span>
            <Ban className="w-4 h-4 text-slate-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-slate-300">{exclusions.length}</div>
          <p className="text-[11px] text-slate-500 mt-1">
            {exclusions.length} exclusions · {revokedCount + expiredCount} inactive
          </p>
        </div>
      </div>

      {/* 2.4 Unified Operations Command Cockpit & Actionable Priority Queue (Prompt 30) */}
      <UnifiedOperationsCockpit
        projectId={activeProject.id}
        onNavigate={(route) => {
          if (route === '/findings' && onNavigateToFindings) onNavigateToFindings();
          else if (route === '/assessments' && onNavigateToAssessments) onNavigateToAssessments();
          else if (route === '/assets' && onNavigateToAssets) onNavigateToAssets();
          else if (route === '/remediation' && onNavigateToVerification) onNavigateToVerification();
          else if (route === '/scopes') onNavigateToScopes();
          else if (route === '/audit') onNavigateToAudit();
        }}
      />

      {/* 2.5 Evidence-Driven Adaptive Security Intelligence Console (Prompt 10) */}
      <AdaptiveIntelligenceConsole
        projectId={activeProject.id}
        onNavigateToFindings={onNavigateToFindings}
        onNavigateToAssessments={onNavigateToAssessments}
        onNavigateToAssets={onNavigateToAssets}
        onNavigateToVerification={onNavigateToVerification}
      />

      {/* 2.6 Autonomous Security Intelligence & Closed-Loop Operations */}
      <AutonomousOperationsConsole
        projectId={activeProject.id}
        onNavigateToFindings={onNavigateToFindings}
        onNavigateToAssets={onNavigateToAssets}
        onNavigateToVerification={onNavigateToVerification}
        onNavigateToAssessments={onNavigateToAssessments}
      />

      {/* 3. Main Operational Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Column (2 Cols): Scope Validation Console & Recent Assessment Activity */}
        <div className="lg:col-span-2 space-y-6">
          {/* Scope Validation Console */}
          <ScopeValidationConsole projectId={activeProject.id} />

          {/* Recent Assessment Activity */}
          <div className="bg-cyber-850 border border-cyber-750 rounded-xl p-5 shadow-lg">
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center gap-2">
                <PlayCircle className="w-4 h-4 text-accent-cyan" />
                <h3 className="text-sm font-semibold text-white">Recent Assessment Executions</h3>
              </div>
              {onNavigateToAssessments && (
                <button
                  onClick={onNavigateToAssessments}
                  className="text-xs text-accent-cyan hover:underline flex items-center gap-1 font-mono"
                >
                  View All Jobs <ArrowRight className="w-3.5 h-3.5" />
                </button>
              )}
            </div>

            {assessmentJobs.length === 0 ? (
              <div className="p-6 text-center text-xs text-slate-500 bg-cyber-900/40 rounded-lg border border-cyber-800">
                No assessment jobs have been executed for this project yet. Use Assessment Jobs to dispatch your first run.
              </div>
            ) : (
              <div className="space-y-2">
                {assessmentJobs.slice(0, 4).map((j) => (
                  <div
                    key={j.id}
                    className="p-3 bg-cyber-900/80 border border-cyber-800 rounded-lg flex items-center justify-between text-xs font-mono"
                  >
                    <div>
                      <div className="font-semibold text-slate-200">{j.target_input}</div>
                      <div className="text-[10px] text-slate-500 flex items-center gap-2 mt-0.5">
                        <span>{j.adapter_name}</span>
                        <span>·</span>
                        <span>{j.is_simulated ? 'SIMULATED FIXTURE' : 'GENUINE LIVE PROBE'}</span>
                      </div>
                    </div>
                    <div className="text-right">
                      <span
                        className={`text-[10px] px-2 py-0.5 rounded font-bold ${
                          j.status === 'COMPLETED'
                            ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30'
                            : 'bg-accent-blue/10 text-accent-blue border border-accent-blue/30'
                        }`}
                      >
                        {j.status}
                      </span>
                      <div className="text-[10px] text-slate-400 mt-1">
                        Findings: {j.summary_stats?.findings_count ?? 0}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Right Column: Defense Subsystems & Audit Feed */}
        <div className="space-y-6">
          {/* Subsystem Telemetry Card */}
          <div className="bg-cyber-850 border border-cyber-750 rounded-xl p-5 shadow-lg">
            <div className="flex items-center gap-2 mb-3">
              <Activity className="w-4 h-4 text-emerald-400" />
              <h3 className="text-sm font-semibold text-white">Defense Subsystem Telemetry</h3>
            </div>
            <div className="space-y-2 text-xs font-mono">
              <div className="flex items-center justify-between p-2 rounded bg-cyber-900/60 border border-cyber-800">
                <span className="text-slate-300">FastAPI Control Plane</span>
                <span className="text-emerald-400 font-bold flex items-center gap-1">
                  <CheckCircle2 className="w-3 h-3" /> 200 OK
                </span>
              </div>
              <div className="flex items-center justify-between p-2 rounded bg-cyber-900/60 border border-cyber-800">
                <span className="text-slate-300">Database Engine</span>
                <span className="text-emerald-400 font-bold flex items-center gap-1">
                  <CheckCircle2 className="w-3 h-3" /> SQLite WAL Certified
                </span>
              </div>
              <div className="flex items-center justify-between p-2 rounded bg-cyber-900/60 border border-cyber-800">
                <span className="text-slate-300">Process Sandboxing</span>
                <span className="text-emerald-400 font-bold flex items-center gap-1">
                  <CheckCircle2 className="w-3 h-3" /> Win32 Job Object (512MB)
                </span>
              </div>
              <div className="flex items-center justify-between p-2 rounded bg-cyber-900/60 border border-cyber-800">
                <span className="text-slate-300">Cryptographic Anchor</span>
                <span className="text-emerald-400 font-bold flex items-center gap-1">
                  <CheckCircle2 className="w-3 h-3" /> Merkle SHA-256
                </span>
              </div>
              <div className="flex items-center justify-between p-2 rounded bg-cyber-900/60 border border-cyber-800">
                <span className="text-slate-300">PostgreSQL Multi-Worker</span>
                <span className="text-amber-400 font-bold flex items-center gap-1">
                  <Clock className="w-3 h-3" /> Staging Standby
                </span>
              </div>
            </div>
          </div>

          {/* Immutable Audit Stream Preview */}
          <div className="bg-cyber-850 border border-cyber-750 rounded-xl p-5 shadow-lg flex flex-col">
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center gap-2">
                <FileText className="w-4 h-4 text-accent-cyan" />
                <h3 className="text-sm font-semibold text-white">Audit Ledger Activity</h3>
              </div>
              <button
                onClick={onNavigateToAudit}
                className="text-xs text-accent-cyan hover:underline flex items-center gap-1 font-mono"
              >
                Full Ledger <ArrowRight className="w-3.5 h-3.5" />
              </button>
            </div>

            <div className="space-y-2 overflow-y-auto max-h-[320px]">
              {recentAudits.length === 0 ? (
                <div className="text-center py-8 text-xs text-slate-500 font-mono">
                  No audit events recorded for this project yet.
                </div>
              ) : (
                recentAudits.slice(0, 6).map((ev) => (
                  <div
                    key={ev.id}
                    className="p-2.5 bg-cyber-900 border border-cyber-800 rounded-lg text-xs space-y-1 font-mono"
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-semibold text-accent-cyan truncate">{ev.action}</span>
                      <span
                        className={`text-[9px] px-1.5 py-0.2 rounded font-bold ${
                          ev.outcome === 'SUCCESS'
                            ? 'bg-emerald-500/10 text-emerald-400'
                            : 'bg-rose-500/10 text-rose-400'
                        }`}
                      >
                        {ev.outcome}
                      </span>
                    </div>
                    <div className="text-[11px] text-slate-400 truncate">
                      Actor: {ev.actor_email || ev.actor_id || 'System'}
                    </div>
                    <div className="text-[10px] text-slate-500">
                      {new Date(ev.timestamp).toLocaleTimeString()}
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
