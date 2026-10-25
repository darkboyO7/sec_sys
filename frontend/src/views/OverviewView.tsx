import React from 'react';
import { Target, ShieldAlert, CheckCircle2, Clock, Ban, FolderPlus, ArrowRight } from 'lucide-react';
import type { Project, ScopeTarget, ScopeExclusion, AuditEvent } from '../types';
import { ScopeValidationConsole } from '../components/ScopeValidationConsole';
import { EmptyState } from '../components/EmptyState';

interface OverviewViewProps {
  activeProject: Project | null;
  targets: ScopeTarget[];
  exclusions: ScopeExclusion[];
  recentAudits: AuditEvent[];
  findingCount?: number;
  onCreateProjectClick: () => void;
  onNavigateToScopes: () => void;
  onNavigateToFindings?: () => void;
  onNavigateToAudit: () => void;
}

export const OverviewView: React.FC<OverviewViewProps> = ({
  activeProject,
  targets,
  exclusions,
  recentAudits,
  findingCount = 0,
  onCreateProjectClick,
  onNavigateToScopes,
  onNavigateToFindings,
  onNavigateToAudit,
}) => {
  if (!activeProject) {
    return (
      <div className="max-w-4xl mx-auto py-12">
        <EmptyState
          icon={FolderPlus}
          title="No Project Workspace Selected"
          description="A security assessment project is required to register target scopes, manage exclusion rules, and perform authorized security testing."
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

  return (
    <div className="space-y-6">
      {/* Active Project Banner */}
      <div className="bg-gradient-to-r from-cyber-850 to-cyber-800 border border-cyber-750 rounded-xl p-6 shadow-md flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-accent-cyan/15 text-accent-cyan border border-accent-cyan/30 uppercase font-semibold">
              Active Assessment Boundary
            </span>
            <span className="text-xs text-slate-500 font-mono">ID: {activeProject.id.slice(0, 8)}...</span>
          </div>
          <h2 className="text-xl font-bold text-white tracking-tight">{activeProject.name}</h2>
          <p className="text-xs text-slate-400 mt-1 max-w-2xl">
            {activeProject.description || 'No formal scope description recorded for this project.'}
          </p>
        </div>

        <div className="flex items-center gap-2">
          {onNavigateToFindings && (
            <button
              onClick={onNavigateToFindings}
              className="px-3.5 py-2 rounded-lg bg-cyber-750 hover:bg-cyber-700 text-xs font-semibold text-slate-200 hover:text-white transition-colors flex items-center gap-1.5"
            >
              <ShieldAlert className="w-4 h-4 text-amber-400" />
              Findings ({findingCount})
            </button>
          )}
          <button
            onClick={onNavigateToScopes}
            className="px-3.5 py-2 rounded-lg bg-cyber-750 hover:bg-cyber-700 text-xs font-semibold text-slate-200 hover:text-white transition-colors flex items-center gap-1.5"
          >
            <Target className="w-4 h-4 text-accent-cyan" />
            Manage Scope
          </button>
        </div>
      </div>

      {/* Real Metric Counters */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <div className="bg-cyber-850 border border-cyber-750 rounded-xl p-4">
          <div className="flex items-center justify-between text-slate-400 text-xs mb-1">
            <span>Authorized Scope</span>
            <CheckCircle2 className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-emerald-400">{authorizedCount}</div>
          <p className="text-[10px] text-slate-500 mt-1">Verified with signed evidence</p>
        </div>

        <div className="bg-cyber-850 border border-cyber-750 rounded-xl p-4">
          <div className="flex items-center justify-between text-slate-400 text-xs mb-1">
            <span>Pending Review</span>
            <Clock className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-amber-400">{pendingCount}</div>
          <p className="text-[10px] text-slate-500 mt-1">Requires lead authorization</p>
        </div>

        <div className="bg-cyber-850 border border-cyber-750 rounded-xl p-4">
          <div className="flex items-center justify-between text-slate-400 text-xs mb-1">
            <span>Scope Exclusions</span>
            <ShieldAlert className="w-4 h-4 text-rose-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-rose-400">{exclusions.length}</div>
          <p className="text-[10px] text-slate-500 mt-1">Preemptive deny rules</p>
        </div>

        <div className="bg-cyber-850 border border-cyber-750 rounded-xl p-4">
          <div className="flex items-center justify-between text-slate-400 text-xs mb-1">
            <span>Revoked / Inactive</span>
            <Ban className="w-4 h-4 text-slate-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-slate-300">{revokedCount + expiredCount}</div>
          <p className="text-[10px] text-slate-500 mt-1">Disallowed by policy</p>
        </div>
      </div>

      {/* Main Grid: Scope Validation Console & Audit Preview */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 space-y-6">
          <ScopeValidationConsole projectId={activeProject.id} />
        </div>

        {/* Audit Activity Preview */}
        <div className="bg-cyber-850 border border-cyber-750 rounded-xl p-5 shadow-lg flex flex-col">
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-sm font-semibold text-white">Recent Audit Events</h3>
            <button
              onClick={onNavigateToAudit}
              className="text-[11px] text-accent-cyan hover:underline flex items-center gap-1"
            >
              View Full Ledger <ArrowRight className="w-3 h-3" />
            </button>
          </div>

          <p className="text-xs text-slate-400 mb-3">
            Immutable log of state mutations, approvals, and authorization checks.
          </p>

          <div className="flex-1 space-y-2 overflow-y-auto max-h-[300px]">
            {recentAudits.length === 0 ? (
              <div className="text-center py-8 text-xs text-slate-500">
                No audit events recorded for this project yet.
              </div>
            ) : (
              recentAudits.slice(0, 5).map((ev) => (
                <div
                  key={ev.id}
                  className="p-2.5 bg-cyber-900 border border-cyber-800 rounded-lg text-xs space-y-1 font-mono"
                >
                  <div className="flex items-center justify-between">
                    <span className="font-semibold text-accent-cyan">{ev.action}</span>
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
  );
};
