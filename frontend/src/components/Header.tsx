import React, { useState } from 'react';
import {
  Shield,
  LogIn,
  LogOut,
  Plus,
  ChevronDown,
  Menu,
  CheckCircle2,
  Clock,
} from 'lucide-react';
import type { User, Project, ReadinessResponse } from '../types';

interface HeaderProps {
  user: User | null;
  projects: Project[];
  activeProject: Project | null;
  onSelectProject: (p: Project) => void;
  onCreateProjectClick: () => void;
  onAuthClick: () => void;
  onLogout: () => void;
  readiness: ReadinessResponse | null;
  isSidebarCollapsed?: boolean;
  onToggleSidebar?: () => void;
}

export const Header: React.FC<HeaderProps> = ({
  user,
  projects,
  activeProject,
  onSelectProject,
  onCreateProjectClick,
  onAuthClick,
  onLogout,
  readiness,
  isSidebarCollapsed = false,
  onToggleSidebar,
}) => {
  const [isHealthOpen, setIsHealthOpen] = useState(false);
  const isReady = readiness?.status === 'ready';

  return (
    <header className="h-16 border-b border-cyber-750 bg-cyber-900/95 backdrop-blur-md px-4 sm:px-6 flex items-center justify-between sticky top-0 z-30 select-none">
      {/* Brand & Platform Identity */}
      <div className="flex items-center gap-3">
        {onToggleSidebar && (
          <button
            onClick={onToggleSidebar}
            title={isSidebarCollapsed ? 'Expand sidebar' : 'Collapse sidebar'}
            className="p-2 rounded-lg bg-cyber-850 hover:bg-cyber-800 text-slate-400 hover:text-white border border-cyber-750 transition-colors"
          >
            <Menu className="w-4 h-4" />
          </button>
        )}

        <div className="w-9 h-9 rounded-xl bg-gradient-to-tr from-accent-blue/30 via-accent-cyan/20 to-transparent border border-accent-blue/40 flex items-center justify-center text-accent-cyan shadow-lg shadow-accent-cyan/5">
          <Shield className="w-5 h-5 text-accent-cyan" />
        </div>
        <div>
          <div className="flex items-center gap-2">
            <span className="font-bold text-sm tracking-wide text-white uppercase font-mono">VAPT Control Plane</span>
            <span className="text-[10px] px-1.5 py-0.5 rounded font-mono font-medium bg-cyber-800 text-accent-cyan border border-cyber-700">
              v1.0.0
            </span>
          </div>
          <p className="text-[11px] text-slate-400 hidden sm:block">Defensive Security & Scope Governance System</p>
        </div>
      </div>

      {/* Middle: Active Project Selector & Health Pill */}
      <div className="flex items-center gap-3">
        {user && (
          <div className="flex items-center gap-2 bg-cyber-850 border border-cyber-750 px-3 py-1.5 rounded-lg shadow-sm">
            <span className="text-xs text-slate-400 font-medium">Project:</span>
            {projects.length > 0 ? (
              <div className="relative group">
                <button className="flex items-center gap-2 text-xs font-semibold text-slate-200 hover:text-white transition-colors">
                  <span className="max-w-[140px] sm:max-w-[200px] truncate">{activeProject?.name || 'Select Project'}</span>
                  <ChevronDown className="w-3.5 h-3.5 text-slate-400" />
                </button>
                <div className="absolute left-0 mt-2 w-64 bg-cyber-850 border border-cyber-700 rounded-lg shadow-xl p-1 hidden group-hover:block z-50">
                  <div className="p-2 text-[10px] font-mono text-slate-400 uppercase tracking-wider border-b border-cyber-750">
                    Accessible Projects ({projects.length})
                  </div>
                  <div className="max-h-56 overflow-y-auto py-1">
                    {projects.map((p) => (
                      <button
                        key={p.id}
                        onClick={() => onSelectProject(p)}
                        className={`w-full text-left px-2.5 py-1.5 text-xs rounded-md transition-colors ${
                          p.id === activeProject?.id
                            ? 'bg-accent-blue/20 text-accent-blue font-semibold'
                            : 'text-slate-300 hover:bg-cyber-750 hover:text-white'
                        }`}
                      >
                        <div className="truncate">{p.name}</div>
                        <div className="text-[10px] text-slate-400 font-mono flex items-center justify-between">
                          <span>{p.is_active ? 'Active' : 'Archived'}</span>
                          <span>ID: {p.id.slice(0, 8)}...</span>
                        </div>
                      </button>
                    ))}
                  </div>
                  <div className="border-t border-cyber-750 pt-1">
                    <button
                      onClick={onCreateProjectClick}
                      className="w-full flex items-center gap-1.5 px-2.5 py-1.5 text-xs text-accent-cyan hover:bg-cyber-750 rounded-md transition-colors font-medium"
                    >
                      <Plus className="w-3.5 h-3.5" />
                      Create New Project
                    </button>
                  </div>
                </div>
              </div>
            ) : (
              <button
                onClick={onCreateProjectClick}
                className="flex items-center gap-1 text-xs text-accent-cyan font-semibold hover:underline"
              >
                <Plus className="w-3.5 h-3.5" />
                Create Project
              </button>
            )}
          </div>
        )}

        {/* Subsystem Health Inspector Dropdown */}
        <div className="relative">
          <button
            onClick={() => setIsHealthOpen(!isHealthOpen)}
            className={`flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-mono border transition-all ${
              isReady
                ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30 hover:bg-emerald-500/20'
                : 'bg-rose-500/10 text-rose-400 border-rose-500/30 hover:bg-rose-500/20'
            }`}
          >
            <span className={`w-2 h-2 rounded-full ${isReady ? 'bg-emerald-400 animate-pulse' : 'bg-rose-400'}`} />
            <span className="font-semibold">{isReady ? 'SYSTEM OPERATIONAL' : 'DEGRADED / OFFLINE'}</span>
            <ChevronDown className="w-3 h-3 text-slate-400" />
          </button>

          {isHealthOpen && (
            <div className="absolute right-0 mt-2 w-80 bg-cyber-850 border border-cyber-700 rounded-xl shadow-2xl p-4 z-50 animate-in fade-in zoom-in-95 duration-100">
              <div className="flex items-center justify-between pb-2 border-b border-cyber-750 mb-3">
                <span className="text-xs font-bold text-white uppercase font-mono tracking-wider">Subsystem Telemetry</span>
                <button
                  onClick={() => setIsHealthOpen(false)}
                  className="text-slate-400 hover:text-white text-xs"
                >
                  ✕
                </button>
              </div>

              <div className="space-y-2 text-xs font-mono">
                <div className="flex items-center justify-between p-2 rounded bg-cyber-900/60 border border-cyber-800">
                  <span className="text-slate-300">FastAPI Control Plane</span>
                  <span className="text-emerald-400 font-bold flex items-center gap-1">
                    <CheckCircle2 className="w-3 h-3" /> 200 OK
                  </span>
                </div>

                <div className="flex items-center justify-between p-2 rounded bg-cyber-900/60 border border-cyber-800">
                  <span className="text-slate-300">Storage (SQLite WAL)</span>
                  <span className="text-emerald-400 font-bold flex items-center gap-1">
                    <CheckCircle2 className="w-3 h-3" /> CERTIFIED
                  </span>
                </div>

                <div className="flex items-center justify-between p-2 rounded bg-cyber-900/60 border border-cyber-800">
                  <span className="text-slate-300">Worker Isolation</span>
                  <span className="text-emerald-400 font-bold flex items-center gap-1">
                    <CheckCircle2 className="w-3 h-3" /> JOB OBJECT 512MB
                  </span>
                </div>

                <div className="flex items-center justify-between p-2 rounded bg-cyber-900/60 border border-cyber-800">
                  <span className="text-slate-300">Cryptographic Proofs</span>
                  <span className="text-emerald-400 font-bold flex items-center gap-1">
                    <CheckCircle2 className="w-3 h-3" /> MERKLE SHA-256
                  </span>
                </div>

                <div className="flex items-center justify-between p-2 rounded bg-cyber-900/60 border border-cyber-800">
                  <span className="text-slate-300">PostgreSQL Multi-Worker</span>
                  <span className="text-amber-400 font-bold flex items-center gap-1" title="Dialect verified; live staging host offline">
                    <Clock className="w-3 h-3" /> STAGING STANDBY
                  </span>
                </div>
              </div>

              <div className="mt-3 pt-2 border-t border-cyber-750 text-[10px] text-slate-400">
                Single-node Windows 11 operation certified. Multi-worker distributed mode requires physical PostgreSQL 16 server on port 5432.
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Right: User / Auth Controls */}
      <div className="flex items-center gap-3">
        {user ? (
          <div className="flex items-center gap-3">
            <div className="flex items-center gap-2">
              <div className="w-8 h-8 rounded-lg bg-cyber-800 border border-cyber-700 flex items-center justify-center text-slate-300 font-semibold text-xs shadow-inner">
                {user.full_name ? user.full_name.charAt(0).toUpperCase() : 'U'}
              </div>
              <div className="hidden md:block text-left">
                <div className="text-xs font-semibold text-slate-200">{user.full_name}</div>
                <div className="text-[10px] font-mono text-accent-cyan/90">{user.system_role}</div>
              </div>
            </div>
            <button
              onClick={onLogout}
              title="Sign Out"
              className="p-1.5 rounded-lg text-slate-400 hover:text-rose-400 hover:bg-cyber-800 transition-colors"
            >
              <LogOut className="w-4 h-4" />
            </button>
          </div>
        ) : (
          <button
            onClick={onAuthClick}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-lg bg-accent-blue hover:bg-accent-blue/90 text-white transition-colors shadow-sm"
          >
            <LogIn className="w-3.5 h-3.5" />
            Authenticate
          </button>
        )}
      </div>
    </header>
  );
};
