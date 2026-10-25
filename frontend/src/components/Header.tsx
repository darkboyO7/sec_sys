import React from 'react';
import { Shield, AlertTriangle, LogIn, LogOut, Plus, ChevronDown } from 'lucide-react';
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
}) => {
  const isReady = readiness?.status === 'ready';

  return (
    <header className="h-16 border-b border-cyber-750 bg-cyber-900/90 backdrop-blur-md px-6 flex items-center justify-between sticky top-0 z-30">
      {/* Brand & Platform Identity */}
      <div className="flex items-center gap-3">
        <div className="w-10 h-10 rounded-xl bg-gradient-to-tr from-accent-blue/30 via-accent-cyan/20 to-transparent border border-accent-blue/40 flex items-center justify-center text-accent-cyan shadow-lg shadow-accent-cyan/5">
          <Shield className="w-5 h-5 text-accent-cyan" />
        </div>
        <div>
          <div className="flex items-center gap-2">
            <span className="font-bold text-sm tracking-wide text-white uppercase font-mono">VAPT Control Plane</span>
            <span className="text-[10px] px-1.5 py-0.5 rounded font-mono font-medium bg-cyber-800 text-accent-cyan border border-cyber-700">
              Phase 1
            </span>
          </div>
          <p className="text-[11px] text-slate-400">Autonomous Security & Scope Governance</p>
        </div>
      </div>

      {/* Middle: Active Project Selector */}
      <div className="flex items-center gap-3">
        {user && (
          <div className="flex items-center gap-2 bg-cyber-850 border border-cyber-750 px-3 py-1.5 rounded-lg">
            <span className="text-xs text-slate-400 font-medium">Project:</span>
            {projects.length > 0 ? (
              <div className="relative group">
                <button className="flex items-center gap-2 text-xs font-semibold text-slate-200 hover:text-white transition-colors">
                  <span className="max-w-[160px] truncate">{activeProject?.name || 'Select Project'}</span>
                  <ChevronDown className="w-3.5 h-3.5 text-slate-400" />
                </button>
                <div className="absolute left-0 mt-2 w-56 bg-cyber-850 border border-cyber-700 rounded-lg shadow-xl p-1 hidden group-hover:block z-50">
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
                      <div className="text-[10px] text-slate-400">{p.is_active ? 'Active' : 'Inactive'}</div>
                    </button>
                  ))}
                  <div className="border-t border-cyber-750 mt-1 pt-1">
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

        {/* Readiness Probe Status */}
        <div
          title={
            isReady
              ? 'Control Plane & DB persistence fully operational'
              : 'Readiness check degraded or backend offline'
          }
          className={`flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-mono border ${
            isReady
              ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20'
              : 'bg-rose-500/10 text-rose-400 border-rose-500/20'
          }`}
        >
          {isReady ? (
            <>
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
              <span>ONLINE</span>
            </>
          ) : (
            <>
              <AlertTriangle className="w-3.5 h-3.5" />
              <span>OFFLINE / NOT READY</span>
            </>
          )}
        </div>
      </div>

      {/* Right: User / Auth Controls */}
      <div className="flex items-center gap-3">
        {user ? (
          <div className="flex items-center gap-3">
            <div className="flex items-center gap-2">
              <div className="w-8 h-8 rounded-lg bg-cyber-800 border border-cyber-700 flex items-center justify-center text-slate-300 font-semibold text-xs">
                {user.full_name ? user.full_name.charAt(0).toUpperCase() : 'U'}
              </div>
              <div className="hidden sm:block text-left">
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
