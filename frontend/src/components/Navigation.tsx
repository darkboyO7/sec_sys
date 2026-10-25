import React from 'react';
import { LayoutDashboard, Target, PlayCircle, ShieldAlert, FileText, Activity, Server, Network } from 'lucide-react';

export type NavigationTab = 'overview' | 'scopes' | 'assessments' | 'findings' | 'assets' | 'graph' | 'audit' | 'health';

interface NavigationProps {
  activeTab: NavigationTab;
  onTabChange: (tab: NavigationTab) => void;
  targetCount?: number;
  assessmentCount?: number;
  findingCount?: number;
  assetCount?: number;
  auditCount?: number;
}

export const Navigation: React.FC<NavigationProps> = ({
  activeTab,
  onTabChange,
  targetCount = 0,
  assessmentCount = 0,
  findingCount = 0,
  assetCount = 0,
  auditCount = 0,
}) => {
  const tabs = [
    {
      id: 'overview' as NavigationTab,
      label: 'Mission Overview',
      icon: LayoutDashboard,
    },
    {
      id: 'scopes' as NavigationTab,
      label: 'Scopes & Target Authorization',
      icon: Target,
      badge: targetCount > 0 ? targetCount : undefined,
    },
    {
      id: 'assessments' as NavigationTab,
      label: 'Assessment Jobs',
      icon: PlayCircle,
      badge: assessmentCount > 0 ? assessmentCount : undefined,
    },
    {
      id: 'findings' as NavigationTab,
      label: 'Finding Lifecycle',
      icon: ShieldAlert,
      badge: findingCount > 0 ? findingCount : undefined,
    },
    {
      id: 'assets' as NavigationTab,
      label: 'Asset Inventory',
      icon: Server,
      badge: assetCount > 0 ? assetCount : undefined,
    },
    {
      id: 'graph' as NavigationTab,
      label: 'Security Knowledge Graph',
      icon: Network,
    },
    {
      id: 'audit' as NavigationTab,
      label: 'Audit Ledger',
      icon: FileText,
      badge: auditCount > 0 ? auditCount : undefined,
    },
    {
      id: 'health' as NavigationTab,
      label: 'Control Plane Health',
      icon: Activity,
    },
  ];

  return (
    <nav className="border-b border-cyber-750 bg-cyber-850/60 px-6">
      <div className="flex gap-2">
        {tabs.map((tab) => {
          const Icon = tab.icon;
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => onTabChange(tab.id)}
              className={`flex items-center gap-2 py-3 px-3.5 text-xs font-semibold border-b-2 transition-all ${
                isActive
                  ? 'border-accent-cyan text-accent-cyan bg-cyber-800/40'
                  : 'border-transparent text-slate-400 hover:text-slate-200 hover:border-cyber-600'
              }`}
            >
              <Icon className="w-4 h-4" />
              <span>{tab.label}</span>
              {tab.badge !== undefined && (
                <span
                  className={`text-[10px] px-1.5 py-0.2 rounded-full font-mono ${
                    isActive ? 'bg-accent-cyan/20 text-accent-cyan' : 'bg-cyber-750 text-slate-400'
                  }`}
                >
                  {tab.badge}
                </span>
              )}
            </button>
          );
        })}
      </div>
    </nav>
  );
};
