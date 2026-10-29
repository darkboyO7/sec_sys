import React from 'react';
import {
  LayoutDashboard,
  Target,
  PlayCircle,
  ShieldAlert,
  FileText,
  Activity,
  Server,
  Network,
  Flame,
  CheckCircle,
  FileSpreadsheet,
  History,
  AlertTriangle,
  Bot,
  Scale,
  Shield,
  ShieldCheck,
  Layers,
  Settings,
  Clock,
  ChevronLeft,
  ChevronRight,
  Database,
  Boxes,
  Gauge,
  Bell,
} from 'lucide-react';

export type NavigationTab =
  | 'overview'
  | 'scheduling'
  | 'compliance'
  | 'governance'
  | 'recovery'
  | 'supply-chain'
  | 'performance'
  | 'mutation-verification'
  | 'deployment'
  | 'evidence-lifecycle'
  | 'alerts'
  | 'scopes'
  | 'orchestration'
  | 'assessments'
  | 'monitoring'
  | 'findings'
  | 'assets'
  | 'drift'
  | 'knowledge'
  | 'graph'
  | 'risk'
  | 'verification'
  | 'reports'
  | 'digital-twin'
  | 'regression'
  | 'ai-analyst'
  | 'learning'
  | 'quality'
  | 'adaptive-defense'
  | 'audit'
  | 'health'
  | 'integrations'
  | 'settings';

interface SidebarProps {
  activeTab: NavigationTab;
  onTabChange: (tab: NavigationTab) => void;
  isCollapsed: boolean;
  onToggleCollapse: () => void;
  targetCount?: number;
  assessmentCount?: number;
  findingCount?: number;
  assetCount?: number;
  auditCount?: number;
}

interface NavItem {
  id: NavigationTab;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  badge?: number;
}

interface NavGroup {
  category: string;
  items: NavItem[];
}

export const Sidebar: React.FC<SidebarProps> = ({
  activeTab,
  onTabChange,
  isCollapsed,
  onToggleCollapse,
  targetCount = 0,
  assessmentCount = 0,
  findingCount = 0,
  assetCount = 0,
  auditCount = 0,
}) => {
  const groups: NavGroup[] = [
    {
      category: 'CORE & GOVERNANCE',
      items: [
        { id: 'overview', label: 'Mission Overview', icon: LayoutDashboard },
        { id: 'governance', label: 'Governance & SoD', icon: ShieldCheck },
        { id: 'scopes', label: 'Scope & Targets', icon: Target, badge: targetCount > 0 ? targetCount : undefined },
        { id: 'settings', label: 'Team & Settings', icon: Settings },
      ],
    },
    {
      category: 'DISCOVERY & GRAPH',
      items: [
        { id: 'assets', label: 'Asset Inventory', icon: Server, badge: assetCount > 0 ? assetCount : undefined },
        { id: 'drift', label: 'Exposure Drift', icon: Activity },
        { id: 'knowledge', label: 'Knowledge Integrity', icon: Shield },
        { id: 'graph', label: 'Knowledge Graph', icon: Network },
        { id: 'risk', label: 'Risk & Attack Paths', icon: Flame },
      ],
    },
    {
      category: 'OPERATIONS & EXECUTION',
      items: [
        { id: 'scheduling', label: 'Intelligent Scheduling', icon: Clock },
        { id: 'orchestration', label: 'Autonomous Orchestrator', icon: Layers },
        { id: 'assessments', label: 'Assessment Jobs', icon: PlayCircle, badge: assessmentCount > 0 ? assessmentCount : undefined },
        { id: 'monitoring', label: 'Continuous Monitor', icon: Clock },
        { id: 'findings', label: 'Finding Lifecycle', icon: ShieldAlert, badge: findingCount > 0 ? findingCount : undefined },
        { id: 'alerts', label: 'Alerting & Escalation', icon: Bell },
        { id: 'verification', label: 'Remediation & Verify', icon: CheckCircle },
      ],
    },
    {
      category: 'DEFENSIVE INTELLIGENCE',
      items: [
        { id: 'quality', label: 'Detection Quality', icon: Activity },
        { id: 'ai-analyst', label: 'AI Security Analyst', icon: Bot },
        { id: 'learning', label: 'Model Governance', icon: Scale },
        { id: 'regression', label: 'Regression Alerts', icon: AlertTriangle },
        { id: 'digital-twin', label: 'Digital Twin', icon: History },
        { id: 'adaptive-defense', label: 'Adaptive Defense', icon: Shield },
      ],
    },
    {
      category: 'COMPLIANCE & TELEMETRY',
      items: [
        { id: 'compliance', label: 'Continuous Compliance', icon: ShieldCheck },
        { id: 'reports', label: 'Reports & Export', icon: FileSpreadsheet },
        { id: 'integrations', label: 'Integrations & Feeds', icon: Layers },
        { id: 'audit', label: 'Audit Ledger', icon: FileText, badge: auditCount > 0 ? auditCount : undefined },
        { id: 'health', label: 'Control Plane Health', icon: Activity },
        { id: 'recovery', label: 'Disaster Recovery', icon: Database },
        { id: 'supply-chain', label: 'Supply Chain & SBOM', icon: Boxes },
        { id: 'performance', label: 'Performance & Scaling', icon: Gauge },
        { id: 'mutation-verification', label: 'Control & Mutation Testing', icon: ShieldCheck },
        { id: 'deployment', label: 'Deployment Governance', icon: Settings },
        { id: 'evidence-lifecycle', label: 'Evidence Retention & Holds', icon: Database },
      ],
    },
  ];

  return (
    <aside
      className={`h-full flex flex-col bg-cyber-900 border-r border-cyber-750 transition-all duration-200 select-none ${
        isCollapsed ? 'w-16' : 'w-64'
      }`}
    >
      {/* Scrollable Navigation Groups */}
      <div className="flex-1 overflow-y-auto overflow-x-hidden p-3 space-y-5 scrollbar-thin">
        {groups.map((group) => (
          <div key={group.category} className="space-y-1">
            {!isCollapsed && (
              <div className="px-2 py-1 text-[10px] font-mono font-bold tracking-wider text-slate-500 uppercase">
                {group.category}
              </div>
            )}
            {isCollapsed && <div className="h-px bg-cyber-800 my-2 mx-1" />}

            <div className="space-y-0.5">
              {group.items.map((item) => {
                const Icon = item.icon;
                const isActive = activeTab === item.id;

                return (
                  <button
                    key={item.id}
                    onClick={() => onTabChange(item.id)}
                    title={isCollapsed ? item.label : undefined}
                    className={`w-full flex items-center gap-3 px-2.5 py-2 rounded-lg text-xs font-medium transition-colors relative group ${
                      isActive
                        ? 'bg-accent-cyan/15 text-accent-cyan border border-accent-cyan/30 shadow-sm'
                        : 'text-slate-400 hover:text-slate-200 hover:bg-cyber-800/60 border border-transparent'
                    }`}
                  >
                    <Icon className={`w-4 h-4 shrink-0 ${isActive ? 'text-accent-cyan' : 'text-slate-400 group-hover:text-slate-200'}`} />

                    {!isCollapsed && (
                      <span className="truncate flex-1 text-left">{item.label}</span>
                    )}

                    {!isCollapsed && item.badge !== undefined && (
                      <span
                        className={`text-[10px] px-1.5 py-0.2 rounded-full font-mono font-bold ${
                          isActive
                            ? 'bg-accent-cyan text-cyber-950'
                            : 'bg-cyber-750 text-slate-400 group-hover:text-slate-200'
                        }`}
                      >
                        {item.badge}
                      </span>
                    )}

                    {/* Collapsed Tooltip on Hover */}
                    {isCollapsed && (
                      <div className="absolute left-full ml-2 px-2.5 py-1.5 bg-cyber-800 border border-cyber-700 text-white text-xs rounded-md shadow-xl whitespace-nowrap opacity-0 pointer-events-none group-hover:opacity-100 transition-opacity z-50 flex items-center gap-2">
                        <span>{item.label}</span>
                        {item.badge !== undefined && (
                          <span className="bg-accent-cyan text-cyber-950 text-[10px] px-1.5 rounded-full font-mono font-bold">
                            {item.badge}
                          </span>
                        )}
                      </div>
                    )}
                  </button>
                );
              })}
            </div>
          </div>
        ))}
      </div>

      {/* Collapse Toggle Footer */}
      <div className="p-3 border-t border-cyber-800 bg-cyber-950/40 flex items-center justify-between">
        {!isCollapsed && (
          <div className="text-[11px] font-mono text-slate-500 truncate">
            Enterprise Control Plane
          </div>
        )}
        <button
          onClick={onToggleCollapse}
          title={isCollapsed ? 'Expand Sidebar' : 'Collapse Sidebar'}
          className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-cyber-800 transition-colors mx-auto"
        >
          {isCollapsed ? <ChevronRight className="w-4 h-4" /> : <ChevronLeft className="w-4 h-4" />}
        </button>
      </div>
    </aside>
  );
};
