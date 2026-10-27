import React, { useState, useEffect, useCallback } from 'react';
import { Lock } from 'lucide-react';
import { Header } from './components/Header';
import { Sidebar } from './components/Sidebar';
import type { NavigationTab } from './components/Sidebar';
import { OverviewView } from './views/OverviewView';
import { ScopeManagementView } from './views/ScopeManagementView';
import { AssessmentJobsView } from './views/AssessmentJobsView';
import { FindingLifecycleView } from './views/FindingLifecycleView';
import { AssetInventoryView } from './views/AssetInventoryView';
import { KnowledgeGraphView } from './views/KnowledgeGraphView';
import { ContextualRiskView } from './views/ContextualRiskView';
import { AuditLedgerView } from './views/AuditLedgerView';
import { SystemHealthView } from './views/SystemHealthView';
import { RemediationVerificationView } from './views/RemediationVerificationView';
import { ReportingView } from './views/ReportingView';
import { DigitalTwinView } from './views/DigitalTwinView';
import { RegressionAlertsView } from './views/RegressionAlertsView';
import { AIAnalystView } from './views/AIAnalystView';
import { ModelGovernanceView } from './views/ModelGovernanceView';
import { AdaptiveDefenseView } from './views/AdaptiveDefenseView';
import { IntegrationsView } from './views/IntegrationsView';
import { SettingsView } from './views/SettingsView';
import { AuthModal } from './components/AuthModal';
import { CreateProjectModal } from './components/CreateProjectModal';
import { api } from './services/api';
import type { User, Project, ScopeTarget, ScopeExclusion, AssessmentJob, AuditEvent, ReadinessResponse } from './types';

export const App: React.FC = () => {
  // Navigation & UI State
  const [activeTab, setActiveTab] = useState<NavigationTab>('overview');
  const [isSidebarCollapsed, setIsSidebarCollapsed] = useState(false);
  const [isAuthModalOpen, setIsAuthModalOpen] = useState(false);
  const [isCreateProjectOpen, setIsCreateProjectOpen] = useState(false);

  // Core Data
  const [currentUser, setCurrentUser] = useState<User | null>(null);
  const [projects, setProjects] = useState<Project[]>([]);
  const [activeProject, setActiveProject] = useState<Project | null>(null);
  const [targets, setTargets] = useState<ScopeTarget[]>([]);
  const [exclusions, setExclusions] = useState<ScopeExclusion[]>([]);
  const [assessmentJobs, setAssessmentJobs] = useState<AssessmentJob[]>([]);
  const [findingCount, setFindingCount] = useState<number>(0);
  const [assetCount, setAssetCount] = useState<number>(0);
  const [graphRootNodeId, setGraphRootNodeId] = useState<string | null>(null);
  const [auditEvents, setAuditEvents] = useState<AuditEvent[]>([]);
  const [readiness, setReadiness] = useState<ReadinessResponse | null>(null);
  const [health, setHealth] = useState<{ status: string; version: string; environment: string; timestamp: string } | null>(null);

  const [loading, setLoading] = useState(false);

  // Probe System Health
  const loadSystemDiagnostics = useCallback(async () => {
    try {
      const [h, r] = await Promise.all([api.getHealth(), api.getReadiness()]);
      setHealth(h);
      setReadiness(r);
    } catch {
      setReadiness(null);
    }
  }, []);

  // Fetch Projects
  const loadProjects = useCallback(async () => {
    if (!api.getToken()) {
      setProjects([]);
      setActiveProject(null);
      return;
    }
    try {
      const list = await api.listProjects();
      setProjects(list);
      if (list.length > 0) {
        setActiveProject((prev) => (prev && list.some((p) => p.id === prev.id) ? prev : list[0]));
      } else {
        setActiveProject(null);
      }
    } catch (err) {
      console.error('Failed to load projects:', err);
    }
  }, []);

  // Fetch Project Scopes, Assessments & Audit
  const loadProjectData = useCallback(async () => {
    if (!activeProject || !api.getToken()) {
      setTargets([]);
      setExclusions([]);
      setAssessmentJobs([]);
      setFindingCount(0);
      setAssetCount(0);
      setAuditEvents([]);
      return;
    }
    setLoading(true);
    try {
      const [tList, eList, jList, fStats, aList, auditRes] = await Promise.all([
        api.listScopeTargets(activeProject.id),
        api.listScopeExclusions(activeProject.id),
        api.listAssessments(activeProject.id),
        api.getFindingStats(activeProject.id).catch(() => ({ total: 0 })),
        api.listAssets(activeProject.id).catch(() => []),
        api.getAuditLedger({ projectId: activeProject.id, limit: 50 }),
      ]);
      setTargets(tList);
      setExclusions(eList);
      setAssessmentJobs(jList);
      setFindingCount((fStats as any).total || 0);
      setAssetCount(aList.length);
      setAuditEvents(auditRes.items);
    } catch (err) {
      console.error('Failed to load project scope data:', err);
    } finally {
      setLoading(false);
    }
  }, [activeProject]);

  // Initial Auth Check
  useEffect(() => {
    const checkAuth = async () => {
      loadSystemDiagnostics();
      if (api.getToken()) {
        try {
          const user = await api.getMe();
          setCurrentUser(user);
        } catch {
          api.logout();
          setCurrentUser(null);
        }
      }
    };
    checkAuth();
  }, [loadSystemDiagnostics]);

  // Load Projects on Auth Change
  useEffect(() => {
    if (currentUser) {
      loadProjects();
    } else {
      setProjects([]);
      setActiveProject(null);
      setTargets([]);
      setExclusions([]);
      setAssessmentJobs([]);
      setAuditEvents([]);
    }
  }, [currentUser, loadProjects]);

  // Load Scope and Assessment data on Active Project Change
  useEffect(() => {
    loadProjectData();
  }, [activeProject, loadProjectData]);

  const handleLogout = () => {
    api.logout();
    setCurrentUser(null);
    setProjects([]);
    setActiveProject(null);
    setTargets([]);
    setExclusions([]);
    setAssessmentJobs([]);
    setAuditEvents([]);
  };

  const authorizedTargets = targets.filter((t) => t.authorization_status === 'AUTHORIZED');

  const requiresProjectTab = [
    'scopes',
    'assessments',
    'findings',
    'assets',
    'graph',
    'risk',
    'verification',
    'reports',
    'digital-twin',
    'regression',
    'ai-analyst',
    'learning',
    'adaptive-defense',
    'integrations',
    'settings',
  ].includes(activeTab);

  return (
    <div className="h-screen w-screen bg-cyber-900 text-slate-100 flex flex-col font-sans overflow-hidden selection:bg-accent-cyan/30">
      <Header
        user={currentUser}
        projects={projects}
        activeProject={activeProject}
        onSelectProject={(p) => setActiveProject(p)}
        onCreateProjectClick={() => setIsCreateProjectOpen(true)}
        onAuthClick={() => setIsAuthModalOpen(true)}
        onLogout={handleLogout}
        readiness={readiness}
        isSidebarCollapsed={isSidebarCollapsed}
        onToggleSidebar={() => setIsSidebarCollapsed(!isSidebarCollapsed)}
      />

      <div className="flex flex-1 overflow-hidden relative">
        <Sidebar
          activeTab={activeTab}
          onTabChange={(t) => setActiveTab(t)}
          isCollapsed={isSidebarCollapsed}
          onToggleCollapse={() => setIsSidebarCollapsed(!isSidebarCollapsed)}
          targetCount={targets.length}
          assessmentCount={assessmentJobs.length}
          findingCount={findingCount}
          assetCount={assetCount}
          auditCount={auditEvents.length}
        />

        <main className="flex-1 overflow-y-auto p-5 sm:p-6 lg:p-8 w-full bg-cyber-950/40">
          {activeTab === 'overview' && (
            <OverviewView
              activeProject={activeProject}
              targets={targets}
              exclusions={exclusions}
              recentAudits={auditEvents}
              findingCount={findingCount}
              assetCount={assetCount}
              assessmentJobs={assessmentJobs}
              onCreateProjectClick={() => setIsCreateProjectOpen(true)}
              onNavigateToScopes={() => setActiveTab('scopes')}
              onNavigateToFindings={() => setActiveTab('findings')}
              onNavigateToAssets={() => setActiveTab('assets')}
              onNavigateToGraph={() => setActiveTab('graph')}
              onNavigateToAssessments={() => setActiveTab('assessments')}
              onNavigateToAudit={() => setActiveTab('audit')}
              onNavigateToRisk={() => setActiveTab('risk')}
            />
          )}

          {requiresProjectTab && !activeProject && (
            <div className="py-20 text-center text-slate-400 bg-cyber-850/40 border border-cyber-750 rounded-xl max-w-2xl mx-auto shadow-lg">
              <div className="w-12 h-12 rounded-xl bg-accent-blue/10 border border-accent-blue/30 text-accent-cyan flex items-center justify-center mx-auto mb-3">
                <Lock className="w-6 h-6 text-accent-cyan" />
              </div>
              <h3 className="text-base font-bold text-white mb-1">Authentication or Project Selection Required</h3>
              <p className="text-xs text-slate-400 mb-4 max-w-md mx-auto">
                Select an active assessment project from the header or authenticate to access governed security intelligence.
              </p>
              {!currentUser && (
                <button
                  onClick={() => setIsAuthModalOpen(true)}
                  className="px-4 py-2 rounded-lg bg-accent-blue hover:bg-accent-blue/90 text-white text-xs font-semibold"
                >
                  Sign In to Control Plane
                </button>
              )}
            </div>
          )}

          {activeProject && (
            <>
              {activeTab === 'scopes' && (
                <ScopeManagementView
                  project={activeProject}
                  targets={targets}
                  exclusions={exclusions}
                  currentUser={currentUser}
                  onRefresh={loadProjectData}
                />
              )}

              {activeTab === 'assessments' && (
                <AssessmentJobsView
                  project={activeProject}
                  authorizedTargets={authorizedTargets}
                  jobs={assessmentJobs}
                  onRefresh={loadProjectData}
                  loading={loading}
                  onNavigateToScopes={() => setActiveTab('scopes')}
                  onNavigateToFindings={() => setActiveTab('findings')}
                />
              )}

              {activeTab === 'findings' && (
                <FindingLifecycleView currentProject={activeProject} />
              )}

              {activeTab === 'assets' && (
                <AssetInventoryView
                  currentProject={activeProject}
                  onNavigateToGraph={(nodeId) => {
                    if (nodeId) setGraphRootNodeId(nodeId);
                    setActiveTab('graph');
                  }}
                />
              )}

              {activeTab === 'graph' && (
                <KnowledgeGraphView
                  currentProject={activeProject}
                  initialNodeId={graphRootNodeId}
                />
              )}

              {activeTab === 'risk' && (
                <ContextualRiskView
                  currentProject={activeProject}
                  currentUserRole={currentUser?.system_role}
                />
              )}

              {activeTab === 'verification' && (
                <RemediationVerificationView currentProject={activeProject} />
              )}

              {activeTab === 'reports' && (
                <ReportingView currentProject={activeProject} />
              )}

              {activeTab === 'digital-twin' && (
                <DigitalTwinView currentProject={activeProject} />
              )}

              {activeTab === 'regression' && (
                <RegressionAlertsView currentProject={activeProject} />
              )}

              {activeTab === 'ai-analyst' && (
                <AIAnalystView currentProject={activeProject} />
              )}

              {activeTab === 'learning' && (
                <ModelGovernanceView projectId={activeProject.id} />
              )}

              {activeTab === 'adaptive-defense' && (
                <AdaptiveDefenseView projectId={activeProject.id} />
              )}

              {activeTab === 'integrations' && (
                <IntegrationsView projectId={activeProject.id} />
              )}

              {activeTab === 'settings' && (
                <SettingsView
                  currentProject={activeProject}
                  currentUser={currentUser}
                  onProjectUpdated={(updated) => {
                    setActiveProject(updated);
                    loadProjects();
                  }}
                />
              )}
            </>
          )}

          {activeTab === 'audit' && (
            <AuditLedgerView
              events={auditEvents}
              activeProject={activeProject}
              onRefresh={loadProjectData}
              loading={loading}
            />
          )}

          {activeTab === 'health' && (
            <SystemHealthView
              health={health}
              readiness={readiness}
              onRefresh={loadSystemDiagnostics}
              loading={loading}
            />
          )}
        </main>
      </div>

      {/* Modals */}
      <AuthModal
        isOpen={isAuthModalOpen}
        onClose={() => setIsAuthModalOpen(false)}
        onSuccess={(user) => {
          setCurrentUser(user);
          loadProjects();
        }}
      />

      <CreateProjectModal
        isOpen={isCreateProjectOpen}
        onClose={() => setIsCreateProjectOpen(false)}
        onSuccess={(p) => {
          setProjects((prev) => [...prev, p]);
          setActiveProject(p);
        }}
      />
    </div>
  );
};

export default App;
