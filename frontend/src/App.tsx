import React, { useState, useEffect, useCallback } from 'react';
import { Header } from './components/Header';
import { Navigation } from './components/Navigation';
import type { NavigationTab } from './components/Navigation';
import { OverviewView } from './views/OverviewView';
import { ScopeManagementView } from './views/ScopeManagementView';
import { AssessmentJobsView } from './views/AssessmentJobsView';
import { FindingLifecycleView } from './views/FindingLifecycleView';
import { AssetInventoryView } from './views/AssetInventoryView';
import { KnowledgeGraphView } from './views/KnowledgeGraphView';
import { ContextualRiskView } from './views/ContextualRiskView';
import { AuditLedgerView } from './views/AuditLedgerView';
import { SystemHealthView } from './views/SystemHealthView';
import { AuthModal } from './components/AuthModal';
import { CreateProjectModal } from './components/CreateProjectModal';
import { api } from './services/api';
import type { User, Project, ScopeTarget, ScopeExclusion, AssessmentJob, AuditEvent, ReadinessResponse } from './types';

export const App: React.FC = () => {
  // Navigation & Modals
  const [activeTab, setActiveTab] = useState<NavigationTab>('overview');
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

  return (
    <div className="min-h-screen bg-cyber-900 text-slate-100 flex flex-col font-sans selection:bg-accent-cyan/30">
      <Header
        user={currentUser}
        projects={projects}
        activeProject={activeProject}
        onSelectProject={(p) => setActiveProject(p)}
        onCreateProjectClick={() => setIsCreateProjectOpen(true)}
        onAuthClick={() => setIsAuthModalOpen(true)}
        onLogout={handleLogout}
        readiness={readiness}
      />

      <Navigation
        activeTab={activeTab}
        onTabChange={(t) => setActiveTab(t)}
        targetCount={targets.length}
        assessmentCount={assessmentJobs.length}
        findingCount={findingCount}
        assetCount={assetCount}
        auditCount={auditEvents.length}
      />

      <main className="flex-1 max-w-7xl w-full mx-auto p-6">
        {activeTab === 'overview' && (
          <OverviewView
            activeProject={activeProject}
            targets={targets}
            exclusions={exclusions}
            recentAudits={auditEvents}
            findingCount={findingCount}
            assetCount={assetCount}
            onCreateProjectClick={() => setIsCreateProjectOpen(true)}
            onNavigateToScopes={() => setActiveTab('scopes')}
            onNavigateToFindings={() => setActiveTab('findings')}
            onNavigateToAssets={() => setActiveTab('assets')}
            onNavigateToGraph={() => setActiveTab('graph')}
            onNavigateToAudit={() => setActiveTab('audit')}
          />
        )}

        {activeTab === 'scopes' && activeProject && (
          <ScopeManagementView
            project={activeProject}
            targets={targets}
            exclusions={exclusions}
            currentUser={currentUser}
            onRefresh={loadProjectData}
          />
        )}

        {activeTab === 'assessments' && activeProject && (
          <AssessmentJobsView
            project={activeProject}
            authorizedTargets={authorizedTargets}
            jobs={assessmentJobs}
            onRefresh={loadProjectData}
            loading={loading}
          />
        )}

        {activeTab === 'findings' && activeProject && (
          <FindingLifecycleView currentProject={activeProject} />
        )}

        {activeTab === 'assets' && activeProject && (
          <AssetInventoryView
            currentProject={activeProject}
            onNavigateToGraph={(nodeId) => {
              if (nodeId) setGraphRootNodeId(nodeId);
              setActiveTab('graph');
            }}
          />
        )}

        {activeTab === 'graph' && activeProject && (
          <KnowledgeGraphView
            currentProject={activeProject}
            initialNodeId={graphRootNodeId}
          />
        )}

        {activeTab === 'risk' && activeProject && (
          <ContextualRiskView
            currentProject={activeProject}
            currentUserRole={currentUser?.system_role}
          />
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

        {(activeTab === 'scopes' || activeTab === 'assessments' || activeTab === 'findings' || activeTab === 'assets' || activeTab === 'graph' || activeTab === 'risk') && !activeProject && (
          <div className="py-12 text-center text-slate-400">
            Please authenticate and select an assessment project to proceed.
          </div>
        )}
      </main>

      <footer className="border-t border-cyber-800 bg-cyber-900/80 py-4 px-6 text-center text-slate-500 text-xs font-mono">
        VAPT Platform Phase 5: Contextual Risk Intelligence, Attack Paths & Remediation · Windows-Native Control Plane
      </footer>

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
