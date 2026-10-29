import type {
  User,
  Project,
  ProjectMember,
  ProjectRole,
  ScopeTarget,
  ScopeExclusion,
  ScopeValidationResult,
  AuditEvent,
  ReadinessResponse,
  AssessmentJob,
  AssessmentFinding,
  AdapterCapability,
  VulnerabilityFinding,
  VulnerabilityFindingDetail,
  FindingStatsResponse,
  FindingTransitionRequest,
  AcceptRiskRequest,
  FalsePositiveRequest,
  ProposeRemediationRequest,
  FindingLifecycleStatus,
  FindingSeverity,
  Asset,
  AssetDetail,
  AssetObservation,
  AssetCreateFixtureRequest,
  ResolveAmbiguityRequest,
  GraphStats,
  GraphNeighborhoodResponse,
  GraphNode,
  GraphRelationship,
  GraphRelationshipCreate,
  RiskPriority,
  RiskAssessment,
  RiskSummary,
  AttackPathAnalysisResponse,
  RemediationRecommendation,
  RecommendationStatus,
  ClosedLoopOverview,
  SecurityDecision,
  PostureChange,
  DecisionStatus,
  ProjectIntelligenceSummary,
  CoverageAudit,
  AdaptivePlan,
  SystemHealthData,
  DiagnosticRun,
  RecoveryActionHistoryRecord,
  FailurePattern,
  QualityOverviewResponse,
  FixtureBenchmarksResponse,
  FindingValidationTransitionRequest,
  FindingProvenanceResponse,
  AssetIdentifierAlias,
  AssetIdentityMergeRecord,
  ExposureDriftRecord,
  ReassessmentProposal,
  ProjectDriftOverview,
  KnowledgeDependencyRecord,
  ExplainableAttackPath,
  KnowledgeReconciliationAudit,
  FindingEpistemicExplanation,
  ProjectGovernancePolicy,
  ProjectGovernancePolicyUpdate,
  ApprovalRequestRecord,
  ApprovalDecisionRequest,
  PermissionMatrixResponse,
  DisasterRecoveryBundle,
  BackupVerificationResult,
  RestoreDrillResult,
  LiveRestoreResult,
  RotationResult,
  RecoveryStatusSummary,
  DependencyInventoryResponse,
  DependencyAuditResponse,
  SecretScanResponse,
  ReleaseVerificationResult,
  WorkloadQueueStatus,
  PerformanceBudgetsResponse,
  BenchmarkSuiteResponse,
  StaleJobReconciliationResult,
  SecurityControlsCatalogResponse,
  MutationScenario,
  MutationDrillResult,
  PreflightReport,
  RedactedConfigResponse,
  UpgradePrecheckResponse,
  RetentionPolicyModel,
  LegalHoldModel,
  LegalHoldCreate,
  DeletionTombstoneModel,
  RetentionPreviewReport,
  RetentionExecutionRequest,
  RetentionExecutionResult,
  EvidenceRedactionRequest,
  EvidenceRedactionResult,
  UnifiedOpsDashboardResponse,
  PriorityQueueResponse,
  AlertResponse,
  AlertListResponse,
  OutboxStatusResponse,
  MaintenanceWindowResponse,
  AssessmentReportManifest,
  ReportCoverageSummary,
  BundleVerificationResult,
  ComplianceControl,
  BaselineProfile,
  ComplianceEvaluationRun,
  ComplianceDriftEvent,
  ComplianceException,
  ComplianceComparison,
  AssessmentQueueItem,
  QueueItemCreate,
  QueueItemPreviewRequest,
  QueueItemPreviewResponse,
  TriggerAssessmentRequest,
  DispatchResultResponse,
  LeaseRecoveryResponse,
  SchedulerCapacity,
  SchedulerDecision,
  SchedulerPolicy,
  SchedulerPolicyUpdate,
  ThreatFeed,
  ThreatFeedSyncRequest,
  ThreatFeedSyncResponse,
  ThreatIntelligenceRecord,
  ThreatCorrelation,
  ThreatCorrelationRunRequest,
  ThreatCorrelationRunResponse,
  ThreatIntelSummary,
  DetailedPermissionMatrixResponse,
  AccessDenialAudit,
  LogoutResponse,
  RevokeAllSessionsResponse,
  ResolutionResult,
  DryRunImpact,
  DeduplicationProposal,
  DataQualityIssue,
  IncidentCaseSummary,
  IncidentCaseDetail,
  CorrelationExplanation,
  TimelineEvent,
} from '../types';

const API_BASE = '/api/v1';

class ApiService {
  private token: string | null = null;

  constructor() {
    if (typeof localStorage !== 'undefined') {
      this.token = localStorage.getItem('vapt_auth_token');
    }
  }

  setToken(token: string | null) {
    this.token = token;
    if (typeof localStorage !== 'undefined') {
      if (token) {
        localStorage.setItem('vapt_auth_token', token);
      } else {
        localStorage.removeItem('vapt_auth_token');
      }
    }
  }

  getToken(): string | null {
    return this.token;
  }

  private async request<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      ...(options.headers as Record<string, string> || {}),
    };

    if (this.token) {
      headers['Authorization'] = `Bearer ${this.token}`;
    }

    const response = await fetch(`${API_BASE}${endpoint}`, {
      ...options,
      headers,
    });

    if (!response.ok) {
      let errorMsg = `HTTP Error ${response.status}: ${response.statusText}`;
      try {
        const errorData = await response.json();
        if (errorData.detail) {
          errorMsg = typeof errorData.detail === 'string'
            ? errorData.detail
            : JSON.stringify(errorData.detail);
        }
      } catch {
        // Fallback to generic message
      }
      throw new Error(errorMsg);
    }

    if (response.status === 204) {
      return null as T;
    }

    return response.json();
  }

  // System Health
  async getHealth(): Promise<{ status: string; version: string; environment: string; timestamp: string }> {
    return this.request('/health');
  }

  async getReadiness(): Promise<ReadinessResponse> {
    return this.request('/ready');
  }

  // Authentication
  async register(data: { email: string; password: string; full_name: string; system_role?: string }): Promise<User> {
    return this.request('/auth/register', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  async login(data: { email: string; password: string }): Promise<{ access_token: string; user: User }> {
    const res = await this.request<{ access_token: string; token_type: string; expires_in: number; user: User }>('/auth/login', {
      method: 'POST',
      body: JSON.stringify(data),
    });
    this.setToken(res.access_token);
    return res;
  }

  async getMe(): Promise<User> {
    return this.request('/auth/me');
  }

  async listUsers(): Promise<User[]> {
    return this.request('/auth/users');
  }

  // Projects
  async listProjects(): Promise<Project[]> {
    return this.request('/projects/');
  }

  async createProject(data: { name: string; description?: string }): Promise<Project> {
    return this.request('/projects/', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  async updateProject(projectId: string, data: { name?: string; description?: string; is_active?: boolean }): Promise<Project> {
    return this.request(`/projects/${projectId}`, {
      method: 'PUT',
      body: JSON.stringify(data),
    });
  }

  async listProjectMembers(projectId: string): Promise<ProjectMember[]> {
    return this.request(`/projects/${projectId}/members`);
  }

  async addProjectMember(projectId: string, data: { user_id: string; role: ProjectRole }): Promise<ProjectMember> {
    return this.request(`/projects/${projectId}/members`, {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  async updateProjectMemberRole(projectId: string, userId: string, role: ProjectRole): Promise<ProjectMember> {
    return this.request(`/projects/${projectId}/members/${userId}`, {
      method: 'PUT',
      body: JSON.stringify({ user_id: userId, role }),
    });
  }

  async removeProjectMember(projectId: string, userId: string): Promise<void> {
    return this.request(`/projects/${projectId}/members/${userId}`, {
      method: 'DELETE',
    });
  }


  // Scopes & Authorizations
  async listScopeTargets(projectId: string): Promise<ScopeTarget[]> {
    return this.request(`/projects/${projectId}/targets`);
  }

  async registerScopeTarget(projectId: string, data: { target_value: string; description?: string }): Promise<ScopeTarget> {
    return this.request(`/projects/${projectId}/targets`, {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  async authorizeScopeTarget(
    projectId: string,
    targetId: string,
    data: { evidence: string; expires_at?: string | null }
  ): Promise<ScopeTarget> {
    return this.request(`/projects/${projectId}/targets/${targetId}/authorize`, {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  async revokeScopeTarget(
    projectId: string,
    targetId: string,
    data: { reason: string }
  ): Promise<ScopeTarget> {
    return this.request(`/projects/${projectId}/targets/${targetId}/revoke`, {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  // Scope Exclusions
  async listScopeExclusions(projectId: string): Promise<ScopeExclusion[]> {
    return this.request(`/projects/${projectId}/exclusions`);
  }

  async addScopeExclusion(
    projectId: string,
    data: { target_value: string; reason: string }
  ): Promise<ScopeExclusion> {
    return this.request(`/projects/${projectId}/exclusions`, {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  async removeScopeExclusion(projectId: string, exclusionId: string): Promise<void> {
    return this.request(`/projects/${projectId}/exclusions/${exclusionId}`, {
      method: 'DELETE',
    });
  }

  // Non-invasive Scope Validation
  async validateTarget(projectId: string, target: string): Promise<ScopeValidationResult> {
    return this.request(`/projects/${projectId}/validate`, {
      method: 'POST',
      body: JSON.stringify({ target }),
    });
  }

  // Assessment Jobs & Findings (Phase 2 & Phase 6A)
  async listAdapterCapabilities(projectId: string): Promise<AdapterCapability[]> {
    return this.request(`/projects/${projectId}/assessments/adapters`);
  }

  async listAssessments(
    projectId: string,
    params?: { status_filter?: string; offset?: number; limit?: number }
  ): Promise<AssessmentJob[]> {
    const qp = new URLSearchParams();
    if (params?.status_filter) qp.append('status_filter', params.status_filter);
    if (params?.offset !== undefined) qp.append('offset', String(params.offset));
    if (params?.limit !== undefined) qp.append('limit', String(params.limit));
    const qs = qp.toString();
    return this.request(`/projects/${projectId}/assessments/${qs ? `?${qs}` : ''}`);
  }

  async createAssessment(
    projectId: string,
    data: {
      target_input: string;
      adapter_name?: string;
      fixture_profile?: string;
      timeout_seconds?: number;
      idempotency_key?: string;
      policy_version?: string;
    }
  ): Promise<AssessmentJob> {
    return this.request(`/projects/${projectId}/assessments/`, {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  async getAssessment(projectId: string, jobId: string): Promise<AssessmentJob> {
    return this.request(`/projects/${projectId}/assessments/${jobId}`);
  }

  async cancelAssessment(projectId: string, jobId: string): Promise<AssessmentJob> {
    return this.request(`/projects/${projectId}/assessments/${jobId}/cancel`, {
      method: 'POST',
    });
  }

  async listAssessmentFindings(projectId: string, jobId: string): Promise<AssessmentFinding[]> {
    return this.request(`/projects/${projectId}/assessments/${jobId}/findings`);
  }

  async getAssessmentFinding(projectId: string, jobId: string, findingId: string): Promise<AssessmentFinding> {
    return this.request(`/projects/${projectId}/assessments/${jobId}/findings/${findingId}`);
  }

  // Finding Lifecycle & Deduplication (Phase 3)
  async listFindings(
    projectId: string,
    params?: {
      status?: FindingLifecycleStatus;
      severity?: FindingSeverity;
      target?: string;
      has_contradictions?: boolean;
      search?: string;
      limit?: number;
      offset?: number;
    }
  ): Promise<VulnerabilityFinding[]> {
    const query = new URLSearchParams();
    if (params?.status) query.append('status', params.status);
    if (params?.severity) query.append('severity', params.severity);
    if (params?.target) query.append('target', params.target);
    if (params?.has_contradictions !== undefined)
      query.append('has_contradictions', params.has_contradictions.toString());
    if (params?.search) query.append('search', params.search);
    if (params?.limit) query.append('limit', params.limit.toString());
    if (params?.offset) query.append('offset', params.offset.toString());

    const qs = query.toString();
    return this.request(`/projects/${projectId}/findings${qs ? `?${qs}` : ''}`);
  }

  async getFindingStats(projectId: string): Promise<FindingStatsResponse> {
    return this.request(`/projects/${projectId}/findings/stats`);
  }

  async getFindingDetail(projectId: string, findingId: string): Promise<VulnerabilityFindingDetail> {
    return this.request(`/projects/${projectId}/findings/${findingId}`);
  }

  async transitionFinding(
    projectId: string,
    findingId: string,
    data: FindingTransitionRequest
  ): Promise<VulnerabilityFindingDetail> {
    return this.request(`/projects/${projectId}/findings/${findingId}/transition`, {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  async acceptFindingRisk(
    projectId: string,
    findingId: string,
    data: AcceptRiskRequest
  ): Promise<VulnerabilityFindingDetail> {
    return this.request(`/projects/${projectId}/findings/${findingId}/accept-risk`, {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  async markFindingFalsePositive(
    projectId: string,
    findingId: string,
    data: FalsePositiveRequest
  ): Promise<VulnerabilityFindingDetail> {
    return this.request(`/projects/${projectId}/findings/${findingId}/false-positive`, {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  async proposeFindingRemediation(
    projectId: string,
    findingId: string,
    data: ProposeRemediationRequest
  ): Promise<VulnerabilityFindingDetail> {
    return this.request(`/projects/${projectId}/findings/${findingId}/propose-remediation`, {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  async sweepExpiredRisks(projectId: string): Promise<{ status: string; expired_count: number }> {
    return this.request(`/projects/${projectId}/findings/sweep-expired-risks`, {
      method: 'POST',
    });
  }

  // Audit Ledger
  async getAuditLedger(params: {
    projectId?: string;
    action?: string;
    outcome?: string;
    limit?: number;
    offset?: number;
  }): Promise<{ total: number; items: AuditEvent[] }> {
    const query = new URLSearchParams();
    if (params.projectId) query.append('project_id', params.projectId);
    if (params.action) query.append('action', params.action);
    if (params.outcome) query.append('outcome', params.outcome);
    if (params.limit) query.append('limit', params.limit.toString());
    if (params.offset) query.append('offset', params.offset.toString());

    const qs = query.toString();
    return this.request(`/audit/${qs ? `?${qs}` : ''}`);
  }

  // Phase 4: Asset Inventory
  async listAssets(
    projectId: string,
    params: {
      assetType?: string;
      criticality?: string;
      status?: string;
      isAmbiguous?: boolean;
      search?: string;
      limit?: number;
      offset?: number;
    } = {}
  ): Promise<Asset[]> {
    const query = new URLSearchParams();
    if (params.assetType) query.append('asset_type', params.assetType);
    if (params.criticality) query.append('criticality', params.criticality);
    if (params.status) query.append('status_filter', params.status);
    if (params.isAmbiguous !== undefined) query.append('is_ambiguous', params.isAmbiguous.toString());
    if (params.search) query.append('search', params.search);
    if (params.limit) query.append('limit', params.limit.toString());
    if (params.offset) query.append('offset', params.offset.toString());

    const qs = query.toString();
    return this.request(`/projects/${projectId}/assets${qs ? `?${qs}` : ''}`);
  }

  async getAsset(projectId: string, assetId: string): Promise<AssetDetail> {
    return this.request(`/projects/${projectId}/assets/${assetId}`);
  }

  async listAssetObservations(
    projectId: string,
    assetId: string,
    params: { limit?: number; offset?: number } = {}
  ): Promise<AssetObservation[]> {
    const query = new URLSearchParams();
    if (params.limit) query.append('limit', params.limit.toString());
    if (params.offset) query.append('offset', params.offset.toString());
    const qs = query.toString();
    return this.request(`/projects/${projectId}/assets/${assetId}/observations${qs ? `?${qs}` : ''}`);
  }

  async listAssetFindings(
    projectId: string,
    assetId: string,
    params: { limit?: number; offset?: number } = {}
  ): Promise<VulnerabilityFinding[]> {
    const query = new URLSearchParams();
    if (params.limit) query.append('limit', params.limit.toString());
    if (params.offset) query.append('offset', params.offset.toString());
    const qs = query.toString();
    return this.request(`/projects/${projectId}/assets/${assetId}/findings${qs ? `?${qs}` : ''}`);
  }

  async createFixtureAsset(projectId: string, data: AssetCreateFixtureRequest): Promise<Asset> {
    return this.request(`/projects/${projectId}/assets/fixture`, {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  async resolveAssetAmbiguity(projectId: string, assetId: string, data: ResolveAmbiguityRequest): Promise<AssetDetail> {
    return this.request(`/projects/${projectId}/assets/${assetId}/resolve-ambiguity`, {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  // Phase 4: Universal Security Knowledge Graph
  async getGraphStats(projectId: string): Promise<GraphStats> {
    return this.request(`/projects/${projectId}/graph/stats`);
  }

  async getGraphNeighborhood(
    projectId: string,
    nodeId: string,
    params: { depth?: number; maxNodes?: number; maxEdges?: number } = {}
  ): Promise<GraphNeighborhoodResponse> {
    const query = new URLSearchParams();
    if (params.depth) query.append('depth', params.depth.toString());
    if (params.maxNodes) query.append('max_nodes', params.maxNodes.toString());
    if (params.maxEdges) query.append('max_edges', params.maxEdges.toString());
    const qs = query.toString();
    return this.request(`/projects/${projectId}/graph/nodes/${nodeId}/neighborhood${qs ? `?${qs}` : ''}`);
  }

  async getGraphNode(projectId: string, nodeId: string): Promise<GraphNode> {
    return this.request(`/projects/${projectId}/graph/nodes/${nodeId}`);
  }

  async createGraphRelationship(projectId: string, data: GraphRelationshipCreate): Promise<GraphRelationship> {
    return this.request(`/projects/${projectId}/graph/relationships`, {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  // Phase 5: Contextual Risk Intelligence, Attack Paths, and Remediation
  async getRiskSummary(projectId: string): Promise<RiskSummary> {
    return this.request(`/projects/${projectId}/risk/summary`);
  }

  async listRiskAssessments(
    projectId: string,
    params?: {
      priority?: RiskPriority;
      assetId?: string;
      includeSuperseded?: boolean;
      limit?: number;
      offset?: number;
    }
  ): Promise<RiskAssessment[]> {
    const query = new URLSearchParams();
    if (params?.priority) query.append('priority', params.priority);
    if (params?.assetId) query.append('asset_id', params.assetId);
    if (params?.includeSuperseded !== undefined)
      query.append('include_superseded', params.includeSuperseded.toString());
    if (params?.limit) query.append('limit', params.limit.toString());
    if (params?.offset) query.append('offset', params.offset.toString());
    const qs = query.toString();
    return this.request(`/projects/${projectId}/risk/assessments${qs ? `?${qs}` : ''}`);
  }

  async getFindingRisk(projectId: string, findingId: string): Promise<RiskAssessment> {
    return this.request(`/projects/${projectId}/risk/findings/${findingId}`);
  }

  async recalculateFindingRisk(projectId: string, findingId: string): Promise<RiskAssessment> {
    return this.request(`/projects/${projectId}/risk/findings/${findingId}/assess`, {
      method: 'POST',
    });
  }

  async recalculateAllProjectRisks(projectId: string): Promise<{ message: string; recalculated_count: number }> {
    return this.request(`/projects/${projectId}/risk/recalculate`, {
      method: 'POST',
    });
  }

  async analyzeAttackPaths(
    projectId: string,
    data: {
      start_node_id?: string;
      target_node_id?: string;
      finding_id?: string;
      max_depth?: number;
      max_paths?: number;
    }
  ): Promise<AttackPathAnalysisResponse> {
    return this.request(`/projects/${projectId}/graph/paths/analyze`, {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  async listRemediations(
    projectId: string,
    params?: { status?: RecommendationStatus; limit?: number; offset?: number }
  ): Promise<RemediationRecommendation[]> {
    const query = new URLSearchParams();
    if (params?.status) query.append('status_filter', params.status);
    if (params?.limit) query.append('limit', params.limit.toString());
    if (params?.offset) query.append('offset', params.offset.toString());
    const qs = query.toString();
    return this.request(`/projects/${projectId}/remediations${qs ? `?${qs}` : ''}`);
  }

  async getFindingRemediation(projectId: string, findingId: string): Promise<RemediationRecommendation> {
    return this.request(`/projects/${projectId}/remediations/findings/${findingId}`);
  }

  async reviewRemediation(
    projectId: string,
    recId: string,
    data: { status: RecommendationStatus; review_notes: string }
  ): Promise<RemediationRecommendation> {
    return this.request(`/projects/${projectId}/remediations/${recId}/review`, {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  // Phase 13: Remediation Planning & Change Authorization
  async authorizeChange(
    projectId: string,
    recommendationId: string,
    externalChangeTicketRef: string
  ): Promise<RemediationRecommendation> {
    return this.request(`/projects/${projectId}/risk/remediations/${recommendationId}/authorize-change`, {
      method: 'POST',
      body: JSON.stringify({ external_change_ticket_ref: externalChangeTicketRef }),
    });
  }

  // Phase 14: Independent Remediation Verification
  async verifyFinding(
    projectId: string,
    findingId: string,
    data: {
      recommendation_id?: string;
      outcome: string;
      verification_method: string;
      verification_criteria: string;
      verification_evidence_summary: string;
      notes?: string;
    }
  ): Promise<any> {
    return this.request(`/projects/${projectId}/findings/${findingId}/verify`, {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  async retestFinding(projectId: string, findingId: string, adapterKey?: string): Promise<any> {
    return this.request(`/projects/${projectId}/findings/${findingId}/verify/retest`, {
      method: 'POST',
      body: JSON.stringify({ adapter_key: adapterKey || 'scanner.passive_header' }),
    });
  }

  // Phase 15 & Prompt 32: Reporting & Verifiable Export Bundles
  async generateReport(
    projectId: string,
    data: { report_type: string; format?: string; report_format?: string; title: string; assessment_id?: string }
  ): Promise<any> {
    const payload = {
      report_type: data.report_type,
      report_format: data.report_format || data.format || 'JSON',
      title: data.title,
      assessment_id: data.assessment_id,
    };
    return this.request(`/projects/${projectId}/reports/generate`, {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  }

  async listReports(projectId: string): Promise<any[]> {
    return this.request(`/projects/${projectId}/reports`);
  }

  async getCanonicalReport(
    projectId: string,
    assessmentId: string,
    title?: string
  ): Promise<AssessmentReportManifest> {
    const qs = title ? `?title=${encodeURIComponent(title)}` : '';
    return this.request<AssessmentReportManifest>(
      `/projects/${projectId}/assessments/${assessmentId}/report/canonical${qs}`
    );
  }

  async getReportCoverage(
    projectId: string,
    assessmentId: string
  ): Promise<ReportCoverageSummary> {
    return this.request<ReportCoverageSummary>(
      `/projects/${projectId}/assessments/${assessmentId}/report/coverage`
    );
  }

  async generateAssessmentReport(
    projectId: string,
    assessmentId: string,
    data: { report_format: string; title?: string }
  ): Promise<any> {
    return this.request(`/projects/${projectId}/assessments/${assessmentId}/report/generate`, {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  async verifyBundle(
    projectId: string,
    bundleBase64: string
  ): Promise<BundleVerificationResult> {
    return this.request<BundleVerificationResult>(`/projects/${projectId}/reports/bundle/verify`, {
      method: 'POST',
      body: JSON.stringify({ bundle_base64: bundleBase64 }),
    });
  }

  // Phase 16: Historical Security Digital Twin
  async captureSnapshot(projectId: string, name: string, description?: string): Promise<any> {
    return this.request(`/projects/${projectId}/digital-twin/snapshots`, {
      method: 'POST',
      body: JSON.stringify({ snapshot_label: name, name, description }),
    });
  }

  async listSnapshots(projectId: string): Promise<any[]> {
    return this.request(`/projects/${projectId}/digital-twin/snapshots`);
  }

  async compareSnapshots(projectId: string, snapshotAId: string, snapshotBId: string): Promise<any> {
    return this.request(`/projects/${projectId}/digital-twin/compare`, {
      method: 'POST',
      body: JSON.stringify({ snapshot_a_id: snapshotAId, snapshot_b_id: snapshotBId }),
    });
  }

  // Phase 17: Regression Detection & Change Intelligence
  async getRegressionBaseline(projectId: string): Promise<any> {
    return this.request(`/projects/${projectId}/regressions/baseline`);
  }

  async evaluateRegressions(projectId: string): Promise<any> {
    return this.request(`/projects/${projectId}/regressions/evaluate`, { method: 'POST' });
  }

  async listRegressionAlerts(projectId: string, status?: string): Promise<any[]> {
    const qs = status ? `?status=${status}` : '';
    return this.request(`/projects/${projectId}/regressions/alerts${qs}`);
  }

  async acknowledgeRegressionAlert(projectId: string, alertId: string, notes?: string): Promise<any> {
    return this.request(`/projects/${projectId}/regressions/alerts/${alertId}/acknowledge`, {
      method: 'POST',
      body: JSON.stringify({ notes }),
    });
  }

  async resolveRegressionAlert(projectId: string, alertId: string, notes: string): Promise<any> {
    return this.request(`/projects/${projectId}/regressions/alerts/${alertId}/resolve`, {
      method: 'POST',
      body: JSON.stringify({ resolution_notes: notes }),
    });
  }

  // Phase 18: Controlled AI Security Analyst
  async explainFindingAI(projectId: string, findingId: string): Promise<any> {
    return this.request(`/projects/${projectId}/ai-analyst/explain-finding/${findingId}`, {
      method: 'POST',
      body: JSON.stringify({ include_mitre_mapping: true, include_defensive_controls: true }),
    });
  }

  async draftRemediationAI(projectId: string, findingId: string, operationalConstraints?: string): Promise<any> {
    return this.request(`/projects/${projectId}/ai-analyst/draft-remediation/${findingId}`, {
      method: 'POST',
      body: JSON.stringify({ operational_constraints: operationalConstraints }),
    });
  }

  async listAIDrafts(projectId: string): Promise<any[]> {
    return this.request(`/projects/${projectId}/ai-analyst/drafts`);
  }

  async reviewAIDraft(projectId: string, draftId: string, approved: boolean, notes: string): Promise<any> {
    return this.request(`/projects/${projectId}/ai-analyst/drafts/${draftId}/review`, {
      method: 'POST',
      body: JSON.stringify({ approved, review_notes: notes }),
    });
  }

  // Phase 19: Controlled Learning & Model Governance
  async curateDataset(projectId: string, name: string, version: string): Promise<any> {
    return this.request(`/projects/${projectId}/learning/datasets/curate`, {
      method: 'POST',
      body: JSON.stringify({ name, version }),
    });
  }

  async listDatasets(projectId: string): Promise<any[]> {
    return this.request(`/projects/${projectId}/learning/datasets`);
  }

  async registerModel(projectId: string, data: { model_name: string; version: string; model_type?: string; dataset_id: string }): Promise<any> {
    return this.request(`/projects/${projectId}/learning/models/register`, {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  async evaluateModel(projectId: string, modelId: string): Promise<any> {
    return this.request(`/projects/${projectId}/learning/models/${modelId}/evaluate`, { method: 'POST' });
  }

  async approveModel(projectId: string, modelId: string, approved: boolean, notes: string): Promise<any> {
    return this.request(`/projects/${projectId}/learning/models/${modelId}/approve`, {
      method: 'POST',
      body: JSON.stringify({ approved, approval_notes: notes }),
    });
  }

  async activateModel(projectId: string, modelId: string): Promise<any> {
    return this.request(`/projects/${projectId}/learning/models/${modelId}/activate`, { method: 'POST' });
  }

  async rollbackModel(projectId: string, modelId: string, reason: string): Promise<any> {
    return this.request(`/projects/${projectId}/learning/models/${modelId}/rollback`, {
      method: 'POST',
      body: JSON.stringify({ reason }),
    });
  }

  async listModels(projectId: string): Promise<any[]> {
    return this.request(`/projects/${projectId}/learning/models`);
  }

  // Prompt 38: Controlled Experiments, Model Evaluation and Defensible Adaptive Learning
  async getLearningInventory(): Promise<any[]> {
    return this.request('/system/learning/inventory');
  }

  async curateTimeAwareDataset(
    projectId: string,
    name: string,
    version: string,
    splitStrategy: string = 'TEMPORAL_AWARE'
  ): Promise<any> {
    return this.request(`/projects/${projectId}/learning/datasets/time-aware`, {
      method: 'POST',
      body: JSON.stringify({ name, version, split_strategy: splitStrategy }),
    });
  }

  async runControlledExperiment(
    projectId: string,
    data: {
      model_id: string;
      experiment_name: string;
      split_strategy?: string;
      force_pass_baseline?: boolean;
    }
  ): Promise<any> {
    return this.request(`/projects/${projectId}/learning/experiments/run`, {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  async listControlledExperiments(
    projectId: string,
    modelId?: string,
    decision?: string
  ): Promise<any[]> {
    const params = new URLSearchParams();
    if (modelId) params.append('model_id', modelId);
    if (decision) params.append('decision', decision);
    const qs = params.toString() ? `?${params.toString()}` : '';
    return this.request(`/projects/${projectId}/learning/experiments${qs}`);
  }

  async getControlledExperiment(projectId: string, experimentId: string): Promise<any> {
    return this.request(`/projects/${projectId}/learning/experiments/${experimentId}`);
  }

  async detectDistributionShift(projectId: string, modelId: string): Promise<any> {
    return this.request(`/projects/${projectId}/learning/models/${modelId}/distribution-shift`);
  }

  // Phase 20: Morph-State Adaptive Defense & Recovery
  async getAdaptivePosture(projectId: string): Promise<any> {
    return this.request(`/projects/${projectId}/adaptive-defense/posture`);
  }

  async evaluateAdaptivePosture(projectId: string): Promise<any> {
    return this.request(`/projects/${projectId}/adaptive-defense/evaluate`, { method: 'POST' });
  }

  async engageKillSwitch(projectId: string, reason: string): Promise<any> {
    return this.request(`/projects/${projectId}/adaptive-defense/kill-switch/engage`, {
      method: 'POST',
      body: JSON.stringify({ reason }),
    });
  }

  async disengageKillSwitch(projectId: string, justification: string): Promise<any> {
    return this.request(`/projects/${projectId}/adaptive-defense/kill-switch/disengage`, {
      method: 'POST',
      body: JSON.stringify({ justification }),
    });
  }

  async getPostureHistory(projectId: string): Promise<any[]> {
    return this.request(`/projects/${projectId}/adaptive-defense/history`);
  }

  // Phase 19.1: Persistent Prediction Ledger
  async listPredictions(projectId: string, filters?: { target_entity_type?: string; evaluation_status?: string }): Promise<any[]> {
    let url = `/projects/${projectId}/learning/predictions?limit=50`;
    if (filters?.target_entity_type) url += `&target_entity_type=${encodeURIComponent(filters.target_entity_type)}`;
    if (filters?.evaluation_status) url += `&evaluation_status=${encodeURIComponent(filters.evaluation_status)}`;
    return this.request(url);
  }

  async recordPrediction(projectId: string, data: any): Promise<any> {
    return this.request(`/projects/${projectId}/learning/predictions`, {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  async evaluatePrediction(projectId: string, predictionId: string, data: { actual_outcome: string; outcome_evidence?: any; notes?: string }): Promise<any> {
    return this.request(`/projects/${projectId}/learning/predictions/${predictionId}/evaluate`, {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  async invalidatePrediction(projectId: string, predictionId: string, reason: string): Promise<any> {
    return this.request(`/projects/${projectId}/learning/predictions/${predictionId}/invalidate`, {
      method: 'POST',
      body: JSON.stringify({ reason }),
    });
  }

  async getPredictionDrift(projectId: string): Promise<any> {
    return this.request(`/projects/${projectId}/learning/predictions/drift`);
  }

  // Phase 31: Enterprise Integrations
  async getIntegrationsStatus(projectId: string): Promise<any[]> {
    return this.request(`/projects/${projectId}/integrations/status`);
  }

  async lookupCveKev(projectId: string, cveId: string): Promise<any> {
    return this.request(`/projects/${projectId}/integrations/kev/lookup?cve_id=${encodeURIComponent(cveId)}`);
  }

  async searchKevCatalog(projectId: string, query?: string): Promise<any[]> {
    const q = query ? `?query=${encodeURIComponent(query)}` : '';
    return this.request(`/projects/${projectId}/integrations/kev/catalog${q}`);
  }

  async testWebhook(projectId: string, data: { event_type: string; custom_payload?: any }): Promise<any> {
    return this.request(`/projects/${projectId}/integrations/webhook/test`, {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  async getWebhookHistory(projectId: string): Promise<any[]> {
    return this.request(`/projects/${projectId}/integrations/webhook/history`);
  }

  async exportSiemAudit(projectId: string, formatType: string = 'CEF'): Promise<any> {
    return this.request(`/projects/${projectId}/integrations/siem/export?format_type=${encodeURIComponent(formatType)}`);
  }

  // Continuous Monitoring & Recurring Assessments
  async listMonitoringSchedules(projectId: string): Promise<any[]> {
    return this.request(`/projects/${projectId}/monitoring/schedules`);
  }

  async createMonitoringSchedule(projectId: string, data: any): Promise<any> {
    return this.request(`/projects/${projectId}/monitoring/schedules`, {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  async pauseMonitoringSchedule(projectId: string, scheduleId: string): Promise<any> {
    return this.request(`/projects/${projectId}/monitoring/schedules/${scheduleId}/pause`, { method: 'POST' });
  }

  async resumeMonitoringSchedule(projectId: string, scheduleId: string): Promise<any> {
    return this.request(`/projects/${projectId}/monitoring/schedules/${scheduleId}/resume`, { method: 'POST' });
  }

  async triggerMonitoringScheduleRun(projectId: string, scheduleId: string): Promise<any> {
    return this.request(`/projects/${projectId}/monitoring/schedules/${scheduleId}/run-now`, { method: 'POST' });
  }

  async getMonitoringOverview(projectId: string): Promise<any> {
    return this.request(`/projects/${projectId}/monitoring/overview`);
  }

  async listMonitoringRuns(projectId: string): Promise<any[]> {
    return this.request(`/projects/${projectId}/monitoring/runs`);
  }
  // Autonomous Security Intelligence & Closed-Loop Decisions (Prompt 6)
  async getClosedLoopOverview(projectId: string): Promise<ClosedLoopOverview> {
    return this.request<ClosedLoopOverview>(`/projects/${projectId}/closed-loop/overview`);
  }

  async listSecurityDecisions(
    projectId: string,
    statusFilter?: DecisionStatus
  ): Promise<SecurityDecision[]> {
    const query = statusFilter ? `?status_filter=${statusFilter}` : '';
    return this.request<SecurityDecision[]>(`/projects/${projectId}/decisions${query}`);
  }

  async evaluateDecisions(
    projectId: string,
    options?: { include_reassessment?: boolean; include_validation?: boolean; include_verification?: boolean }
  ): Promise<SecurityDecision[]> {
    return this.request<SecurityDecision[]>(`/projects/${projectId}/decisions/evaluate`, {
      method: 'POST',
      body: JSON.stringify(options || {
        include_reassessment: true,
        include_validation: true,
        include_verification: true,
      }),
    });
  }

  async approveDecision(projectId: string, decisionId: string): Promise<SecurityDecision> {
    return this.request<SecurityDecision>(`/projects/${projectId}/decisions/${decisionId}/approve`, {
      method: 'POST',
    });
  }

  async executeDecision(
    projectId: string,
    decisionId: string,
    payload?: { notes?: string; force?: boolean }
  ): Promise<SecurityDecision> {
    return this.request<SecurityDecision>(`/projects/${projectId}/decisions/${decisionId}/execute`, {
      method: 'POST',
      body: JSON.stringify(payload || {
        notes: 'Executed via unified security operations dashboard',
        force: false,
      }),
    });
  }

  async listPostureChanges(projectId: string, limit: number = 50): Promise<PostureChange[]> {
    return this.request<PostureChange[]>(`/projects/${projectId}/changes?limit=${limit}`);
  }

  // Security Intelligence & Adaptive Assessment Planning (Prompt 10)
  async getIntelligenceSummary(projectId: string): Promise<ProjectIntelligenceSummary> {
    return this.request<ProjectIntelligenceSummary>(`/projects/${projectId}/intelligence/overview`);
  }

  async getCoverageAudit(projectId: string, staleDays: number = 14): Promise<CoverageAudit> {
    return this.request<CoverageAudit>(`/projects/${projectId}/intelligence/coverage?stale_days=${staleDays}`);
  }

  async getLatestAdaptivePlan(projectId: string): Promise<AdaptivePlan | null> {
    return this.request<AdaptivePlan | null>(`/projects/${projectId}/intelligence/plans/latest`);
  }

  async generateAdaptivePlan(projectId: string, scanBudget: number = 10): Promise<AdaptivePlan> {
    return this.request<AdaptivePlan>(`/projects/${projectId}/intelligence/plans/generate`, {
      method: 'POST',
      body: JSON.stringify({ scan_budget: scanBudget }),
    });
  }

  async executePlannedCheck(
    projectId: string,
    planId: string,
    checkId: string
  ): Promise<{ status: string; job_id: string; target: string }> {
    return this.request<{ status: string; job_id: string; target: string }>(
      `/projects/${projectId}/intelligence/plans/${planId}/execute`,
      {
        method: 'POST',
        body: JSON.stringify({ check_id: checkId }),
      }
    );
  }

  // Unified Autonomous Security Operations (Prompt 11)
  async getOperationsDashboard(projectId: string): Promise<any> {
    return this.request<any>(`/operations/${projectId}/dashboard`);
  }

  async getAutonomousPolicy(projectId: string): Promise<any> {
    return this.request<any>(`/operations/${projectId}/policy`);
  }

  async updateAutonomousPolicy(projectId: string, payload: any): Promise<any> {
    return this.request<any>(`/operations/${projectId}/policy`, {
      method: 'PUT',
      body: JSON.stringify(payload),
    });
  }

  async emergencySuspendAutonomy(projectId: string, reason: string): Promise<any> {
    return this.request<any>(`/operations/${projectId}/policy/emergency-suspend`, {
      method: 'POST',
      body: JSON.stringify({ reason }),
    });
  }

  async resumeAutonomy(projectId: string): Promise<any> {
    return this.request<any>(`/operations/${projectId}/policy/resume`, {
      method: 'POST',
    });
  }

  async getDecisionLedger(projectId: string, limit: number = 50, offset: number = 0): Promise<any> {
    return this.request<any>(`/operations/${projectId}/decision-ledger?limit=${limit}&offset=${offset}`);
  }

  async getNotifications(projectId: string, limit: number = 50, offset: number = 0): Promise<any> {
    return this.request<any>(`/operations/${projectId}/notifications?limit=${limit}&offset=${offset}`);
  }

  async getNotificationProviderStatus(projectId: string): Promise<any> {
    return this.request<any>(`/operations/${projectId}/notifications/provider-status`);
  }

  async retryFailedNotifications(projectId: string): Promise<any> {
    return this.request<any>(`/operations/${projectId}/notifications/retry-failed`, {
      method: 'POST',
    });
  }

  async getSLOMetrics(projectId: string, windowDays: number = 30): Promise<any> {
    return this.request<any>(`/operations/${projectId}/slo-metrics?window_days=${windowDays}`);
  }

  async executeLifecycleTransition(projectId: string, findingId: string, action: string, notes: string = ''): Promise<any> {
    return this.request<any>(`/operations/${projectId}/lifecycle-transition/${findingId}`, {
      method: 'POST',
      body: JSON.stringify({ action, notes }),
    });
  }

  // Prompt 12: Self-Diagnostics & Controlled Recovery
  async getSystemHealth(): Promise<SystemHealthData> {
    return this.request<SystemHealthData>('/diagnostics/health');
  }

  async runProjectDiagnostics(projectId: string): Promise<DiagnosticRun> {
    return this.request<DiagnosticRun>(`/diagnostics/${projectId}/run`, {
      method: 'POST',
    });
  }

  async getRecentDiagnostics(projectId: string, limit: number = 10): Promise<{ project_id: string; recent_runs: DiagnosticRun[] }> {
    return this.request<{ project_id: string; recent_runs: DiagnosticRun[] }>(`/diagnostics/${projectId}/recent?limit=${limit}`);
  }

  async executeRecoveryAction(
    projectId: string,
    actionType: string,
    targetEntityType: string,
    targetEntityId?: string | null,
    targetResource?: string | null,
    reason: string = ''
  ): Promise<any> {
    return this.request<any>(`/diagnostics/${projectId}/recover`, {
      method: 'POST',
      body: JSON.stringify({
        action_type: actionType,
        target_entity_type: targetEntityType,
        target_entity_id: targetEntityId,
        target_resource: targetResource,
        reason,
      }),
    });
  }

  async getRecoveryHistory(projectId: string, limit: number = 20): Promise<{ project_id: string; total: number; records: RecoveryActionHistoryRecord[] }> {
    return this.request<{ project_id: string; total: number; records: RecoveryActionHistoryRecord[] }>(`/diagnostics/${projectId}/recovery-history?limit=${limit}`);
  }

  async getFailurePatterns(projectId: string): Promise<{ project_id: string; patterns_updated: number; total_patterns: number; patterns: FailurePattern[] }> {
    return this.request<{ project_id: string; patterns_updated: number; total_patterns: number; patterns: FailurePattern[] }>(`/diagnostics/${projectId}/patterns`);
  }

  async getFailureKnowledgeBase(): Promise<Record<string, any>> {
    return this.request<Record<string, any>>('/diagnostics/knowledge-base');
  }

  // Autonomous Security Orchestration (Prompt 15)
  async getOrchestrationDashboard(projectId: string): Promise<any> {
    return this.request<any>(`/orchestration/${projectId}/dashboard`);
  }

  async listOrchestrationWorkflows(projectId: string, state?: string, limit: number = 20): Promise<any> {
    const query = state ? `?state=${state}&limit=${limit}` : `?limit=${limit}`;
    return this.request<any>(`/orchestration/${projectId}/workflows${query}`);
  }

  async getOrchestrationWorkflow(projectId: string, workflowId: string): Promise<any> {
    return this.request<any>(`/orchestration/${projectId}/workflows/${workflowId}`);
  }

  async ingestOrchestrationEvent(
    projectId: string,
    eventType: string,
    targetResource: string,
    payload: Record<string, any> = {},
    eventSource: string = 'OPERATOR'
  ): Promise<any> {
    return this.request<any>(`/orchestration/${projectId}/events`, {
      method: 'POST',
      body: JSON.stringify({
        event_type: eventType,
        target_resource: targetResource,
        payload,
        event_source: eventSource,
      }),
    });
  }

  async approveOrchestrationWorkflow(projectId: string, workflowId: string, notes: string = ''): Promise<any> {
    return this.request<any>(`/orchestration/${projectId}/workflows/${workflowId}/approve`, {
      method: 'POST',
      body: JSON.stringify({ notes }),
    });
  }

  async rejectOrchestrationWorkflow(projectId: string, workflowId: string, notes: string = ''): Promise<any> {
    return this.request<any>(`/orchestration/${projectId}/workflows/${workflowId}/reject`, {
      method: 'POST',
      body: JSON.stringify({ notes }),
    });
  }

  async suspendOrchestrationWorkflow(projectId: string, workflowId: string, notes: string = ''): Promise<any> {
    return this.request<any>(`/orchestration/${projectId}/workflows/${workflowId}/suspend`, {
      method: 'POST',
      body: JSON.stringify({ notes }),
    });
  }

  async resumeOrchestrationWorkflow(projectId: string, workflowId: string): Promise<any> {
    return this.request<any>(`/orchestration/${projectId}/workflows/${workflowId}/resume`, {
      method: 'POST',
    });
  }

  async retryOrchestrationWorkflow(projectId: string, workflowId: string): Promise<any> {
    return this.request<any>(`/orchestration/${projectId}/workflows/${workflowId}/retry`, {
      method: 'POST',
    });
  }

  async getAdaptiveOptimizations(projectId: string, limit: number = 10): Promise<any> {
    return this.request<any>(`/orchestration/${projectId}/optimizations?limit=${limit}`);
  }

  async getDependencyInvalidations(projectId: string, limit: number = 20): Promise<any> {
    return this.request<any>(`/orchestration/${projectId}/invalidations?limit=${limit}`);
  }

  // Prompt 19: Detection Quality & Evidence-Driven Intelligence
  async getQualityOverview(projectId: string): Promise<QualityOverviewResponse> {
    return this.request<QualityOverviewResponse>(`/projects/${projectId}/quality/overview`);
  }

  async getFixtureBenchmarks(projectId: string): Promise<FixtureBenchmarksResponse> {
    return this.request<FixtureBenchmarksResponse>(`/projects/${projectId}/quality/fixtures`);
  }

  async getFindingProvenance(projectId: string, findingId: string): Promise<FindingProvenanceResponse> {
    return this.request<FindingProvenanceResponse>(`/projects/${projectId}/quality/findings/${findingId}/provenance`);
  }

  async transitionFindingValidation(
    projectId: string,
    findingId: string,
    data: FindingValidationTransitionRequest
  ): Promise<VulnerabilityFindingDetail> {
    return this.request<VulnerabilityFindingDetail>(`/projects/${projectId}/findings/${findingId}/validation`, {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  // Prompt 20: Asset Identity, Exposure Drift & Continuous Change Intelligence
  async getDriftOverview(projectId: string): Promise<ProjectDriftOverview> {
    return this.request<ProjectDriftOverview>(`/projects/${projectId}/drift/overview`);
  }

  async listDriftRecords(
    projectId: string,
    params?: { materiality?: string; driftType?: string; limit?: number }
  ): Promise<ExposureDriftRecord[]> {
    const query = new URLSearchParams();
    if (params?.materiality) query.append('materiality', params.materiality);
    if (params?.driftType) query.append('drift_type', params.driftType);
    if (params?.limit) query.append('limit', params.limit.toString());
    const qs = query.toString();
    return this.request<ExposureDriftRecord[]>(`/projects/${projectId}/drift/records${qs ? `?${qs}` : ''}`);
  }

  async listReassessmentProposals(projectId: string, status?: string): Promise<ReassessmentProposal[]> {
    const qs = status ? `?status=${status}` : '';
    return this.request<ReassessmentProposal[]>(`/projects/${projectId}/drift/proposals${qs}`);
  }

  async approveReassessmentProposal(projectId: string, proposalId: string): Promise<AssessmentJob> {
    return this.request<AssessmentJob>(`/projects/${projectId}/drift/proposals/${proposalId}/approve`, {
      method: 'POST',
    });
  }

  async rejectReassessmentProposal(
    projectId: string,
    proposalId: string,
    rejectionReason: string
  ): Promise<ReassessmentProposal> {
    return this.request<ReassessmentProposal>(`/projects/${projectId}/drift/proposals/${proposalId}/reject`, {
      method: 'POST',
      body: JSON.stringify({ rejection_reason: rejectionReason }),
    });
  }

  async listAssetAliases(projectId: string, assetId: string): Promise<AssetIdentifierAlias[]> {
    return this.request<AssetIdentifierAlias[]>(`/projects/${projectId}/assets/${assetId}/aliases`);
  }

  async createAssetAlias(
    projectId: string,
    assetId: string,
    data: { identifier_type: string; identifier_value: string; is_primary?: boolean }
  ): Promise<AssetIdentifierAlias> {
    return this.request<AssetIdentifierAlias>(`/projects/${projectId}/assets/${assetId}/aliases`, {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  async mergeAssets(
    projectId: string,
    targetAssetId: string,
    sourceAssetId: string,
    rationale: string
  ): Promise<AssetIdentityMergeRecord> {
    return this.request<AssetIdentityMergeRecord>(`/projects/${projectId}/assets/${targetAssetId}/merge`, {
      method: 'POST',
      body: JSON.stringify({ source_asset_id: sourceAssetId, merge_rationale: rationale }),
    });
  }

  async reverseAssetMerge(
    projectId: string,
    mergeId: string,
    reversalNotes: string
  ): Promise<AssetIdentityMergeRecord> {
    return this.request<AssetIdentityMergeRecord>(`/projects/${projectId}/assets/merges/${mergeId}/reverse`, {
      method: 'POST',
      body: JSON.stringify({ reversal_notes: reversalNotes }),
    });
  }

  // -------------------------------------------------------------------------
  // Prompt 21: Knowledge Integrity, Explainable Attack Paths & Reconciliation
  // -------------------------------------------------------------------------

  async listKnowledgeDependencies(
    projectId: string,
    params?: { source_type?: string; source_id?: string; dependent_type?: string; is_valid?: boolean }
  ): Promise<KnowledgeDependencyRecord[]> {
    const query = new URLSearchParams();
    if (params?.source_type) query.append('source_type', params.source_type);
    if (params?.source_id) query.append('source_id', params.source_id);
    if (params?.dependent_type) query.append('dependent_type', params.dependent_type);
    if (params?.is_valid !== undefined) query.append('is_valid', String(params.is_valid));
    const qs = query.toString();
    return this.request<KnowledgeDependencyRecord[]>(`/projects/${projectId}/knowledge/dependencies${qs ? `?${qs}` : ''}`);
  }

  async listExplainableAttackPaths(
    projectId: string,
    params?: { compute_fresh?: boolean; max_depth?: number }
  ): Promise<ExplainableAttackPath[]> {
    const query = new URLSearchParams();
    if (params?.compute_fresh !== undefined) query.append('compute_fresh', String(params.compute_fresh));
    if (params?.max_depth) query.append('max_depth', String(params.max_depth));
    const qs = query.toString();
    return this.request<ExplainableAttackPath[]>(`/projects/${projectId}/knowledge/attack-paths${qs ? `?${qs}` : ''}`);
  }

  async getExplainableAttackPath(projectId: string, pathId: string): Promise<ExplainableAttackPath> {
    return this.request<ExplainableAttackPath>(`/projects/${projectId}/knowledge/attack-paths/${pathId}`);
  }

  async triggerKnowledgeReconciliation(
    projectId: string,
    autoRepair: boolean = true
  ): Promise<KnowledgeReconciliationAudit> {
    return this.request<KnowledgeReconciliationAudit>(`/projects/${projectId}/knowledge/reconcile`, {
      method: 'POST',
      body: JSON.stringify({ auto_repair: autoRepair }),
    });
  }

  async listReconciliationAudits(projectId: string): Promise<KnowledgeReconciliationAudit[]> {
    return this.request<KnowledgeReconciliationAudit[]>(`/projects/${projectId}/knowledge/reconcile/audits`);
  }

  async getReconciliationAudit(projectId: string, auditId: string): Promise<KnowledgeReconciliationAudit> {
    return this.request<KnowledgeReconciliationAudit>(`/projects/${projectId}/knowledge/reconcile/audits/${auditId}`);
  }

  async explainFinding(projectId: string, findingId: string): Promise<FindingEpistemicExplanation> {
    return this.request<FindingEpistemicExplanation>(`/projects/${projectId}/knowledge/explain/finding/${findingId}`);
  }

  // -------------------------------------------------------------------------
  // Prompt 22: Governance, Separation of Duties & Approvals
  // -------------------------------------------------------------------------

  async getGovernancePolicy(projectId: string): Promise<ProjectGovernancePolicy> {
    return this.request<ProjectGovernancePolicy>(`/projects/${projectId}/governance/policy`);
  }

  async updateGovernancePolicy(
    projectId: string,
    payload: ProjectGovernancePolicyUpdate
  ): Promise<ProjectGovernancePolicy> {
    return this.request<ProjectGovernancePolicy>(`/projects/${projectId}/governance/policy`, {
      method: 'PUT',
      body: JSON.stringify(payload),
    });
  }

  async listApprovals(
    projectId: string,
    params?: { status?: string; workflow?: string; limit?: number; offset?: number }
  ): Promise<ApprovalRequestRecord[]> {
    const query = new URLSearchParams();
    if (params?.status) query.append('status', params.status);
    if (params?.workflow) query.append('workflow', params.workflow);
    if (params?.limit) query.append('limit', String(params.limit));
    if (params?.offset) query.append('offset', String(params.offset));
    const qs = query.toString();
    return this.request<ApprovalRequestRecord[]>(`/projects/${projectId}/governance/approvals${qs ? `?${qs}` : ''}`);
  }

  async requestApproval(
    projectId: string,
    payload: {
      workflow_type: string;
      resource_type: string;
      resource_id: string;
      title: string;
      description?: string;
      parameters?: Record<string, any>;
    }
  ): Promise<ApprovalRequestRecord> {
    return this.request<ApprovalRequestRecord>(`/projects/${projectId}/governance/approvals`, {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  }

  async getApproval(projectId: string, approvalId: string): Promise<ApprovalRequestRecord> {
    return this.request<ApprovalRequestRecord>(`/projects/${projectId}/governance/approvals/${approvalId}`);
  }

  async decideApproval(
    projectId: string,
    approvalId: string,
    payload: ApprovalDecisionRequest
  ): Promise<ApprovalRequestRecord> {
    return this.request<ApprovalRequestRecord>(`/projects/${projectId}/governance/approvals/${approvalId}/decide`, {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  }

  async getPermissionMatrix(projectId: string): Promise<PermissionMatrixResponse> {
    return this.request<PermissionMatrixResponse>(`/projects/${projectId}/governance/matrix`);
  }

  // Prompt 23: Disaster Recovery, Verified Restoration & Data Integrity
  async createRecoveryBundle(): Promise<DisasterRecoveryBundle> {
    return this.request<DisasterRecoveryBundle>('/recovery/bundles', {
      method: 'POST',
    });
  }

  async listRecoveryBundles(): Promise<DisasterRecoveryBundle[]> {
    return this.request<DisasterRecoveryBundle[]>('/recovery/bundles');
  }

  async getRecoveryBundle(bundleId: string): Promise<DisasterRecoveryBundle> {
    return this.request<DisasterRecoveryBundle>(`/recovery/bundles/${bundleId}`);
  }

  async verifyRecoveryBundle(bundleId: string): Promise<BackupVerificationResult> {
    return this.request<BackupVerificationResult>(`/recovery/bundles/${bundleId}/verify`, {
      method: 'POST',
    });
  }

  async runIsolatedRestoreDrill(bundleId: string): Promise<RestoreDrillResult> {
    return this.request<RestoreDrillResult>(`/recovery/bundles/${bundleId}/restore-drill`, {
      method: 'POST',
    });
  }

  async liveRestoreBundle(bundleId: string, confirmationPhrase: string): Promise<LiveRestoreResult> {
    return this.request<LiveRestoreResult>(`/recovery/bundles/${bundleId}/live-restore`, {
      method: 'POST',
      body: JSON.stringify({ confirmation_phrase: confirmationPhrase }),
    });
  }

  async rotateRecoveryBundles(maxRetained: number = 5, preserveLastKnownGood: boolean = true): Promise<RotationResult> {
    return this.request<RotationResult>('/recovery/rotate', {
      method: 'POST',
      body: JSON.stringify({ max_retained: maxRetained, preserve_last_known_good: preserveLastKnownGood }),
    });
  }

  async getRecoveryStatus(): Promise<RecoveryStatusSummary> {
    return this.request<RecoveryStatusSummary>('/recovery/status');
  }

  // ---------------------------------------------------------------------------
  // Prompt 25: Software Supply-Chain Security & Verifiable Release Provenance
  // ---------------------------------------------------------------------------
  async getDependencyInventory(): Promise<DependencyInventoryResponse> {
    return this.request<DependencyInventoryResponse>('/system/supply-chain/inventory');
  }

  async runDependencyAudit(allowNetwork: boolean = true): Promise<DependencyAuditResponse> {
    return this.request<DependencyAuditResponse>(`/system/supply-chain/audit?allow_network=${allowNetwork}`, {
      method: 'POST',
    });
  }

  async getSbom(format: string = 'cyclonedx'): Promise<Record<string, unknown>> {
    return this.request<Record<string, unknown>>(`/system/supply-chain/sbom?format=${format}`);
  }

  async scanSecrets(): Promise<SecretScanResponse> {
    return this.request<SecretScanResponse>('/system/supply-chain/secrets/scan', {
      method: 'POST',
    });
  }

  async verifyRelease(archivePath?: string, manifestPath?: string): Promise<ReleaseVerificationResult> {
    return this.request<ReleaseVerificationResult>('/system/supply-chain/release/verify', {
      method: 'POST',
      body: JSON.stringify({ archive_path: archivePath, manifest_path: manifestPath }),
    });
  }

  // ---------------------------------------------------------------------------
  // Prompt 26: Performance Engineering, Workload Isolation & Scalable Processing
  // ---------------------------------------------------------------------------
  async getWorkloadQueueStatus(): Promise<WorkloadQueueStatus> {
    return this.request<WorkloadQueueStatus>('/system/performance/workload');
  }

  async getPerformanceBudgets(): Promise<PerformanceBudgetsResponse> {
    return this.request<PerformanceBudgetsResponse>('/system/performance/budgets');
  }

  async runPerformanceBenchmark(datasetSize: string = 'SMALL'): Promise<BenchmarkSuiteResponse> {
    return this.request<BenchmarkSuiteResponse>(`/system/performance/benchmark?dataset_size=${encodeURIComponent(datasetSize)}`, {
      method: 'POST',
    });
  }

  async reconcileStaleJobs(timeoutSeconds: number = 300): Promise<StaleJobReconciliationResult> {
    return this.request<StaleJobReconciliationResult>(`/system/performance/reconcile-stale-jobs?timeout_seconds=${timeoutSeconds}`, {
      method: 'POST',
    });
  }

  // ---------------------------------------------------------------------------
  // Prompt 27: Security Control Verification & Mutation Testing
  // ---------------------------------------------------------------------------
  async getSecurityControlsCatalog(): Promise<SecurityControlsCatalogResponse> {
    return this.request<SecurityControlsCatalogResponse>('/system/verification/controls');
  }

  async getMutationScenarios(): Promise<MutationScenario[]> {
    return this.request<MutationScenario[]>('/system/verification/mutations');
  }

  async runMutationDrill(): Promise<MutationDrillResult> {
    return this.request<MutationDrillResult>('/system/verification/run-mutation-drill', {
      method: 'POST',
    });
  }

  // ---------------------------------------------------------------------------
  // Prompt 28: Secure Windows Deployment & Configuration Governance
  // ---------------------------------------------------------------------------
  async getPreflightReport(): Promise<PreflightReport> {
    return this.request<PreflightReport>('/system/deployment/preflight');
  }

  async getRedactedConfig(): Promise<RedactedConfigResponse> {
    return this.request<RedactedConfigResponse>('/system/deployment/config');
  }

  async checkUpgradeReadiness(): Promise<UpgradePrecheckResponse> {
    return this.request<UpgradePrecheckResponse>('/system/deployment/upgrade-check', {
      method: 'POST',
    });
  }

  // ---------------------------------------------------------------------------
  // Prompt 29: Evidence Lifecycle Governance & Data Retention
  // ---------------------------------------------------------------------------
  async getRetentionPolicies(): Promise<RetentionPolicyModel[]> {
    return this.request<RetentionPolicyModel[]>('/system/lifecycle/policies');
  }

  async updateRetentionPolicy(policyId: string, policy: RetentionPolicyModel): Promise<RetentionPolicyModel> {
    return this.request<RetentionPolicyModel>(`/system/lifecycle/policies/${encodeURIComponent(policyId)}`, {
      method: 'PUT',
      body: JSON.stringify(policy),
    });
  }

  async getLegalHolds(): Promise<LegalHoldModel[]> {
    return this.request<LegalHoldModel[]>('/system/lifecycle/holds');
  }

  async createLegalHold(data: LegalHoldCreate): Promise<LegalHoldModel> {
    return this.request<LegalHoldModel>('/system/lifecycle/holds', {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  async releaseLegalHold(holdId: string): Promise<LegalHoldModel> {
    return this.request<LegalHoldModel>(`/system/lifecycle/holds/${encodeURIComponent(holdId)}`, {
      method: 'DELETE',
    });
  }

  async getRetentionPreview(): Promise<RetentionPreviewReport> {
    return this.request<RetentionPreviewReport>('/system/lifecycle/preview');
  }

  async executeRetention(req: RetentionExecutionRequest): Promise<RetentionExecutionResult> {
    return this.request<RetentionExecutionResult>('/system/lifecycle/execute', {
      method: 'POST',
      body: JSON.stringify(req),
    });
  }

  async getDeletionTombstones(): Promise<DeletionTombstoneModel[]> {
    return this.request<DeletionTombstoneModel[]>('/system/lifecycle/tombstones');
  }

  async redactEvidence(req: EvidenceRedactionRequest): Promise<EvidenceRedactionResult> {
    return this.request<EvidenceRedactionResult>('/system/lifecycle/redact-evidence', {
      method: 'POST',
      body: JSON.stringify(req),
    });
  }

  // ---------------------------------------------------------------------------
  // Prompt 30: Unified Security Operations Experience & Priority Queue
  // ---------------------------------------------------------------------------
  async getCockpitSummary(projectId?: string): Promise<UnifiedOpsDashboardResponse> {
    const q = projectId ? `?project_id=${encodeURIComponent(projectId)}` : '';
    return this.request<UnifiedOpsDashboardResponse>(`/system/operations/cockpit/summary${q}`);
  }

  async getPriorityQueue(projectId?: string): Promise<PriorityQueueResponse> {
    const q = projectId ? `?project_id=${encodeURIComponent(projectId)}` : '';
    return this.request<PriorityQueueResponse>(`/system/operations/cockpit/priority-queue${q}`);
  }

  async dismissPriorityQueueItem(itemId: string): Promise<{ status: string; item_id: string }> {
    return this.request<{ status: string; item_id: string }>(`/system/operations/cockpit/priority-queue/${encodeURIComponent(itemId)}/dismiss`, {
      method: 'POST',
    });
  }

  // ---------------------------------------------------------------------------
  // Prompt 31: Reliable Security Alerting, Event Delivery & Escalation
  // ---------------------------------------------------------------------------
  async getAlerts(
    projectId: string,
    lifecycleStatus?: string,
    severity?: string,
    limit: number = 50,
    offset: number = 0,
  ): Promise<AlertListResponse> {
    const params = new URLSearchParams({
      project_id: projectId,
      limit: String(limit),
      offset: String(offset),
    });
    if (lifecycleStatus && lifecycleStatus !== 'ALL') {
      params.append('lifecycle_status', lifecycleStatus);
    }
    if (severity && severity !== 'ALL') {
      params.append('severity', severity);
    }
    return this.request<AlertListResponse>(`/alerts?${params.toString()}`);
  }

  async getAlert(alertId: string, projectId?: string): Promise<AlertResponse> {
    const q = projectId ? `?project_id=${encodeURIComponent(projectId)}` : '';
    return this.request<AlertResponse>(`/alerts/${encodeURIComponent(alertId)}${q}`);
  }

  async acknowledgeAlert(alertId: string, notes?: string, projectId?: string): Promise<{ status: string; alert_id: string }> {
    const q = projectId ? `?project_id=${encodeURIComponent(projectId)}` : '';
    return this.request<{ status: string; alert_id: string }>(`/alerts/${encodeURIComponent(alertId)}/acknowledge${q}`, {
      method: 'POST',
      body: JSON.stringify({ notes }),
    });
  }

  async assignAlert(alertId: string, assignedToId: string, notes?: string, projectId?: string): Promise<{ status: string; alert_id: string }> {
    const q = projectId ? `?project_id=${encodeURIComponent(projectId)}` : '';
    return this.request<{ status: string; alert_id: string }>(`/alerts/${encodeURIComponent(alertId)}/assign${q}`, {
      method: 'POST',
      body: JSON.stringify({ assigned_to_id: assignedToId, notes }),
    });
  }

  async resolveAlert(alertId: string, notes?: string, projectId?: string): Promise<{ status: string; alert_id: string }> {
    const q = projectId ? `?project_id=${encodeURIComponent(projectId)}` : '';
    return this.request<{ status: string; alert_id: string }>(`/alerts/${encodeURIComponent(alertId)}/resolve${q}`, {
      method: 'POST',
      body: JSON.stringify({ notes }),
    });
  }

  async reopenAlert(alertId: string, notes?: string, projectId?: string): Promise<{ status: string; alert_id: string }> {
    const q = projectId ? `?project_id=${encodeURIComponent(projectId)}` : '';
    return this.request<{ status: string; alert_id: string }>(`/alerts/${encodeURIComponent(alertId)}/reopen${q}`, {
      method: 'POST',
      body: JSON.stringify({ notes }),
    });
  }

  async getOutboxStatus(projectId?: string): Promise<OutboxStatusResponse> {
    const q = projectId ? `?project_id=${encodeURIComponent(projectId)}` : '';
    return this.request<OutboxStatusResponse>(`/alerts/outbox/status${q}`);
  }

  async processOutbox(batchSize: number = 50): Promise<{ processed: number; delivered: number; retried: number; dead_letter: number }> {
    return this.request<{ processed: number; delivered: number; retried: number; dead_letter: number }>(`/alerts/outbox/process?batch_size=${batchSize}`, {
      method: 'POST',
    });
  }

  async replayDeadLetterEvent(eventId: string): Promise<{ status: string; event_id: string }> {
    return this.request<{ status: string; event_id: string }>(`/alerts/outbox/${encodeURIComponent(eventId)}/replay`, {
      method: 'POST',
    });
  }

  async getMaintenanceWindows(projectId: string): Promise<MaintenanceWindowResponse[]> {
    return this.request<MaintenanceWindowResponse[]>(`/alerts/maintenance-windows?project_id=${encodeURIComponent(projectId)}`);
  }

  async createMaintenanceWindow(projectId: string, data: { title: string; reason: string; start_time: string; end_time: string; suppress_critical?: boolean }): Promise<MaintenanceWindowResponse> {
    return this.request<MaintenanceWindowResponse>(`/alerts/maintenance-windows?project_id=${encodeURIComponent(projectId)}`, {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  // ---------------------------------------------------------------------------
  // Prompt 33: Continuous Compliance Intelligence, Security Baselines & Drift
  // ---------------------------------------------------------------------------
  async getComplianceControls(category?: string, framework?: string): Promise<ComplianceControl[]> {
    const params = new URLSearchParams();
    if (category) params.append('category', category);
    if (framework) params.append('framework', framework);
    const q = params.toString() ? `?${params.toString()}` : '';
    return this.request<ComplianceControl[]>(`/compliance/controls${q}`);
  }

  async getComplianceControl(controlId: string, version?: string): Promise<ComplianceControl> {
    const q = version ? `?version=${encodeURIComponent(version)}` : '';
    return this.request<ComplianceControl>(`/compliance/controls/${encodeURIComponent(controlId)}${q}`);
  }

  async createComplianceControl(payload: Partial<ComplianceControl>): Promise<ComplianceControl> {
    return this.request<ComplianceControl>('/compliance/controls', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  }

  async getProjectBaselineProfiles(projectId: string): Promise<BaselineProfile[]> {
    return this.request<BaselineProfile[]>(`/projects/${encodeURIComponent(projectId)}/compliance/baselines`);
  }

  async getProjectBaselineProfile(projectId: string, profileId: string): Promise<BaselineProfile> {
    return this.request<BaselineProfile>(`/projects/${encodeURIComponent(projectId)}/compliance/baselines/${encodeURIComponent(profileId)}`);
  }

  async createProjectBaselineProfile(projectId: string, payload: Partial<BaselineProfile>): Promise<BaselineProfile> {
    return this.request<BaselineProfile>(`/projects/${encodeURIComponent(projectId)}/compliance/baselines`, {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  }

  async updateProjectBaselineProfile(projectId: string, profileId: string, payload: Partial<BaselineProfile>): Promise<BaselineProfile> {
    return this.request<BaselineProfile>(`/projects/${encodeURIComponent(projectId)}/compliance/baselines/${encodeURIComponent(profileId)}`, {
      method: 'PUT',
      body: JSON.stringify(payload),
    });
  }

  async evaluateComplianceBaseline(
    projectId: string,
    payload: { baseline_profile_id: string; assessment_id?: string; asset_ids?: string[] }
  ): Promise<ComplianceEvaluationRun> {
    return this.request<ComplianceEvaluationRun>(`/projects/${encodeURIComponent(projectId)}/compliance/evaluate`, {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  }

  async getComplianceEvaluations(projectId: string, baselineProfileId?: string, limit: number = 20): Promise<ComplianceEvaluationRun[]> {
    const params = new URLSearchParams({ limit: String(limit) });
    if (baselineProfileId) params.append('baseline_profile_id', baselineProfileId);
    return this.request<ComplianceEvaluationRun[]>(`/projects/${encodeURIComponent(projectId)}/compliance/evaluations?${params.toString()}`);
  }

  async getComplianceEvaluation(projectId: string, runId: string): Promise<ComplianceEvaluationRun> {
    return this.request<ComplianceEvaluationRun>(`/projects/${encodeURIComponent(projectId)}/compliance/evaluations/${encodeURIComponent(runId)}`);
  }

  async compareComplianceEvaluations(projectId: string, runA: string, runB: string): Promise<ComplianceComparison> {
    return this.request<ComplianceComparison>(`/projects/${encodeURIComponent(projectId)}/compliance/compare?run_a=${encodeURIComponent(runA)}&run_b=${encodeURIComponent(runB)}`);
  }

  async getComplianceDriftEvents(projectId: string, controlId?: string, driftType?: string, limit: number = 50): Promise<ComplianceDriftEvent[]> {
    const params = new URLSearchParams({ limit: String(limit) });
    if (controlId) params.append('control_id', controlId);
    if (driftType) params.append('drift_type', driftType);
    return this.request<ComplianceDriftEvent[]>(`/projects/${encodeURIComponent(projectId)}/compliance/drift?${params.toString()}`);
  }

  async getComplianceExceptions(projectId: string, controlId?: string, status?: string): Promise<ComplianceException[]> {
    const params = new URLSearchParams();
    if (controlId) params.append('control_id', controlId);
    if (status) params.append('status', status);
    const q = params.toString() ? `?${params.toString()}` : '';
    return this.request<ComplianceException[]>(`/projects/${encodeURIComponent(projectId)}/compliance/exceptions${q}`);
  }

  async requestComplianceException(
    projectId: string,
    payload: { control_id: string; justification: string; risk_assessment: string; compensating_controls: string; expires_at: string; asset_id?: string }
  ): Promise<ComplianceException> {
    return this.request<ComplianceException>(`/projects/${encodeURIComponent(projectId)}/compliance/exceptions`, {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  }

  async reviewComplianceException(
    projectId: string,
    exceptionId: string,
    payload: { approved: boolean; review_notes?: string }
  ): Promise<ComplianceException> {
    return this.request<ComplianceException>(`/projects/${encodeURIComponent(projectId)}/compliance/exceptions/${encodeURIComponent(exceptionId)}/review`, {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  }

  async revokeComplianceException(projectId: string, exceptionId: string, notes?: string): Promise<ComplianceException> {
    const q = notes ? `?notes=${encodeURIComponent(notes)}` : '';
    return this.request<ComplianceException>(`/projects/${encodeURIComponent(projectId)}/compliance/exceptions/${encodeURIComponent(exceptionId)}/revoke${q}`, {
      method: 'POST',
    });
  }

  // -------------------------------------------------------------------------
  // Prompt 34: Intelligent Assessment Scheduling & Orchestration
  // -------------------------------------------------------------------------

  async listQueueItems(
    projectId: string,
    params?: { status?: string; priority_band?: string; target?: string; skip?: number; limit?: number }
  ): Promise<AssessmentQueueItem[]> {
    const q = new URLSearchParams();
    if (params?.status) q.append('status', params.status);
    if (params?.priority_band) q.append('priority_band', params.priority_band);
    if (params?.target) q.append('target', params.target);
    if (params?.skip !== undefined) q.append('skip', String(params.skip));
    if (params?.limit !== undefined) q.append('limit', String(params.limit));
    const qs = q.toString() ? `?${q.toString()}` : '';
    return this.request<AssessmentQueueItem[]>(`/projects/${encodeURIComponent(projectId)}/scheduling/queue${qs}`);
  }

  async getQueueItem(projectId: string, queueId: string): Promise<AssessmentQueueItem> {
    return this.request<AssessmentQueueItem>(`/projects/${encodeURIComponent(projectId)}/scheduling/queue/${encodeURIComponent(queueId)}`);
  }

  async enqueueAssessment(projectId: string, payload: QueueItemCreate): Promise<AssessmentQueueItem> {
    return this.request<AssessmentQueueItem>(`/projects/${encodeURIComponent(projectId)}/scheduling/enqueue`, {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  }

  async previewScheduling(projectId: string, payload: QueueItemPreviewRequest): Promise<QueueItemPreviewResponse> {
    return this.request<QueueItemPreviewResponse>(`/projects/${encodeURIComponent(projectId)}/scheduling/preview`, {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  }

  async cancelQueueItem(projectId: string, queueId: string, reason?: string): Promise<AssessmentQueueItem> {
    const q = reason ? `?reason=${encodeURIComponent(reason)}` : '';
    return this.request<AssessmentQueueItem>(`/projects/${encodeURIComponent(projectId)}/scheduling/queue/${encodeURIComponent(queueId)}/cancel${q}`, {
      method: 'POST',
    });
  }

  async dispatchNextJob(projectId: string, workerId: string = 'worker-ui'): Promise<DispatchResultResponse> {
    return this.request<DispatchResultResponse>(`/projects/${encodeURIComponent(projectId)}/scheduling/dispatch-next?worker_id=${encodeURIComponent(workerId)}`, {
      method: 'POST',
    });
  }

  async recoverStaleLeases(projectId: string): Promise<LeaseRecoveryResponse> {
    return this.request<LeaseRecoveryResponse>(`/projects/${encodeURIComponent(projectId)}/scheduling/recover-stale`, {
      method: 'POST',
    });
  }

  async triggerReassessment(projectId: string, payload: TriggerAssessmentRequest): Promise<AssessmentQueueItem> {
    return this.request<AssessmentQueueItem>(`/projects/${encodeURIComponent(projectId)}/scheduling/trigger`, {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  }

  async getSchedulerCapacity(projectId: string): Promise<SchedulerCapacity> {
    return this.request<SchedulerCapacity>(`/projects/${encodeURIComponent(projectId)}/scheduling/capacity`);
  }

  async listSchedulerDecisions(
    projectId: string,
    params?: { decision_type?: string; skip?: number; limit?: number }
  ): Promise<SchedulerDecision[]> {
    const q = new URLSearchParams();
    if (params?.decision_type) q.append('decision_type', params.decision_type);
    if (params?.skip !== undefined) q.append('skip', String(params.skip));
    if (params?.limit !== undefined) q.append('limit', String(params.limit));
    const qs = q.toString() ? `?${q.toString()}` : '';
    return this.request<SchedulerDecision[]>(`/projects/${encodeURIComponent(projectId)}/scheduling/decisions${qs}`);
  }

  async getSchedulerPolicy(projectId: string): Promise<SchedulerPolicy> {
    return this.request<SchedulerPolicy>(`/projects/${encodeURIComponent(projectId)}/scheduling/policy`);
  }

  async updateSchedulerPolicy(projectId: string, payload: SchedulerPolicyUpdate): Promise<SchedulerPolicy> {
    return this.request<SchedulerPolicy>(`/projects/${encodeURIComponent(projectId)}/scheduling/policy`, {
      method: 'PUT',
      body: JSON.stringify(payload),
    });
  }

  // -------------------------------------------------------------------------
  // Prompt 35: Evidence-Grounded Threat Intelligence and Vulnerability Correlation
  // -------------------------------------------------------------------------

  async listThreatFeeds(): Promise<ThreatFeed[]> {
    return this.request<ThreatFeed[]>('/threat-intel/feeds');
  }

  async syncThreatFeed(feedName: string, req?: ThreatFeedSyncRequest): Promise<ThreatFeedSyncResponse> {
    return this.request<ThreatFeedSyncResponse>(`/threat-intel/feeds/${encodeURIComponent(feedName)}/sync`, {
      method: 'POST',
      body: JSON.stringify(req || { force_local: true }),
    });
  }

  async searchThreatRecords(params?: {
    cve_id?: string;
    vendor?: string;
    product?: string;
    is_known_exploited?: boolean;
    limit?: number;
    offset?: number;
  }): Promise<ThreatIntelligenceRecord[]> {
    const q = new URLSearchParams();
    if (params?.cve_id) q.append('cve_id', params.cve_id);
    if (params?.vendor) q.append('vendor', params.vendor);
    if (params?.product) q.append('product', params.product);
    if (params?.is_known_exploited !== undefined) q.append('is_known_exploited', String(params.is_known_exploited));
    if (params?.limit !== undefined) q.append('limit', String(params.limit));
    if (params?.offset !== undefined) q.append('offset', String(params.offset));
    const qs = q.toString() ? `?${q.toString()}` : '';
    return this.request<ThreatIntelligenceRecord[]>(`/threat-intel/records${qs}`);
  }

  async getThreatCveIntel(cveId: string): Promise<ThreatIntelligenceRecord[]> {
    return this.request<ThreatIntelligenceRecord[]>(`/threat-intel/cve/${encodeURIComponent(cveId)}`);
  }

  async listProjectThreatCorrelations(
    projectId: string,
    params?: { match_classification?: string; is_known_exploited?: boolean }
  ): Promise<ThreatCorrelation[]> {
    const q = new URLSearchParams();
    if (params?.match_classification) q.append('match_classification', params.match_classification);
    if (params?.is_known_exploited !== undefined) q.append('is_known_exploited', String(params.is_known_exploited));
    const qs = q.toString() ? `?${q.toString()}` : '';
    return this.request<ThreatCorrelation[]>(`/projects/${encodeURIComponent(projectId)}/threat-intel/correlations${qs}`);
  }

  async getThreatIntelSummary(projectId: string): Promise<ThreatIntelSummary> {
    return this.request<ThreatIntelSummary>(`/projects/${encodeURIComponent(projectId)}/threat-intel/summary`);
  }

  async runProjectThreatCorrelation(
    projectId: string,
    req?: ThreatCorrelationRunRequest
  ): Promise<ThreatCorrelationRunResponse> {
    return this.request<ThreatCorrelationRunResponse>(`/projects/${encodeURIComponent(projectId)}/threat-intel/correlate`, {
      method: 'POST',
      body: JSON.stringify(req || { force_recorrelate: false }),
    });
  }

  // -------------------------------------------------------------------------
  // Prompt 36: Identity Security, Authorization Consistency & Privileged-Action Governance
  // -------------------------------------------------------------------------

  async getDetailedPermissionMatrix(): Promise<DetailedPermissionMatrixResponse> {
    return this.request<DetailedPermissionMatrixResponse>('/system/permissions/matrix');
  }

  async listProjectAccessDenials(
    projectId: string,
    params?: { limit?: number; offset?: number }
  ): Promise<AccessDenialAudit[]> {
    const q = new URLSearchParams();
    if (params?.limit !== undefined) q.append('limit', String(params.limit));
    if (params?.offset !== undefined) q.append('offset', String(params.offset));
    const qs = q.toString() ? `?${q.toString()}` : '';
    return this.request<AccessDenialAudit[]>(`/projects/${encodeURIComponent(projectId)}/governance/access-denials${qs}`);
  }

  async listGlobalAccessDenials(params?: { limit?: number; offset?: number }): Promise<AccessDenialAudit[]> {
    const q = new URLSearchParams();
    if (params?.limit !== undefined) q.append('limit', String(params.limit));
    if (params?.offset !== undefined) q.append('offset', String(params.offset));
    const qs = q.toString() ? `?${q.toString()}` : '';
    return this.request<AccessDenialAudit[]>(`/system/governance/access-denials${qs}`);
  }

  logout(): void {
    this.setToken(null);
  }

  async revokeServerSession(): Promise<LogoutResponse> {
    const res = await this.request<LogoutResponse>('/auth/logout', { method: 'POST' });
    this.setToken(null);
    return res;
  }

  async revokeAllSessions(): Promise<RevokeAllSessionsResponse> {
    const res = await this.request<RevokeAllSessionsResponse>('/auth/revoke-all', { method: 'POST' });
    this.setToken(null);
    return res;
  }

  async changePassword(payload: { current_password: string; new_password: string }): Promise<{ status: string; message: string }> {
    return this.request<{ status: string; message: string }>('/auth/change-password', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  }

  // -------------------------------------------------------------------------
  // Prompt 37: Asset Identity Resolution, Data Quality and Canonical Security Records
  // -------------------------------------------------------------------------

  async resolveAssetEntity(
    projectId: string,
    candidateTarget: string,
    attributes?: Record<string, any>
  ): Promise<ResolutionResult> {
    return this.request<ResolutionResult>(`/projects/${encodeURIComponent(projectId)}/asset-identity/resolve`, {
      method: 'POST',
      body: JSON.stringify({
        candidate_target: candidateTarget,
        attributes: attributes || null,
      }),
    });
  }

  async evaluateDeduplicationDryRun(
    projectId: string,
    sourceAssetId: string,
    targetAssetId: string
  ): Promise<DryRunImpact> {
    const q = new URLSearchParams({
      source_asset_id: sourceAssetId,
      target_asset_id: targetAssetId,
    });
    return this.request<DryRunImpact>(
      `/projects/${encodeURIComponent(projectId)}/asset-identity/deduplication/dry-run?${q.toString()}`,
      { method: 'POST' }
    );
  }

  async listDeduplicationProposals(
    projectId: string,
    statusFilter?: string
  ): Promise<DeduplicationProposal[]> {
    const qs = statusFilter ? `?status_filter=${encodeURIComponent(statusFilter)}` : '';
    return this.request<DeduplicationProposal[]>(
      `/projects/${encodeURIComponent(projectId)}/asset-identity/deduplication/proposals${qs}`
    );
  }

  async proposeAssetDeduplication(
    projectId: string,
    payload: {
      source_asset_id: string;
      target_asset_id: string;
      rationale: string;
      confidence?: number;
    }
  ): Promise<DeduplicationProposal> {
    return this.request<DeduplicationProposal>(
      `/projects/${encodeURIComponent(projectId)}/asset-identity/deduplication/proposals`,
      {
        method: 'POST',
        body: JSON.stringify(payload),
      }
    );
  }

  async approveDeduplicationProposal(
    projectId: string,
    proposalId: string,
    comments?: string
  ): Promise<DeduplicationProposal> {
    return this.request<DeduplicationProposal>(
      `/projects/${encodeURIComponent(projectId)}/asset-identity/deduplication/proposals/${encodeURIComponent(proposalId)}/approve`,
      {
        method: 'POST',
        body: JSON.stringify({ comments: comments || null }),
      }
    );
  }

  async rejectDeduplicationProposal(
    projectId: string,
    proposalId: string,
    comments?: string
  ): Promise<DeduplicationProposal> {
    return this.request<DeduplicationProposal>(
      `/projects/${encodeURIComponent(projectId)}/asset-identity/deduplication/proposals/${encodeURIComponent(proposalId)}/reject`,
      {
        method: 'POST',
        body: JSON.stringify({ comments: comments || null }),
      }
    );
  }

  async revertDeduplicationProposal(
    projectId: string,
    proposalId: string,
    comments?: string
  ): Promise<DeduplicationProposal> {
    return this.request<DeduplicationProposal>(
      `/projects/${encodeURIComponent(projectId)}/asset-identity/deduplication/proposals/${encodeURIComponent(proposalId)}/revert`,
      {
        method: 'POST',
        body: JSON.stringify({ comments: comments || null }),
      }
    );
  }

  async runDataQualityAudit(projectId: string): Promise<DataQualityIssue[]> {
    return this.request<DataQualityIssue[]>(
      `/projects/${encodeURIComponent(projectId)}/asset-identity/data-quality/audit`,
      { method: 'POST' }
    );
  }

  async listDataQualityIssues(
    projectId: string,
    statusFilter?: string
  ): Promise<DataQualityIssue[]> {
    const qs = statusFilter ? `?status_filter=${encodeURIComponent(statusFilter)}` : '';
    return this.request<DataQualityIssue[]>(
      `/projects/${encodeURIComponent(projectId)}/asset-identity/data-quality/issues${qs}`
    );
  }

  async updateDataQualityIssueStatus(
    projectId: string,
    issueId: string,
    status: 'RESOLVED' | 'IGNORED'
  ): Promise<DataQualityIssue> {
    return this.request<DataQualityIssue>(
      `/projects/${encodeURIComponent(projectId)}/asset-identity/data-quality/issues/${encodeURIComponent(issueId)}/status`,
      {
        method: 'POST',
        body: JSON.stringify({ status }),
      }
    );
  }

  // Prompt 39: Security Incident Investigation and Case Management
  async createIncidentCase(projectId: string, data: {
    title: string;
    description?: string;
    severity?: string;
    lead_investigator_id?: string;
    assigned_team?: string;
  }): Promise<IncidentCaseDetail> {
    return this.request<IncidentCaseDetail>(`/projects/${encodeURIComponent(projectId)}/incidents/cases`, {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  async listIncidentCases(
    projectId: string,
    statusFilter?: string,
    severityFilter?: string
  ): Promise<IncidentCaseSummary[]> {
    const params = new URLSearchParams();
    if (statusFilter) params.append('status', statusFilter);
    if (severityFilter) params.append('severity', severityFilter);
    const qs = params.toString() ? `?${params.toString()}` : '';
    return this.request<IncidentCaseSummary[]>(`/projects/${encodeURIComponent(projectId)}/incidents/cases${qs}`);
  }

  async getIncidentCase(projectId: string, caseId: string): Promise<IncidentCaseDetail> {
    return this.request<IncidentCaseDetail>(`/projects/${encodeURIComponent(projectId)}/incidents/cases/${encodeURIComponent(caseId)}`);
  }

  async linkAssetToCase(projectId: string, caseId: string, data: {
    asset_id: string;
    relationship_type?: string;
    confidence?: number;
    is_contradictory?: boolean;
    notes?: string;
  }): Promise<{ status: string; link_id: string }> {
    return this.request<{ status: string; link_id: string }>(`/projects/${encodeURIComponent(projectId)}/incidents/cases/${encodeURIComponent(caseId)}/assets`, {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  async linkFindingToCase(projectId: string, caseId: string, data: {
    finding_id: string;
    correlation_type?: string;
    confidence?: number;
    rationale?: string;
  }): Promise<{ status: string; link_id: string }> {
    return this.request<{ status: string; link_id: string }>(`/projects/${encodeURIComponent(projectId)}/incidents/cases/${encodeURIComponent(caseId)}/findings`, {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  async attachEvidenceToCase(projectId: string, caseId: string, data: {
    evidence_summary: string;
    finding_evidence_id?: string;
    is_contradictory?: boolean;
    provenance_details?: Record<string, any>;
  }): Promise<{ status: string; evidence_id: string; digest: string }> {
    return this.request<{ status: string; evidence_id: string; digest: string }>(`/projects/${encodeURIComponent(projectId)}/incidents/cases/${encodeURIComponent(caseId)}/evidence`, {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  async transitionCaseStatus(projectId: string, caseId: string, data: {
    to_status: string;
    reason: string;
    closure_summary?: string;
    reopening_rationale?: string;
    root_cause_hypothesis?: string;
    is_containment_verified?: boolean;
  }): Promise<IncidentCaseDetail> {
    return this.request<IncidentCaseDetail>(`/projects/${encodeURIComponent(projectId)}/incidents/cases/${encodeURIComponent(caseId)}/transition`, {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  async addCaseNote(projectId: string, caseId: string, data: {
    content: string;
    note_type?: string;
    is_alternative_hypothesis?: boolean;
  }): Promise<{ status: string; note_id: string }> {
    return this.request<{ status: string; note_id: string }>(`/projects/${encodeURIComponent(projectId)}/incidents/cases/${encodeURIComponent(caseId)}/notes`, {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  async getCaseCorrelations(projectId: string, caseId: string): Promise<CorrelationExplanation> {
    return this.request<CorrelationExplanation>(`/projects/${encodeURIComponent(projectId)}/incidents/cases/${encodeURIComponent(caseId)}/correlations`);
  }

  async getCaseTimeline(projectId: string, caseId: string): Promise<TimelineEvent[]> {
    return this.request<TimelineEvent[]>(`/projects/${encodeURIComponent(projectId)}/incidents/cases/${encodeURIComponent(caseId)}/timeline`);
  }
}

export const api = new ApiService();
