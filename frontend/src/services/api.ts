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

  logout() {
    this.setToken(null);
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

  // Phase 15: Reporting & Export
  async generateReport(
    projectId: string,
    data: { report_type: string; format?: string; title: string }
  ): Promise<any> {
    return this.request(`/projects/${projectId}/reports/generate`, {
      method: 'POST',
      body: JSON.stringify(data),
    });
  }

  async listReports(projectId: string): Promise<any[]> {
    return this.request(`/projects/${projectId}/reports`);
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
}

export const api = new ApiService();
