import type {
  User,
  Project,
  ScopeTarget,
  ScopeExclusion,
  ScopeValidationResult,
  AuditEvent,
  ReadinessResponse,
  AssessmentJob,
  AssessmentFinding,
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

  // Assessment Jobs & Findings (Phase 2)
  async listAssessments(projectId: string): Promise<AssessmentJob[]> {
    return this.request(`/projects/${projectId}/assessments/`);
  }

  async createAssessment(
    projectId: string,
    data: {
      target_input: string;
      adapter_name?: string;
      fixture_profile?: string;
      timeout_seconds?: number;
      idempotency_key?: string;
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
}

export const api = new ApiService();
