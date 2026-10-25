export type SystemRole = 'ADMIN' | 'SECURITY_LEAD' | 'SECURITY_TESTER' | 'AUDITOR' | 'VIEWER';
export type ProjectRole = 'LEAD' | 'TESTER' | 'AUDITOR' | 'VIEWER';
export type TargetType = 'IP_ADDRESS' | 'CIDR' | 'DOMAIN' | 'URL';
export type AuthorizationStatus = 'PENDING' | 'AUTHORIZED' | 'REVOKED' | 'EXPIRED';

export type AssessmentStatus = 'QUEUED' | 'RUNNING' | 'COMPLETED' | 'FAILED' | 'CANCELLED' | 'TIMED_OUT' | 'PARTIAL';
export type FindingSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
export type FindingConfidence = 'CERTAIN' | 'FIRM' | 'TENTATIVE';

export interface User {
  id: string;
  email: string;
  full_name: string;
  system_role: SystemRole;
  is_active: boolean;
  created_at: string;
}

export interface Project {
  id: string;
  organization_id: string;
  name: string;
  description: string;
  is_active: boolean;
  created_at: string;
  updated_at: string;
  member_count?: number;
  scope_target_count?: number;
  scope_exclusion_count?: number;
}

export interface ScopeTarget {
  id: string;
  project_id: string;
  target_type: TargetType;
  target_value: string;
  description: string;
  authorization_status: AuthorizationStatus;
  authorization_evidence: string;
  authorized_by_id?: string | null;
  authorized_at?: string | null;
  expires_at?: string | null;
  revocation_reason?: string | null;
  revoked_by_id?: string | null;
  revoked_at?: string | null;
  created_by_id: string;
  created_at: string;
  updated_at: string;
}

export interface ScopeExclusion {
  id: string;
  project_id: string;
  target_type: TargetType;
  target_value: string;
  reason: string;
  created_by_id: string;
  created_at: string;
}

export interface ScopeValidationResult {
  target: string;
  normalized_target: string;
  is_authorized: boolean;
  status: 'AUTHORIZED' | 'EXCLUDED' | 'NOT_IN_SCOPE' | 'PENDING_APPROVAL' | 'REVOKED' | 'EXPIRED' | 'INVALID_TARGET';
  reason: string;
  matched_rule?: Record<string, any> | null;
  matched_exclusion?: Record<string, any> | null;
  evaluated_at: string;
}

export interface FindingEvidence {
  id: string;
  finding_id: string;
  evidence_type: string;
  payload: string;
  sha256_hash: string;
  observed_at: string;
}

export interface AssessmentFinding {
  id: string;
  job_id: string;
  project_id: string;
  target_value: string;
  title: string;
  description: string;
  severity: FindingSeverity;
  confidence: FindingConfidence;
  vuln_id?: string | null;
  cvss_score?: number | null;
  is_simulated: boolean;
  reproduction_steps: string;
  created_at: string;
  evidence_items?: FindingEvidence[];
}

export interface AssessmentJob {
  id: string;
  project_id: string;
  target_id?: string | null;
  target_input: string;
  adapter_name: string;
  adapter_version: string;
  status: AssessmentStatus;
  idempotency_key?: string | null;
  progress_pct: number;
  queued_at: string;
  started_at?: string | null;
  completed_at?: string | null;
  timeout_seconds: number;
  retry_count: number;
  max_retries: number;
  error_message?: string | null;
  is_simulated: boolean;
  created_by_id: string;
  config: Record<string, any>;
  summary_stats: Record<string, any>;
  created_at: string;
  updated_at: string;
}

export interface AuditEvent {
  id: string;
  timestamp: string;
  actor_id?: string | null;
  actor_email?: string | null;
  action: string;
  target_type: string;
  target_id?: string | null;
  project_id?: string | null;
  ip_address?: string | null;
  outcome: 'SUCCESS' | 'DENIED' | 'FAILURE';
  details: Record<string, any>;
}

export interface ReadinessResponse {
  status: 'ready' | 'not_ready';
  timestamp: string;
  checks: {
    database: boolean;
    migrations: boolean;
    storage_writable: boolean;
    details: Record<string, any>;
  };
}
