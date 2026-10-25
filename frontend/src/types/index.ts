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

export type FindingLifecycleStatus =
  | 'DETECTED'
  | 'NEEDS_VALIDATION'
  | 'CONFIRMED'
  | 'FALSE_POSITIVE'
  | 'INCONCLUSIVE'
  | 'REMEDIATION_PROPOSED'
  | 'REMEDIATION_APPROVED'
  | 'REMEDIATION_ATTEMPTED'
  | 'REMEDIATED_PENDING_VERIFICATION'
  | 'VERIFIED_CLOSED'
  | 'REOPENED'
  | 'ACCEPTED_RISK'
  | 'EXPIRED';

export interface FindingTransition {
  id: string;
  finding_id: string;
  from_status: FindingLifecycleStatus;
  to_status: FindingLifecycleStatus;
  actor_id?: string | null;
  reason: string;
  metadata_snapshot: Record<string, any>;
  created_at: string;
}

export interface VulnerabilityFinding {
  id: string;
  project_id: string;
  asset_id?: string | null;
  fingerprint: string;
  target_value: string;
  title: string;
  description: string;
  status: FindingLifecycleStatus;
  severity: FindingSeverity;
  confidence: FindingConfidence;
  vuln_id?: string | null;
  cvss_score?: number | null;
  is_simulated: boolean;
  reproduction_steps: string;
  first_detected_at: string;
  last_observed_at: string;
  occurrence_count: number;
  has_contradictions: boolean;
  contradiction_notes: Array<Record<string, any>>;
  assigned_to_id?: string | null;
  remediation_notes?: string | null;
  risk_accepted_at?: string | null;
  risk_accepted_by_id?: string | null;
  risk_accepted_reason?: string | null;
  risk_accepted_expires_at?: string | null;
  compensating_controls?: string | null;
  false_positive_at?: string | null;
  false_positive_by_id?: string | null;
  false_positive_reason?: string | null;
  verified_at?: string | null;
  verified_by_id?: string | null;
  verification_job_id?: string | null;
  verification_notes?: string | null;
  created_at: string;
  updated_at: string;
}

export interface VulnerabilityFindingDetail extends VulnerabilityFinding {
  transitions: FindingTransition[];
  observation_job_ids: string[];
  evidence_count: number;
}

export interface FindingStatsResponse {
  total: number;
  by_status: Record<string, number>;
  by_severity: Record<string, number>;
  unresolved_count: number;
  reopened_count: number;
  accepted_risk_count: number;
  contradiction_count: number;
}

export interface FindingTransitionRequest {
  to_status: FindingLifecycleStatus;
  reason: string;
  expires_at?: string | null;
  compensating_controls?: string | null;
  verification_job_id?: string | null;
  verification_notes?: string | null;
  remediation_notes?: string | null;
  assigned_to_id?: string | null;
}

export interface AcceptRiskRequest {
  reason: string;
  expires_at: string;
  compensating_controls: string;
}

export interface FalsePositiveRequest {
  reason: string;
}

export interface ProposeRemediationRequest {
  remediation_notes: string;
  assigned_to_id?: string | null;
}

// --- Phase 4: Asset Inventory & Knowledge Graph Types ---

export type AssetType =
  | 'HOST'
  | 'IP_ADDRESS'
  | 'DOMAIN'
  | 'HOSTNAME'
  | 'SERVICE'
  | 'SOFTWARE_COMPONENT'
  | 'WEB_APP'
  | 'API_ENDPOINT'
  | 'CLOUD_RESOURCE'
  | 'IDENTITY'
  | 'DATA_STORE'
  | 'SECURITY_CONTROL';

export type AssetCriticality = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export type AssetStatus = 'ACTIVE' | 'INACTIVE' | 'DECOMMISSIONED' | 'UNDER_REVIEW';

export interface AssetObservation {
  id: string;
  asset_id: string;
  project_id: string;
  assessment_job_id?: string | null;
  observation_source: string;
  adapter_version: string;
  observed_at: string;
  observed_attributes: Record<string, any>;
  evidence_hash?: string | null;
  confidence: number;
  validation_status: string;
  created_at: string;
}

export interface Asset {
  id: string;
  organization_id: string;
  project_id: string;
  asset_type: AssetType;
  name: string;
  canonical_identifier: string;
  environment: string;
  criticality: AssetCriticality;
  status: AssetStatus;
  attributes: Record<string, any>;
  source: string;
  confidence: number;
  first_seen_at: string;
  last_seen_at: string;
  is_ambiguous: boolean;
  ambiguity_reason?: string | null;
  created_at: string;
  updated_at: string;
}

export interface AssetDetail extends Asset {
  observations: AssetObservation[];
  finding_count: number;
  graph_node_id?: string | null;
  related_nodes_count: number;
}

export interface AssetCreateFixtureRequest {
  asset_type: AssetType;
  canonical_identifier: string;
  name?: string;
  environment?: string;
  criticality?: AssetCriticality;
  attributes?: Record<string, any>;
  source?: string;
  confidence?: number;
  is_ambiguous?: boolean;
  ambiguity_reason?: string;
}

export interface ResolveAmbiguityRequest {
  resolution_notes: string;
}

export type GraphNodeCategory =
  | 'ASSET'
  | 'SERVICE'
  | 'APPLICATION'
  | 'IDENTITY'
  | 'ROLE'
  | 'PERMISSION'
  | 'VULNERABILITY'
  | 'FINDING'
  | 'EVIDENCE'
  | 'SECURITY_CONTROL'
  | 'DEPENDENCY'
  | 'REMEDIATION'
  | 'ASSESSMENT';

export type RelationshipType =
  | 'RUNS'
  | 'DEPENDS_ON'
  | 'AUTHENTICATES_TO'
  | 'CAN_ACCESS'
  | 'EXPOSES'
  | 'AFFECTED_BY'
  | 'MITIGATES'
  | 'OBSERVED_AT'
  | 'VERIFIED_BY'
  | 'BELONGS_TO'
  | 'ASSOCIATED_WITH';

export type RelationshipStatus =
  | 'VERIFIED'
  | 'INFERRED'
  | 'HYPOTHETICAL'
  | 'STALE'
  | 'SUPERSEDED';

export interface GraphNode {
  id: string;
  project_id: string;
  category: GraphNodeCategory;
  label: string;
  entity_id?: string | null;
  entity_type?: string | null;
  properties: Record<string, any>;
  created_at: string;
}

export interface GraphRelationship {
  id: string;
  project_id: string;
  source_node_id: string;
  target_node_id: string;
  relationship_type: RelationshipType;
  status: RelationshipStatus;
  confidence: number;
  provenance: string;
  evidence_reference?: string | null;
  properties: Record<string, any>;
  observed_at: string;
  created_at: string;
}

export interface GraphStats {
  total_nodes: number;
  total_edges: number;
  nodes_by_category: Record<string, number>;
  edges_by_type: Record<string, number>;
}

export interface GraphNeighborhoodResponse {
  root_node_id: string;
  max_depth: number;
  nodes: GraphNode[];
  relationships: GraphRelationship[];
  truncated: boolean;
}

export interface GraphRelationshipCreate {
  source_node_id: string;
  target_node_id: string;
  relationship_type: RelationshipType;
  status?: RelationshipStatus;
  confidence?: number;
  provenance?: string;
  evidence_reference?: string;
  properties?: Record<string, any>;
}
