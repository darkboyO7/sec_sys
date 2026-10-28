export type SystemRole = 'ADMIN' | 'SECURITY_LEAD' | 'SECURITY_TESTER' | 'AUDITOR' | 'VIEWER';
export type ProjectRole = 'LEAD' | 'TESTER' | 'AUDITOR' | 'VIEWER';
export type TargetType = 'IP_ADDRESS' | 'CIDR' | 'DOMAIN' | 'URL';
export type AuthorizationStatus = 'PENDING' | 'AUTHORIZED' | 'REVOKED' | 'EXPIRED';

export type AssessmentStatus =
  | 'QUEUED'
  | 'PREFLIGHT'
  | 'READY'
  | 'RUNNING'
  | 'CANCELLATION_REQUESTED'
  | 'CANCELLED'
  | 'COMPLETED'
  | 'PARTIAL'
  | 'FAILED'
  | 'REJECTED'
  | 'TIMED_OUT';
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

export interface ProjectMember {
  id: string;
  user_id: string;
  role: ProjectRole;
  created_at: string;
  user_email?: string | null;
  user_full_name?: string | null;
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
  raw_sha256_hash?: string | null;
  is_truncated: boolean;
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
  idempotency_digest?: string | null;
  claimed_by?: string | null;
  worker_pid?: number | null;
  lock_version: number;
  progress_pct: number;
  policy_version: string;
  authorization_reference?: string | null;
  authorization_status: string;
  scope_snapshot: Record<string, any>;
  scope_snapshot_digest?: string | null;
  queued_at: string;
  preflight_at?: string | null;
  started_at?: string | null;
  heartbeat_at?: string | null;
  cancellation_requested_at?: string | null;
  completed_at?: string | null;
  failure_category?: string | null;
  attempt_count: number;
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

export interface AdapterCapability {
  name: string;
  version: string;
  declared_capabilities: string[];
  supported_profiles: string[];
  permitted_check_categories: string[];
  health: Record<string, any>;
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

// Phase 5: Contextual Risk Intelligence, Attack Paths, and Remediation
export type RiskPriority = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFORMATIONAL';

export interface RiskAssessment {
  id: string;
  project_id: string;
  finding_id: string;
  asset_id?: string | null;
  score: number;
  priority: RiskPriority;
  scoring_version: string;
  factor_breakdown: Record<string, any>;
  contributing_factors: string[];
  missing_factors: string[];
  evidence_references: string[];
  input_snapshot: Record<string, any>;
  calculated_at: string;
  is_superseded: boolean;
  superseded_at?: string | null;
  created_at: string;
}

export interface RiskSummary {
  total_assessed: number;
  by_priority: Record<string, number>;
  average_score: number;
  highest_score: number;
  critical_count: number;
  high_count: number;
  unresolved_risk_count: number;
}

export type PathVerificationStatus = 'VERIFIED' | 'MIXED_EVIDENCE' | 'HYPOTHETICAL' | 'STALE';

export interface AttackPathNode {
  id: string;
  label: string;
  category: string;
  entity_type?: string | null;
  properties: Record<string, any>;
}

export interface AttackPathRelationship {
  id: string;
  source_node_id: string;
  target_node_id: string;
  relationship_type: string;
  status: string;
  confidence: number;
  provenance: string;
}

export interface AttackPath {
  path_verification_status: PathVerificationStatus;
  cumulative_confidence: number;
  step_count: number;
  narrative: string;
  nodes: AttackPathNode[];
  relationships: AttackPathRelationship[];
  missing_evidence: string[];
}

export interface AttackPathAnalysisResponse {
  project_id: string;
  total_paths_found: number;
  max_depth_evaluated: number;
  truncated: boolean;
  paths: AttackPath[];
  methodology_disclaimer: string;
}

export type RecommendationStatus = 'PENDING_REVIEW' | 'APPROVED' | 'DEFERRED' | 'REJECTED';

export interface RemediationRecommendation {
  id: string;
  project_id: string;
  finding_id: string;
  asset_id?: string | null;
  title: string;
  action_type: string;
  description: string;
  rationale: string;
  qualitative_benefit: string;
  estimated_risk_reduction?: number | null;
  prerequisites: string[];
  operational_impact: string;
  rollback_procedure: string;
  verification_criteria: string;
  verification_test_profile?: string | null;
  requires_approval: boolean;
  approval_role: string;
  status: RecommendationStatus;
  reviewed_by_id?: string | null;
  reviewed_at?: string | null;
  review_notes?: string | null;
  execution_governance_stage?: string;
  external_change_ticket_ref?: string;
  created_at: string;
  updated_at: string;
}

// Phase 14: Independent Remediation Verification
export type VerificationOutcome = 'VERIFIED_FIXED' | 'STILL_VULNERABLE' | 'PARTIALLY_REMEDIATED' | 'INCONCLUSIVE';
export type VerificationMethod = 'SCANNER_RETEST' | 'MANUAL_PROBE' | 'CONFIG_INSPECTION' | 'CODE_AUDIT';

export interface RemediationVerification {
  id: string;
  project_id: string;
  finding_id: string;
  recommendation_id?: string | null;
  outcome: VerificationOutcome;
  verification_method: VerificationMethod;
  verification_criteria: string;
  verification_evidence_summary: string;
  notes?: string | null;
  verified_by_id?: string | null;
  verified_at: string;
}

// Phase 15: Reporting and Export
export type ReportType = 'EXECUTIVE' | 'TECHNICAL' | 'GOVERNANCE';
export type ReportFormat = 'JSON' | 'CSV' | 'HTML';

export interface ReportRecord {
  id: string;
  project_id: string;
  report_type: ReportType;
  format: ReportFormat;
  title: string;
  content_sha256: string;
  file_size_bytes: number;
  report_metadata: Record<string, any>;
  generated_by_id?: string | null;
  created_at: string;
}

// Phase 16: Historical Security Digital Twin
export interface SecuritySnapshot {
  id: string;
  project_id: string;
  name: string;
  description?: string | null;
  snapshot_timestamp: string;
  manifest_sha256: string;
  state_manifest: Record<string, any>;
  risk_summary: Record<string, any>;
  captured_by_id?: string | null;
  created_at: string;
}

export interface SnapshotDiffResponse {
  project_id: string;
  snapshot_a_id: string;
  snapshot_b_id: string;
  snapshot_a_timestamp: string;
  snapshot_b_timestamp: string;
  new_findings: any[];
  resolved_findings: any[];
  recurring_findings: any[];
  changed_findings: any[];
  unresolved_findings: any[];
  added_assets: any[];
  removed_assets: any[];
  risk_drift: Record<string, any>;
  overall_posture_trend: 'IMPROVED' | 'DEGRADED' | 'STABLE';
}

// Phase 17: Regression Detection and Change Intelligence
export type RegressionAlertType = 'RECURRING_FINDING' | 'REMEDIATION_REGRESSION' | 'STALE_EVIDENCE' | 'NEW_EXPOSURE';
export type AlertSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
export type AlertStatus = 'ACTIVE' | 'ACKNOWLEDGED' | 'RESOLVED' | 'DISMISSED';

export interface RegressionAlert {
  id: string;
  project_id: string;
  alert_type: RegressionAlertType;
  severity: AlertSeverity;
  status: AlertStatus;
  title: string;
  description: string;
  evidence_rationale: string;
  baseline_reference?: string | null;
  target_resource: string;
  fingerprint: string;
  resolution_notes?: string | null;
  acknowledged_by_id?: string | null;
  acknowledged_at?: string | null;
  created_at: string;
  updated_at: string;
}

export interface RegressionBaseline {
  id: string;
  project_id: string;
  snapshot_id?: string | null;
  name: string;
  is_active: boolean;
  risk_score_threshold_delta: number;
  evidence_stale_days: number;
  created_at: string;
}

// Phase 18: Controlled AI Security Analyst
export type AIDraftType = 'FINDING_EXPLANATION' | 'ASSESSMENT_SUMMARY' | 'REMEDIATION_DRAFT' | 'ATTACK_PATH_SUMMARY' | 'VALIDATION_CHECKLIST';
export type AIDraftStatus = 'DRAFT' | 'REVIEWED_APPROVED' | 'REVIEWED_REJECTED' | 'MODIFIED';

export interface AIAnalystDraft {
  id: string;
  project_id: string;
  draft_type: AIDraftType;
  status: AIDraftStatus;
  prompt_version: string;
  model_identifier: string;
  target_resource: string;
  title: string;
  summary: string;
  content: Record<string, any>;
  citations: Array<{ citation_type: string; resource_id: string; label: string; sha256_digest?: string | null }>;
  uncertainty_notes?: string | null;
  prompt_injection_flags?: string[] | null;
  is_reviewed: boolean;
  reviewed_by_id?: string | null;
  reviewed_at?: string | null;
  review_notes?: string | null;
  created_at: string;
}

// Phase 19: Controlled Learning and Model Governance
export type DatasetSplit = 'TRAIN' | 'VALIDATION' | 'TEST';
export type ModelStatus = 'CANDIDATE' | 'EVALUATED' | 'APPROVED' | 'ACTIVE' | 'DEPRECATED' | 'ROLLED_BACK';

export interface LearningDataset {
  id: string;
  project_id: string;
  name: string;
  version: string;
  dataset_hash: string;
  total_records: number;
  train_count: number;
  val_count: number;
  test_count: number;
  created_at: string;
}

export interface GovernedModel {
  id: string;
  project_id: string;
  model_name: string;
  version: string;
  model_type: string;
  status: ModelStatus;
  dataset_id: string;
  metrics: Record<string, any>;
  hyperparameters: Record<string, any>;
  is_active: boolean;
  activated_at?: string | null;
  approved_by_id?: string | null;
  approved_at?: string | null;
  approval_notes?: string | null;
  rollback_target_id?: string | null;
  created_at: string;
}

// Phase 19.1: Persistent Prediction Ledger
export type PredictionType =
  | 'FALSE_POSITIVE_LIKELIHOOD'
  | 'EXPLOITATION_PROBABILITY'
  | 'REMEDIATION_EFFORT_HOURS'
  | 'RISK_SCORE_FORECAST'
  | 'ATTACK_PATH_REACHABILITY';

export type PredictionEvaluationStatus =
  | 'PENDING'
  | 'VERIFIED_ACCURATE'
  | 'VERIFIED_INACCURATE'
  | 'INCONCLUSIVE'
  | 'EXPIRED'
  | 'INVALIDATED';

export interface PredictionLedgerEntry {
  id: string;
  project_id: string;
  model_id?: string | null;
  model_version: string;
  rule_version?: string | null;
  target_entity_type: string;
  target_entity_id: string;
  prediction_type: PredictionType;
  feature_snapshot: Record<string, any>;
  predicted_outcome: string;
  confidence_score: number;
  limitations?: string | null;
  decision_action_taken?: string | null;
  expected_evaluation_horizon?: string | null;
  actual_outcome?: string | null;
  outcome_evidence?: Record<string, any> | null;
  evaluation_status: PredictionEvaluationStatus;
  invalidation_reason?: string | null;
  evaluated_at?: string | null;
  evaluated_by_id?: string | null;
  created_at: string;
}

export interface ModelDriftMetrics {
  total_predictions: number;
  evaluated_count: number;
  pending_count: number;
  accurate_count: number;
  inaccurate_count: number;
  accuracy_rate: number;
  brier_score: number;
  drift_alert: boolean;
  status: string;
}

// Phase 20: Morph-State Adaptive Defense and Recovery
export type AdaptiveMorphState =
  | 'NORMAL'
  | 'ELEVATED_MONITORING'
  | 'INVESTIGATION_REQUIRED'
  | 'CONTAINMENT_RECOMMENDED'
  | 'RECOVERY_IN_PROGRESS'
  | 'RECOVERY_VERIFICATION_REQUIRED'
  | 'RECOVERY_COMPLETE'
  | 'MANUAL_REVIEW_REQUIRED';

export type AdaptiveTransitionTrigger =
  | 'INITIAL_PROVISIONING'
  | 'CRITICAL_FINDING_DETECTED'
  | 'REGRESSION_ALERT_RAISED'
  | 'CHANGE_AUTHORIZED'
  | 'VERIFICATION_FAILED'
  | 'VERIFICATION_PASSED'
  | 'POSTURE_CLEARED'
  | 'KILL_SWITCH_ENGAGED'
  | 'KILL_SWITCH_DISENGAGED'
  | 'MANUAL_OVERRIDE';

export interface MorphStatePosture {
  id: string;
  project_id: string;
  current_state: AdaptiveMorphState;
  previous_state?: AdaptiveMorphState | null;
  state_version: number;
  kill_switch_active: boolean;
  kill_switch_engaged_at?: string | null;
  kill_switch_reason?: string | null;
  monitoring_cadence_multiplier: number;
  active_recommendations: Array<Record<string, any>>;
  recovery_prerequisites: Array<Record<string, any>>;
  last_transition_at: string;
  last_evaluated_at: string;
}

export interface MorphStateHistory {
  id: string;
  posture_id: string;
  from_state: AdaptiveMorphState;
  to_state: AdaptiveMorphState;
  trigger: AdaptiveTransitionTrigger;
  evidence_rationale: string;
  triggered_by_id?: string | null;
  created_at: string;
}



// Phase 31: Enterprise Integration Architecture
export interface IntegrationHealth {
  name: string;
  version: string;
  status: string;
  details: Record<string, any>;
}

export interface KevEntry {
  cve_id: string;
  vendor_project: string;
  product: string;
  vulnerability_name: string;
  date_added: string;
  short_description: string;
  required_action: string;
  known_ransomware_campaign_use: boolean;
}

export interface WebhookTestRequest {
  event_type: string;
  target_url?: string;
  custom_payload?: Record<string, any>;
}

export interface WebhookDelivery {
  event_id: string;
  event_type: string;
  project_id: string;
  timestamp: string;
  signature: string;
  payload_size: number;
  payload: Record<string, any>;
  delivered: boolean;
  delivered_at: string;
}

export interface SiemExportResponse {
  project_id: string;
  format: string;
  total_events: number;
  stream: string[];
  exported_at: string;
}


// Prompt 6: Autonomous Security Intelligence & Closed-Loop Operations
export type ChangeType =
  | 'NEW_ASSET'
  | 'REMOVED_ASSET'
  | 'MODIFIED_ENDPOINT'
  | 'NEW_SERVICE'
  | 'CHANGED_HTTP_STATUS'
  | 'CHANGED_TLS_CONFIG'
  | 'NEW_VULNERABILITY'
  | 'RECURRING_VULNERABILITY'
  | 'RESOLVED_VULNERABILITY'
  | 'SEVERITY_CHANGED'
  | 'RISK_SCORE_CHANGED'
  | 'ATTACK_PATH_CHANGED'
  | 'REMEDIATION_OUTCOME'
  | 'INCONCLUSIVE_PROBE';

export type DecisionActionType =
  | 'REASSESS_CHANGED_ASSET'
  | 'VALIDATE_UNCERTAIN_FINDING'
  | 'INVESTIGATE_HIGH_IMPACT_EXPOSURE'
  | 'REFRESH_STALE_EVIDENCE'
  | 'PRIORITIZE_REMEDIATION'
  | 'VERIFY_APPLIED_FIX'
  | 'RECALCULATE_RISK_AND_PATHS'
  | 'REQUEST_HUMAN_REVIEW';

export type DecisionStatus =
  | 'PROPOSED'
  | 'APPROVED'
  | 'REJECTED'
  | 'EXECUTING'
  | 'EXECUTED'
  | 'SUPERSEDED'
  | 'FAILED';

export interface PostureChange {
  id: string;
  project_id: string;
  change_type: ChangeType;
  target_resource: string;
  title: string;
  previous_state: Record<string, any>;
  new_state: Record<string, any>;
  evidence_summary: string;
  confidence: number;
  is_confirmed: boolean;
  created_at: string;
}

export interface SecurityDecision {
  id: string;
  project_id: string;
  action_type: DecisionActionType;
  status: DecisionStatus;
  title: string;
  triggering_observation: string;
  evidence_considered: Record<string, any>;
  selected_action: string;
  rationale: string;
  confidence: number;
  uncertainty: number;
  target_id?: string | null;
  target_resource?: string | null;
  job_id?: string | null;
  required_approval_role?: string | null;
  approved_by_id?: string | null;
  approved_at?: string | null;
  executed_at?: string | null;
  execution_outcome?: Record<string, any> | null;
  posture_improvement_measured?: Record<string, any> | null;
  created_at: string;
}

export interface ClosedLoopOverview {
  project_id: string;
  active_posture: string;
  total_posture_changes: number;
  unresolved_changes: number;
  proposed_decisions_count: number;
  executed_decisions_count: number;
  recent_changes: PostureChange[];
  pending_decisions: SecurityDecision[];
  verified_improvements_count: number;
}

export interface PlannedCheck {
  check_id: string;
  target: string;
  adapter_name: string;
  action: string;
  priority: string;
  reason_category: string;
  rationale: string;
  source_evidence: Record<string, any>;
}

export interface SkippedCheck {
  target: string;
  adapter_name: string;
  action: string;
  skip_reason: string;
  rationale: string;
  source_evidence: Record<string, any>;
}

export interface AdaptivePlan {
  id: string;
  project_id: string;
  plan_name: string;
  status: 'GENERATED' | 'PARTIALLY_EXECUTED' | 'COMPLETED' | 'SUPERSEDED' | 'CANCELLED';
  scan_budget: number;
  total_recommended: number;
  total_skipped: number;
  recommended_checks: PlannedCheck[];
  skipped_checks: SkippedCheck[];
  execution_summary: Record<string, any>;
  created_at: string;
  updated_at: string;
}

export interface StaleAssetInfo {
  asset_id: string;
  name: string;
  canonical_identifier: string;
  asset_type: string;
  criticality: string;
  last_seen_at?: string | null;
  days_since_assessment?: number | null;
  staleness_reason: string;
}

export interface CoverageAudit {
  total_assets: number;
  covered_assets_count: number;
  stale_assets_count: number;
  coverage_percentage: number;
  stale_assets: StaleAssetInfo[];
  unassessed_scope_targets: Array<{ target_id: string; target: string; target_type: string; reason: string }>;
  failing_probes: Array<{ job_id: string; target_input: string; adapter_name: string; status: string; failure_category?: string | null }>;
  stale_days_threshold: number;
}

export interface HighestPriorityFinding {
  finding_id: string;
  title: string;
  target_value: string;
  severity: string;
  confidence: string;
  status: string;
  risk_score: number;
  inherent_score?: number | null;
  residual_score?: number | null;
  priority: string;
  scoring_version: string;
  contributing_factors: string[];
  missing_factors: string[];
  uncertainty_range: Record<string, any>;
}

export interface ProjectIntelligenceSummary {
  project_id: string;
  project_name: string;
  timestamp: string;
  risk_summary: {
    total_findings: number;
    active_findings: number;
    risk_distribution: Record<string, number>;
    average_risk_score: number;
    highest_priority_findings: HighestPriorityFinding[];
  };
  coverage_audit: CoverageAudit;
  attack_paths: {
    total_relationships: number;
    verified_paths_count: number;
    hypothetical_paths_count: number;
    critical_chokepoints: Array<Record<string, any>>;
  };
  remediation_intelligence: {
    total_recommendations: number;
    total_verifications: number;
    verified_fixed_count: number;
    failed_verifications_count: number;
    inconclusive_verifications_count: number;
    remediation_verification_rate: number;
  };
  monitoring_and_changes: {
    unhandled_changes_count: number;
    recent_changes: Array<Record<string, any>>;
  };
  adaptive_plan?: AdaptivePlan | null;
  learning_pipeline: {
    model_version: string;
    model_status: string;
    is_rules_baseline: boolean;
    dataset_count: number;
    drift_metrics: Record<string, any>;
    learning_data_sufficiency: string;
    inconclusive_rate: number;
  };
  data_provenance: Record<string, any>;
}

// -----------------------------------------------------------------------------
// Unified Autonomous Security Operations (Prompt 11)
// -----------------------------------------------------------------------------
export interface AutonomousPolicy {
  id: string;
  project_id: string;
  policy_version: string;
  is_active: boolean;
  is_suspended: boolean;
  suspension_reason?: string | null;
  suspended_at?: string | null;
  permitted_assessment_types: string[];
  intensity: 'LOW' | 'NORMAL' | 'AGGRESSIVE';
  max_concurrency: number;
  rate_limit_rps: number;
  permitted_time_windows: Array<{ start_hour: number; end_hour: number }>;
  max_daily_budget: number;
  daily_budget_spent: number;
  permitted_remediation_actions: string[];
  require_approval_for_disruptive: boolean;
  require_approval_for_remediation: boolean;
  max_retries: number;
  failure_threshold: number;
  consecutive_failures: number;
}

export interface DecisionLedgerEntry {
  id: string;
  project_id: string;
  decision_type: string;
  decision_outcome: string;
  initiating_event: string;
  target_type: string;
  target_id?: string | null;
  target_resource?: string | null;
  policy_version: string;
  reason: string;
  evidence_references: Array<Record<string, any>>;
  details: Record<string, any>;
  actor_id?: string | null;
  created_at: string;
}

export interface SecurityNotification {
  id: string;
  project_id: string;
  event_type: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  title: string;
  summary: string;
  deduplication_key: string;
  status: 'PENDING' | 'DELIVERED' | 'FAILED' | 'SUPPRESSED_DUPLICATE' | 'UNCONFIGURED';
  retry_count: number;
  max_retries: number;
  last_attempt_at?: string | null;
  error_message?: string | null;
  delivery_metadata: Record<string, any>;
  created_at: string;
}

export interface OperationalSLOMetric {
  metric_name: string;
  observed_value: number | null;
  target_threshold: number;
  unit: string;
  status: 'MET' | 'BREACHED' | 'MISSING_DATA' | 'UNCONFIGURED';
}

export interface OperationalSLOResponse {
  project_id: string;
  window_days: number;
  generated_at: string;
  overall_health_pct: number | null;
  slos: Record<string, OperationalSLOMetric>;
  raw_telemetry: Record<string, any>;
}

export interface OperationsDashboard {
  project_id: string;
  timestamp: string;
  policy: Record<string, any>;
  operations_summary: Record<string, any>;
  slo_health: {
    overall_health_pct: number | null;
    slos: Record<string, OperationalSLOMetric>;
  };
  recent_decisions: DecisionLedgerEntry[];
  recent_notifications: SecurityNotification[];
  notification_provider: {
    project_id: string;
    webhook_configured: boolean;
    provider_status: string;
    destination_preview?: string | null;
    counts: Record<string, number>;
  };
}

// Prompt 12: Self-Diagnostics, Recovery, and Continuous Improvement
export interface ComponentHealth {
  component_id: string;
  name: string;
  status: 'HEALTHY' | 'DEGRADED' | 'UNHEALTHY' | 'UNKNOWN' | 'NOT_CONFIGURED';
  last_successful_check?: string | null;
  last_failure?: string | null;
  message: string;
  dependencies: Record<string, any>;
  is_live_check: boolean;
  details: Record<string, any>;
}

export interface SystemHealthData {
  timestamp: string;
  overall_status: string;
  healthy_count: number;
  degraded_count: number;
  unhealthy_count: number;
  components: Record<string, ComponentHealth>;
  environment: string;
  version: string;
}

export interface DiagnosticFinding {
  id?: string;
  check_id: string;
  category: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  confidence: 'CONFIRMED' | 'SUSPECTED' | 'UNAVAILABLE';
  title: string;
  description: string;
  observed_issue: string;
  affected_entities: any[];
  recommended_action: string;
  recovery_action_available?: string | null;
}

export interface DiagnosticRun {
  run_id: string;
  project_id: string;
  timestamp: string;
  total_checks: number;
  passed_checks: number;
  warning_checks: number;
  failed_checks: number;
  summary: string;
  findings: DiagnosticFinding[];
}

export interface RecoveryActionHistoryRecord {
  id: string;
  action_type: string;
  target_entity_type: string;
  target_entity_id?: string | null;
  target_resource?: string | null;
  executed_by_id?: string | null;
  execution_timestamp: string;
  reason: string;
  outcome: 'SUCCESS' | 'PARTIAL_SUCCESS' | 'FAILED' | 'INCONCLUSIVE';
  pre_condition: Record<string, any>;
  post_condition: Record<string, any>;
  verification_notes: string;
  verification_timestamp: string;
  ledger_record_id?: string | null;
}

export interface FailurePattern {
  id: string;
  pattern_key: string;
  category: string;
  occurrence_count: number;
  first_observed_at: string;
  last_observed_at: string;
  affected_targets: string[];
  sample_error_message: string;
  advisory_recommendation: string;
}
