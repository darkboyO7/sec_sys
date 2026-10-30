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
  event_hash?: string | null;
  prev_event_hash?: string | null;
}

export interface ReadinessResponse {
  status: 'ready' | 'not_ready';
  timestamp: string;
  degraded?: boolean;
  message?: string;
  checks: {
    database: boolean;
    migrations: boolean;
    storage_writable: boolean;
    details: Record<string, any>;
  };
}

export type OperationalHealthState = 'HEALTHY' | 'DEGRADED' | 'UNAVAILABLE' | 'UNKNOWN';

export interface DependencyItemCheck {
  name: string;
  critical: boolean;
  status: 'healthy' | 'degraded' | 'unhealthy' | 'unknown';
  latency_ms: number;
  message?: string;
  details?: Record<string, any>;
}

export interface DependencyHealthResponse {
  status: 'healthy' | 'degraded' | 'unhealthy';
  critical_healthy: boolean;
  timestamp: string;
  dependencies: Record<string, DependencyItemCheck>;
  summary: string;
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
  validation_status?: FindingValidationStatus | null;
  validation_method?: string | null;
  validation_evidence_ref?: string | null;
  validation_notes?: string | null;
  validation_updated_at?: string | null;
  recurrence_detected?: boolean;
  recurrence_count?: number;
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
  monitoring_run_id?: string | null;
  observation_source: string;
  adapter_version: string;
  observed_at: string;
  observed_attributes: Record<string, any>;
  evidence_hash?: string | null;
  confidence: number;
  validation_status: string;
  authorization_context?: Record<string, any>;
  is_simulated?: boolean;
  completeness?: number;
  collection_errors?: Record<string, any>[];
  observation_schema_version?: string;
  is_successful_absence?: boolean;
  dedup_hash?: string | null;
  created_at: string;
}

export interface AssetIdentifierAlias {
  id: string;
  asset_id: string;
  project_id: string;
  identifier_type: string;
  identifier_value: string;
  is_primary: boolean;
  confidence: number;
  evidence_ref?: string | null;
  first_observed_at: string;
  last_observed_at: string;
  is_active: boolean;
  disassociation_reason?: string | null;
  created_at: string;
  updated_at: string;
}

export interface AssetIdentityMergeRecord {
  id: string;
  project_id: string;
  target_asset_id: string;
  merged_asset_id: string;
  merged_canonical_identifier: string;
  merged_asset_type: string;
  merge_rationale: string;
  confidence: number;
  actor_id?: string | null;
  is_reversed: boolean;
  reversed_at?: string | null;
  reversed_by_id?: string | null;
  reversal_notes?: string | null;
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
  last_successful_observation_at?: string | null;
  completeness_score?: number;
  freshness_status?: string;
  consecutive_absences?: number;
  confirmed_absent?: boolean;
  is_ambiguous: boolean;
  ambiguity_reason?: string | null;
  created_at: string;
  updated_at: string;
}

export interface AssetDetail extends Asset {
  observations: AssetObservation[];
  aliases?: AssetIdentifierAlias[];
  finding_count: number;
  graph_node_id?: string | null;
  related_nodes_count: number;
}

export type DriftType =
  | 'NEW_AUTHORIZED_ASSET'
  | 'ASSET_UNOBSERVED_WARNING'
  | 'ASSET_CONFIRMED_ABSENT'
  | 'IP_ASSOCIATION_CHANGED'
  | 'HOSTNAME_ASSOCIATION_CHANGED'
  | 'SERVICE_ADDED'
  | 'SERVICE_REMOVED'
  | 'SERVICE_METADATA_CHANGED'
  | 'VERSION_CHANGED'
  | 'SECURITY_CONFIG_CHANGED'
  | 'FINDING_APPEARED'
  | 'FINDING_DISAPPEARED'
  | 'EVIDENCE_CONFIDENCE_CHANGED';

export type DriftMateriality = 'MATERIAL' | 'IMMATERIAL' | 'INCONCLUSIVE';

export type ReassessmentPriority = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

export type ReassessmentStatus =
  | 'PROPOSED'
  | 'DEFERRED'
  | 'APPROVED'
  | 'REJECTED'
  | 'QUEUED'
  | 'COMPLETED'
  | 'FAILED';

export interface ExposureDriftRecord {
  id: string;
  project_id: string;
  asset_id?: string | null;
  drift_type: DriftType;
  materiality: DriftMateriality;
  materiality_reason: string;
  target_resource: string;
  title: string;
  previous_observation_id?: string | null;
  current_observation_id?: string | null;
  previous_state: Record<string, any>;
  new_state: Record<string, any>;
  evidence_references: string[];
  confidence: number;
  is_resolved: boolean;
  security_impact_summary?: string | null;
  reassessment_recommended: boolean;
  dedup_key?: string | null;
  detected_at: string;
  evaluated_at: string;
  acted_upon_at?: string | null;
  created_at: string;
}

export interface ReassessmentProposal {
  id: string;
  project_id: string;
  asset_id?: string | null;
  drift_record_id?: string | null;
  target_input: string;
  adapter_name: string;
  fixture_profile: string;
  priority: ReassessmentPriority;
  status: ReassessmentStatus;
  rationale: string;
  scope_authorized: boolean;
  scope_validation_details: Record<string, any>;
  requires_human_approval: boolean;
  approved_by_id?: string | null;
  approved_at?: string | null;
  rejection_reason?: string | null;
  scheduled_job_id?: string | null;
  attempt_count: number;
  max_attempts: number;
  last_error?: string | null;
  created_at: string;
}

export interface ProjectDriftOverview {
  total_assets: number;
  freshness_distribution: Record<string, number>;
  drift_materiality_distribution: Record<string, number>;
  drift_type_distribution: Record<string, number>;
  reassessment_proposals_distribution: Record<string, number>;
  average_collection_completeness: number;
  total_drift_records: number;
  total_reassessment_proposals: number;
  governance_warnings: string[];
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

// Phase 15 & Prompt 32: Reporting, Export & Verifiable Assessment Bundles
export type ReportType = 'EXECUTIVE' | 'TECHNICAL' | 'GOVERNANCE' | 'ASSESSMENT_CANONICAL';
export type ReportFormat = 'JSON' | 'CSV' | 'HTML' | 'BUNDLE';

export interface CanonicalFindingRecord {
  id: string;
  fingerprint: string;
  title: string;
  description: string;
  severity: string;
  confidence: string;
  cvss_score?: number | null;
  target: string;
  status: string;
  remediation_status?: string | null;
  retest_outcome?: string | null;
  is_simulated: boolean;
  evidence_refs: string[];
  has_missing_evidence: boolean;
  contradictory_evidence_noted: boolean;
  uncertainty_rationale?: string | null;
  first_detected_at?: string | null;
  last_observed_at?: string | null;
}

export interface CanonicalEvidenceRef {
  evidence_id: string;
  finding_id: string;
  evidence_type: string;
  sha256_digest: string;
  collected_at?: string | null;
  source: string;
  redacted: boolean;
}

export interface CanonicalAssetRecord {
  id: string;
  name: string;
  target_value: string;
  asset_type: string;
  criticality: string;
  has_active_findings: boolean;
  assessment_covered: boolean;
}

export interface CanonicalRemediationRecord {
  id: string;
  finding_id: string;
  title: string;
  action_type: string;
  governance_stage: string;
  status: string;
}

export interface CanonicalRetestRecord {
  id: string;
  finding_id: string;
  outcome: string;
  verification_method: string;
  verified_at?: string | null;
}

export interface ReportCoverageSummary {
  assessment_id: string;
  target_input: string;
  status: string;
  total_targets_assessed: number;
  total_checks_attempted: number;
  total_checks_completed: number;
  checks_failed_count: number;
  skipped_checks: string[];
  missing_evidence_count: number;
  coverage_gap_identified: boolean;
  is_incomplete: boolean;
  disclaimer: string;
}

export interface AssessmentReportManifest {
  schema_version: string;
  report_id: string;
  project_id: string;
  assessment_id: string;
  title: string;
  assessment_status: string;
  started_at?: string | null;
  completed_at?: string | null;
  generated_at: string;
  methodology: Record<string, any>;
  scope_summary: Record<string, any>;
  coverage_summary: ReportCoverageSummary;
  finding_counts_by_severity: Record<string, number>;
  findings: CanonicalFindingRecord[];
  assets: CanonicalAssetRecord[];
  remediation_summary: CanonicalRemediationRecord[];
  retest_verifications: CanonicalRetestRecord[];
  evidence_manifest: CanonicalEvidenceRef[];
  limitations: string[];
  provenance_digest: string;
}

export interface BundleVerificationResult {
  is_valid: boolean;
  manifest_version?: string | null;
  bundle_version?: string | null;
  assessment_id?: string | null;
  project_id?: string | null;
  file_count: number;
  total_decompressed_bytes: number;
  checked_files: string[];
  corrupted_files: string[];
  missing_files: string[];
  violations: string[];
  assessment_summary?: {
    report_id?: string;
    assessment_id?: string;
    status?: string;
    title?: string;
    findings_count?: number;
    severity_distribution?: Record<string, number>;
    coverage_gap?: boolean;
  } | null;
  inspection_mode: string;
}

export interface ReportRecord {
  id: string;
  project_id: string;
  assessment_id?: string | null;
  report_type: ReportType;
  format?: ReportFormat;
  report_format?: ReportFormat;
  title: string;
  content_sha256?: string;
  report_sha256?: string;
  file_size_bytes?: number;
  content_bytes?: number;
  item_count?: number;
  report_metadata?: Record<string, any>;
  generated_by_id?: string | null;
  created_at?: string;
  generated_at?: string;
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

// Prompt 38: Controlled Experiments, Model Evaluation and Defensible Adaptive Learning
export interface LearningInventoryItem {
  component_name: string;
  prediction_type: string;
  objective: string;
  input_features: string[];
  decision_impact: string;
  governance_mode: string;
  online_self_tuning: boolean;
}

export interface ControlledExperiment {
  id: string;
  project_id: string;
  model_id: string;
  dataset_id: string;
  experiment_name: string;
  split_strategy: string;
  training_sample_size: number;
  test_sample_size: number;
  class_imbalance_ratio: number;
  data_leakage_detected: boolean;
  leakage_details: string[];
  insufficient_data_flag: boolean;
  baseline_model_id?: string | null;
  metrics: Record<string, any>;
  distribution_shift_detected: boolean;
  decision_outcome: 'ACCEPTED' | 'REJECTED_INFERIOR_METRICS' | 'REJECTED_LEAKAGE' | 'REJECTED_INSUFFICIENT_DATA' | 'PENDING_REVIEW';
  decision_rationale?: string | null;
  created_at: string;
}

export interface DistributionShiftResult {
  model_id: string;
  project_id: string;
  distribution_shift_detected: boolean;
  evaluated_count: number;
  accuracy_rate: number;
  brier_score: number;
  status: string;
  recommended_action: string;
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

// Autonomous Security Orchestration (Prompt 15)
export type OrchestrationState =
  | 'IDLE'
  | 'EVENT_RECEIVED'
  | 'CONTEXT_GATHERED'
  | 'DECISION_PENDING'
  | 'AWAITING_APPROVAL'
  | 'ACTION_QUEUED'
  | 'ACTION_RUNNING'
  | 'VERIFYING_OUTCOME'
  | 'COMPLETED'
  | 'PARTIALLY_COMPLETED'
  | 'FAILED'
  | 'SUSPENDED';

export type OrchestrationEventType =
  | 'ASSET_DISCOVERED'
  | 'CONFIG_CHANGED'
  | 'SCAN_COMPLETED'
  | 'FINDING_DETECTED'
  | 'REMEDIATION_APPLIED'
  | 'INTEGRITY_ALERT'
  | 'DIAGNOSTIC_FAILURE'
  | 'SCHEDULED_POLL'
  | 'MANUAL_TRIGGER';

export type OrchestrationActionType =
  | 'REASSESS_CHANGED_ASSET'
  | 'REFRESH_STALE_EVIDENCE'
  | 'RETRY_FAILED_ASSESSMENT'
  | 'RECALCULATE_RISK_AND_PATHS'
  | 'RECOMMEND_REMEDIATION'
  | 'REQUEST_HUMAN_APPROVAL'
  | 'SCHEDULE_INDEPENDENT_RETEST'
  | 'RUN_DIAGNOSTICS'
  | 'SUSPEND_ACTIVITY'
  | 'NO_ACTION_REQUIRED';

export interface OrchestrationEvent {
  id: string;
  project_id: string;
  event_type: OrchestrationEventType;
  event_source: string;
  dedup_key: string;
  target_resource: string;
  payload: Record<string, any>;
  status: 'RECEIVED' | 'PROCESSED' | 'DEDUPLICATED' | 'DEFERRED' | 'REJECTED' | 'FAILED';
  coalesced_count: number;
  received_at: string;
  processed_at?: string | null;
  rejection_reason?: string | null;
}

export interface OrchestrationWorkflow {
  id: string;
  project_id: string;
  state: OrchestrationState;
  trigger_event_id?: string | null;
  workflow_type: string;
  target_resource: string;
  context_data: Record<string, any>;
  recommended_action?: OrchestrationActionType | null;
  action_rationale?: string | null;
  confidence: number;
  uncertainty: number;
  required_approval_role?: string | null;
  approved_by_id?: string | null;
  approved_at?: string | null;
  locked_by?: string | null;
  attempt_count: number;
  max_retries: number;
  suspension_reason?: string | null;
  failure_reason?: string | null;
  partial_results: Record<string, any>;
  outcome_status?: string | null;
  outcome_measurement: Record<string, any>;
  started_at?: string | null;
  completed_at?: string | null;
  created_at: string;
  updated_at: string;
}

export interface OrchestrationDashboard {
  project_id: string;
  timestamp: string;
  summary: {
    total_workflows: number;
    active_workflows: number;
    pending_approvals: number;
    suspended_workflows: number;
    failed_workflows: number;
    completed_workflows: number;
  };
  active_workflows: OrchestrationWorkflow[];
  recent_events: OrchestrationEvent[];
  pending_approvals: OrchestrationWorkflow[];
}

export interface AdaptiveOptimization {
  id: string;
  project_id: string;
  optimization_name: string;
  objective: string;
  evaluation_metric: string;
  baseline_value: number;
  evaluated_value: number;
  threshold_value: number;
  dataset_summary: Record<string, any>;
  is_accepted: boolean;
  rejection_reason?: string | null;
  evaluated_by_model: string;
  evaluated_at: string;
}

export interface DependencyInvalidation {
  id: string;
  project_id: string;
  source_entity_type: string;
  source_entity_id: string;
  invalidation_type: string;
  invalidated_targets: Array<Record<string, any>>;
  recalculation_status: 'PENDING' | 'RECALCULATED' | 'SUPERSEDED' | 'FAILED';
  provenance: Record<string, any>;
  recalculated_at?: string | null;
  created_at: string;
}

// Prompt 19: Detection Quality & Evidence-Driven Intelligence
export type FindingValidationStatus =
  | 'DETECTED'
  | 'EVIDENCE_PENDING'
  | 'EVIDENCE_SUPPORTED'
  | 'INDEPENDENTLY_REPRODUCED'
  | 'CONFIRMED_TRUE_POSITIVE'
  | 'CONFIRMED_FALSE_POSITIVE'
  | 'INCONCLUSIVE'
  | 'UNABLE_TO_VERIFY'
  | 'RESOLVED_AFTER_RETEST';

export interface QualityOverviewResponse {
  project_id: string;
  project_name: string;
  generated_at: string;
  sample_sizes: {
    total_canonical_findings: number;
    total_raw_observations: number;
    reviewed_findings: number;
    remediated_findings: number;
    evidence_supported_findings: number;
    independently_reproduced_findings: number;
  };
  disclosed_denominators: {
    evidence_completeness: string;
    reproduction_rate: string;
    confirmed_false_positive_rate: string;
    retest_recurrence_rate: string;
    duplicate_observation_rate: string;
  };
  metrics: {
    evidence_completeness_rate: number;
    independent_reproduction_rate: number;
    confirmed_false_positive_rate: number;
    inconclusive_finding_rate: number;
    retest_recurrence_rate: number;
    duplicate_observation_rate: number;
  };
  validation_status_distribution: Record<string, number>;
  evaluation_period: {
    earliest_observed_at: string | null;
    latest_observed_at: string | null;
  };
  quality_warnings: string[];
}

export interface FixtureBenchmarkScenarioResult {
  fixture_type: string;
  fixture_version: string;
  is_synthetic: boolean;
  sample_size?: number;
  true_positives?: number;
  false_positives?: number;
  true_negatives?: number;
  false_negatives?: number;
  precision?: number;
  recall?: number;
  false_positive_rate?: number;
  false_negative_rate?: number;
  ground_truth_status: string;
  reported_validation_status?: string;
  valid_failure_handling?: boolean;
  valid_ambiguity_handling?: boolean;
  notes?: string;
}

export interface FixtureBenchmarksResponse {
  project_id: string;
  framework_version: string;
  benchmark_scenarios: Record<string, FixtureBenchmarkScenarioResult>;
}

export interface FindingValidationTransitionRequest {
  to_status: FindingValidationStatus;
  validation_method?: string;
  reason: string;
  evidence_ref?: string | null;
  is_ai_generated?: boolean;
}

export interface FindingProvenanceResponse {
  finding_id: string;
  fingerprint: string;
  title: string;
  severity: string;
  confidence: string;
  operational_status: string;
  validation_status: string | null;
  is_simulated: boolean;
  evidence_quality_score: number;
  cryptographic_integrity_verified: boolean;
  first_observed_at: string | null;
  last_observed_at: string | null;
  observations_count: number;
  observations: Array<{
    observation_id: string;
    job_id: string;
    adapter_name: string;
    adapter_version: string;
    created_at: string | null;
    is_simulated: boolean;
    evidence_items: Array<{
      evidence_id: string;
      evidence_type: string;
      recorded_sha256: string;
      computed_sha256: string;
      is_cryptographically_valid: boolean;
      is_simulated: boolean;
      payload_preview: string;
    }>;
  }>;
  validation_history: Array<{
    from_status: string;
    to_status: string;
    validation_method: string;
    actor_id: string;
    reason: string;
    evidence_ref: string | null;
    created_at: string | null;
    metadata_snapshot: Record<string, any> | null;
  }>;
}

// ---------------------------------------------------------------------------
// Prompt 21: Knowledge Integrity, Explainable Attack Paths & Reconciliation
// ---------------------------------------------------------------------------

export type EpistemicStatus =
  | 'OBSERVED_FACT'
  | 'CORROBORATED_FACT'
  | 'DERIVED_CONCLUSION'
  | 'HYPOTHESIS'
  | 'UNKNOWN'
  | 'CONTRADICTED'
  | 'STALE'
  | 'INVALIDATED';

export type AttackPathStatus =
  | 'VERIFIED'
  | 'PLAUSIBLE'
  | 'HYPOTHETICAL'
  | 'STALE'
  | 'CONTRADICTED'
  | 'INVALIDATED';

export interface KnowledgeDependencyRecord {
  id: string;
  project_id: string;
  source_entity_type: string;
  source_entity_id: string;
  source_version?: string | null;
  dependent_entity_type: string;
  dependent_entity_id: string;
  dependency_type: string;
  is_valid: boolean;
  invalidated_at?: string | null;
  invalidation_reason?: string | null;
  created_at: string;
  updated_at: string;
}

export interface AttackPathStepExplanation {
  step: number;
  from_node: { id: string; label: string; category: string };
  to_node: { id: string; label: string; category: string };
  edge_id: string;
  relationship_type: string;
  status: string;
  epistemic_status: string;
  confidence: number;
  is_authoritative: boolean;
  is_simulated: boolean;
  supporting_evidence: string;
  required_assumptions: string[];
  unverified_conditions: string[];
  invalidation_triggers: string[];
}

export interface ExplainableAttackPath {
  id: string;
  project_id: string;
  name: string;
  start_node_id: string;
  target_node_id: string;
  path_status: AttackPathStatus;
  cumulative_confidence: number;
  risk_impact_score: number;
  step_count: number;
  is_scope_compliant: boolean;
  scope_violations: Array<{
    node_id: string;
    node_label: string;
    exclusion_id: string;
    exclusion_value: string;
    reason: string;
  }>;
  steps_explanation: AttackPathStepExplanation[];
  chokepoints: any[];
  calculation_version: string;
  input_hashes: Record<string, any>;
  is_stale: boolean;
  is_invalidated: boolean;
  invalidation_reason?: string | null;
  created_at: string;
  updated_at: string;
}

export interface KnowledgeReconciliationAudit {
  id: string;
  project_id: string;
  run_by_user_id?: string | null;
  status: 'COMPLETED' | 'IN_PROGRESS' | 'FAILED' | 'PARTIALLY_REPAIRED';
  total_nodes_audited: number;
  total_relationships_audited: number;
  dangling_references_detected: number;
  duplicate_relationships_detected: number;
  invalid_types_detected: number;
  missing_provenance_detected: number;
  stale_conclusions_detected: number;
  scope_violations_detected: number;
  contradictions_detected: number;
  auto_repaired_count: number;
  manual_review_required_count: number;
  reconciliation_log: Array<{
    item_type: string;
    id?: string;
    severity: string;
    description: string;
    auto_repairable: boolean;
    repaired: boolean;
  }>;
  started_at: string;
  completed_at?: string | null;
}

export interface FindingEpistemicExplanation {
  finding_id: string;
  title: string;
  severity: string;
  lifecycle_status: string;
  validation_status: string;
  confidence: string;
  epistemic_status: string;
  is_authoritative: boolean;
  is_simulated: boolean;
  evidence_items: any[];
  validation_history: any[];
  contextual_risk?: {
    score: number;
    inherent_score?: number;
    residual_score?: number;
    priority: string;
    scoring_version: string;
    prior_score?: number | null;
    score_delta?: number | null;
    delta_reasons: string[];
    qualitative_label: string;
    unverified_penalty: number;
    is_invalidated: boolean;
    invalidation_reason?: string | null;
    contributing_factors: string[];
    missing_factors: string[];
    uncertainty_range: Record<string, any>;
  } | null;
  dependent_attack_paths: any[];
  dependencies: KnowledgeDependencyRecord[];
}



// ---------------------------------------------------------------------------
// Prompt 22: Multi-Tenant Governance, Separation of Duties & Approvals
// ---------------------------------------------------------------------------

export type ApprovalWorkflowType =
  | 'SCOPE_AUTHORIZATION'
  | 'SECURITY_DECISION'
  | 'REMEDIATION_CHANGE'
  | 'RISK_ACCEPTANCE'
  | 'MODEL_PROMOTION'
  | 'DATA_PURGE';

export type GovernanceApprovalStatus =
  | 'PENDING'
  | 'APPROVED'
  | 'REJECTED'
  | 'EXECUTED'
  | 'REVOKED'
  | 'INVALIDATED';

export interface ProjectGovernancePolicy {
  id: string;
  project_id: string;
  enforce_separation_of_duties: boolean;
  allow_self_approval_override: boolean;
  require_two_person_rule_for_purge: boolean;
  require_lead_for_scope_authorization: boolean;
  require_lead_for_risk_acceptance: boolean;
  require_lead_for_remediation_approval: boolean;
  require_lead_for_model_promotion: boolean;
  policy_version: string;
  created_at: string;
  updated_at: string;
}

export interface ProjectGovernancePolicyUpdate {
  enforce_separation_of_duties?: boolean;
  allow_self_approval_override?: boolean;
  require_two_person_rule_for_purge?: boolean;
  require_lead_for_scope_authorization?: boolean;
  require_lead_for_risk_acceptance?: boolean;
  require_lead_for_remediation_approval?: boolean;
  require_lead_for_model_promotion?: boolean;
}

export interface ApprovalRequestRecord {
  id: string;
  project_id: string;
  workflow_type: ApprovalWorkflowType;
  resource_type: string;
  resource_id: string;
  status: GovernanceApprovalStatus;
  title: string;
  description?: string | null;
  parameter_hash: string;
  parameters_snapshot: Record<string, any>;
  requester_id: string;
  approver_id?: string | null;
  executed_by_id?: string | null;
  requested_at: string;
  decided_at?: string | null;
  executed_at?: string | null;
  invalidated_at?: string | null;
  decision_reason?: string | null;
  invalidation_reason?: string | null;
  policy_version: string;
  created_at: string;
  updated_at: string;
}

export interface ApprovalDecisionRequest {
  approved: boolean;
  reason: string;
}

export interface PermissionMatrixAction {
  resource: string;
  actions: Record<string, string[]>;
}

export interface PermissionMatrixResponse {
  version: string;
  roles: {
    SystemRole: string[];
    ProjectRole: string[];
  };
  matrix: PermissionMatrixAction[];
}

// Prompt 23: Disaster Recovery, Verified Restoration & Data Integrity Types
export interface DisasterRecoveryBundle {
  bundle_id: string;
  bundle_path: string;
  created_at: string;
  created_by_id?: string | null;
  manifest_sha256: string;
  database_sha256: string;
  size_bytes: number;
  status: 'PENDING' | 'VERIFIED' | 'FAILED' | 'RESTORE_VERIFIED' | 'CORRUPTED';
  last_verified_at?: string | null;
  verification_report?: Record<string, any> | null;
  last_restore_drill_at?: string | null;
  restore_drill_report?: Record<string, any> | null;
  is_last_known_good: boolean;
  table_counts?: Record<string, number> | null;
  schema_revision?: string | null;
}

export interface BackupVerificationCheckDetail {
  passed: boolean;
  detail: string;
}

export interface BackupVerificationResult {
  bundle_id: string;
  status: 'PASSED' | 'FAILED';
  verified_at: string;
  checks: Record<string, BackupVerificationCheckDetail>;
  errors: string[];
}

export interface RestoreDrillResult {
  status: 'SUCCESS' | 'FAILED';
  bundle_id: string;
  drill_type: string;
  sandbox_path: string;
  jobs_reconciled: Array<{ job_id: string; prior_status: string; new_status: string }>;
  tables_verified: number;
  audit_events_count: number;
  sandbox_cleaned: boolean;
  duration_ms: number;
  message: string;
}

export interface LiveRestoreResult {
  status: string;
  bundle_id: string;
  live_db_path: string;
  rollback_path: string;
  tables_restored: number;
  jobs_reconciled_count: number;
  audit_events_count: number;
  integrity_check: string;
  restored_at: string;
}

export interface RotationResult {
  bundles_scanned: number;
  bundles_retained: number;
  bundles_pruned: number;
  incomplete_cleaned: number;
  last_known_good_preserved?: string | null;
  details: string[];
}

export interface RecoveryStatusSummary {
  total_bundles: number;
  incomplete_bundles: number;
  last_attempt_at?: string | null;
  last_verified_bundle_id?: string | null;
  last_verified_at?: string | null;
  last_restore_drill_bundle_id?: string | null;
  last_restore_drill_at?: string | null;
  last_known_good_bundle_id?: string | null;
  total_storage_bytes: number;
  recovery_readiness: 'READY' | 'ATTENTION_REQUIRED' | 'DEGRADED';
}

// Prompt 42: Automated Backup Scheduling & Restoration Assurance
export interface BackupSchedule {
  id: string;
  name: string;
  interval_hours: number;
  retention_days: number;
  max_bundles_to_keep: number;
  storage_location: string;
  include_evidence: boolean;
  auto_verify_after_backup: boolean;
  auto_drill_after_backup: boolean;
  is_active: boolean;
  last_run_at?: string | null;
  last_run_status?: string | null;
  last_run_error?: string | null;
  last_bundle_id?: string | null;
  consecutive_failures: number;
  next_run_at?: string | null;
  created_at: string;
}

export interface BackupScheduleCreate {
  name: string;
  interval_hours: number;
  retention_days: number;
  max_bundles_to_keep: number;
  storage_location?: string;
  include_evidence?: boolean;
  auto_verify_after_backup?: boolean;
  auto_drill_after_backup?: boolean;
  is_active?: boolean;
}

export interface BackupScheduleUpdate {
  name?: string;
  interval_hours?: number;
  retention_days?: number;
  max_bundles_to_keep?: number;
  storage_location?: string;
  include_evidence?: boolean;
  auto_verify_after_backup?: boolean;
  auto_drill_after_backup?: boolean;
  is_active?: boolean;
}

export interface BackupScheduleRunResult {
  schedule_id: string;
  status: string;
  bundle_id?: string | null;
  verification_status?: string | null;
  drill_status?: string | null;
  executed_at: string;
  error?: string | null;
}

export interface DiskSpaceStatus {
  storage_path: string;
  total_bytes: number;
  free_bytes: number;
  used_bytes: number;
  free_gb: number;
  total_gb: number;
  is_sufficient_for_backup: boolean;
  minimum_required_bytes: number;
  message: string;
}

// -----------------------------------------------------------------------------
// Prompt 25: Software Supply-Chain Security & Verifiable Provenance
// -----------------------------------------------------------------------------
export interface DependencyItem {
  name: string;
  version: string;
  ecosystem: 'pypi' | 'npm';
  purl: string;
  is_direct: boolean;
  scope: 'required' | 'optional' | 'dev';
  license?: string | null;
  checksum?: string | null;
  supplier?: string | null;
}

export interface DependencyInventoryResponse {
  total_dependencies: number;
  pypi_count: number;
  npm_count: number;
  direct_count: number;
  transitive_count: number;
  items: DependencyItem[];
  generated_at: string;
}

export type VulnerabilitySeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export interface VulnerabilityAdvisory {
  id: string;
  package_name: string;
  ecosystem: string;
  affected_version: string;
  severity: VulnerabilitySeverity;
  title: string;
  description?: string | null;
  remediation_version?: string | null;
  advisory_url?: string | null;
}

export interface DependencyAuditResponse {
  status: 'CLEAN' | 'VULNERABILITIES_FOUND' | 'DEGRADED_SCAN' | 'CRITICAL_BLOCKED';
  advisory_service_status: 'ONLINE' | 'OFFLINE_FALLBACK' | 'UNAVAILABLE';
  total_vulnerabilities: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  release_gate_passed: boolean;
  advisories: VulnerabilityAdvisory[];
  scanned_at: string;
  details: Record<string, unknown>;
}

export interface SecretFinding {
  file_path: string;
  line_number?: number | null;
  rule_name: string;
  severity: string;
  redacted_match: string;
}

export interface SecretScanResponse {
  status: 'CLEAN' | 'SECRETS_DETECTED';
  total_scanned_files: number;
  total_findings: number;
  findings: SecretFinding[];
  scanned_at: string;
}

export interface ReleaseVerificationResult {
  valid: boolean;
  release_id: string;
  version: string;
  total_files_verified: number;
  mismatched_files: string[];
  missing_files: string[];
  unexpected_files: string[];
  forbidden_files_detected: string[];
  signature_valid: boolean;
  message: string;
  errors: string[];
}

export type WorkloadPriority = 'INTERACTIVE' | 'BACKGROUND' | 'MAINTENANCE';

export interface WorkloadQueueStatus {
  active_workers: number;
  max_concurrent_workers: number;
  queue_depth: number;
  max_queue_depth: number;
  capacity_utilization_pct: number;
  saturated: boolean;
  rejected_tasks_count: number;
  active_tasks: Array<Record<string, unknown>>;
  timestamp: string;
}

export interface PerformanceBudget {
  operation: string;
  budget_ms: number;
  p50_ms: number;
  p95_ms: number;
  p99_ms: number;
  sample_count: number;
  within_budget: boolean;
}

export interface PerformanceBudgetsResponse {
  budgets: PerformanceBudget[];
  overall_healthy: boolean;
  measured_at: string;
}

export interface BenchmarkResult {
  operation: string;
  dataset_size: string;
  record_count: number;
  duration_ms: number;
  ops_per_second: number;
  query_count: number;
}

export interface BenchmarkSuiteResponse {
  environment: Record<string, string>;
  dataset_size: string;
  benchmarks: BenchmarkResult[];
  total_duration_ms: number;
  summary: string;
  executed_at: string;
}

export interface StaleJobReconciliationResult {
  scanned_jobs: number;
  recovered_jobs_count: number;
  reconciled_job_ids: string[];
  details: string[];
  reconciled_at: string;
}

export interface QueryCacheMetrics {
  total_cached_items: number;
  max_capacity: number;
  hits: number;
  misses: number;
  hit_ratio: number;
  evictions: number;
  invalidations: number;
}

export interface SqliteWalStatus {
  journal_mode: string;
  synchronous_level: number;
  busy_timeout_ms: number;
  page_size_bytes: number;
  cache_size_pages: number;
  wal_concurrency_enabled: boolean;
}

export interface CacheClearResponse {
  cleared_scope: string;
  message?: string;
  invalidated_count?: number;
}

export type ControlCategory =
  | 'AUTHENTICATION'
  | 'AUTHORIZATION_RBAC'
  | 'SCOPE_ENFORCEMENT'
  | 'EXCLUSIONS_PRECEDENCE'
  | 'EVIDENCE_INTEGRITY'
  | 'AUDIT_CHAIN_CONSISTENCY'
  | 'REMEDIATION_GOVERNANCE'
  | 'INDEPENDENT_RETEST'
  | 'DISASTER_RECOVERY_POSTCONDITION'
  | 'SSRF_PROTECTION'
  | 'SUPPLY_CHAIN_PROVENANCE'
  | 'CONCURRENCY_WORKLOAD';

export type MutationStatus = 'KILLED' | 'SURVIVED' | 'PENDING' | 'BLOCKED';

export interface SecurityControlRecord {
  control_id: string;
  category: ControlCategory;
  name: string;
  description: string;
  enforcement_point: string;
  positive_test: string;
  negative_test: string;
  failure_behavior: string;
  is_verified: boolean;
  last_verified_at: string;
}

export interface MutationScenario {
  mutation_id: string;
  control_id: string;
  name: string;
  description: string;
  target_component: string;
  mutation_type: string;
  expected_killer_test: string;
  observed_failure?: string | null;
  status: MutationStatus;
  execution_time_ms: number;
}

export interface MutationDrillResult {
  drill_id: string;
  total_mutations: number;
  killed_count: number;
  survived_count: number;
  blocked_count: number;
  kill_ratio_pct: number;
  scenarios: MutationScenario[];
  verdict: 'QUALIFIED' | 'DEFECT_DETECTED';
  executed_at: string;
  details: Record<string, unknown>;
}

export interface SecurityControlsCatalogResponse {
  total_controls: number;
  verified_controls: number;
  verification_pct: number;
  controls: SecurityControlRecord[];
  catalog_updated_at: string;
}

// Prompt 28 â€” Deployment & Configuration Governance
export type CheckSeverity = 'PASS' | 'WARN' | 'FAIL';

export interface PreflightCheckItem {
  name: string;
  category: string;
  status: CheckSeverity;
  details: string;
  remediation_advice?: string | null;
}

export interface PreflightReport {
  status: 'PASSED' | 'WARNINGS' | 'FATAL_ERROR' | string;
  environment: string;
  total_checks: number;
  passed_count: number;
  warning_count: number;
  failure_count: number;
  checks: PreflightCheckItem[];
  evaluated_at: string;
}

export interface RedactedConfigResponse {
  environment: string;
  debug: boolean;
  app_name: string;
  database_type: string;
  database_url_redacted: string;
  allowed_origins: string[];
  audit_strict: boolean;
  data_directories: Record<string, string>;
  cryptographic_algorithm: string;
  token_expiry_minutes: number;
  worker_execution_mode: string;
  retrieved_at: string;
}

export interface UpgradePrecheckResponse {
  current_version: string;
  target_version: string;
  migration_head: string;
  current_db_version: string;
  pending_migrations_count: number;
  backup_required: boolean;
  can_upgrade: boolean;
  recommended_action: string;
  checked_at: string;
}

// Prompt 29 â€” Evidence Lifecycle Governance & Retention
export type DataClassification =
  | 'OPERATIONAL_METADATA'
  | 'ASSET_CONFIG'
  | 'FINDINGS_AND_RISK'
  | 'RAW_EVIDENCE'
  | 'CREDENTIALS_AND_SECRETS'
  | 'AUDIT_RECORDS'
  | 'AUTH_AND_IDENTITY'
  | 'DERIVED_ANALYTICS';

export type RetentionActionType = 'RETAIN' | 'ARCHIVE' | 'REDACT' | 'DELETE';
export type HoldType = 'LEGAL_HOLD' | 'REGULATORY_HOLD' | 'INVESTIGATION_HOLD';
export type HoldStatus = 'ACTIVE' | 'RELEASED';

export interface RetentionPolicyModel {
  policy_id: string;
  classification: DataClassification;
  retention_days: number;
  action: RetentionActionType;
  requires_approval: boolean;
  is_active: boolean;
  description: string;
  created_at: string;
  updated_at: string;
}

export interface LegalHoldModel {
  hold_id: string;
  hold_type: HoldType;
  target_scope: string;
  target_id: string;
  reason: string;
  status: HoldStatus;
  placed_by_id: string;
  placed_at: string;
  released_by_id?: string | null;
  released_at?: string | null;
  metadata?: Record<string, unknown>;
}

export interface LegalHoldCreate {
  hold_type?: HoldType;
  target_scope: string;
  target_id: string;
  reason: string;
}

export interface DeletionTombstoneModel {
  tombstone_id: string;
  evidence_id: string;
  original_sha256_hash: string;
  classification: DataClassification;
  policy_id: string;
  deleted_by_id: string;
  deleted_at: string;
  tombstone_digest: string;
  reason: string;
}

export interface RetentionPreviewItem {
  record_id: string;
  classification: DataClassification;
  entity_type: string;
  created_at: string;
  age_days: number;
  applicable_policy_id: string;
  recommended_action: RetentionActionType;
  is_held: boolean;
  hold_reason?: string | null;
  has_dependent_records: boolean;
  eligible_for_execution: boolean;
}

export interface RetentionPreviewReport {
  preview_id: string;
  generated_at: string;
  total_scanned_records: number;
  eligible_records_count: number;
  excluded_by_hold_count: number;
  excluded_by_dependency_count: number;
  preview_items: RetentionPreviewItem[];
  dry_run_hash: string;
}

export interface RetentionExecutionRequest {
  preview_id: string;
  dry_run_hash: string;
  classification_filter?: DataClassification | null;
  confirmed_by_lead: boolean;
}

export interface RetentionExecutionResult {
  execution_id: string;
  preview_id: string;
  executed_at: string;
  archived_count: number;
  redacted_count: number;
  deleted_count: number;
  tombstones_created_count: number;
  skipped_count: number;
  status: string;
  audit_event_id: string;
  tombstones: DeletionTombstoneModel[];
}

export interface EvidenceRedactionRequest {
  evidence_id: string;
  secret_patterns?: string[];
  redaction_reason?: string;
}

export interface EvidenceRedactionResult {
  evidence_id: string;
  redacted: boolean;
  secrets_masked_count: number;
  original_sha256_hash: string;
  sanitized_preview: string;
  redacted_at: string;
}

// Prompt 30 â€” Unified Security Operations Experience
export type PriorityQueueCategory =
  | 'REMEDIATION_APPROVAL'
  | 'RETEST_FAILED'
  | 'JOB_FAILED'
  | 'EXPOSURE_DRIFT'
  | 'INTEGRITY_ALERT'
  | 'RETENTION_EXPIRATION'
  | 'SCOPE_EXPIRING';

export interface PriorityQueueItem {
  item_id: string;
  priority_score: number;
  category: PriorityQueueCategory;
  title: string;
  reason: string;
  affected_asset?: string | null;
  affected_finding_id?: string | null;
  evidence_ref?: string | null;
  permitted_action: string;
  required_role: string;
  target_route: string;
  created_at: string;
}

export interface PriorityQueueResponse {
  total_items: number;
  urgent_items_count: number;
  items: PriorityQueueItem[];
  retrieved_at: string;
}

export interface OperatorCoreQuestion {
  question_id: number;
  question_text: string;
  status: 'PASS' | 'WARN' | 'FAIL' | 'INFO' | string;
  summary: string;
  details: Record<string, unknown>;
}

export interface UnifiedOpsDashboardResponse {
  overall_posture: 'HEALTHY' | 'ATTENTION_REQUIRED' | 'ELEVATED_RISK' | string;
  control_plane_health: string;
  active_assessments_count: number;
  queued_assessments_count: number;
  failed_assessments_count: number;
  verified_critical_findings: number;
  verified_high_findings: number;
  unresolved_uncertainties_count: number;
  pending_remediation_approvals: number;
  failed_retests_count: number;
  exposure_drift_records_count: number;
  data_freshness_seconds: number;
  core_questions: OperatorCoreQuestion[];
  recommended_next_action: string;
  generated_at: string;
}

// Prompt 31: Reliable Security Alerting, Event Delivery & Escalation
export type AlertLifecycleStatus = 'NEW' | 'ACTIVE' | 'ACKNOWLEDGED' | 'ASSIGNED' | 'RESOLVED' | 'REOPENED';

export interface AlertResponse {
  id: string;
  project_id: string;
  event_type: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  title: string;
  summary: string;
  lifecycle_status: AlertLifecycleStatus;
  delivery_status: string;
  assigned_to_id?: string | null;
  acknowledged_at?: string | null;
  acknowledged_by_id?: string | null;
  resolved_at?: string | null;
  resolved_by_id?: string | null;
  reopened_at?: string | null;
  escalated_at?: string | null;
  correlation_id?: string | null;
  causation_id?: string | null;
  idempotency_key?: string | null;
  schema_version: string;
  suppression_reason?: string | null;
  retry_count: number;
  max_retries: number;
  last_attempt_at?: string | null;
  error_message?: string | null;
  delivery_attempts_count: number;
  created_at: string;
  updated_at: string;
}

export interface AlertListResponse {
  total: number;
  limit: number;
  offset: number;
  active_count: number;
  unresolved_count: number;
  critical_count: number;
  items: AlertResponse[];
}

export interface OutboxStatusResponse {
  pending_count: number;
  delivered_count: number;
  dead_letter_count: number;
  suppressed_count: number;
  oldest_pending_age_seconds?: number | null;
  healthy: boolean;
  generated_at: string;
}

export interface MaintenanceWindowResponse {
  id: string;
  project_id: string;
  title: string;
  reason: string;
  start_time: string;
  end_time: string;
  suppress_critical: boolean;
  is_currently_active: boolean;
  created_at: string;
}

// ---------------------------------------------------------------------------
// Prompt 33: Continuous Compliance Intelligence, Security Baselines & Drift
// ---------------------------------------------------------------------------

export type ComplianceEvaluationStatus =
  | 'PASS'
  | 'FAIL'
  | 'PARTIAL'
  | 'UNKNOWN'
  | 'NOT_APPLICABLE'
  | 'ERROR';

export type ComplianceExceptionStatus =
  | 'REQUESTED'
  | 'APPROVED'
  | 'REJECTED'
  | 'EXPIRED'
  | 'REVOKED';

export type ComplianceDriftType =
  | 'REGRESSION_FAIL'
  | 'EVIDENCE_DISAPPEARED_UNKNOWN'
  | 'NEW_CONTROL_UNSATISFIED'
  | 'REMEDIATED_PASS'
  | 'EXCEPTION_EXPIRED';

export interface ComplianceControl {
  id: string;
  control_id: string;
  version: string;
  category: string;
  title: string;
  description: string;
  requirement_statement: string;
  framework: string;
  framework_reference?: string | null;
  applicability_criteria: Record<string, any>;
  required_evidence_types: string[];
  evaluation_rule: string;
  severity: string;
  remediation_guidance: string;
  evaluation_limitations: string;
  is_active: boolean;
  created_at: string;
  updated_at: string;
}

export interface BaselineProfile {
  id: string;
  project_id: string;
  profile_key: string;
  version: string;
  name: string;
  description: string;
  target_applicability: string;
  is_active: boolean;
  control_ids: string[];
  parameters: Record<string, any>;
  created_by_id?: string | null;
  created_at: string;
  updated_at: string;
}

export interface ComplianceControlResult {
  id: string;
  run_id: string;
  control_id: string;
  control_version: string;
  status: ComplianceEvaluationStatus;
  asset_id?: string | null;
  evidence_refs: Array<Record<string, any>>;
  evidence_digests: string[];
  reasoning: string;
  missing_evidence_types: string[];
  confidence_score: number;
  limitations?: string | null;
  has_exception: boolean;
  exception_id?: string | null;
  created_at: string;
}

export interface ComplianceEvaluationRun {
  id: string;
  project_id: string;
  baseline_profile_id: string;
  baseline_profile_key?: string | null;
  baseline_profile_version?: string | null;
  assessment_id?: string | null;
  run_status: string;
  pass_count: number;
  fail_count: number;
  partial_count: number;
  unknown_count: number;
  not_applicable_count: number;
  error_count: number;
  total_controls_evaluated: number;
  provenance_digest: string;
  evaluated_at: string;
  evaluated_by_id?: string | null;
  control_results: ComplianceControlResult[];
}

export interface ComplianceDriftEvent {
  id: string;
  project_id: string;
  control_id: string;
  asset_id?: string | null;
  drift_type: ComplianceDriftType;
  previous_status: ComplianceEvaluationStatus;
  new_status: ComplianceEvaluationStatus;
  previous_run_id?: string | null;
  current_run_id: string;
  reason: string;
  detected_at: string;
  deduplication_hash: string;
}

export interface ComplianceException {
  id: string;
  project_id: string;
  control_id: string;
  asset_id?: string | null;
  justification: string;
  risk_assessment: string;
  compensating_controls: string;
  requester_id: string;
  approver_id?: string | null;
  status: ComplianceExceptionStatus;
  expires_at: string;
  approved_at?: string | null;
  revoked_at?: string | null;
  review_notes?: string | null;
  created_at: string;
  updated_at: string;
}

export interface ComplianceComparison {
  baseline_profile_id: string;
  run_a: ComplianceEvaluationRun;
  run_b: ComplianceEvaluationRun;
  regressions: Array<Record<string, any>>;
  improvements: Array<Record<string, any>>;
  uncertainties: Array<Record<string, any>>;
  unchanged_count: number;
}

// ---------------------------------------------------------------------------
// Prompt 34: Intelligent Assessment Scheduling & Orchestration
// ---------------------------------------------------------------------------

export type QueueItemStatus =
  | 'PENDING'
  | 'SCHEDULED'
  | 'DISPATCHED'
  | 'COMPLETED'
  | 'FAILED'
  | 'CANCELLED'
  | 'DEFERRED'
  | 'PAUSED';

export type PriorityBand = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

export type EligibilityStatus =
  | 'ELIGIBLE'
  | 'EXCLUDED'
  | 'UNAUTHORIZED'
  | 'APPROVAL_REQUIRED'
  | 'RATE_LIMITED'
  | 'UNKNOWN';

export type SchedulerDecisionType =
  | 'ENQUEUE'
  | 'DISPATCH'
  | 'DEFER'
  | 'DEDUPLICATE'
  | 'REJECT'
  | 'CANCEL'
  | 'RECOVER'
  | 'RETRY_BACKOFF';

export type TriggerSourceType =
  | 'MANUAL_DISPATCH'
  | 'DRIFT_DETECTED'
  | 'HIGH_SEVERITY_FINDING'
  | 'FAILED_RETEST'
  | 'STALE_EVIDENCE'
  | 'COMPLIANCE_FAILURE'
  | 'LEASE_RECOVERY'
  | 'SCHEDULED_TIMER';

export interface AssessmentQueueItem {
  id: string;
  project_id: string;
  target_id?: string | null;
  schedule_name: string;
  target_input: string;
  adapter_name: string;
  adapter_version: string;
  status: QueueItemStatus;
  priority_score: number;
  priority_band: PriorityBand;
  priority_explanation: string;
  priority_factors: Record<string, any>;
  policy_version: string;
  eligibility_status: EligibilityStatus;
  eligibility_reasons: string[];
  idempotency_key?: string | null;
  concurrency_key: string;
  worker_claim_id?: string | null;
  claimed_at?: string | null;
  lease_expires_at?: string | null;
  attempt_count: number;
  retry_count: number;
  max_retries: number;
  backoff_seconds: number;
  next_eligible_at: string;
  deadline_at?: string | null;
  execution_budget_seconds: number;
  cancellation_requested_at?: string | null;
  cancellation_reason?: string | null;
  cancelled_at?: string | null;
  last_error_category?: string | null;
  last_error_message?: string | null;
  job_id?: string | null;
  created_by_id: string;
  created_at: string;
  updated_at: string;
}

export interface QueueItemCreate {
  schedule_name?: string;
  target_input: string;
  adapter_name?: string;
  deadline_at?: string | null;
  execution_budget_seconds?: number;
}

export interface QueueItemPreviewRequest {
  target_input: string;
  adapter_name?: string;
}

export interface QueueItemPreviewResponse {
  target_input: string;
  adapter_name: string;
  is_eligible: boolean;
  eligibility_status: EligibilityStatus;
  eligibility_reasons: string[];
  computed_priority: number;
  priority_band: PriorityBand;
  priority_explanation: string;
  priority_factors: Record<string, any>;
  policy_version: string;
}

export interface TriggerAssessmentRequest {
  trigger_source: TriggerSourceType;
  target_input: string;
  adapter_name?: string;
  metadata?: Record<string, any>;
}

export interface DispatchResultResponse {
  dispatched: boolean;
  message: string;
  queue_item?: AssessmentQueueItem | null;
  job_id?: string | null;
}

export interface LeaseRecoveryResponse {
  recovered_count: number;
  dead_letter_count: number;
  recovered_ids: string[];
  dead_letter_ids: string[];
}

export interface SchedulerCapacity {
  project_id: string;
  max_concurrent_assessments: number;
  current_running_assessments: number;
  available_capacity: number;
  total_queued_items: number;
  active_by_target: Record<string, number>;
  active_by_adapter: Record<string, number>;
  queue_utilization_pct: number;
  stale_unclaimed_leases: number;
}

export interface SchedulerDecision {
  id: string;
  project_id: string;
  queue_item_id?: string | null;
  trigger_source: string;
  target_input: string;
  decision_type: SchedulerDecisionType;
  priority_score: number;
  decision_rationale: string;
  capacity_snapshot: Record<string, any>;
  metadata_payload: Record<string, any>;
  created_at: string;
}

export interface SchedulerPolicy {
  id: string;
  project_id: string;
  policy_version: string;
  max_concurrent_assessments: number;
  max_per_target_concurrency: number;
  max_per_adapter_concurrency: number;
  max_queued_jobs: number;
  max_execution_duration_sec: number;
  max_retries: number;
  aging_factor_per_hour: number;
  stale_lease_timeout_sec: number;
  cooldown_period_sec: number;
  is_active: boolean;
  created_at: string;
  updated_at: string;
}

export interface SchedulerPolicyUpdate {
  max_concurrent_assessments?: number;
  max_per_target_concurrency?: number;
  max_per_adapter_concurrency?: number;
  max_queued_jobs?: number;
  max_execution_duration_sec?: number;
  max_retries?: number;
  aging_factor_per_hour?: number;
  stale_lease_timeout_sec?: number;
  cooldown_period_sec?: number;
  is_active?: boolean;
}

// ---------------------------------------------------------------------------
// Threat Intelligence and Vulnerability Correlation (Prompt 35)
// ---------------------------------------------------------------------------

export type FeedSyncStatus = 'SYNCED' | 'SYNCING' | 'STALE' | 'ERROR' | 'OFFLINE';
export type MatchClassification = 'CONFIRMED_MATCH' | 'POSSIBLE_MATCH' | 'CONFLICTING_DATA' | 'UNKNOWN_MATCH';

export interface ThreatFeed {
  id: string;
  feed_name: string;
  feed_url: string;
  is_authoritative: boolean;
  sync_status: FeedSyncStatus;
  record_count: number;
  last_sync_started_at?: string | null;
  last_synced_at?: string | null;
  last_sync_error?: string | null;
  stale_after_days: number;
  is_stale: boolean;
  feed_checksum?: string | null;
}

export interface ThreatFeedSyncRequest {
  force_local?: boolean;
  custom_payload?: Record<string, any>;
}

export interface ThreatFeedSyncResponse {
  feed_name: string;
  records_ingested: number;
  records_updated: number;
  sync_status: FeedSyncStatus;
  checksum: string;
  message: string;
}

export interface ThreatIntelligenceRecord {
  id: string;
  cve_id: string;
  source: string;
  title?: string | null;
  description?: string | null;
  vendor?: string | null;
  product?: string | null;
  cpe?: string | null;
  version_start_including?: string | null;
  version_end_excluding?: string | null;
  version_end_including?: string | null;
  affected_versions_list: string[];
  cvss_score?: number | null;
  cvss_vector?: string | null;
  epss_score?: number | null;
  epss_percentile?: number | null;
  is_known_exploited: boolean;
  cisa_kev_due_date?: string | null;
  cisa_kev_action?: string | null;
  published_at?: string | null;
  modified_at?: string | null;
  retrieved_at: string;
  confidence: number;
  provenance_url?: string | null;
}

export interface ThreatCorrelation {
  id: string;
  project_id: string;
  finding_id: string;
  finding_title: string;
  finding_severity: string;
  threat_intel_id: string;
  cve_id: string;
  match_classification: MatchClassification;
  confidence_score: number;
  evidence_grounding: Record<string, any>;
  enriched_risk_score: number;
  risk_enrichment_factors: Record<string, any>;
  is_known_exploited: boolean;
  epss_score?: number | null;
  correlated_at: string;
}

export interface ThreatCorrelationRunRequest {
  force_recorrelate?: boolean;
}

export interface ThreatCorrelationRunResponse {
  project_id: string;
  findings_evaluated: number;
  correlations_created: number;
  confirmed_matches: number;
  possible_matches: number;
  conflicting_data: number;
  unknown_or_rejected: number;
  message: string;
}

export interface ThreatIntelSummary {
  total_cves: number;
  known_exploited_count: number;
  active_feeds_count: number;
  stale_feeds_count: number;
  total_project_correlations: number;
  confirmed_correlations_count: number;
  possible_correlations_count: number;
  conflicting_correlations_count: number;
}

// ---------------------------------------------------------------------------
// Identity Security, Authorization Consistency & Privileged-Action Governance (Prompt 36)
// ---------------------------------------------------------------------------

export interface DetailedPermissionMatrixItem {
  role: string;
  role_type: string;
  description: string;
  granted_permissions: string[];
}

export interface DetailedPermissionMatrixResponse {
  available_permissions: string[];
  system_roles: DetailedPermissionMatrixItem[];
  project_roles: DetailedPermissionMatrixItem[];
}

export interface AccessDenialAudit {
  id: string;
  user_id?: string | null;
  user_email?: string | null;
  project_id?: string | null;
  endpoint: string;
  http_method: string;
  required_privilege: string;
  held_privilege?: string | null;
  denial_reason: string;
  client_ip?: string | null;
  denied_at: string;
}

export interface LogoutResponse {
  status: string;
  message: string;
  revoked_token_id?: string | null;
}

export interface RevokeAllSessionsResponse {
  status: string;
  message: string;
  revoked_before: string;
}

// Prompt 37: Asset Identity Resolution, Data Quality and Canonical Security Records
export type ResolutionOutcome =
  | 'EXACT_MATCH'
  | 'STRONG_CORRELATION'
  | 'AMBIGUOUS_CONFLICT'
  | 'UNMATCHED';

export interface ResolutionResult {
  outcome: ResolutionOutcome;
  matched_asset_id?: string | null;
  matched_canonical_identifier?: string | null;
  confidence: number;
  match_reasons: string[];
  conflicts_detected: string[];
}

export interface DryRunImpact {
  source_asset_id: string;
  source_canonical_identifier: string;
  target_asset_id: string;
  target_canonical_identifier: string;
  findings_to_repoint: number;
  aliases_to_transfer: number;
  observations_to_repoint: number;
  conflicts_detected: string[];
  safe_to_merge: boolean;
}

export type DeduplicationProposalStatus = 'PROPOSED' | 'APPROVED' | 'REJECTED' | 'REVERTED';

export interface DeduplicationProposal {
  id: string;
  project_id: string;
  source_asset_id: string;
  target_asset_id: string;
  status: DeduplicationProposalStatus;
  confidence_score: number;
  match_reasons: string[];
  conflicts_detected: string[];
  dry_run_impact: Record<string, any>;
  proposed_by_id?: string | null;
  reviewed_by_id?: string | null;
  review_comments?: string | null;
  created_at: string;
  reviewed_at?: string | null;
  reverted_at?: string | null;
}

export type DataQualityIssueType =
  | 'ORPHANED_FINDING'
  | 'MISSING_ASSET_REFERENCE'
  | 'DUPLICATE_IDENTIFIER'
  | 'INCONSISTENT_TIMESTAMPS'
  | 'INVALID_RELATIONSHIP'
  | 'STALE_OBSERVATION';

export type DataQualityIssueStatus = 'OPEN' | 'RESOLVED' | 'IGNORED';

export interface DataQualityIssue {
  id: string;
  project_id: string;
  issue_type: DataQualityIssueType;
  severity: string;
  affected_resource_type: string;
  affected_resource_id: string;
  details: Record<string, any>;
  status: DataQualityIssueStatus;
  detected_at: string;
  resolved_at?: string | null;
}

// Prompt 39: Security Incident Investigation and Case Management
export type CaseSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFORMATIONAL';
export type CaseStatus = 'OPEN' | 'TRIAGED' | 'INVESTIGATING' | 'CONTAINED' | 'CLOSED' | 'REOPENED';
export type CaseAssetRelationshipType = 'PRIMARY_TARGET' | 'PIVOT_VECTOR' | 'IMPACTED_DEPENDENCY' | 'OBSERVED_CORRELATION';
export type CorrelationType = 'CONFIRMED_CAUSATION' | 'PROBABLE_CORRELATION' | 'TEMPORAL_COINCIDENCE' | 'CONTRADICTORY_EVIDENCE';

export interface LinkedAssetItem {
  id: string;
  asset_id: string;
  relationship_type: CaseAssetRelationshipType;
  confidence: number;
  is_contradictory: boolean;
  notes?: string | null;
  created_at: string;
}

export interface LinkedFindingItem {
  id: string;
  finding_id: string;
  correlation_type: CorrelationType;
  confidence: number;
  rationale?: string | null;
  created_at: string;
}

export interface LinkedEvidenceItem {
  id: string;
  finding_evidence_id?: string | null;
  evidence_digest: string;
  evidence_summary: string;
  is_contradictory: boolean;
  created_at: string;
}

export interface CaseTransitionItem {
  id: string;
  from_status: CaseStatus;
  to_status: CaseStatus;
  transitioned_by_id?: string | null;
  reason: string;
  created_at: string;
}

export interface CaseNoteItem {
  id: string;
  author_id?: string | null;
  note_type: string;
  content: string;
  is_alternative_hypothesis: boolean;
  created_at: string;
}

export interface IncidentCaseSummary {
  id: string;
  project_id: string;
  case_number: string;
  title: string;
  severity: CaseSeverity;
  status: CaseStatus;
  lead_investigator_id?: string | null;
  assigned_team?: string | null;
  opened_at: string;
  closed_at?: string | null;
  is_containment_verified: boolean;
  created_at: string;
}

export interface IncidentCaseDetail {
  id: string;
  project_id: string;
  case_number: string;
  title: string;
  description?: string | null;
  severity: CaseSeverity;
  status: CaseStatus;
  lead_investigator_id?: string | null;
  assigned_team?: string | null;
  opened_at: string;
  closed_at?: string | null;
  reopened_at?: string | null;
  root_cause_hypothesis?: string | null;
  alternative_explanations: Array<Record<string, any>>;
  is_containment_verified: boolean;
  closure_summary?: string | null;
  closure_approved_by_id?: string | null;
  reopening_rationale?: string | null;
  linked_assets: LinkedAssetItem[];
  linked_findings: LinkedFindingItem[];
  linked_evidence: LinkedEvidenceItem[];
  transitions: CaseTransitionItem[];
  notes: CaseNoteItem[];
  created_at: string;
}

export interface CorrelationExplanation {
  case_id: string;
  case_number: string;
  total_linked_findings: number;
  total_linked_assets: number;
  confirmed_causation: Array<Record<string, any>>;
  probable_correlations: Array<Record<string, any>>;
  temporal_coincidences: Array<Record<string, any>>;
  contradictory_findings: Array<Record<string, any>>;
  contradictory_evidence_count: number;
  alternative_hypotheses_count: number;
  correlation_summary: string;
}

export interface TimelineEvent {
  event_type: string;
  timestamp: string;
  actor_id?: string | null;
  summary: string;
  details: Record<string, any>;
}

// Prompt 40: Secure Integration Framework and Connector Contracts
export type ConnectorCapability =
  | 'PULL_ASSETS'
  | 'PULL_FINDINGS'
  | 'PULL_THREAT_INTEL'
  | 'PUSH_ALERTS'
  | 'EXPORT_TELEMETRY'
  | 'TEST_CONNECTIVITY';

export type ConnectorStatus = 'CONFIGURED' | 'HEALTHY' | 'DEGRADED' | 'UNAVAILABLE' | 'DISABLED' | 'ERROR';
export type SyncStatus = 'RUNNING' | 'SUCCESS' | 'PARTIAL_SUCCESS' | 'FAILED';
export type ImplementationStatus = 'IMPLEMENTED' | 'SIMULATED' | 'DISABLED' | 'UNVERIFIED';

export interface ConnectorInventoryItem {
  provider_type: string;
  name: string;
  version: string;
  supported_capabilities: string[];
  implementation_status: string;
  description: string;
  limitations?: string | null;
  config_schema: Record<string, any>;
}

export interface ConnectorConfigCreate {
  name: string;
  provider_type: string;
  version?: string;
  enabled?: boolean;
  capabilities: string[];
  settings: Record<string, any>;
  rate_limit_per_minute?: number;
  timeout_seconds?: number;
  max_retries?: number;
  max_response_size_kb?: number;
}

export interface ConnectorConfigUpdate {
  name?: string;
  enabled?: boolean;
  capabilities?: string[];
  settings?: Record<string, any>;
  rate_limit_per_minute?: number;
  timeout_seconds?: number;
  max_retries?: number;
  max_response_size_kb?: number;
}

export interface ConnectorConfigRead {
  id: string;
  project_id: string;
  name: string;
  provider_type: string;
  version: string;
  enabled: boolean;
  capabilities: string[];
  config_schema_version: string;
  settings_masked: Record<string, any>;
  rate_limit_per_minute: number;
  timeout_seconds: number;
  max_retries: number;
  max_response_size_kb: number;
  last_sync_at?: string | null;
  last_sync_watermark?: string | null;
  last_health_status: string;
  last_health_message?: string | null;
  consecutive_failures: number;
  created_at: string;
  updated_at: string;
}

export interface ConnectorHealthRead {
  connector_id: string;
  name: string;
  provider_type: string;
  status: string;
  latency_ms: number;
  message: string;
  error_category?: string | null;
  details: Record<string, any>;
}

export interface ConnectorSyncTriggerResponse {
  sync_event_id: string;
  connector_id: string;
  status: string;
  records_pulled: number;
  records_normalized: number;
  records_ingested: number;
  records_tombstoned: number;
  raw_payload_digest?: string | null;
  next_watermark?: string | null;
  message: string;
}

export interface ConnectorSyncEventRead {
  id: string;
  connector_id: string;
  project_id: string;
  started_at: string;
  finished_at?: string | null;
  status: string;
  records_pulled: number;
  records_normalized: number;
  records_ingested: number;
  records_tombstoned: number;
  error_message?: string | null;
  error_type?: string | null;
  raw_payload_digest?: string | null;
  sync_watermark?: string | null;
  execution_metadata?: Record<string, any> | null;
}

// Prompt 43: Full-Stack Contract Integrity & Domain Enums
export type ScheduleRunStatus = 'PENDING' | 'SUCCESS' | 'FAILED' | 'SKIPPED_DISK_LOW';
export type RecoveryBundleStatus = 'UNVERIFIED' | 'VERIFIED' | 'CORRUPTED' | 'RESTORE_VERIFIED';
export type ThreatIntelSource = 'CISA_KEV' | 'NVD_CVE' | 'EPSS' | 'VENDOR_ADVISORY' | 'LOCAL_FIXTURE';
export type ExperimentStatus = 'DRAFT' | 'RUNNING' | 'COMPLETED' | 'CANCELLED' | 'INCONCLUSIVE';
export type ExperimentDecision =
  | 'ACCEPTED'
  | 'REJECTED_INFERIOR_METRICS'
  | 'REJECTED_LEAKAGE'
  | 'REJECTED_INSUFFICIENT_DATA'
  | 'PENDING_REVIEW';
export type SplitStrategy = 'TEMPORAL_AWARE' | 'STRATIFIED_HASH' | 'CHRONOLOGICAL_WINDOW';
export type ConnectorType =
  | 'QUALYS'
  | 'TENABLE_IO'
  | 'RAPID7'
  | 'SONARQUBE'
  | 'SNYK'
  | 'DEFECTDOJO'
  | 'AWS_SECURITY_HUB'
  | 'GENERIC_WEBHOOK';
export type NotificationSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

// Prompt 45 — Secrets Management & Credential Lifecycle
export interface ConfigDiagnosticItem {
  key: string;
  is_secret: boolean;
  configured: boolean;
  status: 'PASS' | 'WARN' | 'FAIL';
  strength: 'STRONG' | 'ADEQUATE' | 'WEAK' | 'DEFAULT_INSECURE' | 'NOT_APPLICABLE';
  redacted_value: string;
  message: string;
}

export interface ConfigDiagnosticResponse {
  environment: string;
  total_settings: number;
  passed_count: number;
  warning_count: number;
  failure_count: number;
  items: ConfigDiagnosticItem[];
  evaluated_at: string;
}

export interface ConnectorCredentialRotateRequest {
  settings: Record<string, any>;
}

// Prompt 46 — Authorized Attack-Surface Inventory and Exposure Governance
export type ExposureClassification = 'INTERNET_FACING' | 'INTERNAL_FACING' | 'DMZ' | 'UNKNOWN';

export type ObservationProvenanceType =
  | 'VERIFIED_OBSERVATION'
  | 'PASSIVE_CERTIFICATE_TRANSPARENCY'
  | 'DNS_RECORDS'
  | 'EXTERNAL_TELEMETRY'
  | 'PROPOSED_DISCOVERY'
  | 'HISTORICAL_OBSERVATION';

export type ExposureFreshness =
  | 'FRESH'
  | 'STALE'
  | 'UNVERIFIED_ABSENT'
  | 'CONFIRMED_DECOMMISSIONED';

export type AttackSurfaceProposalStatus = 'PENDING' | 'APPROVED' | 'REJECTED' | 'EXCLUDED';

export interface AttackSurfaceExposure {
  id: string;
  project_id: string;
  asset_id: string;
  canonical_identifier: string;
  service_name: string;
  port: number;
  protocol: string;
  transport_security: string;
  exposure_classification: ExposureClassification;
  provenance_type: ObservationProvenanceType;
  freshness: ExposureFreshness;
  certificate_details: Record<string, any>;
  relevant_hostnames: string[];
  evidence_hashes: string[];
  attributes: Record<string, any>;
  observation_count: number;
  consecutive_absences: number;
  is_simulated: boolean;
  first_observed_at: string;
  last_observed_at: string;
  created_at: string;
  updated_at: string;
}

export interface AssetInclusionProposal {
  id: string;
  project_id: string;
  target_type: 'DOMAIN' | 'IP' | 'CIDR' | 'URL';
  target_value: string;
  discovery_source: string;
  provenance_type: ObservationProvenanceType;
  status: AttackSurfaceProposalStatus;
  rationale: string;
  discovered_at: string;
  evidence_hash?: string | null;
  is_simulated: boolean;
  reviewed_by_id?: string | null;
  reviewed_at?: string | null;
  approval_notes?: string | null;
  resulting_scope_target_id?: string | null;
  created_at: string;
  updated_at: string;
}

export interface ProposalApprovalRequest {
  approval_notes: string;
  authorized_evidence: string;
}

export interface ProposalRejectionRequest {
  reason: string;
  add_to_exclusion?: boolean;
}

export interface AttackSurfaceTimelineEvent {
  timestamp: string;
  event_type: string;
  description: string;
  port: number;
  protocol: string;
  details?: Record<string, any>;
}

export interface AttackSurfaceEvidenceSummary {
  asset_id: string;
  canonical_identifier: string;
  total_exposures: number;
  exposures: AttackSurfaceExposure[];
  distinct_evidence_hashes: string[];
}

export type ForensicEvidenceLifecycleState =
  | 'COLLECTED'
  | 'INGESTED'
  | 'NORMALIZED'
  | 'ANALYZED'
  | 'REPORTED'
  | 'ARCHIVED'
  | 'AUTHORIZED_DELETED';

export type ForensicVerificationOutcome = 'VERIFIED' | 'FAILED' | 'UNAVAILABLE' | 'NOT_CHECKED';

export type ForensicContradictionStatus = 'SUPPORTING' | 'CONTRADICTORY' | 'CORRECTION' | 'SUPERSEDED';

export interface EvidenceCustodyEvent {
  id: string;
  evidence_id: string;
  event_type: string;
  actor_id: string;
  actor_role: string;
  timestamp: string;
  action_details: Record<string, any>;
  prev_custody_hash: string;
  custody_hash: string;
}

export interface ForensicEvidenceRecord {
  id: string;
  finding_id?: string | null;
  job_id?: string | null;
  project_id: string;
  evidence_type: string;
  raw_payload: string;
  raw_digest_sha256: string;
  normalized_payload?: Record<string, any> | null;
  normalized_digest_sha256?: string | null;
  source_identity: string;
  adapter_version: string;
  collection_time: string;
  ingestion_time: string;
  assessment_context: Record<string, any>;
  transformation_history: Array<{
    step: string;
    transformer?: string;
    version?: string;
    reason?: string;
    timestamp: string;
    actor: string;
  }>;
  origin_signature: string;
  signing_key_id: string;
  signature_algorithm: string;
  lifecycle_state: ForensicEvidenceLifecycleState;
  last_verification_status: ForensicVerificationOutcome;
  last_verified_at?: string | null;
  last_verified_by?: string | null;
  verification_details?: Record<string, any> | null;
  contradiction_status: ForensicContradictionStatus;
  superseded_by_id?: string | null;
  prior_evidence_id?: string | null;
  is_contradictory: boolean;
  contradiction_notes?: string | null;
  classification: string;
  is_redacted: boolean;
  is_archived: boolean;
  is_deleted: boolean;
  created_at: string;
  updated_at: string;
  custody_events?: EvidenceCustodyEvent[];
}

export interface EvidenceIngestRequest {
  project_id: string;
  finding_id?: string | null;
  job_id?: string | null;
  evidence_type: string;
  raw_payload: string;
  source_identity: string;
  adapter_version: string;
  collection_time: string;
  assessment_context?: Record<string, any>;
  signing_key_id?: string;
  classification?: string;
}

export interface EvidenceNormalizeRequest {
  normalized_payload: Record<string, any>;
  transformer_identity: string;
  adapter_version: string;
  reason: string;
}

export interface EvidenceContradictionRequest {
  contradictory_payload: string;
  source_identity: string;
  adapter_version: string;
  collection_time: string;
  notes: string;
  supersedes_previous?: boolean;
  assessment_context?: Record<string, any>;
  signing_key_id?: string;
}

export interface ForensicVerificationReportItem {
  evidence_id: string;
  status: ForensicVerificationOutcome;
  raw_digest_match: boolean;
  signature_valid: boolean;
  custody_chain_valid: boolean;
  artifacts_present: boolean;
  contradiction_status: ForensicContradictionStatus;
  discrepancies: string[];
}

export interface ForensicVerificationReport {
  timestamp: string;
  total_records: number;
  verified_count: number;
  failed_count: number;
  unavailable_count: number;
  not_checked_count: number;
  items: ForensicVerificationReportItem[];
}

export interface EvidenceExportBundle {
  export_version: string;
  exported_at: string;
  exported_by: string;
  record_count: number;
  records: Record<string, any>[];
  custody_events: Record<string, any>[];
  bundle_digest_sha256: string;
  bundle_signature: string;
  signing_key_id: string;
}

export interface EvidenceImportResult {
  imported_count: number;
  verification_passed: boolean;
  evidence_ids: string[];
  warnings: string[];
}














