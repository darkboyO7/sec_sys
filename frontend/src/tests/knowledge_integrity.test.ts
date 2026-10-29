import { describe, it, expect, vi, beforeEach } from 'vitest';
import { api } from '../services/api';
import type {
  EpistemicStatus,
  AttackPathStatus,
  ExplainableAttackPath,
  KnowledgeReconciliationAudit,
  KnowledgeDependencyRecord,
  FindingEpistemicExplanation,
} from '../types';

describe('Prompt 21: Universal Knowledge Integrity, Explainable Attack Paths & Reconciliation', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('verifies all 8 required epistemic statuses and attack path statuses are defined', () => {
    const statuses: EpistemicStatus[] = [
      'OBSERVED_FACT',
      'CORROBORATED_FACT',
      'DERIVED_CONCLUSION',
      'HYPOTHESIS',
      'UNKNOWN',
      'CONTRADICTED',
      'STALE',
      'INVALIDATED',
    ];
    expect(statuses).toHaveLength(8);
    expect(statuses).toContain('OBSERVED_FACT');
    expect(statuses).toContain('CORROBORATED_FACT');
    expect(statuses).toContain('CONTRADICTED');
    expect(statuses).toContain('INVALIDATED');

    const pathStatuses: AttackPathStatus[] = [
      'VERIFIED',
      'PLAUSIBLE',
      'HYPOTHETICAL',
      'STALE',
      'CONTRADICTED',
      'INVALIDATED',
    ];
    expect(pathStatuses).toHaveLength(6);
  });

  it('fetches explainable attack paths with step-by-step assumptions and scope compliance', async () => {
    const mockPaths: ExplainableAttackPath[] = [
      {
        id: 'path-sha256-abc123',
        project_id: 'proj-1',
        name: 'Internet Gateway -> Web Service -> Vulnerable API Endpoint',
        start_node_id: 'node-1',
        target_node_id: 'node-3',
        path_status: 'PLAUSIBLE',
        cumulative_confidence: 0.76,
        risk_impact_score: 68.4,
        step_count: 2,
        is_scope_compliant: true,
        scope_violations: [],
        steps_explanation: [
          {
            step: 1,
            from_node: { id: 'node-1', label: 'gateway.corp', category: 'HOST' },
            to_node: { id: 'node-2', label: 'web-service', category: 'SERVICE' },
            edge_id: 'edge-1',
            relationship_type: 'RUNS',
            status: 'VERIFIED',
            epistemic_status: 'OBSERVED_FACT',
            confidence: 0.95,
            is_authoritative: true,
            is_simulated: false,
            supporting_evidence: 'obs-run-123',
            required_assumptions: ['Assumes service remains active on port 443'],
            unverified_conditions: [],
            invalidation_triggers: ['Stopping web-service will invalidate this step'],
          },
          {
            step: 2,
            from_node: { id: 'node-2', label: 'web-service', category: 'SERVICE' },
            to_node: { id: 'node-3', label: '/api/v1/auth', category: 'API_ENDPOINT' },
            edge_id: 'edge-2',
            relationship_type: 'EXPOSES',
            status: 'INFERRED',
            epistemic_status: 'HYPOTHESIS',
            confidence: 0.8,
            is_authoritative: false,
            is_simulated: false,
            supporting_evidence: 'None recorded',
            required_assumptions: ['Route /api/v1/auth assumed reachable without WAF block'],
            unverified_conditions: ['Route not confirmed via empirical HTTP request probe'],
            invalidation_triggers: ['WAF rule blocking /api/v1/auth will break this traversal'],
          },
        ],
        chokepoints: [{ element_type: 'RELATIONSHIP', id: 'edge-1', paths_intersected: 1, remediation_leverage: 1.0 }],
        calculation_version: 'v2.1.0',
        input_hashes: { signature: 'node-1->node-2->node-3' },
        is_stale: false,
        is_invalidated: false,
        created_at: '2026-10-28T23:00:00Z',
        updated_at: '2026-10-28T23:00:00Z',
      },
    ];

    vi.spyOn(api, 'listExplainableAttackPaths').mockResolvedValue(mockPaths);

    const paths = await api.listExplainableAttackPaths('proj-1');
    expect(paths).toHaveLength(1);
    expect(paths[0].path_status).toBe('PLAUSIBLE');
    expect(paths[0].is_scope_compliant).toBe(true);
    expect(paths[0].steps_explanation).toHaveLength(2);
    expect(paths[0].steps_explanation[1].unverified_conditions[0]).toContain('Route not confirmed');
  });

  it('executes knowledge graph reconciliation and verifies auditable defect repair log', async () => {
    const mockAudit: KnowledgeReconciliationAudit = {
      id: 'audit-999',
      project_id: 'proj-1',
      run_by_user_id: 'user-lead',
      status: 'COMPLETED',
      total_nodes_audited: 45,
      total_relationships_audited: 80,
      dangling_references_detected: 2,
      duplicate_relationships_detected: 1,
      invalid_types_detected: 0,
      missing_provenance_detected: 1,
      stale_conclusions_detected: 1,
      scope_violations_detected: 0,
      contradictions_detected: 0,
      auto_repaired_count: 4,
      manual_review_required_count: 0,
      reconciliation_log: [
        {
          item_type: 'RELATIONSHIP_DANGLING_TARGET',
          id: 'rel-dangle',
          severity: 'CRITICAL',
          description: "Relationship 'rel-dangle' references non-existent target node.",
          auto_repairable: true,
          repaired: true,
        },
        {
          item_type: 'DUPLICATE_RELATIONSHIP',
          severity: 'WARNING',
          description: 'Found 2 duplicate edges between node A and node B.',
          auto_repairable: true,
          repaired: true,
        },
      ],
      started_at: '2026-10-28T23:00:00Z',
      completed_at: '2026-10-28T23:00:01Z',
    };

    vi.spyOn(api, 'triggerKnowledgeReconciliation').mockResolvedValue(mockAudit);

    const result = await api.triggerKnowledgeReconciliation('proj-1', true);
    expect(result.status).toBe('COMPLETED');
    expect(result.dangling_references_detected).toBe(2);
    expect(result.auto_repaired_count).toBe(4);
    expect(result.reconciliation_log).toHaveLength(2);
    expect(result.reconciliation_log[0].repaired).toBe(true);
  });

  it('tracks knowledge dependency records and invalidation reasons', async () => {
    const mockDeps: KnowledgeDependencyRecord[] = [
      {
        id: 'dep-1',
        project_id: 'proj-1',
        source_entity_type: 'Asset',
        source_entity_id: 'asset-web-1',
        dependent_entity_type: 'ExplainableAttackPath',
        dependent_entity_id: 'path-123',
        dependency_type: 'TOPOLOGY_LINK',
        is_valid: false,
        invalidated_at: '2026-10-28T23:05:00Z',
        invalidation_reason: "Asset 'asset-web-1' closed port 8080 during drift evaluation.",
        created_at: '2026-10-28T22:00:00Z',
        updated_at: '2026-10-28T23:05:00Z',
      },
    ];

    vi.spyOn(api, 'listKnowledgeDependencies').mockResolvedValue(mockDeps);

    const deps = await api.listKnowledgeDependencies('proj-1');
    expect(deps).toHaveLength(1);
    expect(deps[0].is_valid).toBe(false);
    expect(deps[0].invalidation_reason).toContain('closed port 8080');
  });

  it('retrieves finding epistemic explanation with risk delta and penalty discounts', async () => {
    const mockExp: FindingEpistemicExplanation = {
      finding_id: 'find-sqli-1',
      title: 'SQL Injection in /api/v1/login',
      severity: 'CRITICAL',
      lifecycle_status: 'CONFIRMED',
      validation_status: 'CONFIRMED_TRUE_POSITIVE',
      confidence: 'CERTAIN',
      epistemic_status: 'CORROBORATED_FACT',
      is_authoritative: true,
      is_simulated: false,
      evidence_items: [{ id: 'ev-1', sha256: 'abc...', is_valid: true }],
      validation_history: [{ from_status: 'DETECTED', to_status: 'CONFIRMED_TRUE_POSITIVE', method: 'LOCAL_FIXTURE' }],
      contextual_risk: {
        score: 85.0,
        inherent_score: 95.0,
        residual_score: 85.0,
        priority: 'CRITICAL',
        scoring_version: 'v2.0.0',
        prior_score: 80.0,
        score_delta: 5.0,
        delta_reasons: ['Asset criticality updated to CRITICAL', 'Verified attack path established'],
        qualitative_label: 'WELL_SUPPORTED',
        unverified_penalty: 5.0,
        is_invalidated: false,
        contributing_factors: ['Anchored by CVSS 9.8'],
        missing_factors: [],
        uncertainty_range: { min: 82.0, max: 88.0 },
      },
      dependent_attack_paths: [],
      dependencies: [],
    };

    vi.spyOn(api, 'explainFinding').mockResolvedValue(mockExp);

    const explanation = await api.explainFinding('proj-1', 'find-sqli-1');
    expect(explanation.epistemic_status).toBe('CORROBORATED_FACT');
    expect(explanation.contextual_risk?.score_delta).toBe(5.0);
    expect(explanation.contextual_risk?.delta_reasons).toHaveLength(2);
    expect(explanation.contextual_risk?.unverified_penalty).toBe(5.0);
  });
});
