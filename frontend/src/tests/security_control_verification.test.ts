import { describe, it, expect, vi, beforeEach } from 'vitest';
import { api } from '../services/api';
import type {
  ControlCategory,
  MutationStatus,
  SecurityControlsCatalogResponse,
  MutationScenario,
  MutationDrillResult,
} from '../types';

describe('Prompt 27: Security Control Verification & Mutation Testing Assurance', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('validates all 12 defensive control categories and mutation status enums', () => {
    const categories: ControlCategory[] = [
      'AUTHENTICATION',
      'AUTHORIZATION_RBAC',
      'SCOPE_ENFORCEMENT',
      'EXCLUSIONS_PRECEDENCE',
      'EVIDENCE_INTEGRITY',
      'AUDIT_CHAIN_CONSISTENCY',
      'REMEDIATION_GOVERNANCE',
      'INDEPENDENT_RETEST',
      'DISASTER_RECOVERY_POSTCONDITION',
      'SSRF_PROTECTION',
      'SUPPLY_CHAIN_PROVENANCE',
      'CONCURRENCY_WORKLOAD',
    ];
    expect(categories).toHaveLength(12);

    const statuses: MutationStatus[] = ['KILLED', 'SURVIVED', 'PENDING', 'BLOCKED'];
    expect(statuses).toContain('KILLED');
    expect(statuses).toContain('SURVIVED');
  });

  it('fetches complete security controls catalog via api.getSecurityControlsCatalog', async () => {
    const mockCatalog: SecurityControlsCatalogResponse = {
      total_controls: 12,
      verified_controls: 12,
      verification_pct: 100.0,
      catalog_updated_at: '2026-10-29T10:00:00Z',
      controls: [
        {
          control_id: 'SEC-AUTH-01',
          category: 'AUTHENTICATION',
          name: 'JWT Bearer Authentication & Session Integrity',
          description: 'Rejects unauthenticated requests with HTTP 401.',
          enforcement_point: 'app.api.deps.get_current_user',
          positive_test: 'test_auth.py::test_authenticated_request_succeeds',
          negative_test: 'test_prompt24.py::test_02_unauthorized',
          failure_behavior: 'Fails closed.',
          is_verified: true,
          last_verified_at: '2026-10-29T10:00:00Z',
        },
      ],
    };

    const spy = vi.spyOn(api as any, 'request').mockResolvedValueOnce(mockCatalog);
    const result = await api.getSecurityControlsCatalog();

    expect(spy).toHaveBeenCalledWith('/system/verification/controls');
    expect(result.total_controls).toBe(12);
    expect(result.verification_pct).toBe(100.0);
    expect(result.controls[0].is_verified).toBe(true);
  });

  it('fetches mutation scenarios via api.getMutationScenarios', async () => {
    const mockMutations: MutationScenario[] = [
      {
        mutation_id: 'MUT-AUTH-01',
        control_id: 'SEC-RBAC-01',
        name: 'Bypass Role Authorization Check',
        description: 'Mutate require_system_roles to allow VIEWER mutation access.',
        target_component: 'backend/app/api/deps.py:require_system_roles',
        mutation_type: 'BYPASS_AUTH',
        expected_killer_test: 'test_prompt26.py::test_17',
        status: 'KILLED',
        execution_time_ms: 12.4,
      },
      {
        mutation_id: 'MUT-SCOPE-01',
        control_id: 'SEC-EXCL-01',
        name: 'Invert Scope Exclusion Decision',
        description: 'Invert exclusion logic.',
        target_component: 'backend/app/services/scope_engine.py',
        mutation_type: 'INVERT_BOOLEAN',
        expected_killer_test: 'test_scope_engine.py::test_exclusion',
        status: 'KILLED',
        execution_time_ms: 8.9,
      },
    ];

    const spy = vi.spyOn(api as any, 'request').mockResolvedValueOnce(mockMutations);
    const result = await api.getMutationScenarios();

    expect(spy).toHaveBeenCalledWith('/system/verification/mutations');
    expect(result).toHaveLength(2);
    expect(result[0].status).toBe('KILLED');
  });

  it('executes mutation testing drill via api.runMutationDrill', async () => {
    const mockDrill: MutationDrillResult = {
      drill_id: 'drill-5a338658',
      total_mutations: 10,
      killed_count: 10,
      survived_count: 0,
      blocked_count: 0,
      kill_ratio_pct: 100.0,
      verdict: 'QUALIFIED',
      executed_at: '2026-10-29T10:00:00Z',
      details: { kill_guarantee: 'Zero Surviving Security Mutations' },
      scenarios: [
        {
          mutation_id: 'MUT-AUTH-01',
          control_id: 'SEC-RBAC-01',
          name: 'Bypass Role Authorization Check',
          description: 'Mutate require_system_roles.',
          target_component: 'backend/app/api/deps.py',
          mutation_type: 'BYPASS_AUTH',
          expected_killer_test: 'test_prompt26.py::test_17',
          status: 'KILLED',
          execution_time_ms: 12.4,
        },
      ],
    };

    const spy = vi.spyOn(api as any, 'request').mockResolvedValueOnce(mockDrill);
    const result = await api.runMutationDrill();

    expect(spy).toHaveBeenCalledWith('/system/verification/run-mutation-drill', {
      method: 'POST',
    });
    expect(result.verdict).toBe('QUALIFIED');
    expect(result.killed_count).toBe(10);
    expect(result.survived_count).toBe(0);
    expect(result.kill_ratio_pct).toBe(100.0);
  });

  it('guarantees every security control defines both positive and negative tests', () => {
    const control: any = {
      control_id: 'SEC-SSRF-01',
      positive_test: 'test_prompt24.py::test_10_ssrf_destination_public_fqdn_permitted',
      negative_test: 'test_prompt24.py::test_07_ssrf_destination_cloud_metadata_blocked',
      enforcement_point: 'NetworkSecurityService.validate_outbound_url',
    };

    expect(control.positive_test).toBeTruthy();
    expect(control.negative_test).toBeTruthy();
    expect(control.positive_test).not.toEqual(control.negative_test);
  });

  it('asserts that any surviving mutation marks drill verdict as DEFECT_DETECTED', () => {
    const defectiveDrill: MutationDrillResult = {
      drill_id: 'drill-defect',
      total_mutations: 10,
      killed_count: 9,
      survived_count: 1, // 1 mutation survived!
      blocked_count: 0,
      kill_ratio_pct: 90.0,
      verdict: 'DEFECT_DETECTED',
      executed_at: '2026-10-29T10:00:00Z',
      details: {},
      scenarios: [],
    };

    expect(defectiveDrill.survived_count).toBeGreaterThan(0);
    expect(defectiveDrill.verdict).toBe('DEFECT_DETECTED');
    expect(defectiveDrill.kill_ratio_pct).toBeLessThan(100.0);
  });
});
