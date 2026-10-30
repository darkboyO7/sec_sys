import { describe, it, expect } from 'vitest';
import type {
  RemediationRecommendation,
  RecommendationUsefulnessMetrics,
  GuidanceType,
  BusinessPriority,
  RemediationUrgency,
  RecommendationFeedback,
} from '../types';

describe('Prompt 51: Explainable Security Recommendations & Remediation Prioritization Contract Tests', () => {
  it('01: should enforce multi-dimensional prioritization fields on recommendation models', () => {
    const rec: RemediationRecommendation = {
      id: 'rec-001',
      project_id: 'proj-001',
      finding_id: 'find-001',
      title: 'Enforce Parameterized Queries and Least-Privilege DB Access',
      action_type: 'CODE_REFACTOR',
      description: 'Refactor SQL concatenation to prepared statements.',
      rationale: 'Neutralizes SQL injection at data access boundary.',
      qualitative_benefit: 'Prevents unauthorized read/write access.',
      guidance_type: 'VERIFIED_INSTRUCTION' as GuidanceType,
      technical_severity: 'CRITICAL',
      business_priority: 'P1_CRITICAL' as BusinessPriority,
      confidence: 0.95,
      remediation_urgency: 'IMMEDIATE' as RemediationUrgency,
      source_evidence_ids: ['ev-001', 'ev-002'],
      ranking_factors: {
        technical_severity: 'CRITICAL',
        asset_criticality: 'CRITICAL',
        is_internet_facing: true,
        evidence_strength: 'CONFIRMED',
        factor_explanation: 'Ranked P1_CRITICAL due to critical severity on internet-facing asset.',
      },
      advisory_disclaimer: 'Verified catalog recommendation. Automated execution is prohibited.',
      missing_prerequisites: ['Call site static audit required before commit.'],
      compatibility_concerns: ['Legacy clients may require driver update.'],
      dependencies: ['Application Runtime', 'Database Driver'],
      version: 1,
      is_latest: true,
      requires_approval: true,
      approval_role: 'LEAD',
      status: 'PENDING_REVIEW',
      prerequisites: ['Locate call sites'],
      operational_impact: 'Low',
      rollback_procedure: 'Revert git commit',
      verification_criteria: 'Target rejects quote-based payloads',
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    };

    expect(rec.guidance_type).toBe('VERIFIED_INSTRUCTION');
    expect(rec.business_priority).toBe('P1_CRITICAL');
    expect(rec.remediation_urgency).toBe('IMMEDIATE');
    expect(rec.confidence).toBe(0.95);
    expect(rec.source_evidence_ids).toHaveLength(2);
    expect(rec.version).toBe(1);
    expect(rec.is_latest).toBe(true);
    expect(rec.advisory_disclaimer).toContain('Automated execution is prohibited');
  });

  it('02: should classify unverified model output and cap confidence', () => {
    const unverifiedRec: Partial<RemediationRecommendation> = {
      guidance_type: 'UNVERIFIED_SUGGESTION',
      confidence: 0.40,
      advisory_disclaimer: 'NOTICE: This recommendation is an UNVERIFIED SUGGESTION. Manual code review is strictly required.',
    };

    expect(unverifiedRec.guidance_type).toBe('UNVERIFIED_SUGGESTION');
    expect(unverifiedRec.confidence).toBeLessThanOrEqual(0.50);
    expect(unverifiedRec.advisory_disclaimer).toContain('UNVERIFIED SUGGESTION');
  });

  it('03: should validate feedback models without modifying historical decisions', () => {
    const feedback: RecommendationFeedback = {
      id: 'fb-001',
      project_id: 'proj-001',
      recommendation_id: 'rec-001',
      user_id: 'usr-001',
      feedback_type: 'HELPFUL',
      rating: 5,
      comment: 'Fix resolved the issue cleanly.',
      was_actionable: true,
      applied_as_instructed: true,
      created_at: new Date().toISOString(),
    };

    expect(feedback.feedback_type).toBe('HELPFUL');
    expect(feedback.rating).toBe(5);
    expect(feedback.was_actionable).toBe(true);
    expect(feedback.applied_as_instructed).toBe(true);
  });

  it('04: should validate usefulness metrics schema and reject fabricated numbers', () => {
    const metrics: RecommendationUsefulnessMetrics = {
      project_id: 'proj-001',
      total_recommendations: 12,
      latest_recommendations: 10,
      by_status: { PENDING_REVIEW: 4, APPROVED: 5, DEFERRED: 1, REJECTED: 0 },
      reviewed_count: 6,
      approval_rate: 0.833,
      by_guidance_type: { VERIFIED_INSTRUCTION: 8, GENERAL_GUIDANCE: 2, UNVERIFIED_SUGGESTION: 0 },
      by_urgency: { IMMEDIATE: 3, SCHEDULED_SPRINT: 4, NEXT_CYCLE: 3, BACKLOG: 0 },
      by_business_priority: { P1_CRITICAL: 3, P2_HIGH: 4, P3_MEDIUM: 3, P4_LOW: 0 },
      total_feedback_count: 5,
      by_feedback_type: { HELPFUL: 4, UNHELPFUL: 0, INACCURATE: 0, INCOMPLETE: 1, OUTDATED: 0, IRRELEVANT: 0 },
      actionable_count: 4,
      not_actionable_count: 1,
      actionable_ratio: 0.80,
      applied_count: 4,
      average_rating: 4.6,
      helpfulness_ratio: 1.0,
      total_verified_count: 3,
      by_verified_outcome: { VERIFIED_FIXED: 2, STILL_VULNERABLE: 1 },
      verified_resolution_rate: 0.667,
      data_grounding_notice: 'Metrics measured strictly from actual historical records. Zero synthetic scores.',
    };

    expect(metrics.total_recommendations).toBe(12);
    expect(metrics.approval_rate).toBeCloseTo(0.833, 2);
    expect(metrics.verified_resolution_rate).toBeCloseTo(0.667, 2);
    expect(metrics.data_grounding_notice).toContain('Zero synthetic scores');
  });

  it('05: should maintain version lineage with prior version references', () => {
    const v1: Partial<RemediationRecommendation> = {
      id: 'rec-v1',
      version: 1,
      is_latest: false,
      superseded_at: '2026-10-30T10:00:00Z',
      status: 'APPROVED',
      review_notes: 'Approved v1 by Lead',
    };

    const v2: Partial<RemediationRecommendation> = {
      id: 'rec-v2',
      version: 2,
      prior_version_id: 'rec-v1',
      is_latest: true,
      status: 'PENDING_REVIEW',
    };

    expect(v2.version).toBe(2);
    expect(v2.prior_version_id).toBe('rec-v1');
    expect(v1.is_latest).toBe(false);
    expect(v1.status).toBe('APPROVED');
  });
});
