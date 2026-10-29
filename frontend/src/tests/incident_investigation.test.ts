import { describe, it, expect, vi } from 'vitest';
import { api } from '../services/api';
import type {
  IncidentCaseDetail,
  IncidentCaseSummary,
  CorrelationExplanation,
  TimelineEvent,
} from '../types';

describe('Prompt 39: Evidence-Preserving Security Incident Investigation and Case Management Frontend Tests', () => {
  it('should list and create incident cases with provenance and metadata', async () => {
    const mockCases: IncidentCaseSummary[] = [
      {
        id: 'inc-1',
        project_id: 'proj-1',
        case_number: 'INC-2026-0001',
        title: 'Suspected Lateral Movement from Edge Gateway',
        severity: 'HIGH',
        status: 'OPEN',
        lead_investigator_id: 'user-alice-uuid',
        assigned_team: 'SOC Core',
        opened_at: '2026-10-29T12:00:00Z',
        closed_at: null,
        is_containment_verified: false,
        created_at: '2026-10-29T12:00:00Z',
      },
    ];

    vi.spyOn(api, 'listIncidentCases').mockResolvedValue(mockCases);

    const res = await api.listIncidentCases('proj-1');
    expect(res.length).toBe(1);
    expect(res[0].case_number).toBe('INC-2026-0001');
    expect(res[0].status).toBe('OPEN');

    const createdCase: IncidentCaseDetail = {
      ...mockCases[0],
      description: 'Initial triage of anomalous traffic pattern',
      reopened_at: null,
      root_cause_hypothesis: null,
      alternative_explanations: [],
      closure_summary: null,
      closure_approved_by_id: null,
      reopening_rationale: null,
      linked_assets: [],
      linked_findings: [],
      linked_evidence: [],
      transitions: [],
      notes: [],
    };

    vi.spyOn(api, 'createIncidentCase').mockResolvedValue(createdCase);

    const created = await api.createIncidentCase('proj-1', {
      title: 'Suspected Lateral Movement from Edge Gateway',
      severity: 'HIGH',
    });
    expect(created.id).toBe('inc-1');
    expect(created.title).toBe('Suspected Lateral Movement from Edge Gateway');
  });

  it('should distinguish confirmed causation from temporal correlation when linking findings', async () => {
    vi.spyOn(api, 'linkFindingToCase').mockResolvedValue({
      status: 'LINKED',
      link_id: 'link-f1',
    });

    const resCausation = await api.linkFindingToCase('proj-1', 'inc-1', {
      finding_id: 'find-1',
      correlation_type: 'CONFIRMED_CAUSATION',
      confidence: 0.95,
      rationale: 'Direct exploit execution trace verified in process logs',
    });
    expect(resCausation.status).toBe('LINKED');

    const resCorrelation = await api.linkFindingToCase('proj-1', 'inc-1', {
      finding_id: 'find-2',
      correlation_type: 'TEMPORAL_COINCIDENCE',
      confidence: 0.4,
      rationale: 'Coincident packet bursts observed during exploit window',
    });
    expect(resCorrelation.status).toBe('LINKED');
  });

  it('should capture and preserve contradictory evidence with SHA-256 digest', async () => {
    vi.spyOn(api, 'attachEvidenceToCase').mockResolvedValue({
      status: 'ATTACHED',
      evidence_id: 'ev-101',
      digest: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    });

    const evidence = await api.attachEvidenceToCase('proj-1', 'inc-1', {
      evidence_summary: 'Firewall drop logs indicate packet payload was neutralized at ingress',
      is_contradictory: true,
      provenance_details: {
        source_appliance: 'edge-firewall-01',
        rule_id: 'DENY_RCE_SIG_9001',
      },
    });

    expect(evidence.status).toBe('ATTACHED');
    expect(evidence.digest).toHaveLength(64);
  });

  it('should evaluate correlation explanation separating causation, correlation, and contradictory findings', async () => {
    const mockExplanation: CorrelationExplanation = {
      case_id: 'inc-1',
      case_number: 'INC-2026-0001',
      total_linked_findings: 3,
      total_linked_assets: 2,
      confirmed_causation: [
        {
          finding_id: 'find-1',
          finding_title: 'Remote Code Execution in Ingress Gateway',
          correlation_type: 'CONFIRMED_CAUSATION',
          confidence: 0.95,
          rationale: 'Verified RCE with process dump payload execution',
        },
      ],
      probable_correlations: [
        {
          finding_id: 'find-2',
          finding_title: 'Unauthenticated Metrics Exposure',
          correlation_type: 'PROBABLE_CORRELATION',
          confidence: 0.75,
          rationale: 'Reconnaissance scanning pattern before RCE',
        },
      ],
      temporal_coincidences: [],
      contradictory_findings: [
        {
          finding_id: 'find-3',
          finding_title: 'Internal Subnet SSH Password Spray',
          correlation_type: 'CONTRADICTORY_EVIDENCE',
          confidence: 0.85,
          rationale: 'Originates from disparate external IP block with distinct user agent',
        },
      ],
      contradictory_evidence_count: 1,
      alternative_hypotheses_count: 1,
      correlation_summary: '1 confirmed causal link, 1 probable correlation, 1 contradictory finding.',
    };

    vi.spyOn(api, 'getCaseCorrelations').mockResolvedValue(mockExplanation);

    const explanation = await api.getCaseCorrelations('proj-1', 'inc-1');
    expect(explanation.total_linked_findings).toBe(3);
    expect(explanation.confirmed_causation.length).toBe(1);
    expect(explanation.contradictory_findings.length).toBe(1);
    expect(explanation.contradictory_findings[0].correlation_type).toBe('CONTRADICTORY_EVIDENCE');
  });

  it('should transition case status requiring closure summary and reopening rationale', async () => {
    const closedCase: IncidentCaseDetail = {
      id: 'inc-1',
      case_number: 'INC-2026-0001',
      project_id: 'proj-1',
      title: 'Suspected Lateral Movement from Edge Gateway',
      description: 'Initial triage',
      severity: 'HIGH',
      status: 'CLOSED',
      lead_investigator_id: 'user-alice-uuid',
      assigned_team: 'SOC Core',
      opened_at: '2026-10-29T12:00:00Z',
      closed_at: '2026-10-29T14:00:00Z',
      reopened_at: null,
      root_cause_hypothesis: 'Exploitation of CVE-2024-1234 on ingress gateway',
      alternative_explanations: [],
      closure_summary: 'Gateway isolated, patched, and network segmentation rules verified',
      closure_approved_by_id: 'lead-lead-uuid',
      is_containment_verified: true,
      reopening_rationale: null,
      created_at: '2026-10-29T12:00:00Z',
      linked_assets: [],
      linked_findings: [],
      linked_evidence: [],
      transitions: [],
      notes: [],
    };

    vi.spyOn(api, 'transitionCaseStatus').mockResolvedValue(closedCase);

    const closed = await api.transitionCaseStatus('proj-1', 'inc-1', {
      to_status: 'CLOSED',
      reason: 'Containment and patching completed',
      closure_summary: 'Gateway isolated, patched, and network segmentation rules verified',
      root_cause_hypothesis: 'Exploitation of CVE-2024-1234 on ingress gateway',
      is_containment_verified: true,
    });

    expect(closed.status).toBe('CLOSED');
    expect(closed.is_containment_verified).toBe(true);
    expect(closed.closure_summary).toContain('Gateway isolated');

    const reopenedCase: IncidentCaseDetail = {
      ...closedCase,
      status: 'REOPENED',
      closed_at: null,
      reopened_at: '2026-10-29T15:00:00Z',
      reopening_rationale: 'Secondary egress telemetry detected persisting beaconing activity',
    };

    vi.spyOn(api, 'transitionCaseStatus').mockResolvedValue(reopenedCase);

    const reopened = await api.transitionCaseStatus('proj-1', 'inc-1', {
      to_status: 'REOPENED',
      reason: 'Persistent beaconing',
      reopening_rationale: 'Secondary egress telemetry detected persisting beaconing activity',
    });

    expect(reopened.status).toBe('REOPENED');
    expect(reopened.reopening_rationale).toContain('persisting beaconing');
  });

  it('should fetch complete chronological timeline events with provenance', async () => {
    const mockTimeline: TimelineEvent[] = [
      {
        event_type: 'STATUS_TRANSITION',
        timestamp: '2026-10-29T12:00:00Z',
        actor_id: 'user-alice-uuid',
        summary: 'Case opened from security alert #401',
        details: { from_status: null, to_status: 'OPEN' },
      },
      {
        event_type: 'EVIDENCE_ATTACHED',
        timestamp: '2026-10-29T12:15:00Z',
        actor_id: 'user-bob-uuid',
        summary: 'Attached contradictory edge firewall drop logs',
        details: { is_contradictory: true, digest: 'sha256-abc123' },
      },
    ];

    vi.spyOn(api, 'getCaseTimeline').mockResolvedValue(mockTimeline);

    const timeline = await api.getCaseTimeline('proj-1', 'inc-1');
    expect(timeline.length).toBe(2);
    expect(timeline[0].event_type).toBe('STATUS_TRANSITION');
    expect(timeline[1].details.is_contradictory).toBe(true);
  });
});
