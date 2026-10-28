# Unified Security Intelligence Engine Architecture

## 1. Executive Summary

The **Unified Security Intelligence Engine** (`SecurityIntelligenceService`) provides an evidence-grounded, cross-domain intelligence layer for the VAPT System. Rather than functioning as an isolated analytical module or relying on simulated heuristics, it ingests, correlates, and synthesizes real persisted data from across every operational subsystem:

1. **Scope Authorization & Governance** (`ScopeTarget`, ROE boundaries)
2. **Assessment Execution & Cryptographic Evidence** (`AssessmentJob`, `AssessmentFinding`, `FindingEvidence`)
3. **Asset Inventory & Service Topology** (`Asset`, `canonical_identifier`, criticalities)
4. **Universal Security Knowledge Graph** (`GraphNode`, `GraphRelationship`, `AttackPathService`)
5. **Contextual Risk Intelligence** (`ContextualRiskService` v2.0.0)
6. **Remediation & Independent Verification** (`RemediationPlan`, `RemediationVerification`)
7. **Continuous Monitoring & Posture Evolution** (`PostureChangeRecord`, `ContinuousMonitoringService`)
8. **Controlled Learning Governance** (`PredictionLedgerService`, `ModelGovernanceService`)

All intelligence summaries, risk factor decompositions, and adaptive assessment recommendations trace directly to immutable, database-backed entities with cryptographic SHA-256 evidence hashes.

---

## 2. Cross-Domain Data Fusion Architecture

```
+-----------------------------------------------------------------------------------+
|                         UNIFIED SECURITY INTELLIGENCE                             |
|                    (SecurityIntelligenceService, v2.0.0)                          |
+-----------------------------------------------------------------------------------+
            ^                     ^                     ^                    ^
            |                     |                     |                    |
   [Scope & Authorization]  [Assessment Jobs]    [Asset Inventory]   [Knowledge Graph]
   - ScopeTarget (ROE)      - AssessmentJob      - Asset             - GraphNode
   - TargetType & Bounds    - AssessmentFinding  - AssetCriticality  - GraphRelationship
   - AuthorizationStatus    - FindingEvidence    - Network Exposure  - Attack Paths
            |                     |                     |                    |
            v                     v                     v                    v
   [Contextual Risk v2.0]   [Remediation Plan]   [Posture Tracking]  [Learning Engine]
   - Severity & Confidence  - RemediationPlan    - PostureChange     - PredictionLedger
   - Multipliers & Bounds   - VerificationRecord - Sliding Window    - Verified Ground Truth
   - Contradiction Penalty  - Re-test Outcomes   - Storm Throttling  - Safe Fallbacks
+-----------------------------------------------------------------------------------+
```

### Ingestion Subsystems

1. **Authorized Scope Engine:** Filters all intelligence processing through explicitly approved targets (`AuthorizationStatus.AUTHORIZED`). Any entity outside verified Rules of Engagement (ROE) is strictly excluded from active probe planning.
2. **Finding & Evidence Store:** Ingests normalized vulnerability findings (`VulnerabilityFinding`) paired with their raw, cryptographically verified `FindingEvidence` records.
3. **Graph Topology & Attack Paths:** Integrates validated attack paths and relational exposure directly from the graph database. Bare topological proximity without verified exploitability does not amplify risk.
4. **Remediation & Independent Retests:** Ingests closed-loop verification results (`RemediationVerification`). Unsuccessful remediation attempts trigger prior-failure risk multipliers and prioritize verification re-assessments.
5. **Posture Drift Telemetry:** Monitors configuration modifications, newly discovered ports, or updated certificates, feeding event-driven reassessments.

---

## 3. Cryptographic Provenance & Evidence Verification

Every intelligence summary response carries a `data_provenance` block verifying the exact database footprint used to generate the report:

```json
{
  "data_provenance": {
    "total_jobs": 14,
    "total_assets": 8,
    "total_findings": 12,
    "total_evidence_records": 19,
    "total_verifications": 5,
    "total_changes": 7,
    "generated_at": "2026-10-28T14:30:00Z"
  }
}
```

### Verification Invariants
- **No Synthetic Records in Production:** The engine strictly queries persisted database records. In development/testing environments, synthetic generation is forbidden unless explicitly requested via test harnesses.
- **SHA-256 Evidence Anchors:** Every raw evidence payload is cryptographically hashed (`FindingEvidence.sha256_hash`). Evidence integrity verification runs continuously via the `IntegrityService`.
- **Reproducible State Calculation:** When evaluated against identical database state, intelligence summaries and risk calculations yield identical, bit-for-bit deterministic results.

---

## 4. API Endpoints

The intelligence service exposes five core REST endpoints under `/api/v1/intelligence`:

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/{project_id}/summary` | Comprehensive intelligence summary: risk distributions, asset coverage, posture activity, and provenance digests. |
| `GET` | `/{project_id}/coverage-audit` | Evaluates asset coverage staleness against the organization's SLA (default: 14 days) and highlights unassessed targets. |
| `POST` | `/{project_id}/adaptive-plan` | Synthesizes an evidence-driven adaptive assessment plan honoring scope limits and scan budgets. |
| `POST` | `/{project_id}/execute-check/{plan_id}/{check_index}` | Dispatches an individual recommended assessment check into the execution queue. |
| `POST` | `/{project_id}/posture-change` | Records an external or monitored configuration change with sliding-window deduplication and storm protection. |

---

## 5. Security & Scope Guardrails

1. **Fail-Closed Target Authorization:** If an asset or posture change target does not match an authorized `ScopeTarget` with valid timestamps, it is rejected into the plan's `skipped_checks` collection with the reason `"Target outside authorized project scope"`.
2. **Scan Budget Enforcement:** Probe generation respects operator-configured budget limits (`scan_budget`, default 10). Items exceeding the budget are deferred into `skipped_checks` with `"Scan budget limit reached"`.
3. **Storm Throttling & Deduplication:** To protect the target network and assessment infrastructure:
   - Duplicate changes within 15 minutes are silently dropped as deduplicated.
   - If more than 5 distinct changes arrive within 60 seconds, storm throttling activates, batching updates to prevent runaway worker exhaustion.
