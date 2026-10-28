# Dependency Invalidation and Recalculation Engine (Prompt 15)

## 1. Overview & Architectural Problem
In complex security platforms, derived intelligence (risk scores, attack path graphs, digital-twin snapshots, composite posture ratings) depends on low-level observations (assets, open ports, vulnerability findings, cryptographic evidence).

When an underlying entity changes or fails verification:
- Silently retaining stale derived scores misleads operators into believing high-risk targets are safe.
- Naive global re-computation causes O(N) database locks, CPU thrashing, and circular update loops.

The `DependencyInvalidationService` solves this via **targeted dependency tracking, explicit invalidation records, and non-circular bounded recalculation**.

---

## 2. Invalidation Propagation Matrix

```
[ Mutated Source Entity ]
          │
          ├──► Asset Modified ──────────► Invalidate: Graph Relationships, Asset Risk
          ├──► Finding Status Mutated ──► Invalidate: Contextual Risk, Attack Paths
          ├──► Evidence Hash Mismatch ──► Invalidate: Downstream Finding, Project Posture
          └──► Model Version Updated ───► Invalidate: Governed Predictions (Preserve History)
```

| Source Entity | Trigger Event | Invalidation Targets | Action Taken |
| :--- | :--- | :--- | :--- |
| **`Asset`** | Attribute/Service mutation | Dependent `RiskAssessment`, `GraphRelationship` | Marks risk stale; recalculates asset risk on next cycle. |
| **`VulnerabilityFinding`** | Status/Severity change | `RiskAssessment`, `AttackPath` | Updates asset and project composite risk scores. |
| **`FindingEvidence`** | SHA-256 Tamper Alert | Downstream `VulnerabilityFinding`, `SecurityPosture` | Suspends finding validity; halts autonomous remediation. |
| **`GovernedModel`** | Model version upgrade | `PredictionLedger` | Flags past predictions as `SUPERSEDED`; evaluates new predictions. |

---

## 3. Persistent Invalidation Records

All invalidations are persisted in `dependency_invalidation_records`:
- `source_entity_type`: Entity class (`Asset`, `Finding`, `Evidence`).
- `source_entity_id`: Entity primary key.
- `invalidation_type`: Enum string (`ASSET_CHANGED`, `FINDING_MUTATED`, `EVIDENCE_CORRUPTED`).
- `invalidated_targets`: JSON array of dependent entities requiring recomputation.
- `recalculation_status`: `PENDING`, `RECALCULATED`, `SUPERSEDED`, `FAILED`.
- `provenance`: Originating event and reason for auditability.

---

## 4. Preventing Circular Recalculation Loops

When derived entities are recomputed, they may trigger secondary events. To prevent infinite loops:
1. `process_pending_recalculations` maintains a session-scoped `visited_entities` set.
2. If `f"{entity_type}:{entity_id}"` has already been processed in the current recalculation sweep, the duplicate record is marked `SUPERSEDED` and skipped.
3. Execution batch size is strictly bounded to 20 invalidations per sweep.

---

## 5. Verification Evidence

Verified in `backend/tests/test_prompt15_autonomous_security_orchestration.py`:
- `test_scenario_05`: Mutating asset attributes invalidates dependent `RiskAssessment` records and processes recalculation to `RECALCULATED`.
- `test_scenario_12`: Cryptographic evidence failure suspends downstream conclusions immediately.
