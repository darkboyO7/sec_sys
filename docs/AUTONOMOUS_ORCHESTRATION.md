# Autonomous Security Orchestration Engine (Prompt 15)

## 1. Executive Summary & Purpose
The **Autonomous Security Orchestration Engine** integrates the platform's distributed capabilities—scope authorization, passive network adapters, isolated workers, evidence provenance, finding normalization, epistemic knowledge graphs, contextual risk scoring, governed remediation, independent retesting, digital-twin snapshots, adaptive defense, diagnostics, and controlled recovery—into a coherent, closed-loop security operating system.

The engine coordinates real events into justified, authorized actions and measures whether those actions genuinely improved the target's security posture.

```
       [ Incoming Operational Event ]
                      │
                      ▼
        [ Event Processing & Dedup ] ── (Duplicate? Coalesce / Drop)
                      │
                      ▼
       [ Orchestration State Machine ] ── (IDLE ──► EVENT_RECEIVED)
                      │
                      ▼
         [ Context Gathering Phase ] ── (Snapshot Posture, Scope, Policies)
                      │
                      ▼
        [ Evidence-Driven Planner ] ── (Generate Action & Rationale)
                      │
        ┌─────────────┴─────────────┐
        ▼                           ▼
[ Safe Autonomous ]      [ Disruptive Action ]
        │                           │
        │                           ▼
        │               [ Human Approval Gate ]
        │               (LEAD / ADMIN Role Gate)
        │                           │
        └─────────────┬─────────────┘
                      │ (Approved)
                      ▼
      [ Pre-Execution Authorization ] ── (Revoked/Excluded? FAIL-CLOSED)
                      │
                      ▼
       [ Concurrency Lease & Lock ]
                      │
                      ▼
         [ Execution & Retesting ]
                      │
                      ▼
     [ Closed-Loop Outcome Measure ] ── (Compare Initial vs Final Posture)
                      │
                      ▼
    [ Dependency Tree Invalidation ] ── (Propagate Stale Flags & Recalculate)
                      │
                      ▼
           [ Terminal State Update ] ── (COMPLETED / FAILED / SUSPENDED)
```

---

## 2. Central Orchestration State Machine

The orchestration lifecycle operates with 12 deterministic states governed by `OrchestrationStateMachine`:

| State | Purpose | Permitted Next States |
| :--- | :--- | :--- |
| `IDLE` | Workflow record initialized. | `EVENT_RECEIVED` |
| `EVENT_RECEIVED` | Event persisted and validated against deduplication window. | `CONTEXT_GATHERED`, `FAILED`, `SUSPENDED` |
| `CONTEXT_GATHERED` | Initial security posture captured; scope and policies loaded. | `DECISION_PENDING`, `FAILED`, `SUSPENDED` |
| `DECISION_PENDING` | Evidence planner evaluates action and justification. | `AWAITING_APPROVAL`, `ACTION_QUEUED`, `COMPLETED`, `FAILED`, `SUSPENDED` |
| `AWAITING_APPROVAL` | Disruptive or high-impact action waiting for Lead/Admin. | `ACTION_QUEUED`, `COMPLETED`, `FAILED`, `SUSPENDED` |
| `ACTION_QUEUED` | Action approved and queued; ready for worker pickup. | `ACTION_RUNNING`, `FAILED`, `SUSPENDED` |
| `ACTION_RUNNING` | Worker actively executing task under concurrency lease. | `VERIFYING_OUTCOME`, `COMPLETED`, `PARTIALLY_COMPLETED`, `FAILED`, `SUSPENDED` |
| `VERIFYING_OUTCOME` | Retest or verification active; comparing posture delta. | `COMPLETED`, `PARTIALLY_COMPLETED`, `FAILED`, `SUSPENDED` |
| `COMPLETED` | Terminal state; closed-loop outcome measured and persisted. | *(None — Terminal)* |
| `PARTIALLY_COMPLETED` | Step finished but follow-up action required. | `ACTION_QUEUED`, `COMPLETED` |
| `FAILED` | Execution or authorization failure; failure reason recorded. | `ACTION_QUEUED` *(on retry)*, `SUSPENDED` |
| `SUSPENDED` | Suspended by policy, operator, or safety invariant. | `CONTEXT_GATHERED`, `DECISION_PENDING`, `ACTION_QUEUED`, `FAILED` |

### Invariants:
1. **Transition Integrity:** Any transition not explicitly declared in `ALLOWED_TRANSITIONS` raises `OrchestrationTransitionError`.
2. **Idempotence:** Requesting a transition to the workflow's current state is a safe no-op.
3. **Lease Expiration & Crash Recovery:** Workflows held in running states past `lock_expires_at` are reaped by `recover_expired_leases` and transitioned to `SUSPENDED`, preserving all partial results and error payloads.
4. **Never Assume Success on Missing Data:** A missing verification record yields `OUTCOME_INCONCLUSIVE` or `NO_MEASURABLE_IMPROVEMENT`, never `FINDING_VERIFIED_RESOLVED`.

---

## 3. Concurrency Leases & Worker Isolation

To prevent race conditions, double-execution, and resource starvation across asynchronous workers:
- Each executing workflow must acquire an exclusive concurrency lease:
  - `locked_by`: Worker identifier (e.g. `worker-pid-1049` or `operator-usr-01`).
  - `locked_at`: UTC timestamp of lease acquisition.
  - `lock_expires_at`: UTC timestamp when lease lapses (default: 60 seconds).
- Active locks held by other unexpired workers raise `ConcurrencyLockError`.
- Upon reaching `COMPLETED`, `FAILED`, or `SUSPENDED`, the engine explicitly releases the lease.

---

## 4. Operator Control Plane

The operator control plane provides authenticated access via REST endpoints (`/api/v1/orchestration`) and the React UI (`OrchestrationView.tsx`):
- **Live State Visibility:** Current state, trigger event, target resource, confidence, and uncertainty.
- **Approval Gate Interaction:** One-click `Approve` (advances to `ACTION_QUEUED`) or `Reject` (advances to `COMPLETED`).
- **Safety Overrides:** Real-time `Suspend`, `Resume`, and `Retry` with zero-trust scope re-validation.
- **Manual Event Ingestion:** Operators can manually inject events (`CONFIG_CHANGED`, `DIAGNOSTIC_FAILURE`, etc.) to trigger orchestration cycles.

---

## 5. Automated Verification Summary

The orchestration state machine and lifecycle engine are verified in `test_prompt15_autonomous_security_orchestration.py`:
- `test_scenario_01`: Valid event triggers justified assessment recommendation.
- `test_scenario_07`: Crash recovery reaps expired worker leases safely without re-execution.
- `test_scenario_09`: RBAC gate prevents non-Lead/Admin users from approving restricted actions.
- `test_scenario_17`: REST API returns persisted workflow state rather than stale cached client state.
- `test_scenario_18`: Completed workflows cannot be replayed or rewritten.
