# Intelligent Assessment Scheduling, Risk-Based Prioritization & Resource-Aware Orchestration Matrix (Prompt 34)

## 1. Overview & Architecture

Prompt 34 implements an integrated, explainable scheduling and orchestration capability for the VAPT Platform. It prioritizes authorized assessment workloads according to security risk, evidence freshness, verified exposure drift, and assessment coverage gaps, while respecting strict concurrency bounds, worker lease lifecycles, and anti-starvation aging.

```
+-------------------------------------------------------------------------------------------------+
|                                 VAPT INTELLIGENT SCHEDULER                                      |
+-------------------------------------------------------------------------------------------------+
|                                                                                                 |
|   +--------------------------+        +---------------------------+        +----------------+   |
|   | Incoming Assessment Req  |        | Scope & Policy Pre-flight |        | Evidence State |   |
|   | - Target Host / URL      |------->| - Authorized ScopeTarget  |------->| - Asset Tier   |   |
|   | - Selected Adapter       |        | - ScopeExclusion (Strict!)|        | - Vulnerability|   |
|   | - Trigger Source         |        | - Whitelist & Safety      |        | - Retest Proof |   |
|   +--------------------------+        +---------------------------+        | - Drift Events |   |
|                 |                                   |                      +----------------+   |
|                 v                                   v                               |           |
|   +--------------------------+        +---------------------------+                 |           |
|   | Deduplication & Cooldown |<-------| Multi-Signal Priority     |<----------------+           |
|   | - Dedup Active Scans     |        | - Deterministic Formula   |                             |
|   | - 1h Trigger Cooldown    |        | - Clamped [0.0, 100.0]    |                             |
|   +--------------------------+        +---------------------------+                             |
|                 |                                   |                                           |
|                 +-----------------+-----------------+                                           |
|                                   |                                                             |
|                                   v                                                             |
|   +-----------------------------------------------------------------------------------------+   |
|   | Persistent Assessment Queue (assessment_queue_items)                                    |   |
|   | - Anti-Starvation Aging: effective_prio = min(100, base + hours_queued * aging_factor)   |   |
|   | - Deterministic tie-breaker: effective_priority DESC, created_at ASC                    |   |
|   +-----------------------------------------------------------------------------------------+   |
|                                   |                                                             |
|                 +-----------------+-----------------+                                           |
|                 |                                   |                                           |
|                 v                                   v                                           |
|   +--------------------------+        +---------------------------+        +----------------+   |
|   | Resource Concurrency     |        | Pre-Execution Revalidation|        | Worker Leases  |   |
|   | - Global max concurrent  |------->| - Scope re-checked before |------->| - Claim lease  |   |
|   | - Per-target limit (1)   |        |   claiming                |        | - Crash recovery|  |
|   | - Per-adapter limit (2)  |        | - Fail closed if revoked  |        | - Dead-letter  |   |
|   +--------------------------+        +---------------------------+        +----------------+   |
|                                                                                                 |
|   +-----------------------------------------------------------------------------------------+   |
|   | Append-Only Decision Ledger (scheduler_decision_records)                                 |   |
|   | ENQUEUE | DISPATCH | DEFER | DEDUPLICATE | REJECT | CANCEL | RECOVER | RETRY_BACKOFF      |   |
|   +-----------------------------------------------------------------------------------------+   |
+-------------------------------------------------------------------------------------------------+
```

---

## 2. Deterministic Multi-Signal Priority Formula

Priority is computed deterministically from evidence-backed signals, clamped strictly to $[0.0, 100.0]$, and mapped to priority bands:

$$\text{Priority} = \max\Big(0.0, \min\big(100.0, P_{\text{base}} + S_{\text{criticality}} + S_{\text{findings}} + S_{\text{drift}} + S_{\text{freshness}} + S_{\text{retest}} + S_{\text{compliance}} + P_{\text{penalty}}\big)\Big)$$

| Signal Component | Trigger / Condition | Score Contribution | Evidence Source |
| :--- | :--- | :--- | :--- |
| **Base Score** | Universal baseline | $+20.0$ | Scheduling Policy Default |
| **Asset Criticality** | Asset is `CRITICAL` | $+30.0$ | `Asset.criticality == CRITICAL` |
| | Asset is `HIGH` | $+20.0$ | `Asset.criticality == HIGH` |
| | Asset is `MEDIUM` | $+10.0$ | `Asset.criticality == MEDIUM` |
| | Asset is `LOW` or unregistered | $+5.0$ | `Asset.criticality == LOW` or Unregistered |
| **Finding Severity** | Active finding is `CRITICAL` | $+25.0$ | `VulnerabilityFinding.severity == CRITICAL` |
| | Active finding is `HIGH` | $+15.0$ | `VulnerabilityFinding.severity == HIGH` |
| | Active finding is `MEDIUM` | $+10.0$ | `VulnerabilityFinding.severity == MEDIUM` |
| **Exposure Drift** | Unremediated exposure change | $+15.0$ | `ExposureDriftRecord` on target |
| **Evidence Freshness** | Coverage gap (never scanned) | $+20.0$ | `AssessmentJob` count == 0 |
| | Stale scan ($> 30$ days) | $+15.0$ | `AssessmentJob.completed_at > 30d` |
| | Aging scan ($> 14$ days) | $+10.0$ | `AssessmentJob.completed_at > 14d` |
| | Fresh scan ($< 14$ days) | $+0.0$ | `AssessmentJob.completed_at <= 14d` |
| **Failed Retest** | Active unverified remediation | $+15.0$ | `RemediationVerification.outcome == STILL_VULNERABLE` |
| **Compliance Failure** | Compliance control failing | $+15.0$ | `ComplianceControlResultRecord.status == FAIL` |
| **Failure Penalty** | Repeat infrastructure failure | $-10.0$ | $\ge 2$ consecutive recent scan failures |

### Priority Bands
- **`CRITICAL`**: Score $\ge 80.0$
- **`HIGH`**: Score $\ge 60.0$
- **`MEDIUM`**: Score $\ge 40.0$
- **`LOW`**: Score $< 40.0$

---

## 3. Strict Pre-Flight & Pre-Execution Eligibility

Priority **never** overrides authorization. Pre-flight checks are enforced at **both** enqueue time and immediately before worker claiming:

1. **Defensive Non-Disruptive Boundaries**:
   - Strictly rejects any command or target with disruptive flags (`--flood`, `--dos`, `raw_socket`, `0.0.0.0/0`, `exploit`).
2. **Adapter Whitelist Enforcement**:
   - Only approved non-destructive assessment adapters permitted: `local_fixture_adapter`, `ssl_tls_analyzer`, `http_header_inspector`, `port_service_scanner`, `compliance_evaluator`, `web_app_scanner`.
3. **Scope Exclusions Take Absolute Precedence**:
   - Any matching entry in `ScopeExclusion` immediately invalidates the target, regardless of broad scope inclusions.
4. **Scope Inclusion & Authorization Verification**:
   - Target must match an active `ScopeTarget` with status `AUTHORIZED`.
5. **Immediate Pre-Execution Revalidation**:
   - If scope authorization is revoked or an exclusion is added between enqueue and execution, the dispatcher transitions the job to `FAILED` with category `PREFLIGHT_ELIGIBILITY_REVOKED`, refusing to dispatch.

---

## 4. Resource-Aware Concurrency & Anti-Starvation Aging

The scheduler governs worker pools and prevents workload starvation:

### Resource Throttles
- **Global Concurrency Ceiling**: Configurable `max_concurrent_assessments` (default: 5).
- **Per-Target Concurrency**: Configurable `max_per_target_concurrency` (default: 1). Prevents multi-worker hammering of a single target host.
- **Per-Adapter Concurrency**: Configurable `max_per_adapter_concurrency` (default: 2). Prevents one heavy adapter from monopolizing all slots.
- **Maximum Queue Depth**: Configurable `max_queued_jobs` (default: 100). Fails closed when capacity is reached.

### Anti-Starvation Aging Mechanics
To ensure low-priority tasks are not indefinitely postponed by higher-priority bursts:
$$\text{Effective Priority} = \min\big(100.0, P_{\text{score}} + (\Delta t_{\text{hours}} \times \text{Aging Factor})\big)$$
- Default aging factor: $2.0$ points per hour queued.
- Tie-breaker: `effective_priority DESC`, `created_at ASC`.

---

## 5. Worker Lease Lifecycle, Crash Recovery & Cancellation

### Lease Lifecycle
- Workers claim items atomically in short SQLite WAL transactions.
- Claiming records `worker_claim_id`, `claimed_at`, and `lease_expires_at = now + stale_lease_timeout_sec` (default: 120s).
- Spawns underlying `AssessmentJob` in `RUNNING` status.

### Crash & Abandonment Recovery
- `recover_stale_leases` periodically scans for `DISPATCHED` items where `lease_expires_at <= now`.
- **Transient Worker Crash**: If `retry_count < max_retries`, resets to `SCHEDULED`, increments retry count, and applies bounded exponential backoff:
  $$\text{Backoff} = \min(300, \text{backoff\_seconds} \times 2^{\text{retry\_count}-1})$$
- **Dead-Letter Handling**: If `retry_count >= max_retries`, transitions to `FAILED` with category `DEAD_LETTER_MAX_RETRIES_EXCEEDED`.

### Observable Cancellation
- Cancellation requests persist immediately in `cancellation_requested_at`.
- Queued jobs cancel immediately to `CANCELLED`.
- Dispatched jobs cascade cancellation to the running `AssessmentJob`.

---

## 6. Automated Trigger Cooldown & Deduplication

Automated triggers (`DRIFT_DETECTED`, `HIGH_SEVERITY_FINDING`, `FAILED_RETEST`, `STALE_EVIDENCE`) are governed by a configurable cooldown window (`cooldown_period_sec = 3600s`):
- If an assessment for the same target and adapter is currently `PENDING`, `SCHEDULED`, `DISPATCHED`, or completed within 3600s, the trigger is deduplicated.
- Records `DEDUPLICATE` in the append-only `scheduler_decision_records` ledger.
- Prevents infinite scan storms from repetitive monitoring observations.

---

## 7. Verified Test Scenarios

The test suite in `backend/tests/test_prompt34_intelligent_scheduling.py` covers all 20 required scenarios (100% pass):

| # | Test Scenario | Verification Objective | Outcome |
| :--- | :--- | :--- | :--- |
| 1 | `test_deterministic_priority_calculation` | Multi-signal calculation, clamping, explanation string | **PASSED** |
| 2 | `test_missing_or_stale_evidence_affects_priority_correctly` | Freshness vs staleness vs coverage gap scoring | **PASSED** |
| 3 | `test_priority_never_bypasses_scope` | Out-of-scope targets rejected regardless of priority | **PASSED** |
| 4 | `test_explicit_scope_exclusions_precedence` | Exclusions override broad inclusions | **PASSED** |
| 5 | `test_preflight_eligibility_revocation_blocks_dispatch` | Revocation between queue and execution caught at preflight | **PASSED** |
| 6 | `test_deduplication_of_identical_active_requests` | Prevents duplicate queued items | **PASSED** |
| 7 | `test_concurrency_control_and_worker_leases` | Atomic worker claims, lease expiration, AssessmentJob link | **PASSED** |
| 8 | `test_stale_lease_recovery_and_bounded_backoff` | Crash recovery with exponential backoff | **PASSED** |
| 9 | `test_dead_letter_max_retries_exceeded` | Exhausted retries transition to dead-letter FAILED | **PASSED** |
| 10 | `test_anti_starvation_aging_fairness` | Aging factor elevates starved tasks above newer tasks | **PASSED** |
| 11 | `test_per_target_concurrency_limit` | At most 1 active scan per target host | **PASSED** |
| 12 | `test_observable_cancellation_state` | Cancellation timestamps and state audit durability | **PASSED** |
| 13 | `test_reassessment_trigger_cooldown` | Coalesces automated triggers within 1h cooldown | **PASSED** |
| 14 | `test_api_scheduling_endpoints` | Full REST API, RBAC, outsider 404 isolation, viewer/tester roles | **PASSED** |
| 15 | `test_global_concurrency_limit_deferral` | Defers work when global slots are full | **PASSED** |
| 16 | `test_per_adapter_concurrency_limit` | Isolates tooling concurrency | **PASSED** |
| 17 | `test_queue_capacity_limit_rejection` | Max queue depth rejects excess work | **PASSED** |
| 18 | `test_update_scheduling_policy_governance` | Policy updates by Project LEAD with validation bounds | **PASSED** |
| 19 | `test_disruptive_scanning_boundary_enforcement` | Non-defensive flags rejected | **PASSED** |
| 20 | `test_preview_does_not_reserve_capacity_or_persist` | Read-only calculation without side effects | **PASSED** |
