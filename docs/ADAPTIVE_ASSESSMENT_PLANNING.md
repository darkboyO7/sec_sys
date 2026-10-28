# Adaptive Assessment Planning Specification & Runbook

## 1. Overview & Architecture

The **Adaptive Assessment Planner** (`generate_adaptive_assessment_plan`) synthesizes an evidence-driven assessment plan to optimize scanner resources, minimize disruptive probing, and ensure rapid response to environmental posture changes.

Instead of blind, periodic scanning of entire IP blocks, the planner queries real historical telemetry and evaluates targets against five deterministic priority buckets while enforcing strict authorization and budget constraints.

---

## 2. Priority Hierarchy

The planning engine prioritizes potential assessment targets into five hierarchical categories:

```
+-------------------------------------------------------------------------------+
|                      ADAPTIVE PLANNING PRIORITY LADDER                        |
+-------------------------------------------------------------------------------+
| Priority 1: CHANGE_REASSESSMENT    | Monitored config changes, ports, TLS     |
+------------------------------------+------------------------------------------+
| Priority 2: REMEDIATION_RETEST     | Approved remediations needing re-test    |
+------------------------------------+------------------------------------------+
| Priority 3: FAILING_PROBE_RETRY    | Prior errored/timed-out assessment jobs  |
+------------------------------------+------------------------------------------+
| Priority 4: HIGH_RISK_CONFIRMED    | Active Critical/High confirmed findings  |
+------------------------------------+------------------------------------------+
| Priority 5: STALE_COVERAGE_REFRESH | Assets exceeding coverage staleness SLA  |
+-------------------------------------------------------------------------------+
```

### 2.1 Bucket Definitions

1. **`CHANGE_REASSESSMENT` (Priority 1):**
   - Targets associated with unassessed `PostureChangeRecord` events (e.g. modified web configs, new open ports, TLS downgrades).
   - Prevents stale threat assumptions when external infrastructure mutates.
2. **`REMEDIATION_RETEST` (Priority 2):**
   - Findings in `REMEDIATION_APPLIED` state with approved `RemediationPlan` entries awaiting independent verification.
   - Closes the remediation loop automatically.
3. **`FAILING_PROBE_RETRY` (Priority 3):**
   - Assessment jobs in `FAILED` status within the retry window.
   - Retries transient failures with diagnostic tracing.
4. **`HIGH_RISK_CONFIRMED` (Priority 4):**
   - Confirmed vulnerabilities with contextual risk scores $\ge 60.0$ (`HIGH` or `CRITICAL`).
   - Ensures continuous verification of highest-impact attack vectors.
5. **`STALE_COVERAGE_REFRESH` (Priority 5):**
   - Authorized assets where `last_seen_at` is older than the configured threshold (default: 14 days) or unassessed authorized targets.
   - Restores coverage across dark corners of the attack surface.

---

## 3. Scope Enforcement, Budget Clamping & Redundancy Skipping

### 3.1 Strict Fail-Closed Scope Verification
Every candidate check must resolve to an authorized `ScopeTarget` whose authorization status is `AUTHORIZED` and whose expiration timestamp has not passed.
- If out-of-scope: The check is placed into `skipped_checks` with `reason_category = "OUT_OF_SCOPE"` and message `"Target outside authorized project scope"`.
- Under no circumstances is an unapproved probe added to `recommended_checks`.

### 3.2 Redundancy Prevention (24-Hour Clean Skip)
To prevent scanner fatigue and unnecessary load on production assets:
- Targets that completed an assessment within the last 24 hours with **zero confirmed findings** are excluded from routine probing.
- Skipped entries appear in `skipped_checks` with `reason_category = "RECENT_CLEAN_ASSESSMENT"`.

### 3.3 Scan Budget Enforcement
Operators specify a maximum scan limit (`scan_budget`, default 10). Recommendations are sorted by priority and clamped strictly to this threshold:
- Items beyond the limit are placed into `skipped_checks` with `reason_category = "SCAN_BUDGET_EXCEEDED"`.

---

## 4. Plan Lifecycle & Entity Schema

Assessment plans are persisted in the `adaptive_assessment_plans` database table with the following lifecycle states:

```
  [GENERATED] ----> [EXECUTING] ----> [COMPLETED]
       |                  |
       +------------------+---------> [CANCELLED]
```

### Plan Record Attributes
- `id`: UUID primary key.
- `project_id`: Foreign key to `projects.id`.
- `plan_status`: `GENERATED`, `EXECUTING`, `COMPLETED`, `CANCELLED`.
- `scan_budget`: Total permitted checks.
- `recommended_checks`: JSON list of recommended probe specifications.
- `skipped_checks`: JSON list of skipped checks with explicit reason codes.
- `summary_metadata`: JSON dictionary containing count breakdowns by reason category.
- `created_by_id`: User who initiated or approved the plan.

---

## 5. Operator Execution Runbook

### Step 1: Generate an Adaptive Plan via API

```bash
curl -X POST "http://localhost:8000/api/v1/intelligence/{project_id}/adaptive-plan" \
  -H "Authorization: Bearer $AUTH_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"scan_budget": 5, "stale_days_threshold": 14}'
```

### Step 2: Inspect Recommended and Skipped Checks

Inspect the returned plan to confirm rationale:
- Verify `recommended_checks` against expected changes.
- Review `skipped_checks` to confirm out-of-scope rejections and clean skips.

### Step 3: Execute an Individual Check

Operators can trigger a specific probe by its zero-based index:

```bash
curl -X POST "http://localhost:8000/api/v1/intelligence/{project_id}/execute-check/{plan_id}/0" \
  -H "Authorization: Bearer $AUTH_TOKEN"
```

The endpoint validates scope authorization, creates an `AssessmentJob` in `QUEUED` state, updates the plan status to `EXECUTING`, and returns the dispatched job identifier.
