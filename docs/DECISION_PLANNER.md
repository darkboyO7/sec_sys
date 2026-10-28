# Evidence-Driven Decision Planner (Prompt 15)

## 1. Overview & Architectural Role
The **Decision Planner** evaluates real, persisted operational context to recommend the next justifiable security action. Rather than relying on rigid cron schedules or ungrounded generative predictions, every recommendation is backed by:
- Triggering event metadata.
- Concrete entity references (asset IDs, finding IDs, job IDs).
- Explicit technical rationale.
- Expected security or operational benefit.
- Confidence (0.0 to 1.0) and uncertainty margins.
- Policy and model versions.
- Required permissions and approval roles.
- Resource cost and execution budgets.
- Staleness and invalidation conditions.

---

## 2. Decision Logic Matrix

The planner evaluates events and persisted state through deterministic decision branches:

| Triggering Context | Recommended Action | Required Role | Justification & Benefit |
| :--- | :--- | :--- | :--- |
| **`CONFIG_CHANGED` / `ASSET_DISCOVERED`** | `REASSESS_CHANGED_ASSET` | Autonomous | Target attributes or services changed; refresh security baseline to detect regressions. |
| **`REMEDIATION_APPLIED`** | `SCHEDULE_INDEPENDENT_RETEST` | Autonomous | Remediation completed; independent probe required to verify vulnerability resolution. |
| **`FINDING_DETECTED` (Disruptive)** | `REQUEST_HUMAN_APPROVAL` | `LEAD` | High-risk remediation requires approval to avoid disruption to production systems. |
| **`FINDING_DETECTED` (Safe)** | `RECOMMEND_REMEDIATION` | Autonomous | Safe, non-disruptive configuration fix ready for automated or guided deployment. |
| **`SCAN_COMPLETED`** | `RECALCULATE_RISK_AND_PATHS` | Autonomous | New observation data landed; update contextual risk scores and attack path graphs. |
| **`DIAGNOSTIC_FAILURE` / Failure Storm** | `RUN_DIAGNOSTICS` | Autonomous | Consecutive job failures exceeded threshold; isolate infrastructure faults. |
| **`INTEGRITY_ALERT`** | `SUSPEND_ACTIVITY` | `ADMIN` | Evidence SHA-256 hash mismatch detected; halt downstream operations to prevent untrusted conclusions. |
| **Target Revoked / Excluded** | `SUSPEND_ACTIVITY` | Autonomous | Target was removed from scope; fail closed to prevent unauthorized active probing. |

---

## 3. Zero-Trust Pre-Execution Authorization Check

Before an action can be queued, and again before it can be picked up for execution, `DecisionPlannerService.evaluate_authorization` enforces:
1. **Target Authorization:** Evaluates `ScopeEngine.validate_target_in_scope` at execution time. If status is `REVOKED` or `EXPIRED`, the action is aborted with `AUTHORIZATION_REVOKED`.
2. **Scope Exclusions:** Evaluates `ScopeExclusion`. If an emergency exclusion pattern matches the target, the action is aborted with `EXCLUDED`.
3. **Adaptive Defense State:** Inspects `AdaptiveDefenseService`. If the project is in `LOCKDOWN` mode, all operational probing is suspended.
4. **Autonomous Policy & Budget:** Inspects `AutonomousPolicyRecord`. If `is_suspended` is true or `daily_budget_spent >= max_daily_budget`, active scanning actions are suspended with `BUDGET_EXCEEDED`.

---

## 4. Invalidation & Staleness Governance

Every recommendation records a `staleness_condition`:
- If an asset changes after a recommendation is generated but before execution, the recommendation is marked `SUPERSEDED`.
- If an authorization target is modified, all dependent recommendations are invalidated.
- Recommendations older than 24 hours without execution expire automatically to prevent stale actions against morphed environments.
