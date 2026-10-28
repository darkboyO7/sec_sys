# Autonomous Operation Policies & Governance

## 1. Overview & Purpose

The **Policy Engine** (`PolicyEngineService`) enforces strict operational guardrails on autonomous capabilities within the VAPT Platform. It ensures that scanner execution, remediation recommendations, automated probes, and background tasks adhere to pre-approved intensity profiles, resource budgets, concurrency limits, and scope boundaries.

Furthermore, it incorporates an immediate **Emergency Kill Switch** that suspends all autonomous actions across a project or globally when an incident, threshold violation, or operator intervention occurs.

---

## 2. Autonomy Intensity Tiers

Every project operates under a designated `AutonomyIntensity` tier defined in its `AutonomousPolicyRecord`:

| Tier | Enum Value | Allowed Adapters | Scanner Concurrency | Disruption Permitted | Human Approval Mandate |
|---|---|---|---|---|---|
| **Passive / Read-Only** | `READ_ONLY` | Passive DNS, TLS inspect, HTTP header grab | Max 1-2 concurrent | Strictly Prohibited | Automated execution without approval is blocked. |
| **Balanced (Default)** | `BALANCED` | Active web spider, TLS handshake, port probe, config audit | Max 3 concurrent | Non-disruptive only | Disruptive remediation or intrusive scans require lead approval. |
| **Aggressive / Red Team** | `AGGRESSIVE` | Full adapter suite (fuzzing, active injection checks, deep crawling) | Max 5-10 concurrent | Controlled disruption | Automated scans run; destructive remediation still requires approval. |

---

## 3. Policy Execution Constraints & Guardrails

### 3.1. Daily Assessment Budget
- **Budget Tracking:** Each project policy defines `max_daily_budget` (in platform operational credits/currency, default $100.00) and tracks `daily_budget_spent`.
- **Preflight Deduction:** Before an assessment or retest job starts, `PolicyEngineService.evaluate_action_permission` calculates the estimated cost.
- **Budget Exhaustion:** If `daily_budget_spent + cost > max_daily_budget`, the job is rejected with reason `Daily budget exhausted`.
- **Reset Interval:** Daily spend resets every 24 hours UTC.

### 3.2. Concurrency Limits
- **Threshold:** The policy enforces `max_concurrency` (default 3 concurrent assessment jobs per project).
- **Enforcement:** If currently running jobs meet or exceed `max_concurrency`, new jobs remain in `QUEUED` state until worker capacity frees up.

### 3.3. Failure Thresholds & Consecutive Failure Protection
- **Threshold:** Policies track `consecutive_failures` (default threshold: 3).
- **Auto-Suspension:** If 3 consecutive assessment jobs fail (e.g., target connection reset, rate limiting, adapter crash), the engine automatically suspends autonomous operations for that project, logs an emergency entry in the Security Decision Ledger, and dispatches an escalation notification.

### 3.4. Disruptive Action & Remediation Approval Gate
- **Disruptive Flag:** Any action flagged with `is_disruptive=True` (e.g., firewall modifications, service restarts, intensive fuzzing) cannot run autonomously.
- **Approval Requirement:** The engine sets `requires_approval=True` and returns `Approval required for disruptive action: <action_name>`. The action is suspended until a `ProjectRole.LEAD` or `SystemRole.ADMIN` explicitly reviews and approves the ticket.

---

## 4. Emergency Kill Switch Runbook

The Emergency Kill Switch provides an instantaneous, fail-closed mechanism to suspend all autonomous operations.

### 4.1. Triggering Emergency Suspension

**Via REST API:**
```http
POST /api/v1/operations/{project_id}/emergency-suspend
Authorization: Bearer <lead_or_admin_token>
Content-Type: application/json

{
  "reason": "Target service latency spike observed; upstream incident in progress."
}
```

**Via Python Service:**
```python
PolicyEngineService.emergency_suspend(
    db=db,
    project_id=project_id,
    reason="Operator manual suspension",
    actor=current_user,
)
```

### 4.2. Suspension Effects
When a policy is marked `is_suspended = True`:
1. **Immediate Preflight Rejection:** All incoming calls to `evaluate_action_permission` immediately return:
   ```json
   {
     "allowed": false,
     "reason": "Autonomous operations suspended: <reason>",
     "is_suspended": true
   }
   ```
2. **Active Job Drain / Cancellation:** Background workers reject new job pickups for the project.
3. **Decision Ledger Audit Entry:** An immutable record of type `EMERGENCY_SUSPEND` is logged with the timestamp, actor identity, and suspension reason.
4. **Notification Dispatch:** An urgent notification (`POLICY_VIOLATION` / `EMERGENCY_STOP`) is broadcast to project administrators.

### 4.3. Resuming Normal Operations

Once the root cause is resolved and authorization is reaffirmed:

**Via REST API:**
```http
POST /api/v1/operations/{project_id}/resume
Authorization: Bearer <lead_or_admin_token>
Content-Type: application/json

{
  "notes": "Upstream service incident resolved. Authorization re-verified."
}
```

**Effects:**
- `is_suspended` is reset to `False`.
- `consecutive_failures` is reset to 0.
- A `POLICY_RESUME` audit record is written to the Security Decision Ledger.
- Normal evaluation and scheduling resume immediately.
