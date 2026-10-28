# Closed-Loop Outcome Measurement Engine (Prompt 15)

## 1. Overview & Philosophical Baseline
A foundational flaw in traditional security automation is claiming success upon command completion without verifying whether the security posture actually improved:
- A patching script that returns exit code 0 does not prove the vulnerability is resolved.
- A risk score dropping because a host became unreachable does not indicate improved security.
- An inconclusive retest probe must never close an open finding.

The `ClosedLoopMeasurementService` enforces **evidence-grounded outcome verification**:
1. Captures pre-action baseline posture snapshot (`initial_snapshot`).
2. Records action execution results (`execution_result`).
3. Evaluates independent verification results (`verification_result`).
4. Captures post-action posture snapshot (`final_snapshot`).
5. Computes posture delta and assigns a rigorous, non-fabricated `OutcomeMeasurementStatus`.

---

## 2. Outcome Status Classification

| Outcome Status | Objective Condition Required | Example Scenario |
| :--- | :--- | :--- |
| **`FINDING_VERIFIED_RESOLVED`** | Independent retest record (`RemediationVerification`) has `outcome == VERIFIED_FIXED`. | Port 3306 closed, SSL cipher rejected, or exploit payload fails. |
| **`RISK_SCORE_DECREASED`** | Posture delta shows measurable risk decrease ($\Delta_{\text{risk}} < 0$). | High-risk exposure eliminated from network perimeter. |
| **`ACTION_EXECUTED_SUCCESSFULLY`** | Task completed cleanly but without immediate change in finding status. | Routine configuration audit or evidence refresh job. |
| **`OUTCOME_INCONCLUSIVE`** | Independent verification probe returned `INCONCLUSIVE` or timed out. | Retest probe was blocked by network firewall; finding remains open. |
| **`NO_MEASURABLE_IMPROVEMENT`** | Action completed, but retest showed `STILL_VULNERABLE` or risk remained identical. | Patch was applied but vulnerability remains reachable. |
| **`FAILED`** | Action execution threw an exception, timed out, or was rejected. | Command syntax failure, authentication error, or worker timeout. |

---

## 3. Posture Delta Calculation

Posture improvement is measured across two primary metrics:

$$\Delta_{\text{risk}} = \text{Final Risk Score} - \text{Initial Risk Score}$$
$$\Delta_{\text{resolved}} = \text{Final Closed Findings} - \text{Initial Closed Findings}$$

### Data Schema (`outcome_measurement` JSON in `orchestration_workflows`):
```json
{
  "initial_snapshot": {
    "open_findings_count": 8,
    "critical_count": 2,
    "high_count": 3,
    "verified_closed_count": 12,
    "risk_score": 78.5,
    "timestamp": "2026-10-28T19:30:00Z"
  },
  "final_snapshot": {
    "open_findings_count": 7,
    "critical_count": 1,
    "high_count": 3,
    "verified_closed_count": 13,
    "risk_score": 62.1,
    "timestamp": "2026-10-28T19:31:15Z"
  },
  "posture_delta": {
    "delta_risk_score": -16.4,
    "delta_resolved_findings": 1
  },
  "execution_result": {
    "action": "SCHEDULE_INDEPENDENT_RETEST",
    "status": "COMPLETED",
    "target": "https://api.corp",
    "attempt": 1
  },
  "verification_outcome": "VERIFIED_FIXED",
  "measured_at": "2026-10-28T19:31:16Z"
}
```

---

## 4. Controlled Adaptive Optimization

Verified outcomes feed into `AdaptiveOptimizationService` to evaluate continuous improvement:
- **Optimization Proposals:** Evaluated against defined numerical thresholds (`threshold_value`).
- **Quality Gate:** If `evaluated_value < threshold_value`, the proposal is rejected (`is_accepted = False`), logging an explicit rejection reason and storing the rollback payload.
- **Audit Provenance:** All accepted and rejected optimizations are recorded in `adaptive_optimization_records`.

---

## 5. Verification Evidence

Verified in `backend/tests/test_prompt15_autonomous_security_orchestration.py`:
- `test_scenario_10`: Inconclusive retest results in `OUTCOME_INCONCLUSIVE` and leaves the finding un-closed.
- `test_scenario_11`: Verified fixed retest results in `FINDING_VERIFIED_RESOLVED` and updates downstream posture.
- `test_scenario_15`: Optimization proposal failing the numerical threshold is rejected without changing policy.
