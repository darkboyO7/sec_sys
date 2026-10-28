# Controlled Learning & Model Governance Specification

## 1. Executive Summary & Purpose

The **Learning Governance Framework** (`ModelGovernanceService`, `PredictionLedgerService`) provides verifiable, safe, and controlled model lifecycle management for the VAPT System. Autonomous security operations require machine learning and heuristic models that evolve based on observed ground truth without hallucinating confidence, training on speculative telemetry, or silently failing when data is sparse.

---

## 2. Ground Truth Verification Invariants

```
+-----------------------------------------------------------------------------------+
|                        GROUND TRUTH ADMISSION PIPELINE                            |
+-----------------------------------------------------------------------------------+
| Finding State               | Admitted as Confirmed Ground Truth? | Rationale     |
+-----------------------------+-------------------------------------+---------------+
| CONFIRMED (Verified Re-test)| YES (Weight = 1.0)                  | Indep. proof  |
+-----------------------------+-------------------------------------+---------------+
| CONFIRMED (Manual Analyst)  | YES (Weight = 1.0)                  | Peer-reviewed |
+-----------------------------+-------------------------------------+---------------+
| DETECTED / UNVERIFIED       | NO (Strictly Excluded)              | Hypothesis    |
+-----------------------------+-------------------------------------+---------------+
| FALSE_POSITIVE (Confirmed)  | YES (Negative Ground Truth)         | Verified FP   |
+-----------------------------+-------------------------------------+---------------+
| INCONCLUSIVE Retest         | NO (Decoupled from Ground Truth)    | Ambiguous     |
+-----------------------------------------------------------------------------------+
```

### 2.1 Elimination of Synthetic Samples in Operational Training
- **Strict Ban on Fabricated Ground Truth:** The production data curation pipeline (`curate_dataset`) rejects synthetic records (`is_simulated = True`). Synthetic test sets are confined exclusively to isolated benchmark harnesses via `allow_synthetic_benchmark=True`.
- **Exclusion of Unverified Findings:** Observations in `DETECTED`, `NEEDS_VALIDATION`, or preliminary scanner staging are barred from positive training datasets. This prevents the learning pipeline from amplifying false positive rates or learning idiosyncratic scanner quirks.

---

## 3. Decoupling Inconclusive Outcomes from Inaccuracies

When independent remediation retests or scanner probes yield ambiguous results (e.g. target host unreachable, timeout, transient network firewall block):

- **Evaluation Status:** The prediction is marked as:
  $$\text{PredictionEvaluationStatus.INCONCLUSIVE}$$
- **Decoupled from False Negatives:** It is **never** recorded as `VERIFIED_INACCURATE` or labeled as a missed vulnerability.
- **Drift Monitoring:** Inconclusive outcomes are tracked explicitly via `inconclusive_count` and `inconclusive_rate` in `calculate_drift_metrics`. If the inconclusive rate exceeds $20\%$, a network telemetry alert is raised without corrupting model weights.

---

## 4. Insufficient Data Safeguard & Explicit States

To ensure statistical significance and prevent overfitting on sparse organizational samples:

- **Minimum Verified Records Threshold:** The model governance engine requires a minimum of **10 independently verified ground-truth records** before evaluating or promoting a candidate model.
- **Explicit `INSUFFICIENT_DATA` State:** If fewer than 10 records exist, the evaluation returns:
  ```json
  {
    "status": "INSUFFICIENT_DATA",
    "record_count": 4,
    "required_threshold": 10,
    "action": "HALT_PROMOTION",
    "fallback_active": true
  }
  ```
- **Fallback to Rules Baseline:** In `INSUFFICIENT_DATA` or unpromoted states, the platform transparently defaults to the deterministic v2.0.0 rules baseline (`ContextualRiskService`).

---

## 5. Model Promotion & Atomic Rollback Runbook

### 5.1 Promotion Criteria
A candidate model is promoted to `ACTIVE` only if all four governance gates pass simultaneously:

1. **Held-Out Accuracy Gate:** Accuracy on held-out verified ground truth $\ge 85\%$.
2. **Precision Gate:** Precision $\ge 80\%$ (minimizing false positives).
3. **Recall Gate:** Recall $\ge 90\%$ (preventing missed critical vulnerabilities).
4. **Drift Stability Gate:** Total dataset drift score $< 0.15$ compared to baseline distribution.

### 5.2 Atomic Rollback Mechanism
If production telemetry flags a degradation in model accuracy ($> 10\%$ drop) or drift exceeding safety thresholds:
1. The `ModelGovernanceService.rollback_model` procedure executes an atomic transaction.
2. The active model status transitions from `ACTIVE` $\rightarrow$ `RETIRED`.
3. The platform instantly falls back to the previous stable model or the deterministic rules baseline.
4. An immutable audit event (`AUDIT_MODEL_ROLLBACK`) is recorded in the tamper-evident audit ledger.
