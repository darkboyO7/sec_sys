# Controlled Experiments, Model Evaluation, and Defensible Adaptive Learning Matrix

## 1. Adaptive Learning Inventory and Governance Principles
In accordance with Prompt 38, every component across the platform that learns from outcomes, updates weights, adjusts thresholds, or ranks risks operates under **SUPERVISED_OFFLINE** governance. **Unsupervised online self-tuning is strictly disabled platform-wide** to prevent adversarial poisoning, distribution drift, and unintended privilege relaxation.

| Component Name | Prediction Type | Objective | Input Features | Decision Impact | Governance Mode | Online Self-Tuning |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **False Positive Predictor** | `FALSE_POSITIVE_LIKELIHOOD` | Classify incoming scanner observations into verified vs false positives | `severity`, `title_digest`, `target_url_scheme`, `cwe_id`, `scanner_adapter` | Prioritizes triage; cannot auto-close findings without epistemic proof | `SUPERVISED_OFFLINE` | **Disabled (False)** |
| **Exploitation Probability Engine** | `EXPLOITATION_PROBABILITY` | Forecast likelihood of real-world exploitation using CISA KEV and EPSS signals | `cve_id`, `cvss_score`, `epss_score`, `cisa_kev_flag`, `exposure_surface` | Enriches risk prioritization; never overrides base finding severity | `SUPERVISED_OFFLINE` | **Disabled (False)** |
| **Remediation Effort Estimator** | `REMEDIATION_EFFORT_HOURS` | Estimate labor hours required to remediate and independently verify vulnerability | `cwe_category`, `affected_asset_type`, `compensating_controls_count` | Resource planning and SLA tracking; advisory only | `SUPERVISED_OFFLINE` | **Disabled (False)** |
| **Risk Score Forecasting** | `RISK_SCORE_FORECAST` | Project enterprise risk trajectory over 30/60/90 day horizons | `open_finding_count`, `asset_criticality_distribution`, `sla_breach_rate` | Executive reporting and compliance drift alerting | `SUPERVISED_OFFLINE` | **Disabled (False)** |
| **Attack Path Reachability Ranker** | `ATTACK_PATH_REACHABILITY` | Score traversability of multi-hop attack graphs from perimeter to crown jewels | `hop_count`, `lateral_pivot_confidence`, `credential_exposure_flag` | Graph cockpit path prioritization; advisory only | `SUPERVISED_OFFLINE` | **Disabled (False)** |

---

## 2. Chronological Time-Aware Partitioning & Temporal Leakage Defense

Standard random stratified cross-validation is inappropriate for security time-series and vulnerability lifecycle tracking because it permits future information to leak into past predictions (Temporal Data Leakage).

```
Verifiable Security Outcome Records (Chronologically Ordered by Timestamp T)
[======================== 100% Outcome Observations ========================]
  |                                        |                               |
  v                                        v                               v
[Train Split: 70%]               [Validation Split: 15%]           [Held-Out Test: 15%]
[T_0 ---------> T_train_end]     [T_val_start ---> T_val_end]      [T_test_start -> T_latest]
                |                                  |
                +----------------------------------+---> Enforced Invariant:
                                                         Max(T_train) <= Min(T_test)
```

### Data Leakage Verification Rules:
1. **Identical Digest Leakage:** Feature hash digests generated from inputs ($\text{SHA256}(\text{features})$) in the test partition are verified against the training partition. Any collision triggers `REJECTED_LEAKAGE`.
2. **Temporal Order Inversion:** If any test partition record created timestamp precedes the maximum training record timestamp ($T_{\text{test}} < T_{\text{train}}$), the evaluation is terminated and flagged as `REJECTED_LEAKAGE`.

---

## 3. Evaluation Metrics and Calibration Uncertainty

Candidate models must demonstrate both discriminative power ($F_1$ score) and probabilistic reliability (calibration).

### Evaluation Metric Suite:
- **$F_1$ Score:** Harmonic mean of precision and recall on held-out test data. Minimum acceptance threshold: $F_1 \ge 0.60$.
- **Brier Calibration Score:** Mean squared error of probabilistic predictions:
  $$\text{Brier} = \frac{1}{N} \sum_{i=1}^N (p_i - y_i)^2$$
  where $p_i \in [0, 1]$ is the predicted probability and $y_i \in \{0, 1\}$ is the verified outcome.
- **Expected Calibration Error (ECE):** Root-mean approximation measuring the gap between predicted confidence and observed accuracy.
- **Class Imbalance Ratio:** Ratio of positive to negative samples ($\frac{N_{\text{pos}}}{N_{\text{neg}}}$) to detect sparse vulnerability classes.

---

## 4. Minimum Real Evidence Threshold & Prohibition of Fabricated Data

To ensure epistemic defensibility:
- **Minimum Sample Threshold:** A minimum of $N \ge 10$ real, verified security outcomes is strictly required before an empirical evaluation decision can be accepted.
- **No Synthetic Performance Claims:** If real outcome data is fewer than 10 samples, the platform sets `insufficient_data_flag = True` and records `REJECTED_INSUFFICIENT_DATA`. The system never synthesizes random fake records to claim artificial production readiness.

---

## 5. Experimental Decision Ledger Outcomes

Every evaluation run generates an immutable record in `model_controlled_experiments`:

| Decision Outcome | Trigger Condition | Consequence |
| :--- | :--- | :--- |
| `ACCEPTED` | Zero leakage, $N \ge 10$, $F_1 \ge \text{Baseline}$, $\text{Brier} \le \text{Baseline}$ | Model status promoted to `EVALUATED`, eligible for human Lead approval |
| `REJECTED_LEAKAGE` | Duplicate feature digests or temporal order inversions between Train and Test | Candidate rejected; leakage report logged to audit ledger |
| `REJECTED_INFERIOR_METRICS` | Candidate $F_1$ or Brier score regresses against active baseline model | Candidate rejected; active baseline remains in production |
| `REJECTED_INSUFFICIENT_DATA` | Sample size $N < 10$ | Candidate rejected due to insufficient statistical power |
| `PENDING_REVIEW` | Experiment initialized but pending evaluation execution | Awaiting benchmark execution |

---

## 6. Separation of Duties in Model Promotion & Atomic Rollback

### Separation of Duties (SoD):
In compliance with Prompt 36 and Prompt 38, the dataset or candidate model creator **cannot approve their own model promotion**. Approval requires an independent Security Lead or Administrator:
```
Scientist (Creator) ----> Register Model & Run Benchmark ----> Status: EVALUATED
                                                                     |
Lead (Independent)  ----> Human Review & Governance Gate  ----> Status: APPROVED
                                                                     |
Lead (Deployer)     ----> Atomic Activation               ----> Status: ACTIVE
```

### Atomic Rollback with Concurrency Conflict Defense:
1. When a new model is promoted to `ACTIVE`, the previously active model is demoted to `DEPRECATED` and its ID is atomically recorded as `rollback_target_id`.
2. Rollback execution uses optimistic locking (`synchronize_session="fetch"`); if concurrent state mutation occurred, the operation aborts safely.
3. Upon rollback, the target model is atomically restored to `ACTIVE`, and the failed model is marked `ROLLED_BACK`.

---

## 7. Distribution Shift Detection without Unsafe Self-Tuning

The platform monitors real-world prediction accuracy and Brier calibration drift across time windows. When drift exceeds statistical variance limits:
- A `SHIFT_DETECTED` alert is surfaced in the operations cockpit and model governance view.
- **The system does NOT automatically re-train or auto-update weights in production.**
- A structured recommendation instructs operators to curate a new time-aware dataset, execute a controlled experiment, and seek human Lead approval.
