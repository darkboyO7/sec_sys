# Contextual Risk Scoring Model (v2.0.0)

## 1. Overview & Principles

The VAPT System's Contextual Risk Engine (`ContextualRiskService`) provides an explainable, deterministic, and evidence-grounded risk prioritization model. In version `v2.0.0`, all risk evaluations enforce the following design invariants:

- **Mathematical Determinism:** Identical finding, asset, environmental, and evidence inputs produce identical scores and explanations.
- **Explainability:** Every score is paired with an exact factor breakdown (`factor_breakdown`), contributing factors (`contributing_factors`), and uncertainty bounds (`uncertainty_lower_bound`, `uncertainty_upper_bound`).
- **No Speculative Amplification:** Bare topological network connectivity or theoretical CVE exploitability does not amplify risk without verified evidence.
- **Conservative Handling of Unknowns:** Unknown operator business impact is never assumed to be High or Critical; it defaults to neutral (1.00) and is explicitly documented in `missing_factors`.
- **Evidence Decay & Contradiction Accounting:** Stale evidence and contradictory observations penalize confidence and widen uncertainty bounds.

---

## 2. Mathematical Formulation

The final contextual risk score is computed as:

$$\text{FinalScore} = \text{clamp}_{[0, 100]}\left( \text{BaseScore} \times \prod \text{Multipliers} \right)$$

### 2.1 Base Score Formulation

$$\text{BaseScore} = 100 \times \left( W_{\text{sev}} \times W_{\text{conf}} \times W_{\text{crit}} \times W_{\text{exp}} \right)$$

Where factor weights are normalized as:
- **Severity Weight ($W_{\text{sev}}$):**
  - `CRITICAL`: 1.00
  - `HIGH`: 0.75
  - `MEDIUM`: 0.50
  - `LOW`: 0.25
  - `INFO`: 0.05
- **Confidence Weight ($W_{\text{conf}}$):**
  - Initial weights: `CERTAIN`: 1.00, `FIRM`: 0.80, `TENTATIVE`: 0.50.
  - **Freshness Decay:** If the last observed evidence timestamp is older than 30 days:
    $$W_{\text{conf, decayed}} = \max\left(0.50, W_{\text{conf}} - 0.05 \times \left\lfloor \frac{\text{age\_days}}{30} \right\rfloor\right)$$
  - **Contradiction Penalty:** If contradictory evidence is recorded (`has_contradictions = True`):
    $$W_{\text{conf, final}} = W_{\text{conf, decayed}} \times 0.80$$
- **Asset Criticality Weight ($W_{\text{crit}}$):**
  - `CRITICAL`: 1.00
  - `HIGH`: 0.80
  - `MEDIUM`: 0.60
  - `LOW`: 0.40
- **Network Exposure Weight ($W_{\text{exp}}$):**
  - Derived from asset attributes (`exposure = "INTERNET"` vs `"INTERNAL"`):
    - `INTERNET`: 1.00
    - `INTERNAL`: 0.70

---

## 3. Environmental & Contextual Multipliers

The base score is modulated by explicit environmental multipliers:

| Factor | Condition | Multiplier | Rationale |
|---|---|---|---|
| **Business Impact** | Operator configured `CRITICAL` | `1.25` | Mission-critical system disruption risk. |
| **Business Impact** | Operator configured `HIGH` | `1.15` | Significant business or operational penalty. |
| **Business Impact** | Operator configured `MEDIUM` | `1.00` | Standard business operation impact. |
| **Business Impact** | Operator configured `LOW` | `0.85` | Minor non-critical workflow impact. |
| **Business Impact** | Unconfigured / Unknown | `1.00` | Flagged in `missing_factors`; no speculative penalty. |
| **Verified Exploitability** | Confirmed reproduction or CISA KEV | `1.20` | Weaponized/actively exploited vulnerability. |
| **Validated Attack Path** | Path state is `VERIFIED` | `1.20` | Confirmed multi-hop path reaching high-value target. |
| **Topological Only** | Path state is `HYPOTHETICAL` | `1.00` | Proximity alone does not amplify risk. |
| **Remediation Failure** | Verification failed or finding reopened | `1.20` | Demonstrates persistent systemic vulnerability. |

---

## 4. Uncertainty Intervals & Prioritization Tiers

### 4.1 Uncertainty Bounds

The engine calculates lower and upper confidence bounds based on factor uncertainty:
- **Base Margin:** Inversely proportional to confidence:
  $$\text{Margin} = 15.0 \times (1.0 - W_{\text{conf}})$$
- **Contradiction Widening:** If contradictions are detected, the margin widens by $+8.0$ points.
- **Bounds:**
  $$\text{LowerBound} = \max(0.0, \text{FinalScore} - \text{Margin})$$
  $$\text{UpperBound} = \min(100.0, \text{FinalScore} + \text{Margin})$$

### 4.2 Priority Classification

Final scores map into operational priority buckets:
- **CRITICAL:** Score $\ge 80.0$ (SLA: Immediate 24h remediation)
- **HIGH:** $60.0 \le \text{Score} < 80.0$ (SLA: 7-day remediation)
- **MEDIUM:** $40.0 \le \text{Score} < 60.0$ (SLA: 30-day remediation)
- **LOW:** Score $< 40.0$ (SLA: Routine maintenance window)

---

## 5. Audit & Score Explanation Example

```json
{
  "scoring_version": "v2.0.0",
  "contextual_risk_score": 78.4,
  "risk_priority": "HIGH",
  "uncertainty_lower_bound": 68.4,
  "uncertainty_upper_bound": 88.4,
  "factor_breakdown": {
    "severity_weight": 0.75,
    "confidence_weight": 0.80,
    "criticality_weight": 1.00,
    "exposure_weight": 1.00,
    "business_impact_multiplier": 1.15,
    "exploitability_multiplier": 1.20,
    "validated_attack_path_multiplier": 1.00,
    "remediation_failure_multiplier": 1.00
  },
  "contributing_factors": [
    "High severity baseline factor (0.75)",
    "Asset criticality CRITICAL factor (1.00)",
    "Internet exposed asset factor (1.00)",
    "Operator business impact HIGH multiplier 1.15",
    "Verified exploitability evidence multiplier 1.20"
  ],
  "missing_factors": []
}
```
