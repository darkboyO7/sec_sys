# VAPT Platform — Contextual Risk Scoring Model (Version 1.1.0)

## 1. Epistemic Model Definition & Purpose

The VAPT Platform Contextual Risk Engine calculates an **explainable, deterministic prioritization index** bounded between 0.0 and 100.0.

> [!IMPORTANT]
> **Prioritization Index vs. Probability:** The calculated risk score represents a triage priority ranking for defensive engineering teams. It is explicitly **not** a calibrated statistical probability of a security breach, nor an annualized loss expectancy (ALE).

---

## 2. Mathematical Formulation (Scoring Version: v1.1.0)

The composite risk score is computed through factor decomposition:

$$\text{EffectiveBase} = \text{BaseScore} \times \text{ConfidenceWeight}$$

$$\text{InherentComposite} = \text{EffectiveBase} \times M_{\text{criticality}} \times M_{\text{exposure}}$$

$$\text{InherentScore} = \text{round}\left(\max\left(0.0, \min\left(100.0, \text{InherentComposite}\right)\right), 1\right)$$

$$\text{ResidualScore} = \text{round}\left(\max\left(0.0, \min\left(100.0, \text{InherentComposite} \times M_{\text{freshness}} \times M_{\text{lifecycle}} \times M_{\text{recurrence}} \times M_{\text{quality}}\right)\right), 1\right)$$

---

## 3. Contributing Multipliers & Value Ranges

### 3.1. Base Severity Score ($\text{BaseScore}$)
- If finding has a valid numeric CVSS 3.x base score ($0.0 \le s \le 10.0$), $\text{BaseScore} = s \times 10.0$.
- Otherwise, derived from categorical severity:
  - `CRITICAL`: 90.0
  - `HIGH`: 70.0
  - `MEDIUM`: 45.0
  - `LOW`: 20.0
  - `INFO`: 5.0

### 3.2. Finding Confidence Weight ($\text{ConfidenceWeight}$)
- `CERTAIN`: $1.00$
- `FIRM`: $0.85$
- `TENTATIVE`: $0.65$

### 3.3. Asset Criticality Multiplier ($M_{\text{criticality}}$)
- `CRITICAL`: $1.35$
- `HIGH`: $1.15$
- `MEDIUM`: $1.00$
- `LOW`: $0.85$
- `INFO`: $0.70$

### 3.4. Reachability & Exposure Multiplier ($M_{\text{exposure}}$)
- `INTERNET_FACING`: $1.30$
- `DMZ`: $1.15$
- `INTERNAL`: $0.90$
- `ISOLATED`: $0.70$
- Default (unspecified topology): $1.00$

### 3.5. Lifecycle Multiplier ($M_{\text{lifecycle}}$)
- `VERIFIED_CLOSED`: $0.00$ (Risk eliminated)
- `FALSE_POSITIVE`: $0.00$ (Neutralized)
- `ACCEPTED_RISK`: $0.40$ (Compensating controls acknowledged)
- `REMEDIATED_PENDING_VERIFICATION`: $0.50$ (Provisional reduction pending test)
- `REMEDIATION_ATTEMPTED`: $0.75$
- `REMEDIATION_APPROVED` / `PROPOSED`: $0.90$
- `CONFIRMED`: $1.05$
- `REOPENED`: $1.10$
- Default (`DETECTED`, `NEEDS_VALIDATION`): $1.00$

### 3.6. Observation Freshness Decay ($M_{\text{freshness}}$)
- Age $\le 30$ days: $1.00$
- Linear decay from $1.00$ down to $0.70$ at $180+$ days without re-observation.

### 3.7. Recurrence Penalty ($M_{\text{recurrence}}$)
- First-time detection: $1.00$
- Recurrent (reopened post-closure): $1.20$

### 3.8. Evidence Quality Corroboration ($M_{\text{quality}}$)
- Ranges between $0.80$ and $1.10$ based on multi-scanner corroboration, contradiction presence, and observation frequency.

---

## 4. Contextual Heuristic Uncertainty Range (Score Margin)

To convey data completeness and observation certainty, the engine computes deterministic uncertainty bounds:

$$\text{Margin} = 3.0 + (7.0 \text{ if Tentative}) + (5.0 \text{ if Contradictions}) + \min(8.0, 2.5 \times N_{\text{missing\_factors}})$$

$$\text{MinScore} = \max(0.0, \text{Score} - \text{Margin})$$

$$\text{MaxScore} = \min(100.0, \text{Score} + \text{Margin})$$

### Epistemic Classification:
- **Heuristic Score Margin, NOT a Confidence Interval**: The uncertainty margin reflects missing operational inputs (missing asset criticality, unmapped network edges, divergent scanner findings). It is a deterministic heuristic band, **not** a parametric Gaussian 95% statistical confidence interval.
- **Confidence Bands**:
  - `HIGH`: $\text{Margin} \le 4.0$ (Complete asset metadata, certain scanner confidence, corroborated).
  - `MODERATE`: $4.0 < \text{Margin} \le 10.0$ (Minor metadata gaps or single-source finding).
  - `LOW`: $\text{Margin} > 10.0$ (Tentative scanner confidence, unmapped asset, contradictory findings).

---

## 5. Risk Priority Categorization

The final composite score maps to risk priority:
- **CRITICAL**: $\text{Score} \ge 80.0$
- **HIGH**: $60.0 \le \text{Score} < 80.0$
- **MEDIUM**: $40.0 \le \text{Score} < 60.0$
- **LOW**: $15.0 \le \text{Score} < 40.0$
- **INFORMATIONAL**: $\text{Score} < 15.0$
