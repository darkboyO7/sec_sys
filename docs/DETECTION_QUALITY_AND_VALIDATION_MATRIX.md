# VAPT System — Detection Quality, False-Positive Control & Evidence-Driven Intelligence Matrix (Prompt 19)

**Document Version:** 1.0.0  
**Status:** QUALIFIED & VERIFIED  
**Date:** 2026-10-28  
**Scope:** Epistemic Finding Validation, Deterministic Fixtures, Epistemic FSM, Cryptographic Provenance & Learning Governance  

---

## 1. Executive Summary & Epistemic Finding Validation Architecture

The VAPT Platform incorporates an evidence-driven intelligence and detection-quality validation layer. It establishes an explicit separation between:
1. **Operational Lifecycle Status (`finding.status`):** Tracks workflow disposition (`DETECTED`, `CONFIRMED`, `FALSE_POSITIVE`, `REMEDIATION_PROPOSED`, `VERIFIED_CLOSED`, `REOPENED`, `RISK_ACCEPTED`).
2. **Epistemic Validation Status (`finding.validation_status`):** Tracks proof, reproducibility, and cryptographic evidence confidence across 9 formal states.
3. **Scanner Confidence (`finding.confidence`):** Represents heuristic detection certainty (`TENTATIVE`, `FIRM`, `CERTAIN`) reported by scanner adapters.

The platform distinguishes a vulnerability being detected from a vulnerability being proven, a remediation being attempted from a remediation being verified, and a prediction being generated from a prediction being validated.

---

## 2. 9-State Epistemic Finding Validation Lifecycle & FSM Matrix

The epistemic state machine strictly governs the progression of proof and evidence:

| State | Epistemic Meaning | Permitted Next States | Authorization Gate |
|---|---|---|---|
| `DETECTED` | Initial ingestion of observation from scanner or adapter. | `EVIDENCE_PENDING`, `EVIDENCE_SUPPORTED`, `INCONCLUSIVE`, `UNABLE_TO_VERIFY` | Automated Ingestion / Tester / Lead |
| `EVIDENCE_PENDING` | Finding detected but lacks verified cryptographic raw payload. | `EVIDENCE_SUPPORTED`, `INCONCLUSIVE`, `UNABLE_TO_VERIFY`, `CONFIRMED_FALSE_POSITIVE` | Tester / Lead |
| `EVIDENCE_SUPPORTED` | Finding backed by verified SHA-256 raw payload evidence. | `INDEPENDENTLY_REPRODUCED`, `CONFIRMED_TRUE_POSITIVE`, `CONFIRMED_FALSE_POSITIVE`, `INCONCLUSIVE`, `UNABLE_TO_VERIFY` | Tester / Lead |
| `INDEPENDENTLY_REPRODUCED` | Finding independently corroborated across $\ge 2$ distinct scanner adapters or jobs. | `CONFIRMED_TRUE_POSITIVE`, `CONFIRMED_FALSE_POSITIVE`, `INCONCLUSIVE`, `RESOLVED_AFTER_RETEST`, `UNABLE_TO_VERIFY` | Tester / Lead |
| `CONFIRMED_TRUE_POSITIVE` | Conclusively validated security vulnerability backed by cryptographic evidence. | `RESOLVED_AFTER_RETEST`, `CONFIRMED_FALSE_POSITIVE`, `INCONCLUSIVE`, `UNABLE_TO_VERIFY` | Tester / Lead / Admin (Evidence Mandatory) |
| `CONFIRMED_FALSE_POSITIVE` | Formally confirmed non-vulnerability, false alarm, or compensating control. | `DETECTED`, `EVIDENCE_SUPPORTED`, `CONFIRMED_TRUE_POSITIVE` | **Lead / Admin ONLY** ($\ge 10$ char rationale) |
| `INCONCLUSIVE` | Divergent, contradictory, or fluctuating observation signals. | `EVIDENCE_SUPPORTED`, `INDEPENDENTLY_REPRODUCED`, `CONFIRMED_TRUE_POSITIVE`, `CONFIRMED_FALSE_POSITIVE`, `UNABLE_TO_VERIFY` | Tester / Lead |
| `UNABLE_TO_VERIFY` | Target unreachable, socket timeout, or environment connection failure. | `EVIDENCE_SUPPORTED`, `INDEPENDENTLY_REPRODUCED`, `CONFIRMED_TRUE_POSITIVE`, `INCONCLUSIVE`, `CONFIRMED_FALSE_POSITIVE` | Automated / Tester / Lead |
| `RESOLVED_AFTER_RETEST` | Remediation confirmed via independent retest showing issue is no longer present. | `CONFIRMED_TRUE_POSITIVE` (on recurrence), `INDEPENDENTLY_REPRODUCED` | Tester / Lead |

### Key Epistemic Invariants:
1. **Unreachable Targets Fail-Closed:** Transient network drops or timeouts transition to `UNABLE_TO_VERIFY`, **NEVER** `CONFIRMED_FALSE_POSITIVE`.
2. **AI Promotion Barrier:** AI-generated predictions (`is_ai_generated = True`) cannot confirm a finding without underlying cryptographic proof.
3. **Mandatory False Positive Justification:** Transition to `CONFIRMED_FALSE_POSITIVE` requires Project Lead/Admin role and a rationale of at least 10 characters.
4. **Recurrence Detection:** Re-observing a `RESOLVED_AFTER_RETEST` finding automatically reopens it as `REOPENED` and flags `recurrence_detected = True`.

---

## 3. Deterministic Validation Fixture Framework

All benchmark testbeds run strictly on loopback (`127.0.0.1`) using ephemeral ports (`port 0`), with zero external network access:

| Fixture Name | Target Service State | Ground Truth Vulnerabilities | Ground Truth Expected Status |
|---|---|---|---|
| `PositiveExposedFixture` | Seeded known exposures: Server banner disclosure, missing HSTS, missing CSP, insecure session cookie, missing frame protection, missing nosniff. | 6 True Positives, 0 False Positives | `CONFIRMED_TRUE_POSITIVE` |
| `NegativeCleanFixture` | Fully hardened defense-in-depth web server: HSTS max-age, strict CSP, X-Frame-Options DENY, nosniff, secure cookies, generic banner. | 0 True Positives, 6 True Negatives | `CONFIRMED_FALSE_POSITIVE` (Clean) |
| `UnavailableFixture` | Non-responsive / closed ephemeral port. | 0 TP, 0 FP | `UNABLE_TO_VERIFY` |
| `AmbiguousFixture` | Inconsistent alternating responses (status 200 clean vs status 500 error). | Intermittent / Divergent | `INCONCLUSIVE` |
| `RemediatedFixture` | Starts in vulnerable state; calling `remediate()` applies strict hardening. | Initial: 4 TP; After fix: 0 TP | `RESOLVED_AFTER_RETEST` |

---

## 4. Mathematical Metrics & Denominator Disclosures Matrix

All detection quality metrics are calculated honestly with explicitly disclosed denominators:

| Metric Name | Mathematical Formula | Disclosed Denominator | Fallback / Zero-State Handling |
|---|---|---|---|
| **Precision** | $\frac{TP}{TP + FP}$ | $TP + FP$ | Disclosed; $1.0$ if clean ground truth ($TP=0, FP=0$). |
| **Recall** | $\frac{TP}{TP + FN}$ | $TP + FN$ | Disclosed; $1.0$ if clean ground truth. |
| **False Positive Rate (FPR)** | $\frac{FP}{FP + TN}$ (fixtures)<br>$\frac{\text{Confirmed FP}}{\text{Reviewed Findings}}$ (production) | Reviewed Findings Count | Explicitly discloses `"0 / 0 (no reviewed findings)"` and $0.0\%$. |
| **False Negative Rate (FNR)** | $\frac{FN}{TP + FN}$ | $TP + FN$ | Disclosed ground-truth denominator. |
| **Evidence Completeness Rate** | $\frac{\text{Findings with Valid SHA-256 Evidence}}{\text{Total Canonical Findings}}$ | Total Canonical Findings | Disclosed; $1.0$ if 0 findings. |
| **Independent Reproduction Rate** | $\frac{\text{Corroborated Findings } (\ge 2 \text{ adapters/jobs})}{\text{Total Canonical Findings}}$ | Total Canonical Findings | Disclosed count. |
| **Inconclusive Finding Rate** | $\frac{\text{Inconclusive Findings}}{\text{Total Canonical Findings}}$ | Total Canonical Findings | Disclosed count. |
| **Retest Recurrence Rate** | $\frac{\text{Reopened Findings with Recurrence}}{\text{Total Remediated Findings}}$ | Total Remediated Findings | Disclosed; $0.0\%$ if 0 remediated findings. |
| **Duplicate Observation Rate** | $\frac{\text{Total Observations} - \text{Total Canonical}}{\text{Total Observations}}$ | Total Raw Observations | Disclosed ratio. |

---

## 5. Model Learning Governance & Ground-Truth Dataset Rules

In accordance with Prompt 19 governance specifications:
1. **Unverified Records Excluded:** `ModelGovernanceService.curate_dataset` strictly excludes `INCONCLUSIVE`, `UNABLE_TO_VERIFY`, `EVIDENCE_PENDING`, and unverified `DETECTED` findings from ground-truth training datasets.
2. **Simulation Filtering:** When `allow_synthetic_benchmark=False`, simulated findings (`is_simulated=True`) are filtered out from production training datasets.
3. **Observation Deduplication:** Repeated scans of the same canonical finding do not inflate dataset record counts; each fingerprint is admitted at most once per dataset version.
4. **Partitioning:** Cryptographically deterministic 70% Train, 15% Validation, 15% Test partitioning using SHA-256 provenance hashes.

---

## 6. API Specification & Endpoints

| HTTP Method | Route | Description | RBAC Gate |
|---|---|---|---|
| `GET` | `/api/v1/projects/{project_id}/quality/overview` | Full detection quality metrics, status distributions, disclosed denominators, and warnings. | Project Member / Admin |
| `GET` | `/api/v1/projects/{project_id}/quality/fixtures` | Executes all 4 deterministic benchmark testbeds and reports TP, FP, TN, FN, precision, recall. | Project Member / Admin |
| `GET` | `/api/v1/projects/{project_id}/quality/adapters/{adapter_name}` | Historical quality, corroboration, and false-positive rates for a scanner adapter. | Project Member / Admin |
| `GET` | `/api/v1/projects/{project_id}/quality/findings/{finding_id}/provenance` | Full observation lineage and SHA-256 cryptographic verification of raw evidence payloads. | Project Member / Admin |
| `POST` | `/api/v1/projects/{project_id}/findings/{finding_id}/validation` | Governed validation transition across 9 epistemic states with audit ledger recording. | Lead / Admin for FP; Tester / Lead for others; Viewer forbidden |
