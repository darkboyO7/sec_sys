# VAPT Platform — AI Analyst & Model Governance Architecture

## 1. Overview

The VAPT Platform incorporates assistive AI capabilities for finding summarization, attack-path narrative generation, and intelligent triage recommendations. To ensure that AI components never compromise platform security or fabricate ungrounded claims, all AI workflows operate under **strict prompt quarantine, deterministic citation boundaries, and human-in-the-loop model governance**.

---

## 2. Controlled AI Security Analyst (`AIAnalystService`)

### 2.1. Untrusted Input Sanitization & Prompt Injection Defense
Because vulnerability descriptions, HTTP banners, and server responses originate from untrusted external targets, they represent potential prompt injection vectors.
- **HTML & Control Character Escaping**: All input strings are sanitized before interpolation into prompt templates.
- **Adversarial Pattern Quarantine**: `AIAnalystService.sanitize_untrusted_input()` evaluates text against known prompt-injection signatures:
  - `IGNORE ALL PREVIOUS INSTRUCTIONS`
  - `SYSTEM PROMPT OVERRIDE`
  - `<script>` / `javascript:` execution vectors
  - Role-impersonation tokens (`Assistant:`, `System:`)
- **Quarantine Action**: If an adversarial signature is detected, the input is neutralized, flagged with `is_quarantined = True`, and the analyst issues a security warning rather than executing untrusted instructions.

### 2.2. Grounded Citation Engine
To prevent generative hallucinations:
1. The AI analyst is restricted to analyzing only the findings, assets, and graph edges provided in the query context.
2. Every claim in the analysis output must cite a verifiable `finding_id` or `cve_id` present in the project.
3. Post-generation validators cross-reference all citations against database records; any ungrounded claim is flagged and stripped from the final narrative.

---

## 3. Controlled Learning & Model Governance (`LearningService`)

Machine learning models deployed for finding deduplication, false-positive classification, or risk clustering follow a formal governance lifecycle (`app/models/learning.py`):

```
┌──────────────────┐      Split 70/15/15       ┌──────────────────┐
│ Curation Dataset │ ────────────────────────► │ Governed Model   │
│ SHA-256 Hash     │                           │ State: TRAINED   │
└──────────────────┘                           └────────┬─────────┘
                                                        │
                                                        ▼
                                               ┌──────────────────┐
                                               │ Model Evaluation │
                                               │ Precision/Recall │
                                               └────────┬─────────┘
                                                        │
                                                        │ Passes Thresholds (>= 0.60)
                                                        ▼
┌──────────────────┐     Lead Human Sign-Off   ┌──────────────────┐
│   Active Model   │ ◄──────────────────────── │ PENDING_APPROVAL │
│ State: ACTIVE    │                           └──────────────────┘
└────────┬─────────┘
         │
         │ Anomaly Detected / Performance Drift
         ▼
┌──────────────────┐
│ Atomic Rollback  │ ──► Reverts immediately to previous verified model
└──────────────────┘
```

### 3.1. Dataset Integrity & Partitioning
- **Cryptographic Fingerprint**: Datasets record a canonical SHA-256 hash over all training rows.
- **Strict Partitioning**: Datasets are partitioned into distinct train (70%), validation (15%), and test (15%) splits with zero cross-split overlap.

### 3.2. Empirical Threshold Gates
Before a model can transition from `EVALUATED` to `PENDING_APPROVAL`:
- **Minimum Precision Threshold**: $\ge 0.60$
- **Minimum Recall Threshold**: $\ge 0.60$
- Models falling below either threshold fail closed and transition to `REJECTED`.

### 3.3. Human Approval & Dual-Key Sign-Off
- Machine learning models **never** self-deploy or auto-promote.
- Promotion to `ACTIVE` requires explicit sign-off by a user with `ProjectRole.LEAD` or system `ADMIN` privileges.
- Approver UUID and timestamp are recorded in `governed_models` and the audit ledger.

### 3.4. Atomic Instant Rollback
If a deployed model exhibits degraded operational performance or drift:
- Lead operators can trigger atomic rollback via `/api/v1/projects/{id}/models/{model_id}/rollback`.
- The platform deactivates the current model and restores the previous active version in a single atomic transaction.
