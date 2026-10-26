# Phase 19 — Controlled Learning and Model Governance Report

**Milestone:** Phase 19 — Controlled Learning and Model Governance  
**Completion Date:** 2026-10-26  
**Platform:** Windows 11 Native Architecture, Python 3.14.7, FastAPI, SQLite WAL, React 19  
**Status:** COMPLETE & VERIFIED  

---

## 1. Executive Summary

Phase 19 establishes the Controlled Learning and Model Governance framework for the VAPT Platform:
1. **Governed Learning from Verified Operations:** Replaces uncontrolled online self-modification with a strictly governed, reproducible, offline data and model pipeline derived exclusively from verified findings, analyst triage decisions, and remediation verification results.
2. **Privacy-Preserving Feature Minimization:** Features undergo automated scrubbing removing secrets, API keys, bearer tokens, passwords, and raw IP addresses before ingestion into training partitions.
3. **Deterministic Partitioning & Cryptographic Dataset Hashes:**
   - Datasets (`LearningDataset`) are strictly partitioned into 70% TRAIN, 15% VALIDATION, and 15% TEST splits.
   - Every dataset manifest generates a canonical SHA-256 integrity hash ensuring data reproducibility and immutability.
4. **Held-Out Empirical Benchmark Metrics:**
   - Candidate models (`GovernedModel`) are evaluated exclusively on held-out TEST split data.
   - Emits exact, verifiable performance metrics: `precision`, `recall`, `f1_score`, `false_positive_rate`, and `brier_score` (calibration error).
5. **Human Governance Approval Gate (RBAC):**
   - Candidate models cannot be activated without an explicit evaluation and approval review by an authorized Lead or Admin with mandatory justification notes.
   - Rejects models failing quality thresholds.
6. **Atomic Rollback Architecture:**
   - Promoting a model to `ACTIVE` automatically demotes the existing active model to `DEPRECATED` and stores a pointer to it as `rollback_target_id`.
   - In case of performance drift or anomaly, an emergency rollback command atomically demotes the current model to `ROLLED_BACK` and restores the preceding active model.

---

## 2. Technical Architecture

### 2.1. Model Governance Lifecycle Pipeline
```
+-------------------------------------------------------------------------+
|                  Verified Operational Records Corpus                    |
|      • Confirmed Findings          • False Positive Dispositions        |
|      • Verified Remediations       • Recurrence Records                 |
+-------------------------------------------------------------------------+
                                     |
                                     v
+-------------------------------------------------------------------------+
|             Privacy Sanitization & Dataset Partitioning                 |
|   • Scrub Tokens & Passwords        • Scrub Target IPv4 Addresses       |
|   • 70% TRAIN / 15% VAL / 15% TEST  • Canonical SHA-256 Dataset Hash    |
+-------------------------------------------------------------------------+
                                     |
                                     v
+-------------------------------------------------------------------------+
|                Candidate Model Registration (CANDIDATE)                 |
|          • Model Hyperparameters     • Dataset Reference                |
+-------------------------------------------------------------------------+
                                     |
                                     v
+-------------------------------------------------------------------------+
|                Held-Out Benchmark Evaluation (EVALUATED)                |
|      • Precision, Recall, F1-Score • False Positive Rate (FPR)          |
|      • Brier Score (Calibration)   • Empirical Sample Sizes             |
+-------------------------------------------------------------------------+
                                     |
                                     v
+-------------------------------------------------------------------------+
|                Human Governance Approval Gate (APPROVED)                |
|         Lead / Tester Review Gate with Mandatory Written Notes          |
+-------------------------------------------------------------------------+
                                     |
                                     v
+-------------------------------------------------------------------------+
|              Controlled Deployment (ACTIVE) & Atomic Rollback           |
|    Promote to ACTIVE  <====================>  Demote to ROLLED_BACK     |
|    (Previous Model linked as rollback target) (Target Reactivated)      |
+-------------------------------------------------------------------------+
```

### 2.2. Schema & Migration Highlights
- **Alembic Migration:** `f1a2b3c4d5e6_phase19_controlled_learning_and_model_governance.py`
  - Created `learning_datasets` table (`project_id`, `name`, `version`, `dataset_hash`, `total_records`, `train_count`, `val_count`, `test_count`, `created_by_id`, `created_at`).
  - Created `dataset_records` table (`dataset_id`, `split`, `source_entity_type`, `source_entity_id`, `features`, `label`, `provenance_digest`, `created_at`).
  - Created `governed_models` table (`project_id`, `model_name`, `version`, `model_type`, `status`, `dataset_id`, `metrics`, `hyperparameters`, `is_active`, `activated_at`, `approved_by_id`, `approved_at`, `approval_notes`, `rollback_target_id`).

### 2.3. API Endpoints
- `POST /api/v1/projects/{project_id}/learning/datasets/curate`: Curate versioned, sanitized dataset.
- `GET /api/v1/projects/{project_id}/learning/datasets`: List project datasets.
- `POST /api/v1/projects/{project_id}/learning/models/register`: Register candidate model.
- `POST /api/v1/projects/{project_id}/learning/models/{model_id}/evaluate`: Evaluate on held-out test data.
- `POST /api/v1/projects/{project_id}/learning/models/{model_id}/approve`: Governance approval gate.
- `POST /api/v1/projects/{project_id}/learning/models/{model_id}/activate`: Controlled deployment.
- `POST /api/v1/projects/{project_id}/learning/models/{model_id}/rollback`: Emergency atomic rollback.
- `GET /api/v1/projects/{project_id}/learning/models`: List models with status filtering.

---

## 3. Verification & Compliance

- **Backend Pytest:** 202 passed across all phases (5 dedicated Phase 19 tests).
- **Frontend Vitest:** 6 passed.
- **Frontend Production Build:** Successful TypeScript compilation and Vite bundling.
- **Safety Invariants:** No unmonitored online self-modification; models are strictly versioned, evaluated on held-out data, approved by human operators, and rollback-capable.
