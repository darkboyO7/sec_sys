# Evidence Lifecycle Governance, Data Retention & Verifiable Deletion Traceability Matrix (Prompt 29)

## 1. Overview
This matrix documents the verification, enforcement points, and test mappings for Prompt 29 — Evidence Lifecycle Governance, Data Retention, Privacy, and Verifiable Deletion.

## 2. Requirement to Test & Enforcement Mapping

| Req ID | Requirement Description | Implementation / Enforcement Point | Automated Test Verification | Status |
|---|---|---|---|---|
| **RET-01** | Authoritative data classification taxonomy & retention policies | `DataClassification`, `RetentionPolicyModel`, `EvidenceLifecycleService.get_policies()` | `test_prompt29_evidence_lifecycle_and_retention.py::test_01_retention_policy_catalog_completeness` | **VERIFIED** |
| **RET-02** | Role-based policy update restrictions (Admin only) | `PUT /system/lifecycle/policies/{id}`, `require_system_roles([SystemRole.ADMIN])` | `test_prompt29_evidence_lifecycle_and_retention.py::test_02_retention_policy_requires_admin_to_update` | **VERIFIED** |
| **RET-03** | Legal and investigation hold creation & active tracking | `LegalHoldModel`, `EvidenceLifecycleService.create_hold()` | `test_prompt29_evidence_lifecycle_and_retention.py::test_03_legal_hold_creation_and_listing` | **VERIFIED** |
| **RET-04** | Legal hold release workflow | `EvidenceLifecycleService.release_hold()`, `DELETE /system/lifecycle/holds/{id}` | `test_prompt29_evidence_lifecycle_and_retention.py::test_04_legal_hold_release` | **VERIFIED** |
| **RET-05** | Legal hold strictly blocks retention deletion / redaction | `EvidenceLifecycleService.generate_retention_preview()`, `is_held()` check | `test_prompt29_evidence_lifecycle_and_retention.py::test_05_active_hold_blocks_evidence_deletion_in_preview` | **VERIFIED** |
| **RET-06** | Accurate retention expiration detection (e.g. 90-day raw evidence) | `EvidenceLifecycleService.generate_retention_preview()` | `test_prompt29_evidence_lifecycle_and_retention.py::test_06_retention_preview_detects_expired_records` | **VERIFIED** |
| **RET-07** | Deterministic dry-run preview state hash | `RetentionPreviewReport.dry_run_hash` (SHA-256) | `test_prompt29_evidence_lifecycle_and_retention.py::test_07_retention_preview_computes_deterministic_dry_run_hash` | **VERIFIED** |
| **RET-08** | Security Lead explicit approval requirement for destructive actions | `EvidenceLifecycleService.execute_retention()` (`confirmed_by_lead=True`) | `test_prompt29_evidence_lifecycle_and_retention.py::test_08_retention_execution_requires_security_lead_confirmation` | **VERIFIED** |
| **RET-09** | Rejection of stale or mismatched preview hashes | `EvidenceLifecycleService.execute_retention()` hash validation | `test_prompt29_evidence_lifecycle_and_retention.py::test_09_retention_execution_rejects_stale_preview_hash` | **VERIFIED** |
| **RET-10** | Verifiable deletion generating HMAC-SHA256 suppression tombstones | `DeletionTombstoneModel`, `EvidenceLifecycleService.create_tombstone()` | `test_prompt29_evidence_lifecycle_and_retention.py::test_10_retention_execution_creates_verifiable_tombstone` | **VERIFIED** |
| **RET-11** | Deletion suppression ledger preventing backup restoration resurrection | `EvidenceLifecycleService.is_suppressed()` | `test_prompt29_evidence_lifecycle_and_retention.py::test_11_suppression_tombstone_prevents_restoration_resurrection` | **VERIFIED** |
| **RET-12** | Automated secret detection and in-line payload redaction | `EvidenceLifecycleService.redact_evidence_payload()` | `test_prompt29_evidence_lifecycle_and_retention.py::test_12_automated_secret_redaction_masks_bearer_tokens_and_keys` | **VERIFIED** |
| **RET-13** | Database payload redaction without modifying immutable record ID | `EvidenceLifecycleService.redact_evidence_record()` | `test_prompt29_evidence_lifecycle_and_retention.py::test_13_redact_evidence_record_in_database` | **VERIFIED** |
| **RET-14** | REST endpoints RBAC and authentication enforcement | `/system/lifecycle/*` with `require_system_roles` | `test_prompt29_evidence_lifecycle_and_retention.py::test_14_api_policies_endpoint_requires_auth`, `test_15_api_holds_endpoint_lifecycle` | **VERIFIED** |
| **RET-15** | Standalone CLI tool execution | `scripts/run_retention_lifecycle.py` with `--preview`, `--execute`, `--json` | `test_prompt29_evidence_lifecycle_and_retention.py::test_17_standalone_retention_lifecycle_cli` | **VERIFIED** |
| **RET-16** | Frontend lifecycle governance dashboard | `EvidenceLifecycleGovernanceView.tsx`, `api.ts`, `App.tsx` | `frontend/src/tests/evidence_lifecycle.test.ts` (5 tests passed) | **VERIFIED** |
