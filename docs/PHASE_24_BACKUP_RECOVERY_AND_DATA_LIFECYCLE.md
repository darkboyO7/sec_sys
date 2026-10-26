# PHASE 24: BACKUP, RECOVERY, AND DATA LIFECYCLE

## Executive Summary

Phase 24 establishes resilient disaster recovery, data lifecycle governance, and cryptographic backup verification for the VAPT Platform. It provides online, point-in-time database backups, isolated disposable sandbox recovery verification, tamper-evident SHA-256 hashing, comprehensive project export manifests, authorized right-to-erasure project teardown with immutable audit tombstones, and automated evidence retention lifecycle policies enforcing data minimization.

---

## 1. Architectural Implementation

### 1.1 Non-Blocking Online Database Backup (`BackupRecoveryService.create_database_backup`)
- **SQLite WAL Mode Non-Blocking Backup:** Utilizes SQLite's read-only URI (`file:{path}?mode=ro`) and online backup DBAPI mechanism to stream consistent database pages into destination snapshots without blocking active writers or deadlocking uncommitted write transactions.
- **Cryptographic Digest Integrity:** Computes a SHA-256 hash over the generated backup snapshot and verifies internal database structure (table counts) before completion.
- **Tamper-Evident Audit Logging:** Emits a `SYSTEM_BACKUP_CREATED` event capturing the backup filename, byte size, SHA-256 hash, and table count.

### 1.2 Isolated Sandbox Restore Verification (`BackupRecoveryService.verify_and_test_restore`)
- **Checksum Verification:** Evaluates the candidate backup file against its recorded SHA-256 digest, failing closed if tampered or corrupt.
- **Disposable Sandbox Execution:** Copies the backup snapshot to an ephemeral workspace, opens an isolated connection, and executes `PRAGMA integrity_check`.
- **Schema Validation:** Verifies structural completeness across core domain tables (`projects`, `users`, `assessment_jobs`, `audit_events`), ensuring the snapshot is viable for immediate disaster recovery.

### 1.3 Project Manifest Export (`BackupRecoveryService.export_project_manifest`)
- **Verifiable Project Snapshot:** Aggregates project metadata, scopes, exclusions, assessment jobs, vulnerability findings, knowledge graph nodes, and risk assessments into a canonical JSON representation.
- **Deterministic Digest:** Calculates a SHA-256 hash over canonical JSON (sorted keys, compact separators).
- **Audit Provenance:** Emits `PROJECT_DATA_EXPORTED` with target project ID and export digest.

### 1.4 Project Teardown & Right-to-Erasure (`BackupRecoveryService.purge_project_data`)
- **Explicit Confirmation Gate:** Mandates an exact confirmation phrase (`PURGE PROJECT {project.name}`) to prevent accidental deletion.
- **Relational Cascade:** Safely cascades deletion across findings, evidence, jobs, graphs, and digital twins using database foreign key constraints.
- **Immutable Tombstone:** Generates a permanent `PROJECT_PURGED_TOMBSTONE` audit record documenting project deletion timestamp, name, and actor identity.

### 1.5 Evidence Retention & Data Minimization (`BackupRecoveryService.apply_evidence_retention_policy`)
- **Automated Evidence Pruning:** Scans for completed assessment jobs older than a configurable retention threshold (default 180 days).
- **Safe Truncation:** Replaces bulky raw HTTP response payloads and request blobs with `[ARCHIVED_BY_RETENTION_POLICY]` markers (`is_truncated=True`), drastically reducing storage footprint while preserving canonical finding metadata and risk models.
- **Audit Verification:** Emits `RETENTION_POLICY_APPLIED` detailing jobs evaluated and evidence items pruned.

---

## 2. API Endpoints

| Endpoint | Method | Role | Description |
|---|---|---|---|
| `/api/v1/projects/{project_id}/lifecycle/export` | GET | Security Lead / Admin | Generates verifiable JSON export manifest |
| `/api/v1/projects/{project_id}/lifecycle/purge` | DELETE | Admin | Cascades project deletion requiring exact confirmation phrase |
| `/api/v1/projects/{project_id}/lifecycle/retention` | POST | Security Lead / Admin | Applies data minimization evidence retention policy |
| `/api/v1/admin/backup` | POST | Global Admin | Creates immediate point-in-time database backup |
| `/api/v1/admin/backup/verify` | POST | Global Admin | Restores candidate backup in sandbox and tests integrity |

---

## 3. Test Verification

Automated test suite: `backend/tests/test_phase24_backup_recovery.py`
- `test_online_database_backup_and_integrity`: PASSED
- `test_backup_sandbox_restore_and_verification`: PASSED
- `test_project_manifest_export`: PASSED
- `test_project_purge_lifecycle_and_tombstone`: PASSED
- `test_evidence_retention_policy_archival`: PASSED
- `test_api_lifecycle_endpoints`: PASSED

**Result:** 6 passed in 3.44s.
