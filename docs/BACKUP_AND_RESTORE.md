# VAPT Platform — Backup, Recovery & Data Lifecycle Operations

## 1. Overview

The VAPT Platform provides point-in-time disaster recovery, verifiable backup verification, evidence retention policies, and cryptographically attested data exports. This document details operational runbooks and implementation guarantees for backup, restore, and data teardown workflows.

---

## 2. Online Database Backup Architecture

Backups are executed online without interrupting active web server sessions or locking database readers (`app/services/backup_service.py`).

### 2.1. SQLite Online Snapshot Workflow
1. The backup service opens a read-only URI connection:
   ```python
   sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
   ```
2. Executes SQLite native online snapshot:
   ```sql
   VACUUM INTO '<destination_backup_path>';
   ```
3. Computes the SHA-256 digest over the resulting backup file.
4. Records backup metadata (path, SHA-256 hash, size, timestamp, engine type).
5. Emits an immutable audit record: `DATABASE_BACKUP_CREATED`.

---

## 3. Verifiable Sandbox Restore Testing

Before any backup is certified for disaster recovery, it must pass automated sandbox restoration (`verify_and_restore_sandbox`):

```
[ Backup File (.db) ] ──► 1. Compute & Verify SHA-256 Hash
                                   │
                                   ▼
[ Temp Sandbox Dir ]  ──► 2. Restore Database in Isolated Environment
                                   │
                                   ▼
[ SQLite Pragma ]     ──► 3. Execute 'PRAGMA integrity_check;'
                                   │
                                   ▼
[ Schema Audit ]      ──► 4. Verify Critical Tables Exist & Readable
                                   │
                                   ▼
[ Cleanup ]           ──► 5. Delete Disposable Sandbox & Emit Audit Log
```

### 3.1. Verification Criteria
- SHA-256 checksum matches recorded manifest digest.
- `PRAGMA integrity_check` returns `"ok"`.
- Table count and row queries succeed without disk corruption errors.

---

## 4. Project Teardown & Right-to-Erasure (`purge_project_data`)

To support data minimization and GDPR/CCPA compliance, the platform provides authorized project data purging:

### 4.1. Dual-Key Confirmation Barrier
- An operator cannot accidentally delete a project.
- The request requires the exact confirmation phrase:
  ```
  PURGE PROJECT <Exact Project Name>
  ```
- Only project `OWNER` or system `ADMIN` roles may initiate a purge.

### 4.2. Cascading Erasure & Tombstone Audit
- Cascading foreign key constraints automatically erase all associated findings, evidence payloads, scan jobs, graph nodes, relationships, and risk scores.
- An immutable tombstone record is recorded in `audit_events`:
  - `action`: `PROJECT_PURGED_TOMBSTONE`
  - `details`: Project name, organization ID, actor ID, and ISO timestamp.
  - Tombstone records are preserved permanently for forensic compliance.

---

## 5. Verifiable Project Export Manifests

Operators can generate a self-contained, cryptographically signed JSON manifest of all project data via `/api/v1/projects/{id}/lifecycle/export`:
- Export contains: scope targets, exclusions, job logs, findings, graph nodes, and risk assessments.
- When `verify_evidence=true` is specified, the system recomputes SHA-256 digests for all evidence records in the project and embeds the verification report.
- The entire manifest is serialized canonically and signed with an aggregate SHA-256 checksum (`manifest_sha256`).

---

## 6. Evidence Retention & Archival

Large scan payloads (HTTP banners, raw responses) can be pruned after an aging period (e.g., 180 days) via `BackupRecoveryService.apply_evidence_retention_policy()`:
- Finding records, titles, CVSS scores, and remediation statuses remain intact.
- Evidence payloads older than the retention threshold are cleared.
- Original SHA-256 hashes (`raw_sha256_hash`) are preserved so that historical audit attestations remain verifiable.
