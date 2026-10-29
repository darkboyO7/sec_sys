# Automated Backup Scheduling, Recovery Drills & Restoration Assurance Runbook

**Document Revision:** 1.0.0  
**Phase:** Prompt 42  
**Platform Compliance:** Google Antigravity & NIST SP 800-34 Contingency Planning  

---

## 1. Executive Summary

This runbook establishes standard operating procedures for automated, cryptographic point-in-time backup scheduling, failure detection, storage volume governance, and isolated restoration drills across the VAPT System.

### Core Principles
1. **Never report a backup as verified merely because a file exists:** Every backup must satisfy independent 7-point verification (manifest digest, database SHA-256, SQLite `PRAGMA integrity_check`, foreign key validation, schema consistency, audit chain continuity, and evidence/model presence).
2. **Never execute destructive restoration during scheduled assurance drills:** Periodic drills must execute inside isolated, disposable sandboxes, automatically reconciling in-flight jobs to `INTERRUPTED` and verifying schema and audit integrity before automatic cleanup.
3. **Pre-flight Capacity Governance:** Before creating any snapshot, storage destinations are verified against configurable safety margins (default 50 MB / configured policy). If storage is depleted, the backup aborts safely with `SKIPPED_DISK_LOW` and alerts operators via audit logs.
4. **Governed Emergency Live Restores:** Live database restoration requires explicit administrative role authentication, matching human confirmation phrase (`CONFIRM DISASTER RESTORE <bundle_id>`), and automated generation of a pre-restore rollback snapshot before active file swapping.

---

## 2. Comprehensive State Inventory

Disaster recovery bundles capture the full operational state of the VAPT platform:

| Component | Target Location | Manifest Key | Verification Mechanism |
| :--- | :--- | :--- | :--- |
| **Active SQLite Database** | `./data/vapt.db` | `database` | Online backup API, SHA-256 digest, SQLite `PRAGMA integrity_check` & `PRAGMA foreign_key_check` |
| **Evidence Artifacts** | `./data/evidence/*` | `evidence_files` | SHA-256 file catalog, presence verification |
| **Model Artifacts** | `./data/models/*` | `model_files` | SHA-256 checksum tracking, model versioning |
| **Configuration Reference** | Sanitized config state | `config_reference` | JSON metadata capturing environment, WAL pragma state, engine revision |
| **Audit Log Ledger** | Database `audit_events` | `audit_chain_head` | Cryptographic SHA-256 hash-chain verification from genesis to tip |

---

## 3. Scheduled Assurance Workflow

```
[Cron / Schedule Poller]
          │
          ▼
[Pre-Flight Storage Volume Check] ──(Insufficient Space)──► [SKIPPED_DISK_LOW & Audit Alert]
          │ (Sufficient Space)
          ▼
[SQLite WAL Online Backup (.incomplete)]
          │
          ▼
[Snap Evidence, Models & Config References]
          │
          ▼
[Generate & Cryptographically Sign Manifest]
          │
          ▼
[Atomic Promotion (Remove .incomplete)]
          │
          ▼
[Automated 7-Point Verification Check] ──(Check Fails)──► [FAILED & Increment Consecutive Failures]
          │ (Passed)
          ▼
[Automated Isolated Restore Drill (Sandbox)]
   - Restore database to sandbox
   - Reconcile in-flight jobs -> INTERRUPTED
   - Verify table counts & foreign keys
   - Clean up sandbox
          │
          ▼
[Retention Rotation (Preserve Last-Known-Good)]
          │
          ▼
[SUCCESS Recorded & Next Run Window Calculated]
```

---

## 4. API Endpoints Reference

| Method | Endpoint | RBAC Role | Description |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/v1/recovery/disk-space` | Authenticated | Inspects disk usage and remaining capacity. |
| `GET` | `/api/v1/recovery/schedules` | Authenticated | Lists all configured automated backup schedules. |
| `POST` | `/api/v1/recovery/schedules` | `ADMIN` | Creates a new automated backup schedule. |
| `GET` | `/api/v1/recovery/schedules/{id}` | Authenticated | Retrieves schedule configuration and execution status. |
| `PUT` | `/api/v1/recovery/schedules/{id}` | `ADMIN` | Updates schedule interval, retention, or assurance flags. |
| `DELETE`| `/api/v1/recovery/schedules/{id}` | `ADMIN` | Deletes an automated schedule definition. |
| `POST` | `/api/v1/recovery/schedules/{id}/trigger` | `ADMIN` | Manually triggers immediate execution of a schedule. |
| `POST` | `/api/v1/recovery/schedules/poll-due` | `ADMIN` | Executes all active schedules currently due for execution. |

---

## 5. Verification & Test Evidence

All automated backup scheduling and restoration assurance capabilities are validated by:
- **Backend Test Suite:** `backend/tests/test_prompt42_automated_backup_scheduling_and_restoration_assurance.py` (9 tests, passing in 3.97s).
- **Frontend Test Suite:** `frontend/src/tests/backup_scheduling_assurance.test.ts` (5 tests, passing in 376ms).
- **Disaster Recovery Regressions:** `backend/tests/test_prompt23_disaster_recovery_and_restoration.py` & `frontend/src/tests/recovery.test.ts` (100% passed).
