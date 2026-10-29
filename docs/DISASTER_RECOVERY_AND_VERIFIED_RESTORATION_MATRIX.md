# VAPT Platform: Disaster Recovery, Verified Restoration & Data Integrity Matrix

**Version:** 2026.2.0 (Prompt 23)  
**Standard:** NIST SP 800-34 Rev. 1 / ISO 27001 A.12.1.3 / OWASP ASVS v4.0.3  
**Status:** QUALIFIED & VERIFIED  

---

## 1. Executive Summary & Recovery Boundary Classification

Disaster Recovery in the VAPT Platform is engineered to guarantee business continuity, audit immutability, and state consistency across catastrophic storage or process failures. Backups are never assumed restorable; restoration readiness is established through empirical, non-destructive verification and isolated sandbox restore drills.

### Data Classification & Recovery Boundaries

| Boundary Classification | Data Entities | Storage Location | Recovery Strategy | Guarantee |
| :--- | :--- | :--- | :--- | :--- |
| **Authoritative (Persistent)** | Organizations, Projects, Users, Governance Policies, Approval Records, Findings, Evidence Catalog, Audit Ledger | SQLite Database & Evidence Directory | WAL Online Backup (`sqlite3.backup`), Manifest SHA-256 Signing, Audit Hash Chain | Zero data loss for committed transactions; cryptographic verification |
| **Reconstructable (Derived)** | Knowledge Graph Topology, Risk Scores, Attack Paths, Aggregated Metrics, Drift Records | SQLite Tables / Cache | Recomputed via background graph sync and risk evaluation pipelines | 100% reconstructable from authoritative findings & assets |
| **Ephemeral (In-Flight)** | Worker PIDs, Heartbeat Leases, Live Socket Connections, Temp Scans | Memory / Process Table | In-flight jobs reconciled to `INTERRUPTED`; worker leases cleared | Automated reconciliation; no stale execution |
| **Sensitive (Protected)** | API Tokens, Master Encryption Keys, OAuth Secrets | Environment Variables / OS Keyring | Excluded from ordinary backup bundles; decoupled from application DB | Decoupled credentials; prevents credential leakage |
| **Unrecoverable** | In-progress socket buffers from interrupted external scanner executions | Temporary pipes | Aborted cleanly; job marked `INTERRUPTED` with restart recommendation | Safe fail-stop |

---

## 2. Point-in-Time Online Backup Protocol

### 2.1 SQLite WAL Online Backup Mechanism
Standard file-copy methods (`cp`, `Copy-Item`) on an active SQLite database running in WAL mode risk page torn writes and corruption. The VAPT Platform implements the SQLite Online Backup API (`sqlite3.backup`):
- Connects to the source database using read-only URI mode (`file:///{path}?mode=ro`) to prevent SQLite page locks and concurrency deadlocks.
- Streams consistent database pages to a destination file inside a staging directory.

### 2.2 Atomic Staging Protocol (`.incomplete` Marker)
To guarantee that interrupted, partial, or failed backup attempts can never be mistaken for valid bundles:
1. Bundle is created in a temporary directory suffixed with `.incomplete` (e.g. `dr_bundle_20261029_000001_abc12345.incomplete`).
2. Online backup of `database.db` completes.
3. Cataloged evidence artifacts are archived into `evidence/`.
4. SHA-256 digests are computed for all archived files.
5. Canonical `backup_manifest.json` is generated, containing:
   - System metadata, application version, schema revision (`alembic_version`).
   - Audit hash chain head (`event_id` and `event_hash`).
   - Table record counts.
   - SHA-256 checksums of all cataloged files.
   - Canonical `manifest_sha256` signature.
6. Only upon complete, verified disk sync is the directory atomically renamed to strip the `.incomplete` suffix.

---

## 3. Independent 7-Point Non-Destructive Verification Engine

Verification is executed independently without modifying bundle contents:

| Checkpoint | Scope | Failure Condition | Verification Logic |
| :--- | :--- | :--- | :--- |
| **1. Staging Completion** | Directory marker | Presence of `.incomplete` suffix or directory | `not bundle_path.name.endswith(".incomplete")` |
| **2. Manifest Signature** | `backup_manifest.json` | Any tampering with manifest metadata | Strips `manifest_sha256`, calculates canonical JSON SHA-256, verifies exact match |
| **3. File Checksums** | `database.db` & `evidence/*` | Any altered or corrupt bytes | Recalculates SHA-256 for all cataloged files against manifest entries |
| **4. SQLite Page Integrity** | Database storage engine | Corrupted internal pages or b-trees | Executes `PRAGMA integrity_check`; must return `[('ok',)]` |
| **5. Relational Consistency** | Foreign key constraints | Dangling references or missing parents | Executes `PRAGMA foreign_key_check`; must return 0 violations |
| **6. Schema Revision** | Alembic migration state | Schema version mismatch | Compares `alembic_version` in DB against manifest `schema_revision` |
| **7. Audit Chain Continuity** | `audit_events` | Tampered audit ledger or broken link | Validates `event[i].prev_event_hash == event[i-1].event_hash` through head |

---

## 4. Isolated Sandbox Restore Drill Protocol

To verify restorable integrity without impacting production:
1. **Isolated Sandbox Allocation:** Allocates a temporary drill directory (`data/restore_drill_<uuid>`).
2. **Bundle Verification Pre-Flight:** Pre-verifies the target bundle through the 7-point engine. Unverified bundles are rejected.
3. **Sandbox Extraction:** Restores database and evidence files into the isolated sandbox.
4. **In-Flight Job State Reconciliation:**
   - Any assessment jobs in `RUNNING` or `PREFLIGHT` states are transitioned to `INTERRUPTED`.
   - Reason logged: *"Execution interrupted by disaster recovery backup bundle restoration."*
   - Prevents restored database from triggering duplicate scans or holding stale worker lock leases.
5. **Governance & Separation of Duties Invariant Enforcement:**
   - Pending or revoked approvals (`PENDING`, `REVOKED`) remain strictly in their preserved states.
   - No automatic promotions or state bypasses occur.
6. **Automatic Cleanup:** Verifies all tables and audit records, records telemetry, and cleanly deletes the sandbox directory. The active live database is never touched.

---

## 5. Governed Live Disaster Restoration

For catastrophic disaster recovery of the active system:
- **RBAC Guard:** Restricted strictly to System Administrators (`SystemRole.ADMIN`).
- **Explicit Confirmation Phrase:** Requires explicit phrase: `CONFIRM DISASTER RESTORE <bundle_id>`.
- **Pre-Restore Rollback Snapshot:** Before altering live state, the current active database is saved to `data/backups/prerestore_<timestamp>.bak`.
- **Atomic File Swap:** Database file is replaced atomically.
- **Post-Swap Verification & Auto-Revert:** Immediate `PRAGMA integrity_check` is executed on the live path. If any post-swap check fails, the live database is automatically reverted from the rollback snapshot.

---

## 6. Retention and Rotation Policy

- Configurable retention limit (default: 5 most recent bundles).
- **Protection of Last-Known-Good:** Any bundle flagged as `is_last_known_good` (verified and restore-drilled) is immune to pruning, guaranteeing at least one proven restorable baseline exists at all times.
- Automated purging of abandoned `.incomplete` staging directories.

---

## 7. Deterministic Empirical Test Traceability Matrix

All 17 empirical disaster recovery and restoration test scenarios verified in `backend/tests/test_prompt23_disaster_recovery_and_restoration.py`:

| Test ID | Test Scenario | Expected Outcome | Verification Status |
| :--- | :--- | :--- | :--- |
| `test_01` | Consistent WAL online backup creation | Valid bundle created; manifest signed; `.incomplete` removed | **PASSED** |
| `test_02` | Atomic staging marker prevents partial backup | Staging marker `.incomplete` blocks unfinalized bundle use | **PASSED** |
| `test_03` | Independent 7-point verification on healthy bundle | All 7 checkpoints report `PASSED` with 0 errors | **PASSED** |
| `test_04` | Tampered database file detected | Byte modification triggers SHA-256 mismatch failure | **PASSED** |
| `test_05` | Tampered manifest signature detected | Altered manifest metadata fails signature verification | **PASSED** |
| `test_06` | Corrupted SQLite internal pages detected | Corrupted database pages fail `PRAGMA integrity_check` | **PASSED** |
| `test_07` | Broken foreign keys detected | Constraint violation row triggers `PRAGMA foreign_key_check` failure | **PASSED** |
| `test_08` | Broken audit chain continuity detected | Modified `prev_event_hash` fails cryptographic audit chain check | **PASSED** |
| `test_09` | Missing cataloged evidence files detected | Missing evidence artifact fails file checksum verification | **PASSED** |
| `test_10` | Isolated restore drill reconciles in-flight jobs | `RUNNING` & `PREFLIGHT` jobs reconciled to `INTERRUPTED` | **PASSED** |
| `test_11` | Governance & SoD preserved on restoration | Stale/revoked approvals remain unexecuted; no state bypass | **PASSED** |
| `test_12` | Isolated restore cleans sandbox automatically | Sandbox deleted after drill; live DB untouched | **PASSED** |
| `test_13` | Live restore with governance & rollback | Confirmation phrase verified; pre-restore rollback created | **PASSED** |
| `test_14` | Live restore rolls back on integrity failure | Post-swap corruption automatically reverts to rollback DB | **PASSED** |
| `test_15` | Backup rotation preserves last-known-good | Surplus backups pruned; last-known-good bundle retained | **PASSED** |
| `test_16` | RBAC enforcement on recovery endpoints | Non-admin users denied access with HTTP 403 Forbidden | **PASSED** |
| `test_17` | Recovery posture and readiness status reporting | Telemetry and readiness (`READY`/`ATTENTION`/`DEGRADED`) verified | **PASSED** |

---

## 8. Conclusion

The VAPT Platform's Disaster Recovery, Verified Restoration, and Data Integrity subsystem establishes verifiable recovery readiness. Every backup is cryptographically attributable, independently checkable, drill-tested in isolation, and protected by non-destructive automated rollbacks.
