# Disaster Recovery & Operator Runbook (Prompts 58–62)

## 1. Overview & Operational Assumptions

The VAPT Platform implements a resilient, auditable disaster recovery (DR) architecture designed to protect assessment evidence, vulnerability catalogs, and audit ledgers against host crashes, database corruption, accidental deletion, and operational errors.

### Key Recovery Objectives:
- **Recovery Point Objective (RPO)**: **60 minutes** (`RPO_TARGET_MINUTES = 60`). Automated snapshots run on a recurring schedule; recovery telemetry tracks backup age and warns when RPO is at risk.
- **Recovery Time Objective (RTO)**: **15 minutes** (`RTO_TARGET_MINUTES = 15`). Point-in-time restoration and post-recovery reconciliation complete within minutes.

---

## 2. Disaster Recovery Bundle Architecture

Each disaster recovery bundle (`dr_bundle_<timestamp>_<uuid>`) is an atomic, self-contained snapshot consisting of:

```
data/backups/dr_bundle_20261031_040000_abc123/
├── database.db                # Online, non-blocking SQLite WAL backup (or pg_dump)
├── evidence/                  # All preserved raw and normalized evidence artifacts
├── models/                    # Serialized machine learning models and policy weights
├── config_reference.json      # Redacted runtime configuration (environment, database driver)
├── redacted_settings.json     # Sanitized system settings (secrets & credentials redacted)
├── backup_manifest.json       # Bundle manifest with file catalog, table counts & digests
└── manifest.sig               # Detached Ed25519 cryptographic digital signature
```

### Security Controls:
1. **Secret Scrubbing**: `sanitize_config_metadata()` strips all API keys, database credentials, JWT secrets, and private keys before archiving.
2. **Ed25519 Manifest Signature**: The manifest body is canonically serialized and digitally signed with the platform's private attestation key (`KEY-DEFAULT-ED25519`).
3. **Atomic Finalization**: Backups are written to a `.incomplete` staging directory and promoted atomically only upon successful SHA-256 verification of all constituents.

---

## 3. Operator Runbooks

### Runbook 1: Creating a Disaster Recovery Bundle
To trigger an operator-initiated disaster recovery backup:

```bash
# Via API:
POST /api/v1/system/recovery/bundles
Authorization: Bearer <ADMIN_OR_SECURITY_LEAD_TOKEN>
Content-Type: application/json

{
  "backup_type": "FULL",
  "comment": "Pre-maintenance disaster recovery snapshot"
}
```

---

### Runbook 2: Verifying Backup Bundle Integrity
Before restoration or during scheduled compliance audits:

```bash
POST /api/v1/system/recovery/verify
Authorization: Bearer <TOKEN>
Content-Type: application/json

{
  "bundle_id": "dr_bundle_20261031_040000_abc123"
}
```

The system verifies:
- Manifest JSON integrity and canonical SHA-256 signature.
- Authentic Ed25519 cryptographic digital signature (`manifest.sig`).
- Checksums of `database.db`, evidence blobs, and models against the manifest catalog.
- Database SQLite `PRAGMA integrity_check` and `foreign_key_check`.
- Monotonic Merkle audit ledger continuity across all projects.

---

### Runbook 3: Performing an Isolated Recovery Drill (Non-Destructive)
Recovery drills validate that a backup bundle is restorable without touching or risking active production data.

```bash
POST /api/v1/system/recovery/drill
Authorization: Bearer <ADMIN_OR_SECURITY_LEAD_TOKEN>
Content-Type: application/json

{
  "bundle_id": "dr_bundle_20261031_040000_abc123"
}
```

**Drill Execution Workflow:**
1. Verifies the bundle independently.
2. Unpacks database and evidence files into a disposable, isolated sandbox directory (`./data/restore_drill_<timestamp>_<uuid>`).
3. Connects to the sandbox database and validates all table row counts.
4. Reconciles in-flight jobs: Any jobs found in `RUNNING`, `QUEUED`, or `PREFLIGHT` state are reconciled to `INTERRUPTED` (preventing unmonitored rogue tool executions).
5. Executes post-recovery Merkle custody chain verification.
6. Cleans up disposable sandbox directories completely.

---

### Runbook 4: Governed Live Disaster Recovery Restoration
In the event of active host corruption or disaster recovery declaration:

> [!CAUTION]
> Live restore replaces the active database. It requires dual confirmation, pre-restore safety snapshotting, and strict role authorization.

```bash
POST /api/v1/system/recovery/live-restore
Authorization: Bearer <ADMIN_OR_SECURITY_LEAD_TOKEN>
Content-Type: application/json

{
  "bundle_id": "dr_bundle_20261031_040000_abc123",
  "confirmation_phrase": "CONFIRM DISASTER RESTORE dr_bundle_20261031_040000_abc123"
}
```

**Automated Safety Controls:**
1. **Concurrency Lock & Session Fencing**: Rejects concurrent restores and prevents duplicate execution of the same bundle (`_RESTORED_BUNDLES_IN_SESSION`).
2. **Pre-Restore Rollback Snapshot**: Automatically copies the active live database to `vapt_pre_restore_rollback_<timestamp>.db` before any file operations.
3. **Post-Restore Integrity Gate**: Executes SQLite `PRAGMA integrity_check`. If integrity fails, the system automatically reverts to the pre-restore rollback snapshot.
4. **Post-Recovery Custody Audit**: Audits all 100% of Merkle custody chains and audit ledgers to ensure custody unbrokenness.

---

### Runbook 5: Recovery Readiness Telemetry
To monitor backup freshness, RPO/RTO status, and WORM storage health from the dashboard:

```bash
GET /api/v1/system/recovery/readiness
Authorization: Bearer <TOKEN>
```

**Sample Output:**
```json
{
  "health": "HEALTHY",
  "assumptions": {
    "rpo_target_minutes": 60,
    "rto_target_minutes": 15,
    "evidence_storage_backend": "LOCAL"
  },
  "metrics": {
    "total_backups": 5,
    "latest_backup_id": "dr_bundle_20261031_040000_abc123",
    "latest_backup_age_minutes": 12.4,
    "rpo_compliance": "COMPLIANT",
    "last_restore_drill_at": "2026-10-31T04:05:00+00:00",
    "active_legal_holds_count": 0,
    "evidence_tombstones_count": 2
  },
  "storage_worm_status": {
    "backend": "LOCAL",
    "worm_compliant": false,
    "worm_mode": "OS_READONLY_SIMULATION"
  }
}
```
