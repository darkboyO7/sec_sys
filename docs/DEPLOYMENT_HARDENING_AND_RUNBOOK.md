# VAPT SYSTEM — PRODUCTION DEPLOYMENT HARDENING & OPERATIONAL RUNBOOK

## 1. Production Architecture Overview

The VAPT Platform is architected for defense-in-depth, least privilege, and high availability. It operates across two primary topologies:

1. **Enterprise Multi-Worker Deployment (PostgreSQL):**
   - High-concurrency worker cluster utilizing `psycopg` connection pooling (`pool_size=20`, `max_overflow=10`).
   - Atomic worker task claiming via `SELECT ... FOR UPDATE SKIP LOCKED` (no queue race conditions).
   - Transient database deadlock resilience via exponential backoff with jitter (`with_transaction_retry`).
   - Independent background worker recovery sweep reclaiming abandoned jobs whose heartbeats have expired.

2. **Edge / Standalone Deployment (SQLite WAL):**
   - Single-node operation with Write-Ahead Logging (`PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;`).
   - Non-blocking online database backups streamed via read-only URI mode (`file:{path}?mode=ro`).

---

## 2. Zero-Downtime Migration & Rollback Runbook

### 2.1 Pre-Flight Dry-Run
Before applying any migration in production:
```bash
# 1. Inspect migration history and confirm current revision
alembic current

# 2. Generate SQL preview without applying DDL
alembic upgrade head --sql > migration_dryrun.sql

# 3. Create point-in-time pre-migration backup
curl -X POST https://vapt-api.internal/api/v1/admin/backup \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

### 2.2 Applying Migration
```bash
# 4. Apply migration safely
alembic upgrade head

# 5. Verify readiness probe passes
curl -f https://vapt-api.internal/ready
```

### 2.3 Rollback Procedure
If readiness check fails or post-deploy health degrades:
```bash
# Downgrade to prior revision
alembic downgrade -1

# In emergency database corruption, restore from verified snapshot:
curl -X POST https://vapt-api.internal/api/v1/admin/backup/verify \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"backup_path": "/var/backups/vapt_backup_preflight.db", "expected_sha256": "$PREFLIGHT_SHA256"}'
```

---

## 3. Worker Process Sandboxing & Isolation Runbook

Assessment workers execute within isolated subprocess boundaries:
- **Win32 Job Objects:** Hard memory caps (10MB IPC buffer clamp), no process inheritance, mandatory parent kill on termination.
- **IPC Sanitization:** Typed JSON-RPC payloads over standard I/O; direct terminal injection sanitized.
- **Fail-Safe Worker Heartbeats:** Workers update heartbeats every 5 seconds. Stale workers dead for >60 seconds are transitioned to `FAILED` with `WORKER_HEARTBEAT_TIMEOUT` audit records.
- **Defensive Invariants:** Strictly simulated/synthetic fixture assessment (`is_simulated = True`). Live network probes, raw socket scans, and active exploitation are disabled by design.

---

## 4. Emergency Kill-Switch & Morph-State Control

When an operational disruption or unauthorized scanning anomaly occurs:

### 4.1 Activate Emergency Kill-Switch
```bash
curl -X POST https://vapt-api.internal/api/v1/projects/{project_id}/morph-state/emergency-kill-switch \
  -H "Authorization: Bearer $SECURITY_LEAD_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"reason": "Observed scope boundary discrepancy during active assessment"}'
```
**Effect:**
- Transitions project morph state immediately to `EMERGENCY_HALT`.
- Aborts all active and queued assessment jobs for the project.
- Terminates running worker subprocesses.
- Emits immutable `EMERGENCY_KILL_SWITCH_ENGAGED` audit record.

---

## 5. Security Header Enforcement & Cache Governance

The control plane automatically injects hardened HTTP headers on every response:
- `Content-Security-Policy`: Disallows unauthorized origins and frame embedding (`frame-ancestors 'none'`).
- `X-Frame-Options`: `DENY` prevents clickjacking attacks.
- `X-Content-Type-Options`: `nosniff` prevents MIME-type confusion attacks.
- `Strict-Transport-Security`: `max-age=31536000; includeSubDomains; preload` enforces TLS transport in production.
- `Cache-Control`: `no-store, no-cache, must-revalidate, max-age=0` prevents intermediate proxies or browser history from caching sensitive VAPT vulnerability findings and credentials.
