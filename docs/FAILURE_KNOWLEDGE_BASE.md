# Failure Knowledge Base & Diagnostic Catalog

## 1. Overview & Architectural Principles

The **Failure Knowledge Base** (`FailureKnowledgeBase`) provides a deterministic, structured catalog mapping observed operational symptoms, telemetry anomalies, and scanner failures to causal hypotheses, safe next steps, validated recovery mappings, and verification procedures.

### Core Design Principles:
1. **Hypothesis Separation:** Explanations for unconfirmed causes are explicitly tagged with `[Hypothesis]` to prevent operational teams from confusing a working theory with verified root cause.
2. **Deterministic Rules First:** Grounded in programmatic telemetry (status codes, timeouts, query outcomes, and hash checks). Machine learning or language model integrations treat this catalog as authoritative ground truth.
3. **No Automated Overreach:** The presence of a known signature does not grant the platform permission to alter policies or bypass human authorization gates.
4. **Actionable Verification:** Every entry defines a post-recovery verification procedure to objectively confirm whether recovery resolved the anomaly.

---

## 2. Failure Signature Catalog

### 2.1. Assessment & Background Worker Failures

#### `FAIL_JOB_STUCK_RUNNING` — Assessment Job Stuck in Running State
- **Category:** `JOBS`
- **Severity:** `HIGH`
- **Confidence:** `CONFIRMED`
- **Detection Condition:** Assessment job has been in `RUNNING` status for > 15 minutes without progress or heartbeat update.
- **Likely Causes:**
  - `[Hypothesis]` Scanner subprocess hung on network socket read or host TCP connect timeout.
  - `[Hypothesis]` Host machine terminated the worker process unexpectedly (OOM killer or system reboot).
  - `[Hypothesis]` Worker crashed without executing database state machine teardown handler.
- **Supporting Evidence:** Job ID, target URL/IP, adapter name, elapsed time since `started_at`.
- **Safe Next Steps:** Inspect worker logs; execute controlled job cancellation to release concurrency quota.
- **Recovery Action:** `RECOVER_STUCK_JOB`
- **Required Role:** `LEAD`
- **Verification Procedure:** Query job status to confirm transition to `CANCELLED` and verify project concurrency count is decremented.

#### `FAIL_JOB_STUCK_QUEUED` — Assessment Job Starved in Queued State
- **Category:** `JOBS`
- **Severity:** `MEDIUM`
- **Confidence:** `CONFIRMED`
- **Detection Condition:** Assessment job has remained in `QUEUED` status for > 30 minutes without worker pickup.
- **Likely Causes:**
  - `[Hypothesis]` Background worker queue polling loop is inactive or crashed.
  - `[Hypothesis]` Project maximum concurrency limit is saturated by longer-running jobs.
  - `[Hypothesis]` Worker execution budget has been exhausted for the 24-hour window.
- **Supporting Evidence:** Job creation timestamp, project policy concurrency setting, active worker status.
- **Safe Next Steps:** Check background worker process liveness; evaluate active jobs or cancel starved job.
- **Recovery Action:** `RECOVER_STUCK_JOB`
- **Required Role:** `LEAD`
- **Verification Procedure:** Verify worker queue processing resumes or job is safely terminated.

---

### 2.2. Database & Storage Failures

#### `FAIL_DB_MIGRATION_MISMATCH` — Database Schema Revision Outdated
- **Category:** `DATABASE`
- **Severity:** `CRITICAL`
- **Confidence:** `CONFIRMED`
- **Detection Condition:** Database `alembic_version` does not match current repository head revision (`a8b9c0d1e2f3`).
- **Likely Causes:**
  - `[Hypothesis]` `alembic upgrade head` was not executed after code deployment.
  - `[Hypothesis]` Application instance pointed to an unmigrated staging or ephemeral database.
- **Supporting Evidence:** Active database `alembic_version` vs expected repository head.
- **Safe Next Steps:** Halt non-essential writes; execute database migration toolchain (`alembic upgrade head`).
- **Recovery Action:** None (Manual deployment toolchain required).
- **Required Role:** `ADMIN`
- **Verification Procedure:** Check `alembic current` confirms active head revision.

#### `FAIL_BACKUP_STALE` — Disaster Recovery Backup Overdue
- **Category:** `BACKUP`
- **Severity:** `HIGH`
- **Confidence:** `CONFIRMED`
- **Detection Condition:** No verified database backup exists within the last 24 hours.
- **Likely Causes:**
  - `[Hypothesis]` Scheduled backup cron job failed or was disabled in the host environment.
  - `[Hypothesis]` Storage disk volume ran out of space during backup generation.
- **Supporting Evidence:** Latest backup timestamp in `./data/backups/`, disk storage metrics.
- **Safe Next Steps:** Trigger non-blocking online database backup and run isolated restore sandbox test.
- **Recovery Action:** `TRIGGER_BACKUP`
- **Required Role:** `LEAD`
- **Verification Procedure:** Confirm new `.db` file exists with valid SHA-256 and disposable sandbox restore passes.

---

### 2.3. Evidence & Finding State Inconsistencies

#### `FAIL_EVIDENCE_ORPHANED` — Finding Evidence Missing Valid Association
- **Category:** `EVIDENCE`
- **Severity:** `MEDIUM`
- **Confidence:** `CONFIRMED`
- **Detection Condition:** `FindingEvidence` records exist whose `finding_id` does not correspond to an active finding.
- **Likely Causes:**
  - `[Hypothesis]` An interrupted scanner batch committed partial evidence without parent finding.
  - `[Hypothesis]` Unsynchronized test fixture cleanups in development environments.
- **Supporting Evidence:** List of orphaned evidence IDs, hashes, and foreign key references.
- **Safe Next Steps:** Run asset reconciliation to re-link evidence or archive unassociated artifacts.
- **Recovery Action:** `REBUILD_KNOWLEDGE_GRAPH`
- **Required Role:** `ADMIN`
- **Verification Procedure:** Verify evidence records are properly associated with valid finding fingerprints.

#### `FAIL_FINDING_STATE_INCONSISTENT` — Finding Closed Without Independent Verification
- **Category:** `FINDINGS`
- **Severity:** `HIGH`
- **Confidence:** `CONFIRMED`
- **Detection Condition:** Finding marked `VERIFIED_CLOSED` without an associated `VERIFIED_FIXED` retest record.
- **Likely Causes:**
  - `[Hypothesis]` Direct database update bypassed finding lifecycle state machine.
  - `[Hypothesis]` Legacy database record imported prior to independent verification gate enforcement.
- **Supporting Evidence:** Finding IDs, status history, missing `RemediationVerification` reference.
- **Safe Next Steps:** Trigger independent retest to validate target posture, or revert status to `CONFIRMED`.
- **Recovery Action:** `RETEST_REMEDIATION`
- **Required Role:** `LEAD`
- **Verification Procedure:** Confirm finding is accompanied by an empirical `RemediationVerification` record.

---

### 2.4. Policy & Notification Failures

#### `FAIL_POLICY_KILL_SWITCH_ACTIVE` — Autonomous Operations Suspended via Kill Switch
- **Category:** `SECURITY`
- **Severity:** `HIGH`
- **Confidence:** `CONFIRMED`
- **Detection Condition:** Project policy has `is_suspended=True`, halting all assessment and remediation dispatch.
- **Likely Causes:**
  - `[Hypothesis]` Lead operator manually triggered emergency suspension kill switch.
  - `[Hypothesis]` Automated failure threshold (3 consecutive job failures) triggered auto-suspension.
- **Supporting Evidence:** Suspension timestamp, suspending actor ID, suspension reason from `AutonomousPolicyRecord`.
- **Safe Next Steps:** Investigate root cause of failures; submit formal resumption request with operator notes.
- **Recovery Action:** `RESUME_MONITORING`
- **Required Role:** `LEAD`
- **Verification Procedure:** Verify policy `is_suspended` is `False` and decision ledger records `AUTONOMY_RESUMED`.

#### `FAIL_NOTIFICATION_DELIVERY` — Notification Delivery Failure Accumulated
- **Category:** `NOTIFICATIONS`
- **Severity:** `MEDIUM`
- **Confidence:** `CONFIRMED`
- **Detection Condition:** Alert notification delivery has failed or delivery attempts have exhausted.
- **Likely Causes:**
  - `[Hypothesis]` External SMTP mail server connection refused or timed out.
  - `[Hypothesis]` Destination alert webhook returned HTTP 5xx or rate-limited the payload.
- **Supporting Evidence:** Notification ID, event type, delivery attempts, sanitized error message.
- **Safe Next Steps:** Verify webhook/mail server accessibility; requeue notification if transient.
- **Recovery Action:** `REQUEUE_NOTIFICATION`
- **Required Role:** `LEAD`
- **Verification Procedure:** Verify delivery attempt increments and provider returns success acknowledgement.

---

## 3. Querying the Knowledge Base

### Via REST API:
```http
GET /api/v1/diagnostics/knowledge-base
Authorization: Bearer <user_token>
```
Returns complete failure dictionary with categories, severities, hypotheses, and safe next steps.
