# Fault Injection, Graceful Degradation and Recovery Management Matrix

## 1. Executive Summary & Objective

The **VAPT System Fault Injection and Resilience Framework** (Prompt 52) provides rigorous, empirical verification that the security control plane remains safe, understandable, and resilient when databases, worker subprocesses, scanner adapters, external providers, background tasks, and host storage fail.

### Key Resilience Guarantees
1. **Zero Secret Leakage:** Health endpoints, diagnostic dumps, and failure responses strictly sanitize credentials, tokens, and internal database passwords.
2. **Critical Evidence Preservation:** Ingestion failures in secondary services (e.g. webhook delivery, threat intelligence enrichment, graph synchronization) never roll back or discard primary vulnerability findings, raw evidence hashes, or tamper-proof audit trails.
3. **Fail-Closed Security Boundaries:** Fault injection hooks are strictly disabled and structurally blocked in production and staging environments (`FaultInjectionSecurityError`). Automatic recovery mechanisms are strictly prohibited from weakening scope boundaries, bypassing authorization, or self-approving remediation changes.
4. **Truthful Status Reporting:** Incomplete work, partial execution sweeps, and interrupted background tasks are reported honestly as `PARTIAL` or `FAILED`, and never disguised as clean 100% completion.

---

## 2. Critical Capability Dependencies & Degradation Taxonomy

The platform formally separates **Critical Core Capabilities** (which fail-closed or report HTTP 503 if unavailable) from **Secondary Integrations** (which degrade gracefully while core operations proceed):

| Capability | Criticality | Dependencies | Degradation Behavior | Fail-Closed Guard |
| :--- | :--- | :--- | :--- | :--- |
| **Authentication & RBAC** | `CRITICAL` | Primary Database (`users`), Cryptographic Secret Key | HTTP 401/403/503. Never bypasses authentication or defaults to unauthenticated access. | Yes |
| **Scope & Execution Boundary Governance** | `CRITICAL` | Primary Database (`scope_targets`, `scope_exclusions`) | Fail-closed. Rejects any scan dispatch if target authorization cannot be independently verified. | Yes |
| **Assessment Execution & Worker Supervision** | `CRITICAL` | Worker Subprocess Isolation, Scanner Adapters, Primary Database | Enforces execution deadlines. Stalled workers recovered via supervisory heartbeats; jobs marked `FAILED`, `TIMED_OUT`, or `PARTIAL`. | Yes |
| **Forensic Evidence & Audit Preservation** | `CRITICAL` | Primary Database, Local Storage (`data/evidence`), Ed25519 Origin Signer | Ingestion rolls back corrupt DB transactions without writing bad data; disk I/O errors trigger operator alerts without discarding database findings. | Yes |
| **Remediation Approval Governance** | `CRITICAL` | Primary Database, Project Governance Policy | Fail-closed. Automatic recovery cannot authorize changes, self-approve proposals, or bypass Separation of Duties. | Yes |
| **Notification & Outbound Dispatch** | `SECONDARY` | External Webhook Endpoints, SMTP Relay | Graceful degradation. Delivery failures recorded as `FAILED` with sliding-window deduplication and bounded retries. Core findings committed without delay. | No |
| **Threat Intelligence Feed Enrichment** | `SECONDARY` | CISA KEV, NVD CVE, EPSS Feeds | Graceful degradation. Feed sync errors mark feed status as `ERROR`/`DEGRADED`; existing finding severity and evidence remain intact. | No |
| **Analytics & Knowledge Graph** | `SECONDARY` | Background Reconciliation Workers | Graceful degradation. Analytical drift warnings logged; does not impede assessment execution. | No |

---

## 3. Injected Fault Scenarios & Verification Matrix

The system implements 7 deterministic, test-only fault injection hooks governed by `FaultInjector`:

| Scenario | Fault Type & Trigger Point | Injected Failure Condition | System Response & Self-Healing Outcome | Evidence & Audit Preservation |
| :--- | :--- | :--- | :--- | :--- |
| **1. Database Interruption** | `DATABASE_INTERRUPTION`<br>`db:commit:findings` | Connection dropped during finding persistence transaction | Transaction rolled back cleanly via `db.begin_nested()`; job marked `FAILED` (`INGESTION_TRANSACTION_FAILED`). | Zero orphaned or corrupted finding rows written to database. |
| **2. Worker Termination** | `WORKER_TERMINATION`<br>`worker:termination` | Abrupt worker crash / SIGKILL / OOM before state teardown | Heartbeat left stale in `RUNNING` status; supervisory `recover_abandoned_jobs` transitions job to `FAILED` (`ABANDONED_EXECUTION_RECOVERED`). | Concurrency slot reclaimed cleanly; audit event recorded. |
| **3. Adapter Timeout** | `ADAPTER_TIMEOUT`<br>`adapter:timeout` | Scanner adapter socket read hang or deadline exceeded | Subprocess terminated via Win32 Job Object / `taskkill`; job transitioned to `TIMED_OUT` (`WORKER_PROCESS_TIMEOUT`). | Process tree fully terminated; timeout logged with elapsed duration. |
| **4. Provider Outage** | `PROVIDER_OUTAGE`<br>`provider:webhook` / `secondary:asset_graph` | Webhook receiver or threat intelligence feed returns HTTP 503 | Notification marked `FAILED` and scheduled for bounded retry; secondary asset/graph error logged in `summary_stats["secondary_degradations"]`. | Primary vulnerability findings, evidence hashes, and audit logs are 100% committed. |
| **5. Disk Write I/O Failure** | `DISK_WRITE_FAILURE`<br>`disk:write` | Operating system returns `IOError [Errno 28] No space left on device` | Exception caught; `DiskWriteFailureError` raised; system readiness probe reports `storage_writable=False`. | Database state remains uncorrupted; no partial files left in storage. |
| **6. Malformed Response** | `MALFORMED_RESPONSE`<br>`adapter:execute` / `worker:ipc_response` | Worker returns truncated, corrupt, or non-JSON output | Execution boundary validation rejects payload; job marked `FAILED` (`CORRUPT_IPC_RESPONSE`). | Corrupt payload rejected before database insertion. |
| **7. Interrupted Batch Tasks** | `INTERRUPTED_BACKGROUND_TASK`<br>`background:task` | Operator preemption or cancellation during multi-target sweep | Sweep halts safely; completed targets saved; overall job status marked `PARTIAL` (`PARTIAL_MODULE_FAILURE`). | Truthful reporting: completed targets vs failed targets recorded honestly in `summary_stats`. |

---

## 4. Idempotency, Retry Budgets & Backoff Calculation

To prevent retry storms, infinite loops, and duplicate resources:

### Idempotency Protection
- **Assessment Jobs:** Each job carries an `idempotency_key` and SHA-256 `idempotency_digest`. Submitting a duplicate request with the identical key and payload returns the existing job (`HTTP 200`). Submitting a conflicting payload with an existing key rejects with `HTTP 409 Conflict`.
- **Active Job Guard:** Calling retry on a job that is already `QUEUED`, `PREFLIGHT`, or `RUNNING` is strictly rejected to prevent duplicate execution against the same target.
- **Notification Dedup Guard:** Sliding 1-hour cryptographic deduplication window (`project_id:event_type:target:title`) suppresses duplicate notifications and records them as `SUPPRESSED_DUPLICATE`.

### Bounded Retry Budgets
- **Maximum Retries:** Default `max_retries = 3`. Once attempt count reaches `max_retries`, further automatic or diagnostic retries are rejected with `MAX_RETRIES_EXHAUSTED`.
- **Exponential Backoff with Jitter:**
  $$\text{exponential} = \min(\text{max\_delay}, \text{base\_delay} \times 2^{\text{attempt} - 1})$$
  $$\text{delay} = \text{uniform}(0.5 \times \text{exponential}, \text{exponential})$$
  Where `base_delay = 2.0s` and `max_delay = 60.0s`.

---

## 5. Failure Classification & Operator Recovery Matrix

The platform classifies operational failures into automated self-healing vs. manual intervention playbooks:

```
+---------------------------------------------------------------------------------------------------+
|                                  OPERATIONAL FAILURE CLASSIFICATION                               |
+---------------------------------------------------------------------------------------------------+
| Failure Code                  | Severity | Auto-Recoverable? | Action / Playbook                  |
+-------------------------------+----------+-------------------+------------------------------------+
| DB_CONNECTION_INTERRUPTED     | CRITICAL | YES (Auto)        | Connection pool reconnect & retry  |
| WORKER_ABRUPT_TERMINATION     | HIGH     | YES (Auto)        | recover_abandoned_jobs reclamation |
| ADAPTER_EXECUTION_TIMEOUT     | MEDIUM   | YES (Auto)        | Process tree kill & TIMED_OUT      |
| SECONDARY_WEBHOOK_OUTAGE      | LOW      | YES (Auto)        | Bounded retry with backoff (max 3) |
| EVIDENCE_DISK_WRITE_IO_ERROR  | CRITICAL | NO (Manual)       | Inspect free space & permissions   |
| MALFORMED_SCANNER_PAYLOAD     | HIGH     | NO (Manual)       | Inspect stderr & parser format     |
| BACKGROUND_BATCH_INTERRUPTED  | MEDIUM   | YES (Auto)        | Truthful PARTIAL status reporting  |
| GOVERNANCE_SCOPE_DENIAL       | HIGH     | NO (Manual)       | Scope authorization review by Lead |
| SCHEMA_MIGRATION_MISMATCH     | CRITICAL | NO (Manual)       | alembic upgrade head               |
+-------------------------------+----------+-------------------+------------------------------------+
```

### Manual Intervention Playbooks

#### Playbook 1: Storage Volume Exhaustion (`EVIDENCE_DISK_WRITE_IO_ERROR`)
1. **Diagnosis:** Run `df -h` (Linux) or check drive properties (Windows) for the storage volume backing `./data/evidence`.
2. **Remediation:** Clean up temporary test archives or expand storage partition.
3. **Verification:** Query `GET /api/v1/health/ready` and confirm `storage_writable=True` and `evidence_writable=True`.

#### Playbook 2: Scope Revocation Denial (`GOVERNANCE_SCOPE_DENIAL`)
1. **Diagnosis:** Target input matches an active `ScopeExclusion` or target authorization has expired.
2. **Remediation:** If legitimate target, Project Security Lead must update the Scope Target with documented proof of authorization.
3. **Verification:** Invariant: Automatic recovery CANNOT override or weaken scope boundaries.

#### Playbook 3: Schema Outdated (`SCHEMA_MIGRATION_MISMATCH`)
1. **Diagnosis:** Database `alembic_version` does not match current repository head (`51a0b1c2d3e4`).
2. **Remediation:** Run `alembic upgrade head` in the backend environment.
3. **Verification:** Confirm `GET /api/v1/health/ready` returns `migrations=True`.

---

## 6. Health Probes Separation & Zero Secret Leakage

The platform exposes 4 distinct, non-conflicting health probes:

```
[ HTTP Client / Ingress Controller / Monitoring ]
        |
        +---> /health/live        (Liveness: Lightweight loop check, no DB query)
        +---> /health/ready       (Readiness: DB connectivity, schema, disk writability)
        +---> /health/dependencies(Deep probe: Critical vs optional integrations)
        +---> /health/degradation (Operator status: Degraded capabilities & playbooks)
```

- **Zero Secret Leakage Guarantee:** All responses scrub passwords, secret keys, access tokens, and internal connection strings, preventing accidental reconnaissance by attackers or log aggregators.
