# Distributed Worker and Scalability Architecture Guide
**Platform:** VAPT Security Operations Platform  
**Version:** Enterprise Infrastructure Release (Prompts 53–57)  
**Status:** Certified Architecture & Tested Implementation  
**Date:** October 31, 2026  

---

## 1. Executive Summary
The VAPT Security Operations Platform implements a hybrid execution architecture that decouples job scheduling, preflight authorization, and lifecycle management from the execution engine. The platform natively supports both local Windows subprocess worker execution and distributed remote worker clusters without requiring Kubernetes, cloud vendor lock-in, or third-party infrastructure for local development.

---

## 2. Core Architecture & Interface Abstraction

```
+--------------------------------------------------------------------------------+
|                        FastAPI Core Orchestration API                          |
|         (Tenant Boundary, SoD Authorization, Immutable Scope Signing)          |
+--------------------------------------------------------------------------------+
                                       |
                                       v
                     +-----------------------------------+
                     |    BaseWorkerExecutionEngine      |
                     |  (execution_interface.py)         |
                     +-----------------------------------+
                                       |
                   +-------------------+-------------------+
                   |                                       |
                   v                                       v
    +-----------------------------+        +-------------------------------+
    | LocalSubprocessWorkerEngine |        |   DistributedWorkerEngine     |
    | (Windows Native Runner)     |        |   (Cluster Nodes / Broker)    |
    |  - Win32 Job Objects        |        |  - HMAC-SHA256 Node Auth      |
    |  - Process Tree Termination |        |  - SKIP LOCKED Atomic Claim   |
    |  - Stripped Environment     |        |  - Periodic Heartbeat Lease   |
    |  - 10MB Payload Guard       |        |  - Dead-Letter Queue (DLQ)    |
    +-----------------------------+        +-------------------------------+
```

### 2.1 The Execution Engine Contract
Defined in `app.worker.execution_interface.BaseWorkerExecutionEngine`:
1. `claim_job(worker_id, capabilities, db)`: Atomically acquires an unassigned `QUEUED` job.
2. `execute_job(request, cancellation_check, on_spawn)`: Dispatches the isolated execution payload.
3. `heartbeat(worker_id, active_job_ids, db)`: Renews active lease and retrieves pending cancellation commands.
4. `cancel_job(job_id, reason, db)`: Aborts in-flight execution and reclaims slots.
5. `report_outcome(job_id, worker_id, result, db)`: Finalizes normalized findings and evidence.
6. `get_worker_health()`: Exposes engine health, active concurrency, and diagnostics.

---

## 3. Worker Node Lifecycle & Security Controls

### 3.1 Authenticated Registration (Fail Closed)
- Distributed workers must register with `POST /api/v1/workers/register` using an HMAC-SHA256 authentication token derived from `WORKER_REGISTRATION_SECRET` or `SECRET_KEY`.
- Unauthenticated or tampered registrations are immediately rejected with HTTP 401 (`WorkerAuthenticationError`).
- Successfully registered nodes receive an ephemeral session token required for all subsequent heartbeats and outcome reporting.

### 3.2 Heartbeat Monitoring & Lease Scavenging
- Active workers send heartbeats every `WORKER_HEARTBEAT_INTERVAL_SECONDS` (default: 10s).
- If a worker misses heartbeats exceeding `WORKER_HEARTBEAT_TIMEOUT_SECONDS` (default: 30s), it is marked `WorkerStatus.DEAD`.
- Active jobs associated with dead workers are reclaimed by `worker_registry.reclaim_stale_leases`:
  - **Retryable Jobs (`retry_count < max_retries`):** Increments `retry_count`, resets status to `QUEUED`, and clears the worker claim.
  - **Exhausted Jobs (`retry_count >= max_retries`):** Routed to the Dead-Letter Queue (`AssessmentStatus.DEAD_LETTER`).

### 3.3 Zero-Secret Worker Boundary
Under both local subprocess and distributed execution:
- Workers **never receive database connection strings (`DATABASE_URL`)**, JWT signing keys (`SECRET_KEY`), or cloud provider credentials.
- The execution environment is strictly sanitized via `build_sanitized_env()` allowing only safe OS system variables (`PATH`, `SYSTEMROOT`, `TEMP`).
- Workers operate exclusively on signed `WorkerIPCRequest` payloads containing target inputs, scanner configurations, and the immutable scope snapshot digest.

---

## 4. Poison-Pill Resilience & Dead-Letter Handling (DLQ)

When an assessment payload repeatedly crashes a worker process or exceeds retry budgets:
1. **Transition to DEAD_LETTER:** The state machine transitions the job to `DEAD_LETTER`, persisting the failure reason, stack trace, and timestamp.
2. **Crash Loop Prevention:** Dead-lettered jobs are excluded from the active queue and will never be picked up by automated worker claims.
3. **Operator Inspection & Replay:** Operators can review quarantined jobs via `GET /api/v1/workers/dead-letter` and re-queue them for execution via `POST /api/v1/workers/dead-letter/{job_id}/replay` once patched.

---

## 5. Capacity Management & Backpressure Architecture

Managed by `app.services.capacity_management_service.CapacityManagementService`:

### 5.1 Concurrency & Queue Depth Controls
- `max_global_concurrency`: Global ceiling on active concurrent jobs across the platform (default: 8).
- `max_project_concurrency`: Per-tenant ceiling preventing one project from monopolizing the execution pool (default: 4).
- `max_queue_depth`: Maximum number of pending jobs in queue before backpressure is triggered (default: 50).
- Limits can be dynamically adjusted by Administrators via `PUT /api/v1/system/capacity/limits` without downtime.

### 5.2 Workload Prioritization
Jobs carry an explicit priority level:
1. `CRITICAL`: Active incident investigation, zero-day verification. Granted burst headroom above standard project concurrency limits.
2. `HIGH`: CI/CD blocking release gates and pre-deployment scans.
3. `NORMAL`: Standard scheduled scans.
4. `LOW`: Non-blocking retests.
5. `BACKGROUND`: Continuous asset discovery and passive sweeps.

### 5.3 Backpressure (HTTP 429)
When queue depth exceeds configured bounds, `check_admission` raises `CapacityOverloadError`, returning HTTP 429 (Too Many Requests) with a standard `Retry-After: 15` header.

---

## 6. Verification and Test Results
- **Engine Factory Verification:** Local engine resolves seamlessly; distributed engine operates without requiring external broker installation.
- **Worker Authentication:** Verified rejection of rogue nodes and valid registration of authenticated nodes.
- **Atomic Fencing:** Verified that concurrent worker claims on the same job result in exactly one successful claim.
- **Lease Scavenging & DLQ:** Verified that crashed workers are detected, retryable jobs re-queued, and repeatedly failing jobs quarantined in DLQ.
- **Backpressure Enforcement:** Verified HTTP 429 rejection on project concurrency exhaustion and queue saturation.
