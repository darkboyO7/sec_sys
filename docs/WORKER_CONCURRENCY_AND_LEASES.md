# Worker Concurrency, Background Job Leases, and Fencing Tokens

## 1. Overview
The VAPT platform executes security assessments asynchronously via background worker processes. Because assessment jobs can involve network reconnaissance, port fingerprinting, or passive traffic analysis, worker execution spans seconds to minutes.

To prevent race conditions, duplicate execution, lost worker updates, and zombie worker overwrites, the platform employs:
1. **Atomic Job Claiming**
2. **Heartbeat-Monitored Worker Leases**
3. **Bounded Retries with Exponential Backoff and Jitter**
4. **Fencing Tokens & Attempt Versioning**
5. **Operator Cancellation Safety**

---

## 2. Background Job Lifecycle & State Machine

```
              ┌───────────────┐
              │    QUEUED     │
              └───────┬───────┘
                      │ Atomic Claim (Worker A)
                      ▼
              ┌───────────────┐
              │   PREFLIGHT   │
              └───────┬───────┘
                      │ Capability & Scope Validation
                      ▼
              ┌───────────────┐
              │     READY     │
              └───────┬───────┘
                      │ Worker Process Spawned
                      ▼
              ┌───────────────┐
       ┌─────►│    RUNNING    │◄────────┐
       │      └───────┬───────┘         │
Heartbeat             │                 │ Heartbeat
Absence               │ Outcome         │ Refreshed
       │              ▼                 │
       │      ┌───────────────┐         │
       └──────┤   COMPLETED   │─────────┘
              └───────────────┘
```

Terminal states: `COMPLETED`, `FAILED`, `CANCELLED`, `REJECTED`, `TIMED_OUT`. Terminal states are immutable and cannot be transitioned back to active states.

---

## 3. Atomic Job Claiming Mechanics

### 3.1 SQLite Atomic Conditional Update
Under SQLite, background worker processes or threads compete to claim the next available `QUEUED` job. Atomic claim serialization is guaranteed by combining an ordering query with a conditional update matching the target ID and initial state:

```python
rows = db.query(AssessmentJob).filter(
    AssessmentJob.id == candidate.id,
    AssessmentJob.status == AssessmentStatus.QUEUED,
).update(
    {
        AssessmentJob.status: AssessmentStatus.PREFLIGHT,
        AssessmentJob.claimed_by: worker_id,
        AssessmentJob.preflight_at: now,
        AssessmentJob.progress_pct: 10,
    },
    synchronize_session="fetch",
)
db.commit()
if rows > 0:
    return candidate  # Claim secured
return None  # Claim lost to concurrent worker
```

**Guarantee**: Verified by Test Scenario 1. When two workers simultaneously claim a job, exactly one worker updates the row and receives the job; the second worker receives `None` and proceeds to the next candidate.

### 3.2 PostgreSQL Skip-Locked Queue
Under PostgreSQL, the engine switches to native non-blocking row-level lock acquisition:

```sql
SELECT * FROM assessment_jobs
WHERE status = 'QUEUED'
ORDER BY created_at ASC
FOR UPDATE SKIP LOCKED
LIMIT 1;
```

Workers concurrently claim jobs with zero lock contention, eliminating queue bottlenecks.

---

## 4. Fencing Tokens & Attempt Counter Invariant

A classic distributed systems hazard occurs when a worker appears dead (e.g. CPU stall, GC pause, network partition), loses its lease, and is re-queued or reclaimed by another worker. If the zombie worker suddenly awakens and finishes, it might write obsolete results over the newer attempt.

### 4.1 Fencing Token Check Implementation
Every job execution attempt increments `attempt_count` and updates `claimed_by`. Before writing final execution results, the worker must pass a fencing token check querying the live database (`AssessmentExecutionEngine.execute_job`):

```python
fresh_job = db.query(AssessmentJob).filter(AssessmentJob.id == job.id).first()

if not fresh_job or \
   fresh_job.status != AssessmentStatus.RUNNING or \
   fresh_job.attempt_count != execution_attempt or \
   (fresh_job.claimed_by and fresh_job.claimed_by != worker_id):
    logger.warning(
        f"Fencing token check failed for worker '{worker_id}' attempt {execution_attempt}: "
        f"Job '{job.id}' status is '{fresh_job.status if fresh_job else 'DELETED'}' "
        f"claimed by '{fresh_job.claimed_by if fresh_job else None}'. Obsolete worker result discarded."
    )
    return fresh_job or job
```

**Guarantee**: Verified by Test Scenario 5. An obsolete worker result cannot overwrite a newer attempt or corrupt a re-queued job.

---

## 5. Worker Lease Monitoring & Stale Worker Recovery

Background workers periodically emit heartbeats updating `heartbeat_at` on the `AssessmentJob` record.

### 5.1 Recovery Algorithm (`recover_stale_workers`)
The supervisor scans for jobs in `PREFLIGHT` or `RUNNING` whose last activity timestamp exceeds `heartbeat_timeout_seconds` (default: 120s):

1. **If `attempt_count < max_retries`**:
   - Calculates exponential backoff delay with uniform random jitter:
     $$T_{\text{delay}} = \min(T_{\text{max}}, T_{\text{base}} \times 2^{\text{attempt}} + \text{jitter})$$
   - Increments `attempt_count` (generating a new fencing token).
   - Clears `claimed_by` and `worker_pid`.
   - Re-queues job to `AssessmentStatus.QUEUED`.
   - Logs `ASSESSMENT_STALE_WORKER_RECOVERED` in the immutable audit ledger.

2. **If `attempt_count >= max_retries`**:
   - Transitions job to terminal `AssessmentStatus.FAILED`.
   - Sets `failure_category = "WORKER_HEARTBEAT_TIMEOUT"`.
   - Logs `ASSESSMENT_STALE_WORKER_FAILED` audit event.

---

## 6. Operator Cancellation Safety

When a security lead or operator cancels an active assessment:
1. `AssessmentExecutionEngine.cancel_job` transitions the job to `AssessmentStatus.CANCELLED` and sets `cancellation_requested_at = now`.
2. Active worker runners inspect `check_cancellation()` before and during execution.
3. If a worker finishes execution concurrently with cancellation, Step 7's fencing check observes `fresh_job.status == CANCELLED` and rejects the completion.
4. **Guarantee**: Verified by Test Scenario 11. The job permanently remains in the `CANCELLED` terminal state.
