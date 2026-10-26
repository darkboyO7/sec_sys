# Subprocess Worker Threat Model & Isolation Architecture

**Component:** VAPT Assessment Engine — Worker Subsystem  
**Scope:** Phase 7A through Phase 7B+  
**Target Environment:** Windows 11 Native Architecture  

---

## 1. System Architecture & Trust Boundaries

The VAPT assessment engine decouples control plane operations (REST API, database persistence, state transitions) from adapter execution by delegating scan tasks to an isolated worker process.

```
+-------------------------------------------------------------------+
|                       CONTROL PLANE                               |
|  FastAPI / SQLAlchemy / SQLite WAL / Audit Ledger / Auth Engine  |
|                                                                   |
|   [SubprocessWorkerRunner]                                        |
|         |                                                         |
|         | 1. Spawn worker with sanitized env (NO SECRETS)         |
|         | 2. Attach to WindowsJobObject (kernel limit & kill)     |
|         | 3. Write WorkerIPCRequest JSON to worker stdin          |
|         | 4. Read WorkerIPCResponse JSON from worker stdout       |
+---------|---------------------------------------------------------+
          |
     IPC STDIN/STDOUT (JSON protocol v1.0.0)
          |
+---------v---------------------------------------------------------+
|                  ISOLATED WORKER PROCESS                          |
|  backend/app/worker/process_worker.py                             |
|                                                                   |
|  - Drops physical stdout during execution (sys.stdout -> stderr)  |
|  - Loads target adapter from restricted AdapterRegistry           |
|  - Executes adapter.run(target_url, config)                       |
|  - Validates results against Pydantic WorkerIPCResponse schema    |
|  - Emits single serialized response frame to physical stdout      |
+-------------------------------------------------------------------+
```

### Trust Boundary Definitions
1. **Control Plane Domain:** Holds cryptographic keys (`SECRET_KEY`), database credentials, user sessions, audit write privileges, and state machine authority.
2. **IPC Pipe Boundary:** Standard input / standard output stream passing strongly typed, bounded JSON messages (`WorkerIPCRequest` and `WorkerIPCResponse`).
3. **Worker Execution Domain:** Subprocess executing untrusted or semi-trusted scanner adapters. Forbidden from direct database access or control-plane secret knowledge.

---

## 2. STRIDE Threat Analysis Matrix

| Threat Category | Specific Attack Vector | Potential Impact | Defensive Control Implemented |
| :--- | :--- | :--- | :--- |
| **Spoofing** | Worker returns response with altered `job_id` or `project_id`. | Cross-tenant data injection; results attributed to wrong assessment. | **Rejection on mismatch:** `SubprocessWorkerRunner` checks response `job_id` and `project_id` against request; mismatches trigger `IPC_IDENTITY_MISMATCH` and discard payload. |
| **Tampering** | Corrupted or malicious adapter injects non-finite floats (NaN, Inf) or massive arrays into results. | JSON deserialization crashes, database integrity violations, or memory exhaustion. | **Defensive schema validators:** Pydantic `mode="before"` validators sanitize NaN/Inf/-ve numbers to `0.0`, clamp string fields, and limit array lengths. |
| **Tampering** | Adapter prints debugging logs to stdout. | JSON stream parsing failure, unhandled EOF, job treated as crashed. | **Stdout Redirection:** `process_worker.py` redirects `sys.stdout` to `sys.stderr` during adapter run; only the final IPC payload is written to real stdout. |
| **Repudiation** | Worker crashes silently without returning an execution log. | Assessment job hangs in `RUNNING` status indefinitely. | **Bounded timeout & exit code capture:** Subprocess runner waits with timeout; non-zero exit code or crash immediately maps to `FAILED` with stderr capture. |
| **Information Disclosure** | Adapter inspects `os.environ` to harvest JWT secret keys, API tokens, or DB paths. | Complete platform compromise via leaked administrator credentials. | **Environment sanitization:** `build_sanitized_env()` strips all environment variables except a minimal whitelist (`PATH`, `SYSTEMROOT`, `PYTHONPATH`, `TEMP`). `SECRET_KEY` and `DATABASE_URL` are strictly omitted. |
| **Denial of Service** | Adapter hangs forever, spawns recursive background child processes (fork bomb), or consumes all memory. | Control plane starvation, resource exhaustion. | **Win32 Job Objects:** Kernel-level job object sets `ActiveProcessLimit = 10` and `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`. Runner terminates entire process tree with `taskkill /F /T /PID`. |
| **Elevation of Privilege** | Adapter executes raw network socket probes or attempts port scanning. | Unauthorized offensive network activity from host. | **Adapter capability allowlisting:** Phase 7B framework enforces non-live synthetic fixtures; raw sockets and network tools are prohibited. |

---

## 3. Invariants & Security Guarantees

1. **Fail-Closed Principle:** Any IPC protocol violation, schema validation failure, timeout, unhandled exception, or PID termination automatically sets the assessment job state to `FAILED`.
2. **Audit Logging:** Every subprocess lifecycle event (spawn, timeout, crash, identity mismatch, completion) is recorded with high-fidelity telemetry in the platform audit log.
3. **No Dynamic Code Injection:** Workers only load registered adapter classes defined in the authoritative `AdapterRegistry`. Arbitrary imports or code strings cannot be passed via the IPC request.
4. **State Machine Exclusivity:** The worker cannot transition the job state directly in the database. Only the control plane's `AssessmentEngine` updates job statuses via verified database transactions.

---

## 4. Isolation Evolution Roadmap

- **Phase 7A/7A.1 (Current):** In-process subprocess separation on Windows, environment scrubbing, Win32 Job Object containment, JSON IPC via stdio.
- **Phase 7B (Next):** Capability-typed adapter contracts and restricted registry.
- **Future Hardening (Tier 2/3):** Dedicated low-privilege Windows service accounts (`LocalService`), Windows AppContainer sandbox, or containerized execution boundaries for high-risk binary scanners.
