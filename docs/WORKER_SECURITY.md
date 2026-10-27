# VAPT Platform — Worker Security & Subprocess Sandboxing

## 1. Overview

The VAPT Platform executes assessment tasks in isolated subprocess workers rather than within the primary web application process. This document specifies the operating-system-level sandbox controls, process isolation boundaries, IPC security protocols, and memory governors implemented for Windows 11 environments.

---

## 2. Windows Worker Process Architecture

```
┌────────────────────────────────────────────────────────┐
│             FastAPI Web Application Process            │
│  - Database Connection Pool (SQLite/PostgreSQL)        │
│  - JWT Authentication & RBAC Verification              │
│  - SubprocessWorkerRunner Execution Manager            │
└──────────────────────────┬─────────────────────────────┘
                           │
             1. Sanitize Environment Variables
             2. Generate Ephemeral IPC Auth Token
             3. Spawn Worker Process
             4. Attach to Windows Job Object
                           │
                           ▼
┌────────────────────────────────────────────────────────┐
│            Isolated Worker Subprocess (Python)         │
│  - ProcessWorker CLI                                   │
│  - Native Windows Job Object:                          │
│      * Process Memory Limit: 512 MB                    │
│      * Job Memory Limit: 1024 MB                       │
│      * Kill-On-Job-Close: True                         │
│  - Communicates via stdin / stdout JSON-RPC            │
│  - ZERO direct database connectivity                   │
│  - ZERO unredacted system environment secrets          │
└────────────────────────────────────────────────────────┘
```

---

## 3. Windows Job Object Sandboxing

On Windows platforms, `SubprocessWorkerRunner` utilizes the Win32 Job Object API (via Python `ctypes`) to enforce strict resource governance:

### 3.1. Implemented Job Object Limits
1. **`JOB_OBJECT_LIMIT_PROCESS_MEMORY`**:
   - Caps physical commit memory per worker process to **512 MB**.
   - If an adapter attempts to allocate memory beyond this threshold, the OS immediately denies the allocation, triggering a controlled memory error rather than exhausting host RAM.
2. **`JOB_OBJECT_LIMIT_JOB_MEMORY`**:
   - Caps aggregate memory across the worker and any spawned subprocesses to **1024 MB**.
3. **`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`**:
   - Guarantees that if the parent runner process crashes or exits, all worker child processes are immediately and atomically terminated by the Windows kernel, preventing orphaned background processes.

---

## 4. Environment Sanitization & Secret Isolation

When spawning a worker subprocess, the runner **never** inherits the parent process's environment variables directly:
- **Purged Variables**: `SECRET_KEY`, `DATABASE_URL`, `POSTGRES_PASSWORD`, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AZURE_CLIENT_SECRET`, `GITHUB_TOKEN`, and all custom authorization headers.
- **Allowed Variables**: Minimal runtime paths required for the Python interpreter (`SYSTEMROOT`, `PATH`, `PYTHONPATH`, `TEMP`, `TMP`).
- **Database Boundary**: Worker processes do not receive database credentials, connection strings, or ORM sessions. They receive only the JSON assessment parameters and return structured JSON results via IPC pipes.

---

## 5. IPC Protocol & Ephemeral Authentication

### 5.1. Protocol Schema
Communication between the control plane and worker occurs over standard input/output (`stdin`/`stdout`) using strongly-typed JSON-RPC schemas defined in `app/worker/ipc_schemas.py`:
- `WorkerRequest`: Contains `request_id`, `command` (`EXECUTE_ASSESSMENT`, `PING`, `SHUTDOWN`), `auth_token`, and `payload`.
- `WorkerResponse`: Contains `request_id`, `status` (`OK`, `ERROR`), `payload`, and `error`.

### 5.2. Ephemeral Authentication Token
1. Before spawning a worker, the runner generates a cryptographically secure 256-bit random token (`secrets.token_hex(32)`).
2. The token is passed to the worker via standard input in the initial handshake message.
3. Every subsequent command sent to the worker must supply this identical token.
4. Any command received with an invalid or missing token causes the worker to fail closed and immediately terminate with exit code 401.

### 5.3. Payload Boundary Protection
- `WORKER_MAX_IPC_PAYLOAD_BYTES`: 10,485,760 bytes (10 MB).
- Messages exceeding 10 MB are rejected at the IPC transport layer to prevent buffer overflow attacks or memory exhaustion.

---

## 6. Process Lifecycle & Error Governance

1. **Graceful Timeout Enforcement**:
   - If an assessment exceeds the configured timeout budget (default: 180 seconds), the runner initiates graceful cancellation.
   - If the worker does not exit within the 5-second grace period, `runner.terminate()` invokes Win32 `TerminateProcess` with exit code 99.
2. **Non-Zero Exit Code Handling**:
   - If a worker crashes due to an unhandled exception or segmentation fault, the runner captures `stderr`, transitions the assessment job to `FAILED`, and records an audit log entry detailing the crash.
