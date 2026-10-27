# VAPT Platform — Scanner Readiness & Authorization Gate Specification

**Classification:** Security Architecture & Execution Governance  
**Operational Status:** Simulated-Only Mode Certified (`is_simulated = True`)  

---

## 1. Scanner Adapter Architecture

The platform decouples the control plane from scanner execution through a strictly typed adapter interface:

```text
app/services/scanner_adapters/
├── base.py                   <-- BaseScannerAdapter abstract contract & AdapterMetadata
├── local_fixture_adapter.py  <-- Deterministic fixture adapter for synthetic testing
├── passive_header_adapter.py <-- Non-intrusive HTTP security header inspection
└── ssl_cipher_adapter.py     <-- Non-intrusive TLS/SSL cipher suite evaluator
```

### 1.1 Adapter Contract Requirements
Every scanner adapter must implement:
1. **Metadata Declaration:**
   - `name`: Unique canonical name (e.g. `scanner.passive_header`).
   - `version`: Semantic version string.
   - `is_simulated`: Boolean flag. Must be `True` for simulation mode.
   - `timeout_seconds`: Hard execution ceiling.
   - `supported_target_types`: List of allowed types (`IP_ADDRESS`, `CIDR_BLOCK`, `URL`, `FQDN`).
2. **Readiness Evaluation:**
   - `evaluate_readiness()`: Assesses whether the scanner binary, environment, and required permissions exist on the host before scheduling.
3. **Execution Boundary:**
   - `execute(target, config)`: Returns structured findings with evidence payloads. Must not perform unbounded network scans or run external shell scripts without validation.

---

## 2. The 8-State Scanner Readiness Gate

Before any assessment job can be scheduled or claimed by a worker, the `ScopeEngine` and `AssessmentExecutionEngine` evaluate the target against an 8-state readiness space:

| State Code | Readiness State | System Behavior |
| :--- | :--- | :--- |
| **01** | `SIMULATION_ONLY` | Target is authorized only for deterministic simulated execution. Real network sockets are blocked. |
| **02** | `READY_FOR_REVIEW` | Scope is defined by operator but pending Project Lead dual-key review. |
| **03** | `AUTHORIZATION_REQUIRED` | Scope is invalid, expired, or missing authorized signature. Job creation is blocked. |
| **04** | `SCOPE_INVALID` | Target input violates RFC 1918 / FQDN format or matches an active exclusion rule. Fails closed. |
| **05** | `WORKER_NOT_READY` | Process worker queue is saturated, Win32 Job Object is unavailable, or heartbeat timeout occurred. |
| **06** | `RESOURCE_LIMIT_UNAVAILABLE`| Concurrency limit reached or host memory usage exceeds threshold (512MB ceiling). |
| **07** | `REAL_EXECUTION_DISABLED` | Host policy enforces simulation mode. Real scanner execution is prohibited by environment configuration. |
| **08** | `READY_FOR_AUTHORIZED_EXECUTION` | Scope is valid, dual-key authorized, unexpired, worker is healthy, and policy explicitly permits real scanning. |

---

## 3. Real Scanning Safety Invariant & Prerequisites

In this native Windows deployment, **real scanning is disabled by default** (`REAL_EXECUTION_DISABLED`).

To qualify a real scanning adapter for production execution in an approved staging environment, the following prerequisites must be met:
1. **Legal Authorization Agreement:** Operator must possess signed Rules of Engagement (RoE) covering the exact target CIDR/FQDN.
2. **Explicit Dual-Key Approval:** Lead Operator and Tester must both sign the scope record (`authorized_by_id != created_by_id`).
3. **Isolated Network Namespace:** Execution must occur within an isolated security testing subnet with strict egress filtering.
4. **Adapter Binary Verification:** External binaries (e.g. Nmap) must be verified via SHA-256 hash before execution.
5. **Worker Subprocess Containment:** Process must execute inside a Win32 Job Object with active timeout and memory limits.
