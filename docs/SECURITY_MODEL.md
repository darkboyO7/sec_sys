# VAPT Platform — Security Model & Governance Architecture

## 1. Executive Summary

The VAPT Platform is an enterprise-grade, defensive vulnerability assessment and penetration testing intelligence system. Because the platform stores vulnerability intelligence, governs scanning scopes, and analyzes attack paths, it operates under a **defense-in-depth zero-trust architectural model**.

This document defines the core security boundaries, authorization principles, cryptographic invariants, and execution controls enforced across all platform tiers.

---

## 2. Multi-Tenant Project Isolation Boundary

### 2.1. Tenancy Model
The platform partitions all security intelligence across two administrative boundaries:
1. **Organizations (`Organization`)**: The top-level administrative boundary representing a business entity or corporate tenant.
2. **Projects (`Project`)**: Subordinate workspace boundaries representing distinct applications, infrastructures, or assessment campaigns.

### 2.2. Access Control & Non-Enumeration
Every request to a project-scoped resource is guarded by the server-side dependency `verify_project_access`:
- Users must hold an active assignment in `project_members` or possess global `SystemRole.ADMIN` privileges.
- Four granular project roles are enforced:
  - `OWNER`: Full administrative control, deletion, and lifecycle purge.
  - `LEAD`: Scope authorization, assessment job dispatch, remediation verification approval, and model deployment.
  - `MEMBER`: Assessment initiation, finding triage, and remediation task management.
  - `VIEWER`: Read-only access to findings, reports, and knowledge graphs.
- **Timing and Enumeration Defense**: Any unauthorized attempt to access a project resource returns `404 Not Found` (never `403 Forbidden`). This prevents malicious actors from determining the existence or naming patterns of other organizations' projects.

---

## 3. Dual-Key Scope Governance & Preflight Validation

### 3.1. Target Decoupling & Registration States
Scope targets exist in a strict three-state lifecycle:
- `PENDING`: Target is registered but unauthorized for any automated or manual assessment.
- `AUTHORIZED`: Target has undergone cryptographically signed lead authorization with written evidence.
- `REVOKED`: Target is revoked; any active or scheduled jobs targeting this host fail immediately.

### 3.2. Dual-Key Authorization Rule
To prevent rogue operators from scanning arbitrary infrastructure without oversight, the platform enforces dual-key authorization:
- A user cannot self-authorize a target if they are the sole operator dispatching the assessment.
- The `authorized_by_id` must reference a valid project `LEAD` or system `ADMIN` whose identity is cryptographically recorded in the audit ledger.

### 3.3. Exclusion Preemption Invariant
Exclusions (`ScopeExclusion`) represent strict "DO NOT SCAN" boundaries (e.g. production billing systems, shared multi-tenant gateways).
- **Rule:** Exclusions *unconditionally override* authorized inclusions.
- If `10.0.0.0/16` is authorized, but `10.0.1.50` is excluded, any scan targeting `10.0.1.50` or resolving to `10.0.1.50` is denied by `ScopeEngine.validate_target_in_scope()` with reason `EXCLUDED_TARGET`.

---

## 4. Execution Sandbox & Worker Process Isolation

```
+-------------------------------------------------------------------------+
|                         Control Plane (FastAPI)                         |
|  - Manages SQLite/PostgreSQL Database                                  |
|  - Enforces Scope Validation & Dual-Key Authorization                   |
|  - Dispatches Jobs to Subprocess Workers                                |
+-------------------------------------------------------------------------+
                                    |
                    IPC Pipe (JSON-RPC over stdin/stdout)
                    Auth Token: SHA-256 HMAC ephemeral token
                                    |
                                    v
+-------------------------------------------------------------------------+
|                  Sandboxed Worker Process (Python)                      |
|  - Native Windows Job Object Sandbox                                   |
|  - Clean Environment (API keys, DB URLs, Secrets purged)                |
|  - No Database Socket / No Raw Network Capabilities                     |
|  - Memory Limit: 512 MB | Process Active Limit: 180s                     |
|  - Restricted Scanner Adapters (is_simulated = True)                    |
+-------------------------------------------------------------------------+
```

### 4.1. Process Boundaries
- The control plane **never** executes security scanner adapters inside the FastAPI web server process.
- All assessments run in dedicated Windows subprocess workers managed by `SubprocessWorkerRunner`.

### 4.2. Windows Job Object Hardening
Worker processes are bound to Windows Job Objects with operating-system-level constraints:
- `JOB_OBJECT_LIMIT_PROCESS_MEMORY`: 512 MB hard ceiling per worker.
- `JOB_OBJECT_LIMIT_JOB_MEMORY`: 1024 MB cumulative memory ceiling.
- `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`: Guarantees process tree termination if the runner exits.

### 4.3. Ephemeral Single-Use IPC Authentication
- Communication occurs via standard I/O pipes using JSON-RPC schemas.
- Each worker spawn receives a unique 256-bit ephemeral authentication token passed via arguments.
- Every IPC message must present this token; unauthorized commands immediately terminate the worker.

---

## 5. Tamper-Evident Cryptographic Audit Ledger & Trust Anchors

### 5.1. Audit Hash Chaining
Every administrative, authorization, and scan action records an immutable record in `audit_events`.
Each record computes:
$$\text{EventHash}_i = \text{SHA256}(\text{EventHash}_{i-1} \parallel \text{Timestamp} \parallel \text{ActorID} \parallel \text{Action} \parallel \text{Details})$$
Any attempt to insert, delete, or alter historical audit records breaks the chain and is detected by `IntegrityService.verify_audit_ledger_integrity()`.

### 5.2. Merkle Tree Evidence Verification
Scan artifacts (raw headers, simulated payloads, configuration outputs) are hashed with SHA-256 and indexed in binary Merkle trees. Operators can generate cryptographic inclusion proofs to prove to third-party auditors that evidence was captured at a specific point in time without modification.

### 5.3. External Trust Anchoring
Internal Merkle roots can be anchored out-of-band via the `ExternalTrustAnchor` interface:
- **`HMACExternalTrustAnchor`**: Local system-level HMAC-SHA256 anchoring bound to an isolated secure key.
- **RFC 3161 / Cloud Anchor**: Clean plugin interface allowing Merkle roots to be committed to an immutable external timestamping authority or cloud WORM storage.

---

## 6. AI Safety & Model Governance

### 6.1. Prompt Injection Neutralization
All untrusted data sourced from scan outputs, HTTP headers, or asset banners is treated as adversarial:
- Scanned text is HTML-escaped before entering AI analysis contexts.
- Sanitizer flags adversarial patterns (e.g. `IGNORE PREVIOUS INSTRUCTIONS`, `<script>`, system prompt overrides) and quarantines suspicious payloads.

### 6.2. Empirical Threshold Gates
Machine learning models (Phase 19) for finding categorization or triage cannot be deployed without human sign-off:
- Precision $\ge 0.60$ and Recall $\ge 0.60$ must be empirically demonstrated on an isolated test partition.
- Models failing thresholds are rejected at the approval boundary.
- Atomic rollback mechanisms ensure instant reversion to previous verified models if performance degrades.

---

## 7. Emergency Controls & Adaptive Defense

### 7.1. Morph-State Adaptive Defense
The platform dynamically transitions between 8 defensive posture states based on anomalous events (e.g., unexpected network changes, credential alerts, high false-positive rates):
- Normal: standard automated scanning cadence.
- High Alert: throttled scan rates, elevated logging.
- Containment: automated scans blocked, requires manual authorization for all actions.

### 7.2. Emergency Kill-Switch
A global or project-level kill-switch (`kill_switch_engaged = True`) immediately aborts all running worker processes, clears pending queues, transitions the posture to `MANUAL_REVIEW_REQUIRED`, and emits an immutable audit alert.
