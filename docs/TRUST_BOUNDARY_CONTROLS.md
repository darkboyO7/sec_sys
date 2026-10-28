# VAPT SYSTEM — TRUST BOUNDARY CONTROLS
## Preventive and Detective Control Specifications Across Zero-Trust Boundaries (Prompt 14)

---

## 1. Zero-Trust Architecture Control Framework

The **VAPT Defensive Security Platform** implements a Zero-Trust Architecture (ZTA) governed by the following core principles:
1. **Never Trust, Always Verify:** Every subsystem request is re-validated at the point of execution, regardless of prior submission-time checks.
2. **Fail-Closed by Default:** Unknown target states, expired authorizations, missing credentials, and unverified data structures default immediately to access denial and job rejection.
3. **Least Privilege & Role Segregation:** Read-only roles (`VIEWER`) cannot mutate state; administrative or governance actions (`REMEDIATION_APPROVED`, `FALSE_POSITIVE`, `ACCEPTED_RISK`) mandate explicit `LEAD` or `ADMIN` roles.
4. **Defense in Depth:** Outer perimeter gateway checks (API tokens, CORS) are backed by inner domain controls (scope preflight, socket pinning, authoritative cryptographic digests).

---

## 2. Comprehensive Control Implementation Matrix

| Trust Boundary | Threat Category | Preventive Control Mechanism | Detective Control Mechanism | Fail-Safe Behavior | Verification Evidence |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **B1: Frontend $\leftrightarrow$ API** | Parameter Tampering, Unauthorized Action | Strict Pydantic schema validation, server-side RBAC, optimistic concurrency check (`expected_status`). | Structured FastAPI access logging, Merkle audit ledger events. | Reject with **HTTP 400/409/422** without state mutation. | `test_scenario_12`, Vitest suite. |
| **B2: Authentication & RBAC** | Privilege Escalation, Impersonation | Cryptographic JWT verification, `require_system_roles` dependency, `_validate_transition_rules`. | Failed authentication alerts, audit logging with `actor_id` and client IP. | Reject with **HTTP 401/403**. | `test_auth.py`, `test_adv_03`. |
| **B3: Tenant Boundaries** | Cross-Tenant Data Access (IDOR) | Mandatory `verify_project_access` dependency, strict SQL `project_id` filtering. | Audit records track `project_id`, cross-project access attempts flagged. | Fail closed with **HTTP 404** (prevents project enumeration). | `test_projects_isolation.py`, `test_adv_06`. |
| **B4: Scope & Exclusions** | Unauthorized Scanning, Excluded Target Probing | Dual-key authorization requirement, exclusion precedence over inclusions, preflight revalidation. | Worker preflight logs `ASSESSMENT_PREFLIGHT_DENIED` to audit ledger. | Job transitions to `REJECTED`, worker aborts execution. | `test_scope_engine.py`, `test_adv_01`, `test_adv_02`. |
| **B5: Worker Scheduler** | Resource Starvation, Subprocess Breakout | Win32 Job Object (512MB RAM clamp, no child procs), 10MB IPC limit, hard execution timeouts. | Worker heartbeat monitor, `DIAG_STUCK_JOBS` diagnostic check. | Forced process tree termination (`terminate_process_tree`), job marked `TIMED_OUT`. | `test_phase7a_worker_isolation.py`, `test_scenario_2`. |
| **B6: Scanner $\leftrightarrow$ Target** | SSRF, Cloud Metadata, DNS Rebinding | `check_ip_ssrf` filter, IP normalization (`norm_ip`), socket pinning to verified IP, per-hop redirect checks. | Target resolution logs, security event alerts on blocked metadata IPs. | Socket connection aborted, error recorded as `SSRF_BLOCKED`. | `test_live_network_adapter.py`, `test_adv_07`, `test_adv_08`. |
| **B7: Evidence Collection** | Evidence Tampering, Forged Hashes | Authoritative server-side SHA-256 hashing, 1MB payload clamping, dual hash tracking. | `verify_evidence_integrity` re-hashes payloads and verifies Merkle proofs. | Tampered evidence flagged in integrity report; job marked unverified. | `test_phase8_evidence_integrity.py`, `test_adv_10`, `test_adv_11`. |
| **B8: Knowledge Graph** | Cyclic Loops, Data Overwrites | Cycle-safe BFS with bounded depth ($\le 4$) and node limits, composite deduplication keys. | Epistemic contradiction tracking (`has_contradictions = True`), confidence discounts. | Graph traversal terminates cleanly at limits; conflicts preserved. | `test_knowledge_graph.py`, `test_adv_12`. |
| **B9: Contextual Risk** | Non-Deterministic Scores, Speculation | Pure deterministic formula v2.0.0, empirical uncertainty margin ($\pm \Delta$). | Risk audit logs record score inputs, factor breakdowns, and policy versions. | Undetermined attributes widen margin rather than inflating score. | `test_phase11_contextual_risk.py`, `test_adv_13`. |
| **B10: AI & Learning** | Prompt Injection, Training Data Poisoning | Input sanitization (`sanitize_untrusted_input`), advisory draft isolation, held-out test split gates. | Injection trigger flags recorded, model evaluation reports logged. | Injection neutralized; unapproved models rejected from deployment. | `test_phase18_ai_analyst.py`, `test_adv_14`. |
| **B11: Remediation** | Unauthorized Closure, Retest Bypass | Gated FSM (`REMEDIATION_APPROVED` requires Lead/Admin), 4-state retest outcome space. | Independent verification records, change authorization audit logs. | `INCONCLUSIVE` retests blocked from closing findings. | `test_phase14_remediation_verification.py`, `test_adv_04`. |
| **B12: Diagnostics & Recovery**| Destructive Self-Healing, Data Loss | Read-only diagnostic checks, two-phase pre/post condition comparison, bounded recovery actions. | Diagnostic sweep logs, recovery outcome records (`SUCCESS`, `FAILED`, `INCONCLUSIVE`). | Unmet preconditions yield `INCONCLUSIVE` without mutating records. | `test_prompt12_self_diagnostics_and_recovery.py`, `test_scenario_8`. |
| **B13: Persistence & Audit** | Audit Record Tampering, Backup Loss | Monotonic audit hash chain with thread lock, verified sandbox backup restore. | `verify_audit_ledger_integrity` checks chain links and monotonic timestamps. | Corrupted records detected immediately; restore aborted on hash mismatch. | `test_audit_ledger.py`, `test_scenario_9`, `test_scenario_13`. |

---

## 3. Detailed Technical Control Mechanisms

### 3.1 Point-of-Execution Scope Revalidation
Authorization is never assumed based on submission-time status.
1. When a job is submitted: `ScopeEngine.validate_target_in_scope` generates a snapshot digest.
2. While queued: An operator or change control may revoke the target or add an exclusion.
3. At worker execution: `preflight_and_claim_job` re-invokes `ScopeEngine.validate_target_in_scope`. If authorization is missing or an exclusion matches, the job is transitioned to `REJECTED`.
4. At retry: `AssessmentExecutionEngine.retry_job` re-invokes `ScopeEngine.validate_target_in_scope` before placing the job back into `QUEUED`.

### 3.2 Dynamic Per-Hop Socket Pinning
To eliminate DNS rebinding TOCTOU gaps across multi-hop redirects:
1. Destination hostname is normalized using `normalize_and_detect_ip` (resolving hex, octal, dword, percent-encoded variations).
2. Host is checked against cloud metadata endpoints (`169.254.169.254`, `fd00:ec2::254`, `100.100.100.200`), link-local, and private RFC 1918 space.
3. Destination DNS is resolved once, producing `verified_ip`.
4. `BoundedRedirectHandler` annotates the redirected request: `new_req._verified_ip = verified_ip`.
5. Custom handlers (`SafeHTTPHandler` and `SafeHTTPSHandler`) extract `_verified_ip` and pin the underlying TCP socket connection directly to `(connect_host, port)`.
6. For HTTPS connections, TLS SNI (`server_hostname`) is set to the redirect destination hostname, ensuring strict certificate validation while guaranteeing packets route only to the verified IP.

### 3.3 Authoritative Control Plane Evidence Digest Ingestion
To prevent compromised or buggy worker processes from injecting pre-fabricated hashes or misrepresenting evidence integrity:
1. Worker returns raw payload string and metadata.
2. At persistence time, `AssessmentExecutionEngine.execute_job` authoritatively calculates:
   $$\text{sha256\_hash} = \text{SHA256}(\text{payload.encode('utf-8')})$$
3. Any mismatched or forged hash submitted in `raw_ev.sha256_hash` is overwritten with the authoritative digest.
4. `verify_evidence_integrity` recomputes leaf hashes from persisted payload bytes and cross-checks `job.summary_stats["evidence_count"]` to ensure no rows were deleted or omitted.
