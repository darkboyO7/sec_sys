# VAPT Platform — Threat Model & Security Architecture (Phase 1)

## 1. Threat Modeling Overview

As a Vulnerability Assessment and Penetration Testing management system, the platform is inherently a high-value security target. An adversary who compromises the control plane could obtain sensitive intelligence regarding infrastructure vulnerabilities, manipulate scope boundaries to target unauthorized third parties, or forge authorization records.

This threat model follows the **STRIDE** methodology (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, and Elevation of Privilege).

---

## 2. STRIDE Assessment Matrix

| Threat Category | Potential Attack Vector | Platform Defensive Control | Verification Method |
| :--- | :--- | :--- | :--- |
| **Spoofing** | Attacker impersonates an authorized security lead to authorize out-of-scope targets. | 1. Argon2/Bcrypt password hashing (cost factor 12).<br>2. Short-lived signed JWT bearer tokens.<br>3. Approver attribution (`authorized_by_id`) recorded in DB and immutable audit ledger. | `test_auth.py`<br>`test_tampered_token_rejected` |
| **Tampering** | Operator attempts to bypass scope exclusion by injecting malformed URLs or path traversal. | 1. Syntactic target normalization before evaluation (`ScopeEngine.normalize_target`).<br>2. Precedence of exclusions over inclusions.<br>3. Hostname/IP extraction and strict CIDR boundary testing. | `test_scope_engine.py`<br>`test_exclusions_preempt_authorized_inclusions` |
| **Repudiation** | Operator authorizes testing against a target and later claims they did not. | 1. Mandatory `authorization_evidence` field.<br>2. Immutable `audit_events` ledger recording actor, timestamp, client IP, action, and outcome.<br>3. Strict audit failure policy (`AUDIT_LOG_STRICT`). | `test_audit_ledger.py` |
| **Information Disclosure** | Operator from Project A queries or infers the existence of Project B's scope or targets. | 1. Server-side isolation check in API dependency (`verify_project_access`).<br>2. Fails closed with `404 Not Found` (avoids leaking project existence).<br>3. Password and token scrubbing in audit logs. | `test_projects_isolation.py`<br>`test_audit_event_generation_and_scrubbing` |
| **Denial of Service** | Flooding control plane with millions of candidate scope targets or giant subnets. | 1. `MAX_SCOPE_TARGETS_PER_PROJECT` limit.<br>2. Non-invasive in-memory scope evaluation (zero network lookups or socket connections).<br>3. SQLite WAL mode avoiding reader locks. | `test_persistence.py` |
| **Elevation of Privilege** | Standard `SECURITY_TESTER` attempts to call `/authorize` or `/revoke` endpoints. | 1. Server-side RBAC enforcement (`require_project_role`, `SystemRole.ADMIN`, `SystemRole.SECURITY_LEAD`).<br>2. Frontend controls are advisory; server fails closed with `403 Forbidden`. | `test_scope_api_lifecycle.py` |

---

## 3. High-Priority Threat Scenarios & Mitigations

### 3.1. Unauthorized Scanning of Third-Party Infrastructure (The "Friendly Fire" Risk)
- **Risk:** An operator registers an unauthorized external domain or IP (e.g., an AWS or Azure shared infrastructure IP, CDN, or third-party payment gateway).
- **Control Plane Guarantee:**
  - Scope registration and scope authorization are separate, decoupled states.
  - Newly created targets are locked in `PENDING` status.
  - The validation engine (`ScopeEngine.validate_target_in_scope`) strictly returns `DENIED` (`PENDING_APPROVAL`) until an authorized lead explicitly signs off with evidence.
  - Exclusions always override: if `10.0.1.1` is excluded, any scan of that IP is rejected even if `10.0.0.0/16` was authorized.
  - Future scanner workers will query the server-side validator prior to dispatching any network probe.

### 3.2. Secret Leakage in Logs and API Responses
- **Risk:** Passwords, API tokens, or cryptographic session keys leak into application logs, error traces, or audit records.
- **Defensive Guarantees:**
  - Password hashes are never returned in `UserResponse` Pydantic schemas.
  - The `AuditService.record_event()` runs a recursive sanitization filter (`sanitize_audit_details()`) that replaces any field key containing `password`, `token`, `secret`, `authorization`, `cookie`, `key`, or `credentials` with `[REDACTED]`.
  - Automated tests verify that audit records contain no unredacted credentials.

### 3.3. Project Isolation & Tenant Boundary Violations
- **Risk:** In a multi-team environment, Team Alpha accesses confidential targets or findings belonging to Team Beta.
- **Defensive Guarantees:**
  - Every project endpoint runs `verify_project_access()`.
  - Non-members attempting to query an unassigned project receive a `404 Not Found` rather than a `403 Forbidden`, preventing discovery of project IDs.
  - Foreign key constraints with cascading deletes ensure project scopes cannot become orphaned.

### 3.4. Scanner Worker Boundary Isolation (Phase 2 Preparation)
- **Invariant:** No scanner binaries (Nmap, nuclei, etc.) are executed by the control plane process.
- In future phases, scanner workers will run in sandboxed containers on isolated worker nodes, communicating only via an authenticated message queue with mutual TLS, with zero privilege to alter authorization rules in the database.
