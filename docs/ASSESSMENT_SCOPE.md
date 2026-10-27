# VAPT Platform — Assessment Scope Governance & Preflight Validation

## 1. Overview

The Assessment Scope subsystem is the foundational defensive barrier of the VAPT Platform. Its primary purpose is to ensure that no scan, observation, or probe can ever be executed against an asset without explicit, authorized, dual-key administrative consent, and that sensitive exclusions unconditionally supersede inclusions.

---

## 2. Target Representation & Classification

Scope items are modeled as two distinct database entities:
1. **`ScopeTarget`**: Permitted assessment boundaries within a project.
2. **`ScopeExclusion`**: Explicitly forbidden assets, subnets, or services within a project.

### 2.1. Supported Target Types (`TargetType`)
- **`IP_ADDRESS`**: A single IPv4 or IPv6 address (e.g., `192.168.1.10`, `::1`).
- **`CIDR_BLOCK`**: An IPv4 or IPv6 subnet notation (e.g., `10.0.0.0/24`, `fe80::/64`).
- **`DOMAIN_NAME`**: A fully-qualified domain name (FQDN) or wildcard (e.g., `api.example.com`, `*.corp.local`).
- **`URL`**: An HTTP/HTTPS endpoint URL (e.g., `https://app.example.com/login`).

---

## 3. Canonical Target Normalization

Before any scope validation or matching occurs, all candidate targets are normalized by `ScopeEngine.normalize_target()` to prevent evasion via URL encoding, uppercase variations, or extraneous whitespace:
1. Strips leading and trailing whitespace.
2. Converts hostnames and URL schemes to lowercase.
3. Parses URLs to isolate scheme, host, and port components.
4. Normalizes IPv4 and IPv6 string representations using Python's standard `ipaddress.ip_address` library.
5. Validates CIDR notation validity using `ipaddress.ip_network(strict=False)`.

---

## 4. Exclusion Precedence Invariant

The core security axiom of the scope engine is:

$$\text{ScopeDecision} = \text{DENIED if Target} \in \text{Exclusions else } (\text{ALLOWED if Target} \in \text{Inclusions and Status} = \text{AUTHORIZED else DENIED})$$

### Precedence Rules:
1. **Exclusion Preemption**: If a target matches any active `ScopeExclusion`, the validation engine returns `DENIED` with reason `EXCLUDED_TARGET`. This rule holds even if the target is explicitly included in an authorized `ScopeTarget`.
   - *Example:* Inclusion `10.0.0.0/16` (Authorized) + Exclusion `10.0.1.50` (Active) $\rightarrow$ Target `10.0.1.50` is **DENIED**.
2. **Subnet Containment**: An IP address target is checked for subnet containment against all CIDR exclusions and inclusions using bitwise IP network checks.
3. **Wildcard & Subdomain Matching**: A domain target `sub.corp.local` matches domain inclusion `*.corp.local` or exact match `sub.corp.local`.

---

## 5. Dual-Key Authorization Lifecycle

Scope targets transition through three strict states (`AuthorizationStatus`):

```
     [ Creation ]
          │
          ▼
    ┌───────────┐
    │  PENDING  │ ◄── Target registered by Project Member; cannot be scanned
    └─────┬─────┘
          │
          │ Lead Review & Authorization (Dual-Key Check)
          ▼
   ┌──────────────┐      Revocation / Scope Change
   │  AUTHORIZED  │ ───────────────────────────────────► ┌───────────┐
   └──────────────┘                                      │  REVOKED  │
          │                                              └───────────┘
          ▼
   [ Scan Dispatch Permitted ]
```

### 5.1. Dual-Key Authorization Constraints
1. **Role Enforcement**: Only users with `ProjectRole.LEAD` or system `SystemRole.ADMIN` may call the `/authorize` endpoint.
2. **Dual-Key Separation**: The operator authorizing the scope target must be recorded in `authorized_by_id`.
3. **Mandatory Evidence**: An authorization request must include written justification (`authorization_evidence`, e.g. written approval document ticket ID or sign-off identifier).
4. **Audit Trail**: Every state change emits an immutable audit event recording target ID, authorizer ID, and timestamp.

---

## 6. Preflight Assessment Dispatch Validation

When an assessment job is initiated via `AssessmentExecutionEngine.execute_job()`:
1. The engine queries all targets associated with the job's target specification.
2. Each target is passed to `ScopeEngine.validate_target_in_scope(db, project_id, target)`.
3. If **any** target fails validation (e.g. status is `PENDING`, target is `EXCLUDED`, or target is unknown), preflight fails closed:
   - Job transitions to `CANCELLED` or `FAILED`.
   - Error reason is recorded in the job log.
   - An audit event `ASSESSMENT_PREFLIGHT_DENIED` is emitted.
   - Subprocess worker is **never spawned**.
