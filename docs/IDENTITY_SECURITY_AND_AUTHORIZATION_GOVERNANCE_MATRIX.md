# Identity Security, Authorization Consistency, and Privileged-Action Governance Matrix

## 1. Architectural Overview & Threat Model

The VAPT Platform implements a multi-tenant, zero-trust authorization architecture designed to defend against:
- **Horizontal Privilege Escalation (BOLA / IDOR):** Prevent authenticated actors in Organization/Project $A$ from querying, mutating, or inferring assets, findings, scans, or policies belonging to Organization/Project $B$.
- **Vertical Privilege Escalation (Privilege Bypasses):** Prevent lower-privileged actors (e.g., `VIEWER`, `TESTER`) from executing operations reserved for higher-privileged roles (e.g., `LEAD`, `ADMIN`), including policy alterations, scheduling dispatches, or threat correlation triggers.
- **Stale Credential / Session Hijacking:** Ensure that when users log out, rotate passwords, or are deactivated, all existing JWT bearer tokens are invalidated cryptographically and persistently across all distributed services.
- **Attributable Access Denial Auditing:** Maintain an auditable, tamper-evident ledger of every denied authorization attempt without logging sensitive credentials, plaintext passwords, or raw cryptographic tokens.

---

## 2. Centralized Role & Permission Hierarchy

### 2.1 System-Level Roles (`SystemRole`)
| System Role | Scope of Authority | Granted System Permissions |
| :--- | :--- | :--- |
| `ADMIN` | Global platform administration, user lifecycle, system configuration | All system permissions, full override capabilities |
| `AUDITOR` | Read-only inspection of global logs, compliance postures, and security events | `system:audit:read`, `system:governance:read`, `project:read` |
| `USER` | Standard operational participant; authority derived from project memberships | Assigned project-level roles only |

### 2.2 Project-Level Roles (`ProjectRole`)
| Project Role | Typical Personas | Granted Operational Permissions |
| :--- | :--- | :--- |
| `LEAD` | Security Lead, Principal Assessor, Project Owner | Full project governance: `project:admin`, `scope:manage`, `assessment:launch`, `finding:manage`, `finding:validate`, `report:generate`, `scheduling:manage`, `threat_intel:correlate`, `compliance:manage` |
| `TESTER` | Security Engineer, Penetration Tester | Assessment execution & evidence capture: `project:read`, `scope:manage`, `assessment:launch`, `finding:create`, `evidence:upload`, `finding:manage` |
| `VIEWER` | Executive, Compliance Auditor, Guest Observer | Strictly read-only visibility: `project:read`, `scope:read`, `assessment:read`, `finding:read`, `evidence:download`, `report:read` |

---

## 3. Cryptographic Token Lifecycle & Revocation Mechanics

```
                  +-------------------------------------------------+
                  |   User Request (Bearer eyJhbGciOiJIUzI1Ni...)   |
                  +-------------------------------------------------+
                                           |
                                           v
                          [Decode & Verify Signature (HS256)]
                                           |
                                           v
                         [Check User Account Active (403)]
                                           |
                                           v
                       +---------------------------------------+
                       | Token Revocation Verification Check   |
                       +---------------------------------------+
                        /                                     \
           [Global Revocation Check]             [JTI Blocklist Check]
           iat_precise <= token_revoked_before?   jti IN token_revocations?
                        \                                     /
                         \                                   /
                          +---------[Any Revoked?]----------+
                                         |
                       +-----------------+-----------------+
                      YES                                  NO
                       |                                    |
                       v                                    v
            [HTTP 401 UNAUTHORIZED]              [Authorization Checks]
        "Authentication token revoked"           (Project / Object Level)
```

### 3.1 Sub-Second Precision Token Invalidation
- Standard RFC 7519 JWT `iat` timestamps are constrained to integer seconds, which causes clock-granularity race conditions during rapid session rotations.
- The platform injects an authoritative `iat_precise` float claim (`now.timestamp()`) alongside unique cryptographic `jti` identifiers.
- `AuthorizationService.is_token_revoked` compares high-resolution UTC timestamps, ensuring that tokens created prior to password reset or global logout are immediately blocked, while newly issued tokens in the same second remain valid.

### 3.2 Persistent JTI Blocklisting
- When a user explicitly logs out via `POST /api/v1/auth/logout`, the token's unique `jti` is inserted into `token_revocations` with its expiration time (`expires_at`).
- Revocation records are retained until token expiration, ensuring minimal database growth while providing absolute replay immunity.

---

## 4. Object-Level Authorization & Project Boundary Containment

Direct object references (findings, targets, evidence, scan jobs) must never be loaded solely by their primary keys. All data access layers must enforce object containment:

```python
def verify_resource_ownership(
    model_class: Type[Any],
    resource_id: str,
    project_id: str,
    db: Session,
    resource_name: str = "Resource",
) -> Any:
    # Fail closed with 404 to avoid leaking resource existence across project boundaries
    resource = db.query(model_class).filter(
        model_class.id == resource_id,
        model_class.project_id == project_id,
    ).first()
    if not resource:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"{resource_name} not found in this project",
        )
    return resource
```

---

## 5. Attributable Access Denial Ledger & Zero Credential Leakage

### 5.1 Denial Event Logging
Every failed authorization attempt (401, 403, 404-containment) is recorded in `access_denial_audit_records`:
- `user_id` / `user_email`: Authenticated identity (or `None` for unauthenticated probing).
- `project_id`: Targeted project boundary.
- `endpoint` & `http_method`: Target API path and HTTP verb.
- `required_privilege` vs `held_privilege`: Explicit disparity analysis.
- `denial_reason`: Sanitized diagnostic message.
- `client_ip`: Source network address.

### 5.2 Zero-Leakage Sanitization Rules
`redact_sensitive_strings` executes deterministic regular expression masking:
- `Bearer [eyJ... tokens]` $\rightarrow$ `Bearer [REDACTED_JWT]`
- `"password": "..."` $\rightarrow$ `"password": "[REDACTED]"`
- `"token": "..."` $\rightarrow$ `"token": "[REDACTED]"`
- Raw cryptographic keys, API keys, and Authorization headers are scrubbed prior to persistence or logging.
