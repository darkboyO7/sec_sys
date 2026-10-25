# VAPT Platform — Security Policy & Operational Safety Model

## 1. Security Philosophy & Guarantees

The VAPT Platform is designed with a defense-in-depth posture:

1. **Explicit Server-Side Authorization:**
   - Every assessment target must be registered and explicitly authorized by an authorized lead before any test execution can take place.
   - Frontend controls are purely user experience aids; all authorization decisions are enforced by the server.

2. **Decoupled Scope Registration vs Authorization:**
   - Registering a target creates it strictly in `PENDING` status.
   - Authorization requires verifiable evidence (e.g. signed Rules of Engagement memo, change ticket reference) and an authorized approver.
   - Revocation requires an operational reason and immediately prevents further testing.

3. **Precedence of Exclusions:**
   - Scope exclusions take absolute precedence over inclusions.
   - Any target falling within an exclusion boundary is immediately denied, even if enclosed by an authorized CIDR block or wildcard domain.

4. **Execution Boundary Re-Validation:**
   - Immediately before any assessment job runs, the execution boundary re-evaluates the target against active authorization and exclusion rules.
   - If authorization was revoked or expired while queued, the execution fails closed.

5. **Non-Invasive Architecture (Phase 1 & 2):**
   - Active raw socket network scanning, arbitrary shell execution, and autonomous remediation are strictly disabled.
   - In Phase 2, assessment workflows operate exclusively on deterministic, simulated local test fixtures.

6. **Audit Trail & Credential Redaction:**
   - All state mutations and security evaluations record immutable audit entries.
   - Sensitive fields (`password`, `token`, `secret`, `authorization`, `cookie`, `key`, `credentials`) are automatically scrubbed and replaced with `[REDACTED]`.
   - In strict mode (`AUDIT_LOG_STRICT=true`), failure to record an audit event fails the enclosing transaction.

---

## 2. Cryptographic and Token Standards

- **Password Hashing:** Bcrypt with 12 rounds of salt (or Argon2id where supported).
- **Session Tokens:** JSON Web Tokens (JWT) signed with HMAC-SHA256 (`HS256`), short lifetimes (30 minutes default), requiring `iat`, `exp`, and `sub` claims.
- **Evidence Integrity:** Raw evidence transcripts compute and store SHA-256 digests for tamper-evident provenance.

---

## 3. Vulnerability Reporting & Contact

If you discover a potential vulnerability in the VAPT Platform codebase or control plane, please report it privately to the security lead:
- Security Team: `security@vapt-platform.local`
- GPG Key: Available upon request.
- Please do not open public GitHub issues for security vulnerabilities.
