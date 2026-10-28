# VAPT Platform — Secure Configuration & Environment Governance

**Document Version:** 1.0.0  
**Baseline Date:** 2026-10-28  
**Repository:** `D:\alt`  
**Configuration Controller:** [`backend/app/core/config.py`](file:///D:/alt/backend/app/core/config.py)  
**Security Standard:** OWASP Top 10, ASVS Level 2, NIST SP 800-53 Rev 5

---

## 1. Environment Variables Specification

The VAPT Platform is configured via environment variables or a local `.env` file (loaded via `pydantic-settings`). In production environments, sensitive values must be injected securely via secrets managers or operating system environment variables—never committed to source control.

| Environment Variable | Type | Development Default | Recommended Production Value | Security Purpose & Governance Rule |
|:---|:---:|:---|:---|:---|
| `ENVIRONMENT` | string | `development` | `production` | Enables strict fail-closed security validations, hides API documentation, and disables internal debug errors. |
| `DEBUG` | boolean | `False` | `False` | **Mandatory False in production.** When True, Swagger docs (`/docs`) and OpenAPI schema (`/openapi.json`) are exposed. |
| `SECRET_KEY` | string | `dev_insecure_secret_key...` | Cryptographically random $\ge 32$ chars (e.g. `openssl rand -hex 32`) | Used to sign and verify HMAC-SHA256 JWT bearer tokens and audit trust anchors. Fails closed if default key is used in production. |
| `ALGORITHM` | string | `HS256` | `HS256` | Symmetric HMAC-SHA256 algorithm for JWT signing. |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | integer | `30` | `15` to `30` | Limits token replay window. Requires re-authentication upon expiration. |
| `DATABASE_URL` | string | `sqlite:///.../vapt.db` | `sqlite:///.../vapt.db` or `postgresql://...` | Connection URI. Supports SQLite WAL mode or PostgreSQL 16. |
| `ALLOWED_ORIGINS` | string | `http://localhost:5173,...` | Explicit FQDNs (e.g. `https://vapt.corp.internal`) | Comma-delimited list of allowed CORS origins. **Wildcard `*` is strictly forbidden in production.** |
| `AUDIT_LOG_STRICT` | boolean | `True` | `True` | **Mandatory True in production.** Enforces synchronous, tamper-evident SHA-256 hash chaining on all audit events. |
| `EXECUTION_MODE` | string | `SUBPROCESS` | `SUBPROCESS` | Runs scanner jobs in isolated Win32 Job Object subprocesses with hard 512MB memory ceilings. |
| `WORKER_MAX_IPC_PAYLOAD_BYTES` | integer | `10485760` (10MB) | `10485760` (10MB) | Clamps JSON-lines IPC communication between control plane and scanner subprocesses. |
| `MAX_SCOPE_TARGETS_PER_PROJECT`| integer | `500` | `500` | Upper bound on registered scope targets per project to prevent denial-of-service. |
| `DB_RETRY_MAX_ATTEMPTS` | integer | `3` | `5` | Maximum retry attempts on transient SQLite database lock or PostgreSQL serialization conflicts. |

---

## 2. Fail-Closed Startup Validation Rules

The platform implements automated fail-closed configuration verification in [`Settings.validate_production_hardening`](file:///D:/alt/backend/app/core/config.py#L57). If `ENVIRONMENT = "production"`, the application aborts startup immediately with a descriptive error if any of the following rules are violated:

1. **Weak / Default Secret Key Rejection:**
   If `SECRET_KEY` contains substrings like `"insecure"`, `"change_in_production"`, or `"test"`, startup is aborted:
   ```
   ValueError: Default or development SECRET_KEY is strictly forbidden in production mode.
   ```
2. **Secret Key Minimum Entropy:**
   If `SECRET_KEY` is fewer than 32 characters in length, startup is aborted:
   ```
   ValueError: SECRET_KEY must be at least 32 characters long for cryptographic security.
   ```
3. **Debug Mode Prohibition:**
   If `DEBUG = True` when `ENVIRONMENT = "production"`, startup is aborted:
   ```
   ValueError: DEBUG mode must be set to False in production.
   ```
4. **CORS Wildcard Prohibition:**
   If `ALLOWED_ORIGINS` contains `*` when `ENVIRONMENT = "production"`, startup is aborted:
   ```
   ValueError: Wildcard '*' in ALLOWED_ORIGINS is strictly forbidden in production mode.
   ```
5. **Audit Governance Invariant:**
   If `AUDIT_LOG_STRICT = False` in production, startup is aborted:
   ```
   ValueError: AUDIT_LOG_STRICT must be set to True in production.
   ```

---

## 3. Network, Header, and Boundary Security Controls

### 3.1 Defense-in-Depth HTTP Security Headers
Every HTTP response emitted by the FastAPI backend includes mandatory security headers via [`SecurityHeadersMiddleware`](file:///D:/alt/backend/app/main.py#L42):
- **Content-Security-Policy (CSP):** `default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none';`
- **X-Frame-Options:** `DENY` (Prevents clickjacking in all frames/iframes).
- **X-Content-Type-Options:** `nosniff` (Prevents MIME-confusion attacks).
- **Referrer-Policy:** `strict-origin-when-cross-origin` (Prevents leaking path data in cross-origin referrers).
- **Permissions-Policy:** `camera=(), microphone=(), geolocation=(), payment=()` (Disables unnecessary browser APIs).
- **Strict-Transport-Security (HSTS):** `max-age=31536000; includeSubDomains; preload` (Enforced on HTTPS and in production).
- **Cache-Control:** `no-store, no-cache, must-revalidate, max-age=0` (Enforced on all `/api/v1/` routes to prevent caching sensitive vulnerability data).

### 3.2 Request-Size Limiting Middleware
[`ContentLengthLimitMiddleware`](file:///D:/alt/backend/app/main.py#L43) rejects incoming requests whose `Content-Length` header exceeds 10 MB (10,485,760 bytes) with **HTTP 413 Payload Too Large**, defending the application against memory exhaustion DoS.

### 3.3 Scope Authorization & SSRF Prevention Engine
[`ScopeEngine`](file:///D:/alt/backend/app/services/scope_engine.py) validates all assessment targets at the API gateway and re-validates them immediately before execution at the worker boundary:
- **SSRF / Cloud Metadata:** `169.254.169.254`, `metadata.google.internal`, and link-local IPv6 addresses are blocked fail-closed.
- **Carrier-Grade NAT (CGNAT):** `100.64.0.0/10` is blocked fail-closed.
- **Private Subnets & Loopback:** `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, and `127.0.0.1` are blocked unless explicitly registered and authorized in the project scope boundary with signed Rules of Engagement (ROE) evidence.

---

## 4. Logging Sanitization & Error Masking

1. **Access Log Redaction:**
   Request URLs logged by `RequestContextMiddleware` log exclusively `request.url.path`. Query strings, form bodies, JSON payloads, and headers are never written to standard access logs.
2. **Audit Ledger Redaction:**
   `AuditService` enforces a strict redaction mask on sensitive keys:
   `["password", "token", "secret", "authorization", "cookie", "key", "access_token", "refresh_token"]`.
   Any matching key in an event payload is replaced with `"[REDACTED]"`.
3. **Diagnostic Sanitization:**
   - The `/ready` diagnostic endpoint verifies connectivity to database and storage but returns sanitized status flags (`"reachable"`, `"writable"`, `"initialized"`) without exposing connection strings, usernames, passwords, or disk mount paths.
   - In production, unhandled 500 exceptions return a generic message referencing the unique request UUID (`X-Request-ID`). Internal Python tracebacks and source code lines are suppressed.

---

## 5. Production Environment Setup Checklist

Before deploying the platform into a production or customer environment, verify each item:

- [ ] `ENVIRONMENT=production` is set in the host environment.
- [ ] `DEBUG=False` is set.
- [ ] A unique, high-entropy `SECRET_KEY` ($\ge 32$ characters) has been generated and injected via secrets manager.
- [ ] `ALLOWED_ORIGINS` is configured with the exact origin URLs of the authorized frontend hosts (no wildcards).
- [ ] Reverse proxy (Nginx, Caddy, or IIS) is configured with valid TLS certificates (HTTPS).
- [ ] Directory `backend/data/` has appropriate Windows file permissions (restricted to the service account).
- [ ] The automated release package audit (`audit_release_archive`) passed with zero secrets and zero prohibited paths.
