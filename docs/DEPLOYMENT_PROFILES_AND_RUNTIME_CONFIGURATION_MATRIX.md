# Deployment Profiles and Runtime Configuration Matrix (Prompt 49)

## 1. Executive Summary & Objective
This specification formalizes the **Deployment Profiles and Safe Runtime Configuration Framework** for the VAPT Platform. It establishes strict separation between developer conveniences and production-grade security requirements, validates all environment settings at application startup, eliminates secret leakage in diagnostics and error responses, enforces isolated databases and evidence repositories for automated testing, and ensures predictable, cross-platform operation without mandatory WSL dependencies.

---

## 2. Environment Profile Taxonomy

| Profile | Target Audience / Use Case | Database Engine | Debug Mode | CORS Policy | Secret Key Policy | Evidence Directory |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `DEVELOPMENT` | Local engineering & developer workflows | SQLite (`backend/data/vapt.db`) | Configurable (`True` default) | Localhost allowed (`localhost:5173`, `127.0.0.1:5173`) | Development fallback permitted with warning | `backend/data/evidence` |
| `TESTING` | Automated test suites & CI/CD verification | Isolated test store (`vapt_test.db` / memory) | `False` | Localhost allowed | Dedicated test secret key | `backend/data/test_evidence` |
| `STAGING` | Pre-production validation & integration drills | Managed PostgreSQL | **Strictly Forbidden** (`False`) | Explicit corporate domains; no wildcards, no localhost | High-entropy key required (min 32 chars, entropy >= 8) | Secure cloud/shared storage |
| `PRODUCTION` | Live operational deployment | Managed Enterprise PostgreSQL | **Strictly Forbidden** (`False`) | Strict origin whitelist; no wildcards, no localhost | High-entropy cryptographically strong key | Encrypted object/file storage |

---

## 3. Strict Fail-Closed Startup Validations

When `ENVIRONMENT` is set to `staging` or `production`, the platform enforces fail-closed validation at application startup:

1. **Secret Key Hardening:**
   - Must be at least 32 characters long.
   - Must possess a character entropy of at least 8 unique characters.
   - Must not contain default substrings: `"insecure"`, `"change_in_production"`, `"changeme"`, `"test"`, `"default"`, `"sample"`, `"password"`, `"admin"`, `"123456"`.
2. **Debug Mode Lockdown:**
   - `DEBUG` must be `False`. If set to `True`, the process terminates immediately with `ValueError`.
3. **Database Security:**
   - SQLite is **strictly forbidden**. An enterprise PostgreSQL connection is mandatory.
   - Default credentials (`postgres:postgres@`) are strictly rejected.
   - Empty or omitted database passwords are strictly rejected.
4. **CORS Governance:**
   - Wildcard (`*`) origins are strictly prohibited.
   - Localhost / loopback origins (`localhost`, `127.0.0.1`, `::1`) are strictly prohibited.
5. **Audit Trail Integrity:**
   - `AUDIT_LOG_STRICT` must be `True` to ensure cryptographic hash-chaining of all privileged actions.
6. **Secret Redaction:**
   - `SECRET_REDACTION_ENABLED` must be `True`. All stack traces, log lines, and diagnostic outputs are filtered before egress.

---

## 4. Test Isolation Guarantees

To ensure tests never mutate user data:
1. **Database Routing:** When `ENVIRONMENT == "testing"`, any attempt to connect to the default working database (`vapt.db`) is automatically redirected to an isolated database (`vapt_test.db`) or in-memory database.
2. **Evidence Segregation:** File-based artifacts, raw payloads, and scan dumps are stored in `backend/data/test_evidence/` during test runs, completely decoupled from production evidence in `backend/data/evidence/`.
3. **Teardown Cleanup:** Test runners automatically clean up test databases and temporary evidence upon test completion.

---

## 5. Component Readiness and Health Probes

The `/health/ready` endpoint performs active verification of all critical platform components:
- **Database Reachability:** Active query check (`SELECT 1`).
- **Schema & Migrations:** Verification that database schema tables exist (`SELECT count(*) FROM users`).
- **Storage Writability:** Verification of disk write permissions in the data store.
- **Evidence Storage:** Verification that the active evidence directory is accessible and writable.
- **Profile Compliance:** Verification that runtime configuration satisfies the constraints of the active `ENVIRONMENT`.

If any critical component check fails, the readiness probe returns **HTTP 503 Service Unavailable** with machine-readable JSON details, preventing ingress traffic from routing to an unready node.

---

## 6. Frontend Configuration & Secret Segregation

1. **Environment Configuration Files:**
   - `frontend/.env.development`: Points to local backend (`http://localhost:8000/api/v1`).
   - `frontend/.env.staging`: Points to staging ingress (`/api/v1`).
   - `frontend/.env.production`: Points to production ingress (`/api/v1`).
2. **Zero-Secret Client Bundling:**
   - No backend secrets (`SECRET_KEY`, `CREDENTIAL_ENCRYPTION_KEY`, DB passwords) are ever prefixed with `VITE_` or included in frontend source files.
   - Vite distribution builds are actively scanned in release qualification gates for secret leakage.
3. **Localhost Egress Guard:**
   - In `production` builds, any attempt to configure a localhost API URL is automatically overridden to relative `/api/v1` with a console security warning.

---

## 7. Windows Compatibility & Cross-Platform Support

All scripts, paths, and server invocations adhere to portable standards:
- **Predictable Anchors:** All file paths are anchored to repository root using `Path(__file__).resolve().parent.parent`.
- **Pure Python Execution:** Zero reliance on bash, WSL, or Linux-specific utilities for core operations.
- **Native PowerShell & Cmd Support:** All automation scripts run natively in Windows environments.
