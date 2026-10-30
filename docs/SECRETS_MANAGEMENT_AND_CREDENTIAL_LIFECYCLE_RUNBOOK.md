# Secrets Management, Configuration Validation & Credential Lifecycle Runbook

**Document Revision:** 1.0.0  
**Prompt Target:** Prompt 45  
**Classification:** Internal Security Operations & Infrastructure Runbook  
**Applicability:** VAPT Security Platform (Control Plane, Workers, and Connectors)

---

## 1. Architectural Overview & Security Guarantees

The VAPT Security Platform enforces zero secret leakage across console output, log files, administrative APIs, database exports, and release artifacts.

```
+-----------------------------------------------------------------------------------------+
|                                    Application Layer                                    |
|   +-----------------------+   +------------------------+   +------------------------+   |
|   |  Strict Config System |   | Universal Log Filter   |   | Config Diagnostics     |   |
|   |  - Fail-closed in prod|   | - Intercepts all logs  |   | - Reports health/rating|   |
|   |  - Safe dev fallbacks |   | - Redacts JWT/pass/key |   | - Zero plaintext values|   |
|   +-----------+-----------+   +-----------+------------+   +-----------+------------+   |
+---------------|---------------------------|----------------------------|----------------+
                |                           |                            |
+---------------v---------------------------v----------------------------v----------------+
|                                  Secret Vault                                           |
|   - Authenticated Symmetric Encryption at Rest (Fernet AES-128-CBC + HMAC-SHA256)      |
|   - Deterministic Key Derivation via SHA-256 / Base64 from CREDENTIAL_ENCRYPTION_KEY   |
|   - Transparent Migration of Legacy Unencrypted JSON Records                          |
|   - Non-Leaking Re-encryption for Key Rotation Drill                                   |
+-------------------------------------------+---------------------------------------------+
                                            |
+-------------------------------------------v---------------------------------------------+
|                                 External Boundary                                       |
|   - Connectors: Masked views in UI/API (`syn****xyz`), Encrypted at Rest (`enc:v1:...`) |
|   - Frontend: Strictly forbidden from defining VITE_* secrets                           |
|   - Release Gate: Automated scan for unredacted tokens, private keys, and env files     |
+-----------------------------------------------------------------------------------------+
```

### Key Security Invariants:
1. **Production Fail-Closed Guarantee:**
   - Any deployment with `ENVIRONMENT=production` or `ENVIRONMENT=staging` terminates startup if `SECRET_KEY` is under 32 characters, has low entropy (< 8 unique characters), or contains known dictionary patterns (`insecure`, `changeme`, `test`, `default`, `password`, `admin`).
   - Rejects `DEBUG=True`, `AUDIT_LOG_STRICT=False`, wildcard `*` CORS origins, localhost origins, and SQLite engines in production.
2. **Authenticated Encryption at Rest:**
   - External connector settings (e.g. AWS access keys, GitHub tokens, webhook secrets) are encrypted before insertion into `connector_configurations.settings_encrypted` using the `enc:v1:` Fernet envelope.
3. **Safe Legacy Migration:**
   - Pre-Prompt-45 plaintext JSON settings in database records are transparently decrypted during retrieval and upgraded to `enc:v1:` on the next save or rotation.
4. **Universal Output Scrubbing:**
   - `SecretRedactionLoggingFilter` intercepts log records and eliminates database passwords, JWT signatures, Bearer tokens, GitHub PATs, Slack tokens, AWS keys, and PEM private keys.

---

## 2. Configuration Matrix & Diagnostic Posture

The platform exposes runtime configuration posture via `GET /api/v1/system/deployment/config/diagnostic`:

| Setting Key | Sensitivity | Development Default | Production Requirement | Diagnostic Rule |
| :--- | :--- | :--- | :--- | :--- |
| `ENVIRONMENT` | Public | `development` | `production` | Validated against `EnvironmentType` enum |
| `DEBUG` | Public | `False` (or `True` for dev) | Strictly `False` | Fails closed in production if `True` |
| `SECRET_KEY` | **Secret** | 64-char hex dev key | 64-char random hex (`openssl rand -hex 32`) | Masked (`c8f****c8d7`); checked for entropy & dictionary words |
| `CREDENTIAL_ENCRYPTION_KEY` | **Secret** | Derived from `SECRET_KEY` | Dedicated 32-byte key or derived | Masked (`[DERIVED_FROM_SECRET_KEY]` or `abc****xyz`) |
| `DATABASE_URL` | **Secret** | `sqlite:///.../vapt.db` | `postgresql://user:<password>@host:5432/db` | Password stripped (`postgresql://user:***REDACTED***@host...`) |
| `ALLOWED_ORIGINS` | Public | `http://localhost:5173` | Explicit HTTPS FQDNs | Fails closed on `*` or `localhost` in production |
| `AUDIT_LOG_STRICT` | Public | `True` | Strictly `True` | Fails closed if audit immutability disabled |
| `SECRET_REDACTION_ENABLED`| Public | `True` | Strictly `True` | Ensures global log interception active |

---

## 3. Operational Runbooks

### Procedure 1: Rotating Connector Credentials
When an external API token or service credential expires or is suspected of compromise:

1. Identify the connector ID via `GET /api/v1/projects/{project_id}/connectors`.
2. Issue the rotation request:
   ```http
   POST /api/v1/projects/{project_id}/connectors/{connector_id}/rotate-credentials
   Authorization: Bearer <ADMIN_OR_SECURITY_LEAD_JWT>
   Content-Type: application/json

   {
     "settings": {
       "api_endpoint": "https://api.provider.com",
       "api_token": "<NEW_EXPEDIENT_TOKEN>",
       "region": "us-east-1"
     }
   }
   ```
3. **Verification:**
   - The API responds with `200 OK` and a `settings_masked` object displaying `new****xyz`.
   - The backend encrypts the new credential at rest with a new Fernet initialization vector.
   - Run `POST /api/v1/projects/{project_id}/connectors/{connector_id}/test` to verify health.

---

### Procedure 2: Rotating the Platform Secret Key (`SECRET_KEY`)
Rotating `SECRET_KEY` invalidates active user sessions and requires re-encrypting vault records if `CREDENTIAL_ENCRYPTION_KEY` is not separately pinned.

1. **Scheduled Maintenance:** Notify users that active web sessions will be invalidated.
2. **Generate New Secret:**
   ```bash
   openssl rand -hex 32
   ```
3. **Vault Re-Encryption Drill:**
   Execute the re-encryption utility to migrate stored connector ciphertexts:
   ```python
   from app.core.database import SessionLocal
   from app.models.connector import ConnectorConfiguration
   from app.core.secret_vault import SecretVault

   db = SessionLocal()
   old_key = "OLD_SECRET_KEY_HERE"
   new_key = "NEW_SECRET_KEY_HERE"

   connectors = db.query(ConnectorConfiguration).all()
   for c in connectors:
       if c.settings_encrypted:
           c.settings_encrypted = SecretVault.reencrypt_credentials(
               c.settings_encrypted,
               old_secret_key=old_key,
               new_secret_key=new_key
           )
   db.commit()
   db.close()
   ```
4. **Update Environment:** Replace `SECRET_KEY` in `.env.production` or container orchestration secret manager.
5. **Restart Service:** Execute `scripts/windows/start_platform.bat` or restart the service unit.

---

### Procedure 3: Rotating Database Credentials
1. Create new credentials on the database server.
2. Update `DATABASE_URL` in `.env.production` (or runtime secret store).
3. Test connectivity using `python -c "from app.core.config import settings; print(settings.get_config_diagnostics())"`.
4. Gracefully restart backend workers.

---

### Procedure 4: Incident Response & Emergency Secret Revocation
If a credential or platform secret is accidentally exposed:

1. **Immediate Revocation:**
   - Revoke the compromised API token or database user at the upstream provider immediately.
2. **Rotate Platform Key:**
   - Immediately update `SECRET_KEY` in production environment to invalidate all active JWT tokens.
3. **Audit Log Inspection:**
   - Query `audit_events` for unauthorized actions during the exposure window:
     ```sql
     SELECT id, action, actor_email, ip_address, timestamp 
     FROM audit_events 
     WHERE timestamp >= '<INCIDENT_START>'
     ORDER BY timestamp DESC;
     ```
4. **Supply Chain & Release Verification:**
   - Run `python scripts/release_qualification_gate.py` to ensure no repository files contain leaked tokens.

---

## 4. Frontend Security & Build Gate Rules

To protect against frontend asset leakage:
- **Zero VITE_* Secrets:** Frontend build tools embed all `VITE_*` variables into public JavaScript bundles.
- **Forbidden Names:** Any variable containing `SECRET`, `PASSWORD`, `PRIVATE`, `KEY`, `TOKEN`, or `CREDENTIAL` is blocked by `SupplyChainSecurityService.audit_frontend_build_variables()`.
- **Runtime Public Values Only:** Frontend configuration must strictly consist of public base URLs (`VITE_API_URL`) or application titles.
