# VAPT Platform — Architecture & Design Document (Phase 1)

## 1. Executive Summary

The VAPT (Vulnerability Assessment and Penetration Testing) Platform is an enterprise cybersecurity intelligence and operational testing control plane. The system is engineered as a **Modular Monolith** for Phase 1, prioritizing high cohesion, strong tenant/project boundaries, non-invasive scope validation, and verifiable proof-of-authorization.

Future scanner workers, exploitation engines, and AI-driven analysis tools are strictly segregated behind an isolated message and execution boundary, remaining dormant until explicit authorization, resource limits, and worker sandboxing are verified.

---

## 2. System Architecture

```mermaid
flowchart TD
    subgraph UI ["Client Layer (Browser)"]
        ReactDashboard["React 19 + TypeScript + Vite Dashboard"]
        ScopeConsole["Scope Validation & Governance Console"]
        AuditViewer["Immutable Audit Feed"]
    end

    subgraph ControlPlane ["Control Plane (FastAPI Modular Monolith)"]
        API_Gateway["API Layer (/api/v1 Router)"]
        AuthMiddleware["JWT Authentication & RBAC Filter"]
        AuditService["Audit Logger & Redaction Engine"]
        ScopeEngine["Non-Invasive Scope Evaluation Engine"]
        ProjectService["Project & Member Isolation Engine"]
    end

    subgraph Persistence ["Persistence Layer"]
        DB[(Database Engine\nSQLite WAL in Dev / PostgreSQL in Prod)]
        AuditLedger[(Audit Event Ledger)]
    end

    subgraph WorkerBoundary ["Isolated Worker Boundary (Future Phases)"]
        WorkerQueue[["Assessment Job Queue (Isolated)"]]
        ScannerWorker[["Scanner Execution Container (Disabled)"]]
    end

    UI -->|HTTPS / REST API| API_Gateway
    API_Gateway --> AuthMiddleware
    AuthMiddleware --> ProjectService
    ProjectService --> ScopeEngine
    ScopeEngine --> Persistence
    API_Gateway --> AuditService
    AuditService --> AuditLedger
    ScopeEngine -.->|Pre-Flight Proof Check| WorkerQueue
    WorkerQueue -.->|Isolated Execution| ScannerWorker
```

---

## 3. Core Architectural Modules

| Module | Purpose | Phase 1 Status |
| :--- | :--- | :--- |
| **1. Core & Lifecycle** | Configuration management (`pydantic-settings`), request context tracking, liveness (`/health`) and readiness (`/ready`) probes. | **Implemented & Tested** |
| **2. Auth & Identity** | Bcrypt password hashing (cost factor 12), short-lived JWT token issuance, RBAC (`ADMIN`, `SECURITY_LEAD`, `SECURITY_TESTER`, `AUDITOR`, `VIEWER`). | **Implemented & Tested** |
| **3. Organizations & Projects** | Multi-tenant project hierarchy, project roles (`LEAD`, `TESTER`), and project-level boundary isolation. | **Implemented & Tested** |
| **4. Scopes & Target Authorization** | Target registration (`PENDING`), explicit evidence-backed authorization (`AUTHORIZED`), scope exclusions, and fail-closed validation. | **Implemented & Tested** |
| **5. Audit Logging** | Immutable security event logging with automated credential scrubbing and strict failure-mode enforcement. | **Implemented & Tested** |
| **6. Scanner Adapters & Workers** | Job queue, containerized scanner runners (Nmap, nuclei, zap, etc.). | *Deferred to Phase 2 (Workers remain disabled)* |
| **7. Findings & Evidence Provenance** | Vulnerability findings, reproduction payloads, cryptographic evidence hashes. | *Deferred to Phase 2* |
| **8. Security Knowledge Graph** | Attack surface relationships, asset discovery links. | *Deferred to Phase 3* |
| **9. AI Integration Guardrails** | Policy-governed LLM agents with restricted deterministic tool execution. | *Deferred to Phase 4* |

---

## 4. Scope Governance & Fail-Closed Validation Engine

A foundational premise of this platform is that **no target can ever be scanned without explicit, recorded proof of authorization**.

```mermaid
flowchart TD
    Start["Candidate Target Input\n(IP, CIDR, Domain, or URL)"] --> Normalize["ScopeEngine.normalize_target()\nSyntactic Parsing & Canonicalization"]
    Normalize --> ExclusionCheck{"Does candidate match\nANY Scope Exclusion?"}
    
    ExclusionCheck -- YES --> RejectExcl["DENIED: Status EXCLUDED\nImmediate Fail-Closed"]
    ExclusionCheck -- NO --> TargetCheck{"Does candidate match\nANY Scope Target?"}
    
    TargetCheck -- NO --> RejectNotInScope["DENIED: Status NOT_IN_SCOPE\nFail-Closed"]
    TargetCheck -- YES --> StatusCheck{"What is Scope Target\nauthorization_status?"}
    
    StatusCheck -- PENDING --> RejectPending["DENIED: Status PENDING_APPROVAL\nRegistration is NOT Authorization"]
    StatusCheck -- REVOKED --> RejectRevoked["DENIED: Status REVOKED\nExplicitly Revoked with Reason"]
    StatusCheck -- EXPIRED --> RejectExpired["DENIED: Status EXPIRED\nAuthorization Window Elapsed"]
    StatusCheck -- AUTHORIZED --> ExpiryCheck{"Has expires_at\npassed?"}
    
    ExpiryCheck -- YES --> RejectExpired
    ExpiryCheck -- NO --> Allow["PERMITTED: Status AUTHORIZED\nReturns Matched Rule & ROE Evidence"]
```

### Precedence Rules
1. **Scope Exclusions take absolute precedence**: Even if an entire subnet (e.g., `10.0.0.0/16`) is authorized, an exclusion for `10.0.1.1` immediately rejects any evaluation of that specific host.
2. **Registration != Authorization**: Creating a target sets status to `PENDING`. It requires a distinct operation (`/authorize`) with documented Rules of Engagement (ROE) evidence and approver attribution.
3. **Fail-Closed by Default**: Any target not matching a verified, active rule is rejected with `NOT_IN_SCOPE`.

---

## 5. Data Persistence & Portability (SQLite WAL vs PostgreSQL)

### Local Development Architecture (Native Windows)
- Engine: **SQLite 3**
- Pragma Configuration:
  - `PRAGMA foreign_keys = ON;` (Strict referential integrity)
  - `PRAGMA journal_mode = WAL;` (Concurrent reader performance without locking)
  - `PRAGMA synchronous = NORMAL;`

### Production Architecture (PostgreSQL)
All SQLAlchemy 2.0 models and Alembic migrations are designed for seamless PostgreSQL deployment:
1. **Primary Keys:** RFC 4122 UUID strings (36 characters) portable across SQLite and PostgreSQL.
2. **Timestamps:** UTC timezone-aware DateTime (`DateTime(timezone=True)`).
3. **JSON Metadata:** SQLAlchemy generic `JSON` column mapping to SQLite JSON functions locally and `JSONB` on PostgreSQL.
4. **Migrations:** Managed through Alembic (`alembic upgrade head`) with offline and online migration execution.

To transition to PostgreSQL in production:
```bash
# Update .env
DATABASE_URL="postgresql+psycopg2://vapt_user:secure_password@localhost:5432/vapt_db"
# Run migrations
alembic upgrade head
```

---

## 6. Audit Logging Integrity Guarantees

Every sensitive security event records:
- `actor_id` & `actor_email` (Attribution)
- `action` (Taxonomy: `AUTH_LOGIN`, `PROJECT_CREATE`, `SCOPE_TARGET_AUTHORIZE`, etc.)
- `target_type` & `target_id` (Entity under operation)
- `timestamp` (UTC)
- `ip_address` (Network origin)
- `outcome` (`SUCCESS`, `DENIED`, `FAILURE`)
- `details` (Structured context)

**Credential Redaction Filter:**
The `AuditService` recursively inspects all detail dictionaries and scrubs keys matching `password`, `token`, `secret`, `authorization`, `cookie`, `key`, and `credentials`, replacing values with `[REDACTED]`.
If `AUDIT_LOG_STRICT=True` is set in configuration, any database failure during audit event creation triggers an automatic transaction rollback and exception raise, preventing sensitive state mutations from executing without an audit record.
