# VAPT Platform — Architecture & Design Document (Phase 1 & 2)

## 1. Executive Summary

The VAPT (Vulnerability Assessment and Penetration Testing) Platform is an enterprise cybersecurity intelligence and operational testing control plane. The system is engineered as a **Modular Monolith** for Phase 1 & 2, prioritizing high cohesion, strong tenant/project boundaries, non-invasive scope validation, verifiable proof-of-authorization, and a deterministic assessment orchestration pipeline.

Future live scanner workers, exploitation engines, and AI-driven analysis tools are strictly segregated behind an isolated execution boundary, remaining dormant until explicit authorization, resource limits, and worker sandboxing are verified.

---

## 2. System Architecture

```mermaid
flowchart TD
    subgraph UI ["Client Layer (React 19 + TypeScript + Vite)"]
        Dashboard["Mission Overview"]
        ScopeConsole["Scope Validation & Governance Console"]
        AssessmentConsole["Assessment Orchestration Console"]
        AuditViewer["Immutable Audit Feed"]
    end

    subgraph ControlPlane ["Control Plane (FastAPI Modular Monolith)"]
        API_Gateway["API Layer (/api/v1 Router)"]
        AuthMiddleware["JWT Authentication & RBAC Filter"]
        AuditService["Audit Logger & Redaction Engine"]
        ScopeEngine["Non-Invasive Scope Evaluation Engine"]
        AssessmentEngine["Assessment Execution Boundary Engine"]
        StateMachine["Assessment State Machine (QUEUED -> RUNNING -> COMPLETED)"]
    end

    subgraph AdapterLayer ["Scanner Adapter Boundary"]
        LocalAdapter["LocalFixtureAdapter\n(Deterministic Synthetic Fixtures)"]
        RawScannerWorkers[["Live Network Scanners\n(STRICTLY DISABLED)"]]
    end

    subgraph Persistence ["Persistence Layer (SQLite WAL in Dev / PostgreSQL in Prod)"]
        DB[(Database Engine)]
        AuditLedger[(Audit Event Ledger)]
        Findings[(Assessment Findings & Cryptographic Evidence)]
    end

    UI -->|HTTPS / REST API| API_Gateway
    API_Gateway --> AuthMiddleware
    AuthMiddleware --> ScopeEngine
    ScopeEngine --> Persistence
    API_Gateway --> AssessmentEngine
    AssessmentEngine -->|Mandatory Pre-Flight Scope Re-Validation| ScopeEngine
    AssessmentEngine --> StateMachine
    AssessmentEngine --> LocalAdapter
    LocalAdapter --> Findings
    API_Gateway --> AuditService
    AuditService --> AuditLedger
```

---

## 3. Core Architectural Modules

| Module | Purpose | Phase Status |
| :--- | :--- | :--- |
| **1. Core & Lifecycle** | Configuration management (`pydantic-settings`), request context tracking, liveness (`/health`) and readiness (`/ready`) probes. | **Implemented & Verified** |
| **2. Auth & Identity** | Bcrypt password hashing (cost factor 12), short-lived JWT token issuance, RBAC (`ADMIN`, `SECURITY_LEAD`, `SECURITY_TESTER`, `AUDITOR`, `VIEWER`). | **Implemented & Verified** |
| **3. Organizations & Projects** | Multi-tenant project hierarchy, project roles (`LEAD`, `TESTER`), and project-level boundary isolation. | **Implemented & Verified** |
| **4. Scopes & Target Authorization** | Target registration (`PENDING`), explicit evidence-backed authorization (`AUTHORIZED`), scope exclusions, and fail-closed validation. | **Implemented & Verified** |
| **5. Audit Logging** | Immutable security event logging with automated credential scrubbing and strict failure-mode enforcement. | **Implemented & Verified** |
| **6. Assessment Orchestration & Evidence Pipeline** | Persistent job state machine, idempotency keys, deterministic local fixture adapter, finding persistence, and cryptographic SHA-256 evidence provenance. | **Implemented & Verified (Phase 2)** |
| **7. Finding Lifecycle & Deduplication** | 13-state finding lifecycle, deduplication, revalidation, and risk acceptance. | *Target: Phase 3* |
| **8. Asset Inventory & Knowledge Graph** | Asset graph topology, multi-hop relationship modeling, and choke-point discovery. | *Target: Phase 4* |
| **9. Contextual Risk Engine** | Transparent, deterministic risk scoring combining severity, exposure, and asset criticality. | *Target: Phase 5* |

---

## 4. Assessment State Machine & Execution Boundary

Assessment jobs follow a strict, deterministic finite state machine:

```mermaid
stateDiagram-v2
    [*] --> QUEUED : Job Created (Idempotent)
    QUEUED --> RUNNING : Execution Boundary Scope Check Passed
    QUEUED --> CANCELLED : Operator Request
    QUEUED --> FAILED : Pre-flight Scope Re-Validation Failed
    RUNNING --> COMPLETED : All Fixture Tests Passed
    RUNNING --> PARTIAL : Tests Passed with Auxiliary Warnings/Errors
    RUNNING --> FAILED : Unhandled Adapter Exception
    RUNNING --> TIMED_OUT : Execution Exceeded timeout_seconds
    RUNNING --> CANCELLED : Operator Request
    COMPLETED --> [*]
    FAILED --> [*]
    CANCELLED --> [*]
    TIMED_OUT --> [*]
    PARTIAL --> [*]
```

### Pre-Flight Execution Invariant
Before any adapter runs, the `AssessmentExecutionEngine`:
1. Re-evaluates `ScopeEngine.validate_target_in_scope()` against the database.
2. If authorization expired, was revoked, or an exclusion was added while the job was queued, the job transitions immediately to `FAILED` with an explicit reason, and an `ASSESSMENT_EXECUTION_DENIED` audit event is emitted.
3. Network scanning is strictly disabled. The adapter interface dispatches solely to approved adapters (default: `LocalFixtureAdapter`).

---

## 5. Audit Logging & Tamper-Evident Distinction

### Implemented Model: Structured Transactional Append-Only Ledger
The platform currently implements an **append-only relational audit ledger**:
- Immutable rows stored in `audit_events`.
- Transactional integrity tied to database transactions (`AUDIT_LOG_STRICT=True`).
- Client IP, actor ID, action, outcome, and timestamp recorded.
- Automated recursive scrubbing of all credentials and sensitive keys.

### Architectural Boundary: Cryptographic Tamper-Evidence
An append-only ledger differs from a cryptographically tamper-evident or tamper-proof system:
- In the current Phase 1/2 model, an attacker with direct, administrative SQL database access could theoretically alter historical rows.
- Future phases (Phase 8) will introduce **Merkle trees and cryptographic hash-chaining** (`previous_record_hash`) anchored to external, independent timestamping authorities to establish verifiable mathematical tamper-evidence.
