# Vulnerability Assessment and Penetration Testing (VAPT) Platform
## Phase 1–6A: Secure Foundation, Assessment Orchestration, Finding Lifecycle, Asset Inventory, Knowledge Graph, Contextual Risk Intelligence, & Execution Boundary Governance

A modular, multi-tenant cybersecurity intelligence and testing control plane. Built natively for Windows with Python 3.14, FastAPI, SQLAlchemy 2.0, Alembic, React 19, TypeScript, Vite, and Tailwind CSS.

---

## 1. Architectural Highlights

- **Control Plane Architecture:** Modular monolith control plane providing governance, authorization, and auditability prior to introducing isolated assessment workers.
- **Fail-Closed Target Scoping:** Target registration and proof of authorization are strictly decoupled. A target registered in the system remains `PENDING` and cannot be scanned until an authorized lead records verified evidence (Rules of Engagement, approval ticket, expiry).
- **Scope Exclusions:** Exclusions take absolute precedence over inclusions, ensuring critical infrastructure or third-party services are immediately rejected.
- **Non-Invasive Scope Console:** In-memory pre-flight validator that checks candidate targets without initiating network probes or DNS traffic.
- **Secure Assessment Execution Boundary & Governance (Phase 6A):**
  - **Typed, Versioned Execution Contract:** Immutable job contract capturing job ID, project ID, principal, authorization reference/status, canonical scope snapshot & SHA-256 digest, policy version, adapter metadata, capabilities, timestamps, attempt count, failure categories, and evidence hashes.
  - **Fail-Closed Preflight Boundary Re-Validation:** Independent scope re-evaluation immediately before worker claim; fails closed to `REJECTED` (`SCOPE_AUTHORIZATION_DENIED`) if scope is expired, revoked, or excluded.
  - **Tampering Detection:** Scope snapshot cryptographic digest verification; tampering transitions job to `REJECTED` (`SCOPE_SNAPSHOT_TAMPERING_DETECTED`).
  - **Bounded 11-State Finite State Machine:** `QUEUED`, `PREFLIGHT`, `READY`, `RUNNING`, `CANCELLATION_REQUESTED`, `CANCELLED`, `COMPLETED`, `PARTIAL`, `FAILED`, `REJECTED`, `TIMED_OUT`.
  - **Worker Heartbeat Monitoring:** `heartbeat_at` live worker tracking; detects abandoned jobs exceeding 60s and transitions to `FAILED` (`WORKER_HEARTBEAT_LOST`).
  - **Typed Scanner Adapter Protocol:** `BaseScannerAdapter` interface with central `AdapterRegistry`, capability discovery endpoint (`GET /assessments/adapters`), and preflight configuration checks.
  - **Untrusted Evidence Boundary Sanitization:** Server-side enforcement rejecting `NaN`/`inf` CVSS, bounding evidence payload size to 64KB, capping findings count to 50, computing SHA-256 digests, and decoupling execution from automated finding closure.
  - **Clean Host Benchmark Support:** `HARDENED_HOST_BASELINE` produces 0 findings with `COMPLETED` status, cleanly distinguished from failure.
- **Deterministic Assessment Orchestration (Phase 2):**
  - Persistent finite state machine: `QUEUED`, `RUNNING`, `COMPLETED`, `FAILED`, `CANCELLED`, `TIMED_OUT`, `PARTIAL`.
  - Idempotency key support to prevent duplicate executions.
  - Mandatory execution boundary re-validation: targets are re-checked against active scope immediately before adapter execution.
  - Pluggable adapter interface (`BaseScannerAdapter`). Phase 2 operates strictly with `LocalFixtureAdapter` on deterministic synthetic fixtures.
  - Active network scanning, arbitrary shell execution, and autonomous remediation remain strictly disabled.
  - Cryptographic evidence provenance: every raw evidence artifact computes and stores a SHA-256 digest.
- **Finding Validation & 13-State Lifecycle Pipeline (Phase 3):**
  - Strict 13-state deterministic lifecycle: `DETECTED`, `NEEDS_VALIDATION`, `CONFIRMED`, `FALSE_POSITIVE`, `INCONCLUSIVE`, `REMEDIATION_PROPOSED`, `REMEDIATION_APPROVED`, `REMEDIATION_ATTEMPTED`, `REMEDIATED_PENDING_VERIFICATION`, `VERIFIED_CLOSED`, `REOPENED`, `ACCEPTED_RISK`, `EXPIRED`.
  - Deterministic SHA-256 finding fingerprinting and deduplication correlation engine.
  - Non-destructive contradictory evidence handling: preserves divergent scanner observations and confidence without silent data loss.
  - Automated reopening: if a closed or remediated finding is re-detected on target, it automatically transitions to `REOPENED`.
  - Reviewer sign-off provenance: `FALSE_POSITIVE` requires Project LEAD / System ADMIN and mandatory justification (>= 10 chars).
  - Time-bounded `ACCEPTED_RISK` governance: requires Project LEAD / System ADMIN, mandatory future expiration date, and compensating controls.
  - Automated sweep mechanism transitioning overdue accepted risks to `EXPIRED`.
  - Full audit history: `FindingTransition` ledger and immutable audit events for every transition.
- **Persistent Asset Inventory & Conservative Reconciliation (Phase 4):**
  - Strict decoupling of current authoritative asset state (`assets`) from raw historical scanner outputs (`asset_observations`).
  - Standards-safe normalization: strictly rejects ambiguous IPv4 octets and CIDRs containing leading zeros (CWE-1288 / CVE-2021-29921) to eliminate socket ambiguity vulnerabilities.
  - Deterministic identifier normalization across Web Apps, API Endpoints, IPv6 compression, CIDRs, Services, and Domains with strict character sanitization (`^[a-zA-Z0-9*_\-.]+$`).
  - Automatic canonical SHA-256 evidence digest calculation over JSON observation payloads.
  - Conflict-preserving attribute reconciliation tracking chronological changes in `_attribute_history`.
  - Identity ambiguity tracking (`is_ambiguous`, `ambiguity_reason`) with audit-logged operator resolution governance.
- **Universal Security Knowledge Graph (Phase 4 & 4.1):**
  - PostgreSQL-compatible relational graph tables (`graph_nodes`, `graph_relationships`) with index-backed adjacency joins.
  - 13 security entity categories (`ASSET`, `SERVICE`, `APPLICATION`, `IDENTITY`, `ROLE`, `PERMISSION`, `VULNERABILITY`, `FINDING`, `EVIDENCE`, `SECURITY_CONTROL`, `DEPENDENCY`, `REMEDIATION`, `ASSESSMENT`) and 11 relationship types.
  - Epistemic verification statuses (`VERIFIED`, `INFERRED`, `HYPOTHETICAL`, `STALE`, `SUPERSEDED`) and confidence metrics ($0.0 \le c \le 1.0$).
  - Self-referential edge prohibition (`source_node_id == target_node_id` rejected) and synthetic node idempotency (`entity_id` is None).
  - Dual parent-child project scoping across all asset observation and graph relationship endpoints.
  - Bounded, cycle-safe BFS traversal with strict depth, node, and edge bounds, plus truncation signaling.
  - Execution outcome alignment: failed scans do not record misleading asset observations or verified edges; partial scans mark relationships as `INFERRED`.
  - Full React 19 visualizer with SVG layout, verification status styling, node inspector, and edge creator.
- **Contextual Risk Intelligence & Prioritization (Phase 5):**
  - Explainable Contextual Risk Engine (`ContextualRiskService`, formula `v1.0.0`) producing a bounded 0–100 prioritization index.
  - Multi-dimensional decomposition: base severity, confidence weight, asset criticality, network reachability, evidence freshness decay, and lifecycle mitigating controls.
  - Epistemic transparency: preserves original scanner severity and freezes complete input snapshots (`input_snapshot`) for historical reproducibility. Explicitly logs missing factors without inventing data.
  - Bounded, evidence-aware attack path analysis (`AttackPathAnalysisService`) categorizing candidate paths as `VERIFIED`, `MIXED_EVIDENCE`, or `HYPOTHETICAL` with cumulative confidence ($\prod c_i$) and cycle avoidance.
  - Advisory remediation decision support (`RemediationPrioritizationService`) with defensive playbooks, operational impact analysis, rollback procedures, and independent verification criteria.
  - Role-gated remediation sign-off (`APPROVED`, `DEFERRED`, `REJECTED`) requiring Project LEAD / System ADMIN roles.
  - Strict non-executing guarantee: never executes shell commands, alters firewall rules, or modifies production systems.
  - React 19 Contextual Risk Dashboard with KPI counters, factor decomposition drawer, attack path explorer, and remediation approval modals.
- **Immutable Audit Ledger:** All sensitive actions record actor attribution, client IP, outcome, and timestamp with automated credential scrubbing.
- **Data Persistence:** Native Windows development uses SQLite 3 with `PRAGMA journal_mode=WAL` and `PRAGMA foreign_keys=ON`. The data layer is fully compatible with PostgreSQL in production via SQLAlchemy 2.0 and Alembic.

---

## 2. Directory Structure

```text
VAPT_System/
├── .env.example              # Configuration template with secure defaults
├── .gitignore                # Windows, Python, Node, Vite, SQLite exclusions
├── README.md                 # Setup, verification, and operation guide
├── docs/
│   ├── ARCHITECTURE.md       # Modular design, state machine, fail-closed engine
│   ├── THREAT_MODEL.md       # STRIDE analysis, project isolation, secret redaction
│   ├── ROADMAP.md            # Multi-year phase milestones (Phases 1 - 5)
│   ├── SECURITY.md           # Security policy and operational safety model
│   └── DEVELOPMENT.md        # Windows development guide and workflow
├── backend/
│   ├── requirements.txt      # Pinned Python dependencies verified on Python 3.14
│   ├── pyproject.toml        # Pytest configuration & settings
│   ├── alembic.ini           # Migration configuration
│   ├── alembic/              # Versioned database migrations (001, 002)
│   ├── app/
│   │   ├── main.py           # FastAPI entrypoint, middleware, lifespan
│   │   ├── core/             # Configuration, security (Bcrypt/JWT), database
│   │   ├── models/           # Declarative models (User, Org, Project, Scope, Audit, Assessment)
│   │   ├── schemas/          # Strict Pydantic v2 schemas
│   │   ├── services/         # Scope validation, assessment state machine, fixture adapter
│   │   └── api/v1/           # Versioned endpoints (Health, Auth, Projects, Scopes, Assessments, Audit)
│   └── tests/                # Automated pytest suite (28 tests)
└── frontend/
    ├── package.json          # React 19, TypeScript, Vite, Tailwind CSS, Vitest
    ├── vite.config.ts        # Vite configuration with API reverse proxy
    ├── src/
    │   ├── components/       # Header, Navigation, ScopeValidationConsole, Modals
    │   ├── views/            # Overview, ScopeManagement, AssessmentJobs, AuditLedger, SystemHealth
    │   ├── services/         # Typed API client connecting to /api/v1
    │   ├── tests/            # Vitest unit test suite (4 tests)
    │   └── types/            # TypeScript interfaces matching backend models
```

---

## 3. Native Windows Quickstart Instructions

### Prerequisites
- Windows 10/11 (AMD64)
- Python 3.12+ (Python 3.14.7 verified)
- Node.js v20+ (Node v24.21.0, npm 11.19.0 verified)
- PowerShell 5.1+

---

### Step 1: Environment Configuration

Open PowerShell in the project root:

```powershell
Copy-Item .env.example .env
```

---

### Step 2: Backend Setup & Database Migration

```powershell
# Create virtual environment (if not already created)
python -m venv .venv

# Activate virtual environment
.\.venv\Scripts\Activate.ps1

# Install backend dependencies
python -m pip install -r backend\requirements.txt

# Apply Alembic database migrations (creates initial schema + assessment tables)
Set-Location backend
..\.venv\Scripts\alembic.exe upgrade head
Set-Location ..
```

---

### Step 3: Frontend Setup

```powershell
Set-Location frontend
npm install
Set-Location ..
```

---

### Step 4: Running the Applications

#### Terminal 1 — Start FastAPI Control Plane:
```powershell
.\.venv\Scripts\Activate.ps1
Set-Location backend
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```
- API Root: `http://127.0.0.1:8000/api/v1`
- Interactive OpenAPI Docs: `http://127.0.0.1:8000/docs`
- Health Probe: `http://127.0.0.1:8000/api/v1/health`
- Readiness Probe: `http://127.0.0.1:8000/api/v1/ready`

#### Terminal 2 — Start React Dashboard:
```powershell
Set-Location frontend
npm run dev
```
- Dashboard URL: `http://localhost:5173`

---

## 4. Bootstrapping Your First Admin Account & Testing an Assessment

1. Open `http://localhost:5173` in your browser.
2. Click **Authenticate** in the upper-right corner.
3. Select **Don't have an operator account? Register**.
4. Enter your details (e.g. `ciso@defense.corp`, password min 8 characters). The first registered user automatically receives the `ADMIN` role.
5. Create an Assessment Project (e.g. "Core Banking API Assessment").
6. Navigate to **Scopes & Target Authorization**:
   - Register a scope target (e.g. `api.banking.corp`). It starts in `PENDING` status.
   - Click **Authorize** on the target and enter signed ROE proof of authorization (e.g. `ROE-2026-ENGAGEMENT-401`).
7. Navigate to **Assessment Jobs**:
   - Click **Launch Assessment Job**.
   - Select your authorized target (`api.banking.corp`) and select a test profile (e.g. `WEB_APPLICATION_BASELINE` or `TLS_CONFIGURATION_CHECK`).
   - Click **Dispatch Assessment**.
   - Inspect the job status, findings, and click **Inspect Evidence Provenance** to view the raw payload and verified SHA-256 cryptographic digest.

---

## 5. Automated Verification & Testing

### Running Backend Tests (pytest):
```powershell
.\.venv\Scripts\Activate.ps1
.\.venv\Scripts\pytest.exe backend/tests
```
*Executes 92 automated tests covering:*
- *Phase 6A Secure Assessment Execution Boundary & Job Governance: typed execution contract, canonical scope snapshot & SHA-256 digest tampering detection, 11-state machine legal/illegal transition safety, worker heartbeat loss timeout detection (`WORKER_HEARTBEAT_LOST`), cancellation flow, hard pagination limit enforcement (`limit <= 100`), adapter capability registry discovery API, untrusted evidence boundary sanitization (`NaN`/`inf` CVSS rejection, 64KB payload truncation, finding clamp to 50), and clean host benchmark (`HARDENED_HOST_BASELINE`) zero-finding success decoupled from finding closures.*
- *Phase 5 & 5.1 Contextual Risk Intelligence & Security Audit: formula versioning (`v1.0.0`), deterministic factor decomposition, non-finite/NaN/inf CVSS rejection, CVSS vs. severity precedence rules, temporal freshness and timezone normalization, historical preservation on `FALSE_POSITIVE` / `VERIFIED_CLOSED`, residual risk tracking on `ACCEPTED_RISK`, recurrence penalties on `REOPENED`.*
- *Evidence-Aware Attack Path Traversal: bounded DFS ($\le 4$ depth, $\le 10$ paths), cycle avoidance, classification into `VERIFIED` ($\ge 0.7$ confidence), `MIXED_EVIDENCE`, `HYPOTHETICAL`, and `STALE` paths with explicit missing evidence.*
- *Defensive Remediation Governance: non-executing advisory playbooks, idempotency, Project LEAD / System ADMIN sign-off RBAC, mandatory justification, and finding lifecycle status invariance.*
- *API Dual-Scoping: strict parent-child project boundary validation on all risk, path, and remediation endpoints, plus hard pagination limits (`le=100`).*
- *Phases 1-4 Core: asset inventory normalization, conservative reconciliation, ambiguity resolution, relational knowledge graph node & edge idempotency, 13-state finding lifecycle transitions, deduplication fingerprinting, contradiction preservation, assessment state machines, execution boundary re-validation, cross-project isolation, and audit logging.*

### Running Frontend Tests (Vitest):
```powershell
Set-Location frontend
npm run test
Set-Location ..
```
*Executes 6 frontend unit tests covering token storage, request routing, scope validation, assessment orchestration, finding stats, and state machine transition requests.*

### Running Frontend Production Build:
```powershell
Set-Location frontend
npm run build
Set-Location ..
```
*Verifies TypeScript compilation and creates the production distribution in `frontend/dist` with zero errors.*
