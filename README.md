# Vulnerability Assessment and Penetration Testing (VAPT) Platform
## Phase 1–4: Secure Foundation, Assessment Orchestration, Finding Lifecycle, Asset Inventory & Knowledge Graph

A modular, multi-tenant cybersecurity intelligence and testing control plane. Built natively for Windows with Python 3.14, FastAPI, SQLAlchemy 2.0, Alembic, React 19, TypeScript, Vite, and Tailwind CSS.

---

## 1. Architectural Highlights

- **Control Plane Architecture:** Modular monolith control plane providing governance, authorization, and auditability prior to introducing isolated assessment workers.
- **Fail-Closed Target Scoping:** Target registration and proof of authorization are strictly decoupled. A target registered in the system remains `PENDING` and cannot be scanned until an authorized lead records verified evidence (Rules of Engagement, approval ticket, expiry).
- **Scope Exclusions:** Exclusions take absolute precedence over inclusions, ensuring critical infrastructure or third-party services are immediately rejected.
- **Non-Invasive Scope Console:** In-memory pre-flight validator that checks candidate targets without initiating network probes or DNS traffic.
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
  - Deterministic identifier normalization across Web Apps, API Endpoints, IPv4 (with octal zero stripping), IPv6 compression, CIDRs, Services, and Domains.
  - Conflict-preserving attribute reconciliation tracking chronological changes in `_attribute_history`.
  - Identity ambiguity tracking (`is_ambiguous`, `ambiguity_reason`) with audit-logged operator resolution governance.
- **Universal Security Knowledge Graph (Phase 4):**
  - PostgreSQL-compatible relational graph tables (`graph_nodes`, `graph_relationships`) with index-backed adjacency joins.
  - 13 security entity categories (`ASSET`, `SERVICE`, `APPLICATION`, `IDENTITY`, `ROLE`, `PERMISSION`, `VULNERABILITY`, `FINDING`, `EVIDENCE`, `SECURITY_CONTROL`, `DEPENDENCY`, `REMEDIATION`, `ASSESSMENT`) and 11 relationship types.
  - Epistemic verification statuses (`VERIFIED`, `INFERRED`, `HYPOTHETICAL`, `STALE`, `SUPERSEDED`) and confidence metrics ($0.0 \le c \le 1.0$).
  - Bounded, cycle-safe BFS traversal with strict depth, node, and edge bounds, plus truncation signaling.
  - Automatic assessment integration: assessments automatically reconcile assets, record observations, link findings, and generate graph nodes and edges.
  - Full React 19 visualizer with SVG layout, verification status styling, node inspector, and edge creator.
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
*Executes 50 automated tests covering asset inventory normalization, conservative reconciliation, ambiguity resolution, relational knowledge graph node & edge idempotency, cycle-safe bounded traversal, cross-project graph isolation, assessment-to-asset-to-graph auto-linkage, 13-state finding lifecycle transitions, deduplication fingerprinting, contradiction preservation, reopening, risk acceptance expiration sweeps, assessment state machines, boundary re-validation, cross-project isolation, and audit logging.*

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
