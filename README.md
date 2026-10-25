# Vulnerability Assessment and Penetration Testing (VAPT) Platform
## Phase 1: Secure Foundation

A modular, multi-tenant cybersecurity intelligence and testing control plane. Built with Python, FastAPI, SQLAlchemy, Alembic, React, TypeScript, Vite, and Tailwind CSS.

---

## 1. Architectural Highlights

- **Control Plane Architecture:** Modular monolith design with strict separation of concerns, providing the control and governance layer before introducing isolated assessment workers.
- **Fail-Closed Target Scoping:** Target registration and proof of authorization are strictly decoupled. A target registered in the system remains `PENDING` and cannot be scanned until an authorized lead records verified evidence (Rules of Engagement, approval ticket, expiry).
- **Scope Exclusions:** Exclusions take absolute precedence over inclusions, ensuring critical infrastructure or third-party services are immediately rejected.
- **Non-Invasive Scope Console:** In-memory pre-flight validator that checks candidate targets without initiating network probes or DNS traffic.
- **Immutable Audit Ledger:** All sensitive actions (login, project creation, target registration, scope authorization, scope revocation, exclusion management) record actor attribution, client IP, outcome, and timestamp with automated credential scrubbing.
- **Data Persistence:** Native Windows development uses SQLite 3 with `PRAGMA journal_mode=WAL` and `PRAGMA foreign_keys=ON`. The data layer is fully compatible with PostgreSQL in production via SQLAlchemy 2.0 and Alembic.

---

## 2. Directory Structure

```text
VAPT_System/
├── .env.example              # Configuration template with secure defaults
├── .gitignore                # Windows, Python, Node, Vite, SQLite exclusions
├── README.md                 # Setup, verification, and operation guide
├── docs/
│   ├── ARCHITECTURE.md       # Modular design, fail-closed engine, data models
│   ├── THREAT_MODEL.md       # STRIDE analysis, project isolation, secret redaction
│   └── ROADMAP.md            # Multi-year phase milestones
├── backend/
│   ├── requirements.txt      # Pinned Python dependencies
│   ├── pyproject.toml        # Pytest configuration & settings
│   ├── alembic.ini           # Migration configuration
│   ├── alembic/              # Versioned database migrations
│   ├── app/
│   │   ├── main.py           # FastAPI entrypoint, middleware, lifespan
│   │   ├── core/             # Configuration, security (Bcrypt/JWT), database
│   │   ├── models/           # Declarative models (User, Org, Project, Scope, Audit)
│   │   ├── schemas/          # Strict Pydantic v2 schemas
│   │   ├── services/         # Scope validation engine, audit service
│   │   └── api/v1/           # Versioned endpoints (Health, Auth, Projects, Scopes, Audit)
│   └── tests/                # Automated pytest suite (20 tests)
└── frontend/
    ├── package.json          # React 19, TypeScript, Vite, Tailwind CSS, Vitest
    ├── vite.config.ts        # Vite configuration with API reverse proxy
    ├── src/
    │   ├── components/       # Header, Navigation, ScopeValidationConsole, Modals
    │   ├── views/            # Overview, ScopeManagement, AuditLedger, SystemHealth
    │   ├── services/         # Typed API client connecting to /api/v1
    │   ├── tests/            # Vitest unit test suite
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
# Copy the environment template
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

# Apply Alembic database migrations
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

## 4. Bootstrapping Your First Admin Account

1. Open `http://localhost:5173` in your browser.
2. Click **Authenticate** in the upper-right corner.
3. Select **Don't have an operator account? Register**.
4. Enter your details (e.g. `ciso@defense.corp`, password min 8 characters).
5. **Bootstrap Guarantee:** The very first user created in an empty database is automatically assigned the `ADMIN` role. Subsequent users receive their chosen or assigned role.

---

## 5. Automated Verification & Testing

### Running Backend Tests (pytest):
```powershell
.\.venv\Scripts\Activate.ps1
Set-Location backend
..\.venv\Scripts\pytest.exe
Set-Location ..
```
*Executes 20 automated tests covering health probes, authentication, persistence across restarts, foreign keys, project isolation, scope exclusions, authorization expiry, and audit trail scrubbing.*

### Running Frontend Tests (Vitest):
```powershell
Set-Location frontend
npm run test
Set-Location ..
```
*Executes frontend unit tests covering token storage, request routing, and scope validation console.*

### Running Frontend Production Build:
```powershell
Set-Location frontend
npm run build
Set-Location ..
```
*Verifies TypeScript compilation and creates the production distribution in `frontend/dist`.*
