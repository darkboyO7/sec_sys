# VAPT Platform — Native Windows Deployment Guide

**Target Environment:** Native Windows 11 Enterprise / Pro or Windows Server 2022+ (No WSL, No Docker)  
**Architecture:** FastAPI Control Plane + Native Windows Subprocess Workers with Win32 Job Objects + SQLite 3 WAL Mode + Vite/React Frontend  
**Security Status:** Hardened, Fail-Closed, Non-Destructive  

---

## 1. System Prerequisites

| Component | Minimum Requirement | Verified Version | Purpose |
| :--- | :--- | :--- | :--- |
| **Operating System** | Windows 11 (build 22621+) or Windows Server 2022 | Windows 11 Enterprise | Host OS |
| **Shell** | PowerShell 5.1 / PowerShell 7+ | PowerShell 5.1+ | Operations & Automation |
| **Python** | Python 3.12+ (64-bit) | Python 3.14.7 | Backend runtime & scanner execution |
| **Node.js & npm** | Node 20+ LTS / npm 10+ | Node v24.21.0 / npm 11.19.0 | Frontend build & static assets |
| **Database** | SQLite 3.40+ (built into Python) | SQLite 3.50.4 | Single-node production database with WAL mode |
| **PostgreSQL Driver** | `psycopg` 3.x | psycopg 3.3.6 | Multi-worker staging readiness |

---

## 2. Directory Structure & Filesystem Permissions

Set up the production directory layout:
```text
C:\VAPT_System\
├── backend\
│   ├── app\
│   ├── alembic\
│   ├── data\             <-- SQLite database (vapt.db) and backups (RESTRICTED ACL)
│   └── logs\             <-- Structured operational and audit logs
├── frontend\
│   └── dist\             <-- Compiled production web assets
└── .env.production       <-- Production configuration (PROTECTED ACL)
```

### Windows Security & File Access Controls (ICACLS)
Enforce strict least-privilege ACLs so only the dedicated service user and Administrators have access to sensitive directories:
```powershell
# Disable inheritance and grant exclusive access to the VAPT service account
icacls "C:\VAPT_System\backend\data" /inheritance:r /grant:r "Administrators:(OI)(CI)F" "SYSTEM:(OI)(CI)F"
icacls "C:\VAPT_System\.env.production" /inheritance:r /grant:r "Administrators:F" "SYSTEM:F"
```

---

## 3. Environment & Secret Provisioning

Create `C:\VAPT_System\.env.production` with high-entropy cryptographic keys:

```ini
# Production Mode & Fail-Closed Enforcement
ENVIRONMENT=production
DEBUG=False
PROJECT_NAME="VAPT Intelligence Platform"

# Cryptographic Trust Anchor
# Sourced from 64-char hex or high-entropy base64 string
SECRET_KEY=9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=480

# Primary Single-Node Database (SQLite WAL)
DATABASE_URL=sqlite:///./data/vapt.db

# Process Execution & Win32 Sandbox Boundaries
EXECUTION_MODE=SUBPROCESS
PROCESS_WORKER_TIMEOUT_SECONDS=120
MAX_CONCURRENT_JOBS=4
WORKER_MEMORY_LIMIT_BYTES=536870912   # 512MB ceiling enforced via Win32 Job Object
WORKER_HEARTBEAT_TIMEOUT_SECONDS=30

# CORS & Frontend Origins (Explicit, no wildcards allowed in production)
ALLOWED_ORIGINS=["http://localhost:8000","http://127.0.0.1:8000"]

# Risk & Knowledge Graph Governance
RISK_MODEL_VERSION=1.1.0
GRAPH_TRAVERSAL_MAX_DEPTH=5
GRAPH_TRAVERSAL_MAX_NODES=100
```

---

## 4. Database Initialization & Migration

1. Activate virtual environment:
```powershell
Set-Location "C:\VAPT_System\backend"
& ..\.venv\Scripts\Activate.ps1
```

2. Run Alembic database migrations:
```powershell
python -m alembic upgrade head
```
Expected output: Migrates through 22 revisions up to `b3c4d5e6f7a8` (Phase 23 composite performance indexes).

3. Verify SQLite WAL mode:
```powershell
python -c "import sqlite3; conn = sqlite3.connect('data/vapt.db'); print('Journal Mode:', conn.execute('PRAGMA journal_mode;').fetchone()[0])"
# Expected output: Journal Mode: wal
```

---

## 5. Frontend Production Compilation

1. Install dependencies and compile Vite bundle:
```powershell
Set-Location "C:\VAPT_System\frontend"
npm install
npm test -- --run
npm run build
```
2. Verify compiled bundle in `frontend/dist/`:
- `dist/index.html`
- `dist/assets/*.css`
- `dist/assets/*.js`

---

## 6. Service Execution & Verification

### Launching the Backend Control Plane
Run Uvicorn bound to localhost with production workers:
```powershell
Set-Location "C:\VAPT_System\backend"
$env:ENV_FILE = "C:\VAPT_System\.env.production"
uvicorn app.main:app --host 127.0.0.1 --port 8000 --workers 2 --no-access-log
```

### Health & Readiness Probes
```powershell
# Liveness probe
Invoke-RestMethod -Uri http://127.0.0.1:8000/api/v1/health
# Expected: @{ status = "ok" }

# Readiness probe (verifies database connectivity and storage writability)
Invoke-RestMethod -Uri http://127.0.0.1:8000/api/v1/ready
# Expected: @{ status = "ready"; checks = @{ database = $true; storage_writable = $true } }
```
