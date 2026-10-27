# VAPT Platform — Windows Operations & Administration Runbook

## 1. Operating Environment Overview

The VAPT Platform is natively engineered for **Windows 11 / Windows Server 2022+** environments. It requires **no WSL dependency** and **no Docker containers** for local execution and development.

### 1.1. Host Prerequisites
- **Operating System**: Windows 11 Enterprise / Pro or Windows Server 2022.
- **Python**: 3.11 through 3.14 (Verified: Python 3.14.7 in `.venv`).
- **Node.js**: 18.x through 24.x (Verified: Node.js v24.21.0, npm 11.19.0).
- **Shell**: PowerShell 5.1+ or PowerShell 7+.
- **Database**: Native SQLite 3 (WAL mode) or external PostgreSQL service.

---

## 2. Directory Structure & Layout

```
C:\Users\Dark_Boy_\Downloads\VAPT_System
├── backend/
│   ├── alembic/             # Database migration scripts
│   ├── app/                 # FastAPI application core
│   │   ├── api/v1/          # REST API endpoints & route handlers
│   │   ├── core/            # Config, security, DB connections
│   │   ├── models/          # SQLAlchemy ORM models
│   │   ├── schemas/         # Pydantic request/response schemas
│   │   ├── services/        # Business logic & security engines
│   │   └── worker/          # Subprocess worker runner & IPC
│   ├── data/                # SQLite databases (vapt.db, vapt_test.db)
│   └── tests/               # Pytest automated test suites
├── frontend/
│   ├── src/                 # React 18, TypeScript, Tailwind CSS
│   ├── dist/                # Production build output
│   └── package.json         # Frontend dependencies & scripts
├── docs/                    # Architecture, threat model, runbooks
└── .venv/                   # Python virtual environment
```

---

## 3. Step-by-Step Service Startup

### 3.1. Backend Service Startup (PowerShell)
```powershell
# Navigate to backend root
cd C:\Users\Dark_Boy_\Downloads\VAPT_System\backend

# Run database migrations to head
..\.venv\Scripts\python -m alembic upgrade head

# Start FastAPI application
..\.venv\Scripts\python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```
- API Documentation (Swagger UI): `http://127.0.0.1:8000/docs`
- Health Probe: `http://127.0.0.1:8000/health`
- Readiness Probe: `http://127.0.0.1:8000/ready`

### 3.2. Frontend Web Interface Startup (PowerShell)
```powershell
# Navigate to frontend directory
cd C:\Users\Dark_Boy_\Downloads\VAPT_System\frontend

# Start Vite development server
npm run dev
```
- Web Application: `http://localhost:5173`

### 3.3. Production Frontend Compilation
```powershell
cd C:\Users\Dark_Boy_\Downloads\VAPT_System\frontend
npm run build
```
- Generates optimized static assets in `frontend/dist/`.

---

## 4. Subprocess Worker Management on Windows

- Workers are dynamically spawned by `SubprocessWorkerRunner` when assessment jobs transition to `RUNNING`.
- Each worker runs `backend/app/worker/process_worker.py` in an isolated Python subprocess attached to a Win32 Job Object.
- Workers automatically terminate upon job completion or if a 180-second timeout is exceeded.
- Emergency shutdown can be initiated via API (`/api/v1/projects/{id}/adaptive-defense/kill-switch`) or by restarting the backend service.

---

## 5. Safe Secondary Mirror Synchronization (`D:\alt`)

To maintain a backup mirror in `D:\alt` without risking accidental file loss:

> [!WARNING]
> **Never use `robocopy /MIR`** to synchronize repositories, as it can erase uncommitted edits and destroy Git metadata.

### Approved Git Mirror Push Workflow:
```powershell
# Check working tree in primary repository
cd C:\Users\Dark_Boy_\Downloads\VAPT_System
git status

# Commit changes locally
git add .
git commit -m "feat/fix: descriptive commit message"

# Push directly to the secondary mirror remote
git push alt main
```
To verify status on `D:\alt`:
```powershell
cd D:\alt
git status
git log -1 --oneline
```
