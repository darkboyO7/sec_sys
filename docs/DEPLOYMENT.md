# VAPT Platform — Deployment, Setup & Maintenance Guide

**Document Version:** 1.0.0  
**Baseline Date:** 2026-10-28  
**Repository:** `D:\alt`  
**Target Operating Environment:** Windows Native (Windows 10/11, Windows Server 2019/2022)  
**Deployment Architecture:** Single-Machine Control Plane + Worker Daemon + SQLite WAL Mode (PostgreSQL 16 Staging Ready)

---

## 1. System Architecture & Prerequisites

The VAPT Platform consists of three primary execution tiers operating on a single host:

```mermaid
graph LR
    User["Security Operator / Browser"] --> ReverseProxy["Reverse Proxy (IIS / Caddy / Nginx)"]
    ReverseProxy -->|Static Assets| Frontend["Frontend UI (React 19 / Vite dist/)"]
    ReverseProxy -->|API Proxy /api/v1| Backend["FastAPI Control Plane (Port 8000)"]
    Backend --> DB[("SQLite WAL Database (vapt.db)")]
    WorkerDaemon["Background Worker Daemon"] -->|Poll & Claim Queue| DB
    WorkerDaemon -->|Win32 Job Object (512MB)| Scanner["Scanner Subprocess (ProcessWorker)"]
    Scanner -->|Probes / Live Sockets| Targets["Authorized Target Systems"]
```

### Host Prerequisites
- **Operating System:** Windows 10/11 (64-bit) or Windows Server 2019/2022.
- **Python:** Version 3.11, 3.12, 3.13, or 3.14 (64-bit).
- **Node.js:** Version 20.x or 22.x LTS (with npm).
- **Git:** Version 2.40+.
- **Disk Space:** Minimum 2 GB free space for database, logs, and audit archives.
- **Memory (RAM):** Minimum 4 GB RAM (8 GB recommended for concurrent worker execution).

---

## 2. Clean Windows Setup & Installation Procedure

Follow these steps to set up a reproducible installation from scratch:

### Step 1: Clone Repository & Create Virtual Environment
```powershell
# Set workspace directory
Set-Location D:\alt

# Create Python virtual environment
python -m venv .venv

# Activate virtual environment
.\.venv\Scripts\Activate.ps1
```

### Step 2: Install Backend Dependencies
```powershell
Set-Location D:\alt\backend
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### Step 3: Install Frontend Dependencies & Build Static Assets
```powershell
Set-Location D:\alt\frontend
npm install
npm run build
```
Verify that `frontend/dist/` is created cleanly containing `index.html` and bundled assets.

### Step 4: Initialize Database & Run Alembic Migrations
```powershell
Set-Location D:\alt\backend
$env:PYTHONPATH="D:\alt\backend"

# Run all 23 database migrations to head
..\.venv\Scripts\alembic upgrade head
```
Verify that `backend/data/vapt.db` is created with tables initialized.

### Step 5: Seed Initial Administrator & Project
```powershell
# Create initial LEAD administrator user
..\.venv\Scripts\python -c "from app.core.database import SessionLocal; from app.models.user import User, SystemRole; from app.core.security import hash_password; db = SessionLocal(); user = User(email='lead@example.com', hashed_password=hash_password('password123'), full_name='Security Lead', system_role=SystemRole.ADMIN, is_active=True); db.add(user); db.commit(); print('Initial admin created.'); db.close()"
```

---

## 3. Starting the Platform Services

For reliable operation, run the three platform tiers in dedicated processes (or configure them as Windows Services via NSSM / Task Scheduler):

### Service 1: API Control Plane (FastAPI / Uvicorn)
```powershell
# Terminal 1: FastAPI Control Plane
Set-Location D:\alt\backend
$env:PYTHONPATH="D:\alt\backend"
D:\alt\.venv\Scripts\uvicorn app.main:app --host 127.0.0.1 --port 8000
```

### Service 2: Background Assessment Worker Daemon
```powershell
# Terminal 2: Worker Daemon (handles queued scans, recovery, and recurring schedules)
Set-Location D:\alt\backend
$env:PYTHONPATH="D:\alt\backend"
D:\alt\.venv\Scripts\python scripts/run_background_worker.py --poll-interval 1.0
```

### Service 3: Frontend Web Interface
```powershell
# Terminal 3: Vite Development / Preview Server (Port 5173)
Set-Location D:\alt\frontend
npm run dev -- --host 127.0.0.1 --port 5173
```
Access the application at `http://127.0.0.1:5173`. Login with `lead@example.com` / `password123`.

---

## 4. Building Clean Release Artifacts

The repository includes an automated packaging tool that creates production distribution archives and performs automated security auditing:

```powershell
Set-Location D:\alt\backend
..\.venv\Scripts\python scripts/create_clean_release_package.py
```

### Release Invariants
- Output location: [`release/vapt_system_clean_release.zip`](file:///D:/alt/release/vapt_system_clean_release.zip)
- **Strictly Excluded:** `.git/`, `.venv/`, `node_modules/`, `data/`, `release/`, `.env`, `*.db`, `*.sqlite`, `*.log`, `*.tmp`.
- **Automated Security Audit:** The script validates that the generated zip file contains **zero** prohibited paths and **zero** unapproved private keys or API tokens before declaring success.

---

## 5. Upgrade, Maintenance, and Rollback Procedures

### Upgrading the Platform
1. **Take Backup:**
   Execute a consistent WAL backup following the procedure in [`docs/DISASTER_RECOVERY.md`](file:///D:/alt/docs/DISASTER_RECOVERY.md).
2. **Stop Daemons:**
   Stop the uvicorn API server and background worker processes.
3. **Pull Code & Install Dependencies:**
   ```powershell
   git pull origin main
   pip install -r backend/requirements.txt
   npm --prefix frontend install && npm --prefix frontend run build
   ```
4. **Run Migrations:**
   ```powershell
   Set-Location D:\alt\backend
   ..\.venv\Scripts\alembic upgrade head
   ```
5. **Restart Daemons:**
   Restart the API server and worker daemon. Verify `/ready` endpoint.

### Rollback Procedure
If a deployment fails:
1. Stop running services.
2. Revert Git repository to the prior release commit (`git checkout <PREVIOUS_COMMIT>`).
3. Restore the pre-upgrade database backup to `backend/data/vapt.db`.
4. Rebuild the frontend (`npm run build`).
5. Restart services and verify `/health` and `/ready`.
