# VAPT Platform — Development Guide (Native Windows)

## 1. Native Windows Development Environment

The VAPT Platform is natively developed and operated on Windows 10/11 using PowerShell without requiring WSL or administrative system changes.

### Runtime Requirements
- **Python:** 3.12+ (Python 3.14.7 verified)
- **Node.js:** v20+ (Node v24.21.0, npm 11.19.0 verified)
- **PowerShell:** 5.1 or PowerShell 7+

---

## 2. Workspace Setup

### 1. Environment Configuration
```powershell
Copy-Item .env.example .env
```

### 2. Python Virtual Environment & Backend Setup
```powershell
# Create venv
python -m venv .venv

# Activate venv in PowerShell
.\.venv\Scripts\Activate.ps1

# Install pinned backend dependencies
python -m pip install -r backend\requirements.txt

# Run database migrations
Set-Location backend
..\.venv\Scripts\alembic.exe upgrade head
Set-Location ..
```

### 3. Frontend Setup
```powershell
Set-Location frontend
npm install
Set-Location ..
```

---

## 3. Running Development Servers

### Terminal 1 — Backend (FastAPI + Uvicorn)
```powershell
.\.venv\Scripts\Activate.ps1
Set-Location backend
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```
- API Base: `http://127.0.0.1:8000/api/v1`
- Swagger UI: `http://127.0.0.1:8000/docs`
- Health: `http://127.0.0.1:8000/api/v1/health`
- Readiness: `http://127.0.0.1:8000/api/v1/ready`

### Terminal 2 — Frontend (Vite)
```powershell
Set-Location frontend
npm run dev
```
- Dashboard: `http://localhost:5173`

---

## 4. Running Test Suites

### Backend Unit & Integration Tests (pytest)
```powershell
.\.venv\Scripts\Activate.ps1
.\.venv\Scripts\pytest.exe backend/tests
```

### Frontend Tests (Vitest)
```powershell
Set-Location frontend
npm run test
Set-Location ..
```

### Frontend Production Build
```powershell
Set-Location frontend
npm run build
Set-Location ..
```

---

## 5. Coding & Security Invariants

1. **Explicit Permissions:** Every route must use dependency injection (`verify_project_access`, `get_current_user`). Never rely on client-side state.
2. **Scope First:** Never introduce active scanning. In Phase 2, use `LocalFixtureAdapter` to simulate scanner output.
3. **Audit Everything Sensitive:** Sensitive state mutations must invoke `AuditService.record_event()`.
4. **No Secrets in Logs:** Detail payloads in audit logs and error messages must not contain raw passwords, keys, or tokens.
