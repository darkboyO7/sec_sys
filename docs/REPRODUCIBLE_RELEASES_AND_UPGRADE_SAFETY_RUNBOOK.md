# Reproducible Releases, Upgrade Safety and Deployment Acceptance Runbook (Prompt 44)

## 1. Objective and System Architecture
Prompt 44 establishes a repeatable, verifiable, and recoverable release packaging and safe application upgrade process for the VAPT Platform in the supported Windows environment.

It ensures:
- **Zero Configuration Overwrites:** User databases (`vapt.db`), recovery bundles, and environment configurations are strictly protected from overwrite during releases and upgrades.
- **Dependency Reproducibility:** Exact pinned versions for all runtime dependencies; clear separation between production runtime requirements and development/testing tools.
- **Safe Candidate Staging:** Release candidates are staged in `dist/candidates/` and independently verified before atomic promotion to `dist/`, preserving the last known-good release.
- **Automated Upgrade Safety:** Automated point-in-time database snapshot backups before running Alembic migrations, followed by post-upgrade schema integrity checks and an unambiguous rollback path.
- **Secure Windows Native Operations:** Native `.bat` and `.ps1` scripts that operate without requiring WSL, avoid hardcoded user paths, redact secrets, and implement bounded health probes.

---

## 2. Dependency Strategy & Manifest Governance

### 2.1 Backend Python Manifests
- **Runtime Manifest (`backend/requirements.txt`):**
  Contains only the packages required to run the production FastAPI application and database engines:
  ```text
  fastapi==0.162.0
  uvicorn[standard]==0.54.0
  pydantic==2.14.1
  pydantic-settings==2.16.1
  email-validator==2.3.0
  dnspython==2.9.0
  sqlalchemy==2.1.6
  alembic==1.20.1
  bcrypt==5.0.0
  pyjwt[crypto]==2.15.1
  cryptography==50.0.2
  httpx==0.28.1
  python-dotenv==1.2.4
  psycopg==3.3.6
  psycopg-binary==3.3.6
  ```
- **Development & Test Manifest (`backend/requirements-dev.txt`):**
  Extends `requirements.txt` with testing fixtures and test runners:
  ```text
  -r requirements.txt
  pytest==8.4.2
  pytest-asyncio==1.4.0
  ```

### 2.2 Frontend Node Manifests
- **Production Runtime (`frontend/package.json` -> `dependencies`):**
  Includes UI libraries (`react`, `react-dom`, `lucide-react`).
- **Development Tools (`frontend/package.json` -> `devDependencies`):**
  Includes `vite`, `vitest`, `typescript`, `tailwindcss`, and build plugins. Locked reproducibly via `package-lock.json`.

---

## 3. Packaging Rules, Exclusions & Asset Inclusion

### 3.1 Strict Packaging Exclusions (`FORBIDDEN_RELEASE_PATTERNS`)
The packaging engine in `SupplyChainSecurityService.build_release_package()` unconditionally audits and excludes:
- Git internals: `^\.git`
- Dependency trees & environments: `^node_modules`, `^\.venv`
- Caches: `^__pycache__`, `^\.pytest_cache`, `^\.coverage`, `^htmlcov`
- Local databases & transaction logs: `vapt.db`, `vapt_test.db`, `*.sqlite*`, `*-wal`, `*-shm`, `*-journal`
- Environment secrets & private configurations: `^\.env$`, `^\.env\.local$`
- Temporary test evidence & log files: `^temp_evidence`, `*.log`
- User data directories: `backend/data`, `backend/tests`

### 3.2 Bundled Runtime Assets
The release archive (`vapt-platform-v{version}.tar.gz`) bundles:
- `backend/app/` (Application source code, routers, services, models, schemas)
- `backend/alembic/` & `backend/alembic.ini` (Database migration scripts)
- `backend/requirements.txt` (Runtime dependency manifest)
- `frontend/dist/` (Pre-compiled production static distribution bundle)
- `scripts/windows/` (`start_platform.bat`, `start_platform.ps1`, `upgrade_platform.bat`, `upgrade_platform.ps1`)
- Root launchers: `start_platform.bat`, `upgrade_platform.bat`
- Templates: `.env.example`, `.env.production.example`
- Documentation: `README.md`
- Software Bill of Materials: `reports/sbom/vapt-sbom.cdx.json`

---

## 4. Release Packaging & Staging Workflow

### 4.1 Step 1: Pre-Release Acceptance Qualification
Before building a candidate, execute the full release qualification gate:
```powershell
python scripts/release_qualification_gate.py
```
*Gate fails closed if any test, type check, build, secret scan, or migration check fails.*

### 4.2 Step 2: Build Staged Release Candidate
Stage the candidate without touching existing production releases:
```powershell
python scripts/build_release.py --candidate --version 1.0.0
```
- Artifact: `dist/candidates/vapt-platform-v1.0.0-candidate.tar.gz`
- Manifest: `dist/candidates/release-manifest-v1.0.0-candidate.json`

### 4.3 Step 3: Verify Candidate & Atomic Promotion
Verify archive checksums and HMAC-SHA256 signature, then promote:
```powershell
python scripts/build_release.py --candidate --promote --version 1.0.0
```
- Promoted Archive: `dist/vapt-platform-v1.0.0.tar.gz`
- Promoted Manifest: `dist/release-manifest.json`

---

## 5. Safe Platform Upgrade Procedure

### 5.1 Automated Upgrade Execution
To upgrade an existing installation safely:
```cmd
upgrade_platform.bat
```
or via PowerShell:
```powershell
.\scripts\windows\upgrade_platform.ps1
```

### 5.2 Upgrade Phases & Safeguards
1. **Pre-Upgrade Evaluation:** Evaluates current database version and pending migration count.
2. **Point-in-Time Database Backup:** Creates a timestamped snapshot of `backend/data/vapt.db` in `backend/data/backups/vapt_pre_upgrade_YYYYMMDD_HHMMSS.db`.
3. **Migration Application:** Runs `python -m alembic upgrade head` within transactional safety.
4. **Post-Upgrade Preflight:** Verifies database schema, connectivity, and cryptographic keys.

### 5.3 Rollback & Recovery Path
If a schema migration fails or post-upgrade checks report fatal errors:
1. Stop running platform processes.
2. Restore the pre-upgrade snapshot from `backend\data\backups\`:
   ```powershell
   Copy-Item "backend\data\backups\vapt_pre_upgrade_<timestamp>.db" "backend\data\vapt.db" -Force
   ```
3. Re-launch the platform via `start_platform.bat`.

---

## 6. Windows Startup & Process Supervision

### 6.1 Launching the Platform
```cmd
start_platform.bat
```
or with PowerShell:
```powershell
.\scripts\windows\start_platform.ps1 -Environment development -Port 8000
```

### 6.2 Security Controls
- **No Hardcoded Paths:** Resolves directories relative to `%~dp0` / `$PSScriptRoot`.
- **Secret Redaction:** Console output displays sanitized status without printing `SECRET_KEY` or passwords.
- **Port Conflict Awareness:** Checks whether port 8000 is occupied and warns operators before attempting bind.
- **Bounded Readiness Wait:** Probes `http://127.0.0.1:8000/api/v1/health` with a 15-second bounded loop.
