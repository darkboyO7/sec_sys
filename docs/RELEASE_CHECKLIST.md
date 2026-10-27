# VAPT Platform — Pre-Release Verification Checklist & Sign-Off

**Target Checkpoint:** Release Milestone  
**Deployment Profile:** Native Windows 11 Enterprise (SQLite WAL)  

---

## 1. Pre-Flight Verification Gates

All verification gates must be executed and confirmed prior to tagging any release:

- [x] **Gate 1: Repository & Working Tree Hygiene**
  - Branch: `main`
  - Working tree clean (0 uncommitted modifications, 0 untracked files).
  - Mirror parity: `git diff alt/main` returns 0 differences.
  - Secret scan: No passwords, keys, or tokens committed in Git history.

- [x] **Gate 2: Database Migration Integrity**
  - Full upgrade executed: `alembic upgrade head` reaches head revision (`b3c4d5e6f7a8`).
  - Disposable downgrade test: `alembic downgrade base` and re-upgrade `alembic upgrade head` succeed cleanly.
  - Offline PostgreSQL DDL: `alembic upgrade head --sql` generates valid transactional SQL without errors.

- [x] **Gate 3: Automated Backend Test Suite**
  - Complete backend test suite passes: `pytest -q` (248+ tests passed, 0 failures).
  - Security regression suite passes: `pytest <security_files> -v` (69+ tests passed).
  - PostgreSQL readiness suite passes: `pytest tests/test_phase22_postgres_readiness.py -v` (12 tests passed).
  - Simulated 13-step acceptance workflow passes: `test_e2e_operational_acceptance.py`.

- [x] **Gate 4: Frontend Contract & Build Verification**
  - Frontend unit tests pass: `npm test -- --run` (6 / 6 passed).
  - Production build succeeds: `npm run build` compiles clean bundle (`dist/index.html`, 74KB CSS, 506KB JS).

- [x] **Gate 5: Deployment Hardening & Security Configuration**
  - `ENVIRONMENT=production` rejects default weak keys (`test-secret-key-for-development-only`).
  - `DEBUG=False` blocks internal tracebacks.
  - CORS rejects wildcards (`*`) in production.
  - Security headers present on all endpoints (`X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Strict-Transport-Security`, `Content-Security-Policy`).

- [x] **Gate 6: Disaster Recovery & Data Governance**
  - Online non-blocking SQLite WAL backup verified (`VACUUM INTO`).
  - Sandbox restore test passes `PRAGMA integrity_check == 'ok'`.
  - Right-to-Erasure project purge cascading verified.

---

## 2. Release Rollback Procedures

If an unexpected critical defect is discovered immediately post-release:
1. **Application Code Rollback:**
   ```powershell
   git checkout <PreviousStableCommit>
   ```
2. **Database Rollback:**
   - If migrations were applied, run:
   ```powershell
   python -m alembic downgrade <TargetRevision>
   ```
   - If schema downgrade is non-trivial, restore verified pre-release database snapshot following [`docs/BACKUP_RECOVERY.md`](file:///C:/Users/Dark_Boy_/Downloads/VAPT_System/docs/BACKUP_RECOVERY.md).
3. **Frontend Rollback:**
   ```powershell
   cd frontend
   npm run build
   ```
4. **Service Restart & Health Probe:**
   ```powershell
   Invoke-RestMethod -Uri http://127.0.0.1:8000/api/v1/ready
   ```
