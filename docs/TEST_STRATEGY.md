# VAPT Platform — Comprehensive Test Strategy & Verification Framework

**Document Version:** 1.0.0
**Target Environment:** Native Windows 11 Enterprise (PowerShell)
**Last Verified Commit:** Current Baseline
**Governing Standard:** IEEE 829 / ISO/IEC/IEEE 29119

---

## 1. Testing Philosophy & Verification Axioms

The VAPT Platform adheres to strict evidence-based quality assurance standards:
1. **Never Substitute Tests:** SQLite or mock tests are never used as a proxy for PostgreSQL concurrency tests.
2. **Fail-Closed Reporting:** A test is only marked **VERIFIED** when executed directly with exit code 0. Blocked tests are transparently classified as **BLOCKED** with explicit staging runbooks.
3. **Continuous Regression Testing:** After any bug fix or architectural enhancement, focused regression tests and full test suites must be executed before committing.
4. **Isolated & Disposable Fixtures:** Destructive migration, purge, and recovery tests must use isolated disposable test databases (`test_disp_*.db`).

---

## 2. Testing Taxonomy & Execution Matrix

```
+---------------------------------------------------------------------------------------------+
|                                    TESTING TAXONOMY MATRIX                                  |
+--------------------------+-----------------------+------------+-----------------------------+
| Test Domain              | Scope & Focus         | Tooling    | Execution Command           |
+--------------------------+-----------------------+------------+-----------------------------+
| 1. Backend Core Suite    | Unit, services, ORM,  | pytest     | cd backend                  |
|                          | state machines, APIs  | anyio      | ..\.venv\Scripts\pytest -q  |
+--------------------------+-----------------------+------------+-----------------------------+
| 2. Security Regression   | Scope boundary, auth, | pytest     | cd backend                  |
|                          | IPC sandbox, hashing  |            | ..\.venv\Scripts\pytest -q  |
|                          | injection defense     |            | tests/test_phase*security*.py|
+--------------------------+-----------------------+------------+-----------------------------+
| 3. PostgreSQL Readiness  | Dialect AST, pooling, | pytest     | cd backend                  |
|                          | SKIP LOCKED queries,  | psycopg    | ..\.venv\Scripts\pytest -v  |
|                          | transient retries     |            | tests/test_phase22_postgres |
+--------------------------+-----------------------+------------+-----------------------------+
| 4. Enterprise Integrations| CISA KEV enrichment,  | pytest     | cd backend                  |
|                          | signed webhooks, SIEM |            | ..\.venv\Scripts\pytest -v  |
|                          | CEF & Syslog exports  |            | tests/test_integrations.py  |
+--------------------------+-----------------------+------------+-----------------------------+
| 5. Frontend Unit & Build | React 19 views, typed | Vitest     | cd frontend                 |
|                          | API client, Vite      | Vite       | npm test -- --run           |
|                          | production bundle     | tsc        | npm run build               |
+--------------------------+-----------------------+------------+-----------------------------+
| 6. Database Migrations   | Bidirectional Alembic | Alembic    | cd backend                  |
|                          | forward upgrade and   | SQLAlchemy | alembic upgrade head        |
|                          | downgrade to base     |            | alembic downgrade base      |
+--------------------------+-----------------------+------------+-----------------------------+
```

---

## 3. Test Classification Guidelines

Every test execution result is classified into one of four mutually exclusive states:
- **PASSED:** The test ran to completion, all assertions evaluated to true, and the process exited with code 0.
- **FAILED:** An assertion failed or an unexpected exception was raised. Halts release immediately.
- **SKIPPED (BLOCKED):** An external infrastructure dependency is unavailable on the local host (e.g. a physical PostgreSQL 16 staging cluster on port 5432). The test fixture explicitly skips with the reason `BLOCKED: POSTGRES_TEST_DATABASE_URL is not set`.
- **NOT RUN:** The test has not yet been executed in the current audit cycle.

---

## 4. Reproducible Execution Commands

### Full Backend Verification
```powershell
cd C:\Users\Dark_Boy_\Downloads\VAPT_System\backend
..\.venv\Scripts\pytest.exe -v
```

### Focused Security Suite
```powershell
cd C:\Users\Dark_Boy_\Downloads\VAPT_System\backend
..\.venv\Scripts\pytest.exe tests/test_phase4_security_audit.py tests/test_phase5_security_audit.py tests/test_phase6b1_security_audit.py tests/test_phase7a1_security_review.py tests/test_phase7b1_readiness_audit.py tests/test_phase25_deployment_hardening.py tests/test_phase26_final_security_assessment.py tests/test_integrations.py -v
```

### Frontend Tests & Production Compilation
```powershell
cd C:\Users\Dark_Boy_\Downloads\VAPT_System\frontend
npm test -- --run
npm run build
```

### Disposable Database Migration Lifecycle Verification
```powershell
cd C:\Users\Dark_Boy_\Downloads\VAPT_System\backend
$env:DATABASE_URL = "sqlite:///test_disp_verify.db"
..\.venv\Scripts\alembic.exe upgrade head
..\.venv\Scripts\alembic.exe downgrade base
..\.venv\Scripts\alembic.exe upgrade head
Remove-Item test_disp_verify.db -ErrorAction SilentlyContinue
```

### PostgreSQL Staging Verification (When Staging Instance is Provisioned)
```powershell
cd C:\Users\Dark_Boy_\Downloads\VAPT_System\backend
$env:POSTGRES_TEST_DATABASE_URL = "postgresql+psycopg://staging_user:secure_pass@192.168.1.50:5432/vapt_staging_test"
..\.venv\Scripts\pytest.exe tests/test_phase22_postgres_readiness.py -v
```
