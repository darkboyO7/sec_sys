# Database Migration and Rollback Guide
**Platform:** VAPT Security Operations Platform  
**Target Environments:** Development (SQLite WAL), Staging & Production (PostgreSQL 14+)  
**Date:** October 31, 2026  

---

## 1. Overview
This guide provides authoritative procedures for executing, verifying, and rolling back database migrations across local development and enterprise PostgreSQL production environments.

---

## 2. Environment Configuration

### Local Development (SQLite WAL Mode)
No configuration required. The platform defaults to:
```bash
DATABASE_URL="sqlite:///D:/alt/backend/data/vapt.db"
```
SQLite WAL pragmas and busy timeouts (30,000ms) are configured automatically on engine connection.

### Production & Staging (Enterprise PostgreSQL)
Production environments require a managed PostgreSQL 14+ instance. Configure `.env`:
```bash
ENVIRONMENT="production"
DEBUG="false"
DATABASE_URL="postgresql+psycopg2://vapt_admin:<STRONG_PASSWORD>@db.prod.internal:5432/vapt_production"
POSTGRES_POOL_SIZE=20
POSTGRES_MAX_OVERFLOW=10
POSTGRES_POOL_TIMEOUT=30
POSTGRES_POOL_RECYCLE=1800
DB_RETRY_MAX_ATTEMPTS=3
DB_RETRY_BASE_DELAY_SECONDS=0.05
```

> [!IMPORTANT]
> The platform's startup preflight checks (`validate_production_hardening`) reject SQLite databases, empty passwords, and default credentials (`postgres:postgres`) when running in `production` or `staging` mode.

---

## 3. Migration Runbook

### Step 1: Pre-Migration Backup
Before running migrations on any production database, capture an immutable snapshot:
```bash
# PostgreSQL pg_dump snapshot
pg_dump -Fc -v -h db.prod.internal -U vapt_admin vapt_production > vapt_pre_migration_$(date +%Y%m%d_%H%M%S).dump

# Verify backup integrity
pg_restore --list vapt_pre_migration_*.dump > /dev/null
```

### Step 2: Check Current Migration State
```powershell
cd D:\alt\backend
..\.venv\Scripts\python.exe -m alembic current
```

### Step 3: Apply Latest Migrations
```powershell
cd D:\alt\backend
..\.venv\Scripts\python.exe -m alembic upgrade head
```

### Step 4: Verify Schema Health
Verify all models and tables exist and match declarative definitions:
```powershell
cd D:\alt
.venv\Scripts\python.exe -c "
import sys; sys.path.insert(0, 'backend')
from app.core.database import SessionLocal
from app.services.database_diagnostics_service import DatabaseDiagnosticsService
s = SessionLocal()
diag = DatabaseDiagnosticsService.run_diagnostics(s)
print('Health:', diag['healthy'])
print('Engine:', diag['database']['engine'])
print('Alembic Revision:', diag['schema']['alembic_revision'])
s.close()
"
```

---

## 4. Rollback Runbook

### Scenario A: Clean Alembic Downgrade
If an issue is identified immediately after applying a migration:
```powershell
# Downgrade to previous revision (e.g. 51a0b1c2d3e4)
cd D:\alt\backend
..\.venv\Scripts\python.exe -m alembic downgrade 51a0b1c2d3e4

# Verify downgraded head
..\.venv\Scripts\python.exe -m alembic current
```

### Scenario B: Emergency Point-In-Time Restoration
If schema corruption occurs during migration:
1. Stop the application backend service.
2. Restore the pre-migration snapshot:
   ```bash
   dropdb -h db.prod.internal -U vapt_admin vapt_production
   createdb -h db.prod.internal -U vapt_admin vapt_production
   pg_restore -v -h db.prod.internal -U vapt_admin -d vapt_production vapt_pre_migration_*.dump
   ```
3. Run schema diagnostics to verify table count and integrity.
4. Restart application services.

---

## 5. Dual-Dialect Verification Checklist

- [x] All 93 tables compile cleanly under PostgreSQL and SQLite dialects.
- [x] All 420 indexes compile without syntax errors.
- [x] Circular foreign keys configured with `use_alter=True`.
- [x] All primary keys use standardized UUID strings (`VARCHAR(36)`).
- [x] Timestamps use `DateTime(timezone=True)` mapping to `TIMESTAMPTZ` on PostgreSQL.
- [x] Safe transaction retries (`@with_safe_transaction_retry`) configured for transient deadlocks and locked states.
- [x] Non-idempotent operations strictly excluded from transaction retries.
- [x] Real-time connection pool metrics exposed via diagnostics endpoints.
