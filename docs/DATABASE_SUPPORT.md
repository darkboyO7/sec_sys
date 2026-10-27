# VAPT Platform — Database Support & Concurrency Architecture

## 1. Overview

The VAPT Platform implements a dual-engine database architecture designed for zero-dependency local Windows deployment and high-throughput multi-worker enterprise clustering:
1. **SQLite 3 with Write-Ahead Logging (WAL)**: Verified single-node production engine and primary local development database.
2. **PostgreSQL (v15+) with `psycopg` 3**: Multi-worker cluster engine with transactional retries and distributed row locking.

---

## 2. SQLite WAL Production Engine

On single-server deployments (e.g. Windows native workstation or on-premise security appliance), SQLite provides exceptional performance, low operational overhead, and robust ACID transaction guarantees when configured with WAL mode.

### 2.1. Verified SQLite Pragmas
When initialized in `backend/app/core/database.py` and `conftest.py`, the following PRAGMAs are enforced:
```sql
PRAGMA journal_mode = WAL;          -- Allows concurrent readers while writer writes
PRAGMA synchronous = NORMAL;        -- High durability with minimal disk sync overhead
PRAGMA busy_timeout = 5000;         -- 5-second wait queue for writer lock contention
PRAGMA foreign_keys = ON;           -- Strict referential integrity enforcement
```

### 2.2. Concurrency Characteristics
- **Single-Writer / Many-Readers**: Multiple web worker threads can read concurrently without blocking.
- **Write Serialization**: Write operations are serialized. If two requests attempt to write simultaneously, SQLite waits up to 5,000ms (`busy_timeout`) before raising `OperationalError: database is locked`.

---

## 3. PostgreSQL Multi-Worker Readiness

For distributed enterprise deployments with multiple concurrent scan worker nodes, the platform includes a complete PostgreSQL dialect integration:

### 3.1. Connection Pooling Configuration
- **Engine**: `postgresql+psycopg://` (`psycopg` v3.3.6 verified in `.venv`)
- **Pool Type**: SQLAlchemy `QueuePool`
- **Pool Sizing & Lifecycle**:
  - `POSTGRES_POOL_SIZE`: 20 connections.
  - `POSTGRES_MAX_OVERFLOW`: 10 connections.
  - `POSTGRES_POOL_TIMEOUT`: 30 seconds.
  - `POSTGRES_POOL_RECYCLE`: 1800 seconds (30 minutes).
  - `pool_pre_ping`: `True` (automatic dead connection eviction before checkout).

### 3.2. Deadlock Detection & Transaction Retry
High concurrency across workers can lead to transaction serialization failures (`40001`), deadlocks (`40P01`), or lock timeouts (`55P03`). The platform implements exponential backoff retry logic:
- `with_transaction_retry(max_retries=3, base_delay=0.05, backoff_factor=2.0)`: Decorator that intercepts PostgreSQL transient serialization errors, rolls back the subtransaction, and retries with jittered exponential delay.

### 3.3. Distributed Job Claims (`FOR UPDATE SKIP LOCKED`)
To prevent duplicate job dispatch when multiple worker processes poll for pending assessments:
- The job query engine compiles PostgreSQL-specific `SELECT ... FOR UPDATE SKIP LOCKED` queries (`AssessmentExecutionEngine.claim_next_available_job`).
- Each worker locks only the unassigned job it is claiming; other workers seamlessly skip locked rows without waiting or blocking.

### 3.4. Credential & Secret Protection
- `get_masked_database_url`: Database credentials in connection strings (e.g. `postgresql+psycopg://user:password@host/db`) are automatically masked as `***` in error formatting and logs.

### 3.5. Verification Status
- **Dialect AST & Pooling**: **VERIFIED** — 12 automated tests in `tests/test_phase22_postgres_readiness.py` passing:
  - Table DDL generation for all 17+ domain tables under PostgreSQL dialect.
  - `FOR UPDATE SKIP LOCKED` AST query generation verified.
  - Connection pool configuration (`QueuePool`, pool size, recycle limits).
  - Transient SQLSTATE retry logic (`40001`, `40P01`, `55P03`).
  - Secret redaction in connection URLs.
  - Offline Alembic DDL migration generation across all 22 revisions (759 lines of static SQL).
- **Live Physical Clustering**: **IMPLEMENTED_NOT_VERIFIED** — No PostgreSQL instance is running on the local host (port 5432/5433 closed; Windows service not installed). In accordance with defensive safety rules, no services or firewall rules were modified silently.

---

## 4. Alembic Migration Governance

Schema evolution is governed by Alembic with linear revision tracking:
- **Migration Directory**: `backend/alembic/versions/`
- **Current Head**: `b3c4d5e6f7a8` (`phase23_performance_indexes_and_resource_governance`)
- **Compatibility Guarantee**: All migrations are written to support both SQLite and PostgreSQL syntax:
  - Batch mode (`with op.batch_alter_table`) is conditionally enabled only on SQLite.
  - Offline SQL mode (`alembic upgrade head --sql`) produces transactional PostgreSQL DDL without runtime inspection crashes.

---

## 5. PostgreSQL 16 Staging Environment Runbook

To deploy and validate the platform against a physical PostgreSQL 16 cluster, follow this staging runbook:

### 5.1. Prerequisites & Engine Installation
- **Engine Version**: PostgreSQL 16.x (recommended: 16.2+).
- **Operating System**: Linux (Ubuntu 22.04 LTS / Debian 12) or managed cloud database (AWS RDS PostgreSQL, Azure Database for PostgreSQL).
- **Host Firewall**: Open port 5432 to worker subnets only.

### 5.2. Database & User Provisioning
Execute the following SQL as the PostgreSQL `postgres` superuser:
```sql
CREATE DATABASE vapt_staging;
CREATE USER vapt_app WITH ENCRYPTED PASSWORD 'StrongStagingPasswordHere!123';
GRANT ALL PRIVILEGES ON DATABASE vapt_staging TO vapt_app;
\c vapt_staging
GRANT ALL ON SCHEMA public TO vapt_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO vapt_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO vapt_app;
```

### 5.3. Staging Environment Configuration
Set the following environment variables on the backend application server:
```bash
# PostgreSQL psycopg Connection URI
export DATABASE_URL="postgresql+psycopg://vapt_app:StrongStagingPasswordHere!123@db.staging.internal:5432/vapt_staging"

# High-Concurrency Connection Pooling
export POSTGRES_POOL_SIZE=20
export POSTGRES_MAX_OVERFLOW=10
export POSTGRES_POOL_TIMEOUT=30
export POSTGRES_POOL_RECYCLE=1800

# Transaction Retry Backoff
export DB_RETRY_MAX_ATTEMPTS=3
export DB_RETRY_BASE_DELAY_SECONDS=0.05
```

### 5.4. Execute Database Migrations
Run Alembic migration against the live staging cluster:
```bash
cd backend
alembic upgrade head
```
Verify the migration head in PostgreSQL:
```sql
SELECT version_num FROM alembic_version;
-- Expected output: b3c4d5e6f7a8
```

### 5.5. Live Concurrency & Integrity Validation
Execute the PostgreSQL readiness suite against the live cluster:
```bash
pytest tests/test_phase22_postgres_readiness.py -v
```
All 12 tests will validate multi-worker claiming, idempotency locks, and transaction retry against physical PostgreSQL locks.
