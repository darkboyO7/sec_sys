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
- **Engine**: `postgresql+psycopg://`
- **Pool Type**: SQLAlchemy `QueuePool`
- **Pool Sizing**:
  - `POSTGRES_POOL_SIZE`: 20 connections.
  - `POSTGRES_MAX_OVERFLOW`: 10 connections.
  - `POSTGRES_POOL_TIMEOUT`: 30 seconds.
  - `POSTGRES_POOL_RECYCLE`: 1800 seconds (30 minutes).

### 3.2. Deadlock Detection & Transaction Retry
High concurrency across workers can lead to transaction serialization failures (`40001`) or deadlocks (`40P01`). The platform implements exponential backoff retry logic:
- `retry_on_deadlock(max_attempts=3, base_delay=0.05)`: Decorator that intercepts PostgreSQL serialization errors, rolls back the subtransaction, and retries with jittered exponential delay.

### 3.3. Distributed Job Claims (`FOR UPDATE SKIP LOCKED`)
To prevent duplicate job dispatch when multiple worker processes poll for pending assessments:
- The job query engine compiles PostgreSQL-specific `SELECT ... FOR UPDATE SKIP LOCKED` queries.
- Each worker locks only the unassigned job it is claiming; other workers seamlessly skip locked rows without waiting.

### 3.4. Verification Status
- **Dialect AST & Pooling**: Fully implemented and verified through automated test suites (`test_phase22_postgres_readiness.py`).
- **Live Clustering**: Marked `IMPLEMENTED_NOT_VERIFIED` for live physical PostgreSQL servers until deployed to a provisioned staging cluster.

---

## 4. Alembic Migration Governance

Schema evolution is governed by Alembic with linear revision tracking:
- **Migration Directory**: `backend/alembic/versions/`
- **Current Head**: `b3c4d5e6f7a8` (`phase23_performance_indexes_and_resource_governance`)
- **Compatibility Guarantee**: All migrations are written to support both SQLite and PostgreSQL syntax, utilizing batch mode (`with op.batch_alter_table`) for table alterations on SQLite.
