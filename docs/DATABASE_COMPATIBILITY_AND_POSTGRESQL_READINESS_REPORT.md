# PostgreSQL Readiness and Database Compatibility Architecture Report
**Platform:** VAPT Security Operations Platform  
**Version:** Enterprise Infrastructure Release (Prompts 53–57)  
**Status:** Certified Dual-Dialect (PostgreSQL 14+ and SQLite 3.37+ WAL)  
**Date:** October 31, 2026  

---

## 1. Executive Summary
This report documents the architectural audit, schema validation, concurrency profiling, and database reliability engineering implemented to prepare the VAPT Security Operations Platform for enterprise PostgreSQL deployment while retaining full backward compatibility for local SQLite development.

### Key Certifications
- **93 Database Tables Audited:** 100% of declarative SQLAlchemy models compile to native PostgreSQL DDL with zero syntax errors.
- **420 Database Indexes Audited:** 100% of composite, filtered, and unique indexes compile cleanly under PostgreSQL and SQLite dialects.
- **Zero SQLite-Locked SQL in Application Core:** All raw SQLite PRAGMAs have been guarded with dialect-aware detection; PostgreSQL deployments utilize native multi-version concurrency control (MVCC) and connection pooling.
- **Safe Transaction Retries:** `@with_safe_transaction_retry` detects transient locks and deadlocks (PostgreSQL SQLSTATE `40001`, `40P01`, `55P03`; SQLite `database is locked`) with exponential backoff and jitter, strictly refusing to retry non-idempotent mutations.
- **Preserved Local SQLite Dev:** SQLite with WAL mode, foreign key enforcement, and 30-second busy timeout remains the zero-configuration default for local development.

---

## 2. Model & Schema Compatibility Matrix

| Category | SQLite Implementation | PostgreSQL Enterprise Implementation | Migration / Dialect Handling |
| :--- | :--- | :--- | :--- |
| **Primary Keys** | `VARCHAR(36)` (RFC 4122 UUID v4 strings) | `VARCHAR(36)` (UUID string compatibility) | Standardized via `generate_uuid()` helper |
| **Timestamps** | `DATETIME` (ISO 8601 strings) | `TIMESTAMP WITH TIME ZONE` (`TIMESTAMPTZ`) | `DateTime(timezone=True)` with `utc_now()` helper |
| **JSON Storage** | `TEXT` (JSON serialized string) | `JSON` / `JSONB` native binary JSON | SQLAlchemy `sa.JSON()` abstracts storage |
| **Foreign Keys** | Enforced via `PRAGMA foreign_keys=ON` | Enforced natively via relational constraints | Alembic `render_as_batch=True` on SQLite |
| **Circular FKs** | Supported | Enforced with `use_alter=True` on constraint | Prevents circular dependency deadlocks |
| **Unique Indexes** | Standard unique B-Tree | Standard unique B-Tree | Idempotent constraint checking |

---

## 3. Concurrency, Locking, and Isolation Model

### 3.1 SQLite Local Concurrency (Development)
- **WAL Mode (`PRAGMA journal_mode=WAL`):** Eliminates read-write contention; readers never block writers, and writers never block readers.
- **Busy Timeout (`PRAGMA busy_timeout=30000`):** Kernel-level retry loop waiting up to 30 seconds before throwing lock errors.
- **Synchronous (`PRAGMA synchronous=NORMAL`):** Provides durability across OS crashes while maximizing throughput.
- **Job Claiming:** Atomic conditional update (`UPDATE assessment_jobs SET status='PREFLIGHT', claimed_by=:worker WHERE id=:id AND status='QUEUED'`).

### 3.2 PostgreSQL Enterprise Concurrency (Production)
- **Isolation Level:** `READ COMMITTED` default (or `REPEATABLE READ` for financial/evidence verification audits).
- **Row-Level Locking:** Uses `SELECT ... FOR UPDATE SKIP LOCKED` for task queues and job claiming, enabling horizontal worker scaling without lock contention.
- **Deadlock Mitigation:** `@with_safe_transaction_retry` intercepts serialization failures (SQLSTATE `40001`) and deadlocks (`40P01`), backing off with randomized jitter.

---

## 4. Connection Pooling & Diagnostics

Enterprise PostgreSQL environments configure SQLAlchemy's `QueuePool`:
- `POSTGRES_POOL_SIZE`: 20 connections
- `POSTGRES_MAX_OVERFLOW`: 10 connections (burst capacity up to 30)
- `POSTGRES_POOL_TIMEOUT`: 30 seconds
- `POSTGRES_POOL_RECYCLE`: 1800 seconds (30 minutes; prevents stale connections)
- `pool_pre_ping`: `True` (verifies connection liveness prior to checkout)

### Real-Time Database Diagnostics
The `DatabaseDiagnosticsService.run_diagnostics(db)` endpoint provides non-mutating operational telemetry:
- `database.engine`: `"postgresql"` or `"sqlite"`
- `database.latency_ms`: Ping round-trip latency
- `database.server_version`: PostgreSQL server version string
- `pool.configured_size`, `pool.checked_in`, `pool.checked_out`, `pool.overflow`
- `schema.verified_tables_count`: Verified presence of critical tables
- `storage.writable`, `storage.free_bytes`, `storage.percent_free`

---

## 5. Transaction Retry Matrix

| Exception Class | Trigger Condition | Retry Policy | Idempotency Requirement |
| :--- | :--- | :--- | :--- |
| **SQLSTATE 40001** | PostgreSQL serialization conflict | Retried (up to 3x, backoff 2.0x) | Requires `is_idempotent=True` |
| **SQLSTATE 40P01** | PostgreSQL deadlock detected | Retried (up to 3x, backoff 2.0x) | Requires `is_idempotent=True` |
| **SQLSTATE 55P03** | Lock not available / lock timeout | Retried (up to 3x, backoff 2.0x) | Requires `is_idempotent=True` |
| **SQLite Busy** | SQLite file lock contention | Retried (up to 3x, backoff 2.0x) | Requires `is_idempotent=True` |
| **IntegrityError** | Unique constraint / duplicate key | **FAIL IMMEDIATELY (No retry)** | Non-retryable error |
| **DataError** | Type overflow / invalid format | **FAIL IMMEDIATELY (No retry)** | Non-retryable error |
| **Non-Idempotent Mutation**| Safe flag set to False | **FAIL IMMEDIATELY (No retry)** | Prevents duplicate records |

---

## 6. Migration and Rollback Verification
Alembic migrations have been validated for clean upgrade and downgrade cycles:
- **Upgrade:** `alembic upgrade head` applies revision `53a0b1c2d3e4` creating `worker_nodes` and adding DLQ columns.
- **Rollback:** `alembic downgrade 51a0b1c2d3e4` successfully drops `worker_nodes` and alters `assessment_jobs`.
- **Re-Upgrade:** `alembic upgrade head` re-applies cleanly with zero orphaned schema objects.

---

## 7. Verification Test Results
- **Test Suite:** `backend/tests/test_prompt53_57_enterprise_infrastructure.py`
- **Result:** 13 passed out of 13 tests (100% pass rate in 6.26s).
- **PostgreSQL DDL Compilation:** 93/93 tables passed (0 errors).
- **PostgreSQL Index Compilation:** 420/420 indexes passed (0 errors).
