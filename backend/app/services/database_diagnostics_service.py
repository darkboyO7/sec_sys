"""
Database and Storage Diagnostic Service for VAPT Platform.
Verifies database concurrency configurations (SQLite WAL pragmas, PostgreSQL pool metrics),
storage disk capacity and writability, schema tables, connection pool status, and backup verification status.
"""

import os
import shutil
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Optional
from sqlalchemy.orm import Session
from sqlalchemy import text

from app.core.config import settings
from app.core.database import engine
from app.models.base import utc_now


class DatabaseDiagnosticsService:
    """
    Executes non-mutating operational diagnostics on database, connection pool, and local persistence.
    """

    @classmethod
    def run_diagnostics(cls, db: Session) -> Dict[str, Any]:
        """
        Gathers comprehensive diagnostics for database, storage, schema, connection pool, and backups.
        """
        now = utc_now()
        is_sqlite = "sqlite" in settings.DATABASE_URL.lower()

        db_diag = cls._check_database_pragmas(db, is_sqlite)
        pool_diag = cls._check_connection_pool()
        storage_diag = cls._check_storage_capacity()
        schema_diag = cls._check_schema_status(db)
        backup_diag = cls._check_backup_status(db)

        # Evaluate health
        all_ok = (
            db_diag.get("healthy", False)
            and storage_diag.get("writable", False)
            and schema_diag.get("healthy", False)
        )

        storage_warning = storage_diag.get("percent_free", 100.0) < 10.0

        return {
            "timestamp": now.isoformat(),
            "healthy": all_ok and not storage_warning,
            "status": "HEALTHY" if all_ok and not storage_warning else ("DEGRADED" if all_ok else "UNHEALTHY"),
            "database": db_diag,
            "pool": pool_diag,
            "storage": storage_diag,
            "schema": schema_diag,
            "backups": backup_diag,
        }

    @classmethod
    def _check_connection_pool(cls) -> Dict[str, Any]:
        """Inspects SQLAlchemy connection pool metrics."""
        try:
            pool = getattr(engine, "pool", None)
            if not pool:
                return {"type": "unknown", "status": "no_pool"}

            pool_class = pool.__class__.__name__
            pool_info: Dict[str, Any] = {
                "pool_class": pool_class,
                "pre_ping": getattr(pool, "_pre_ping", True),
                "recycle_seconds": getattr(pool, "_recycle", None),
            }

            # QueuePool (PostgreSQL) metrics
            if hasattr(pool, "size"):
                pool_info["configured_size"] = pool.size()
            if hasattr(pool, "checkedin"):
                pool_info["checked_in"] = pool.checkedin()
            if hasattr(pool, "checkedout"):
                pool_info["checked_out"] = pool.checkedout()
            if hasattr(pool, "overflow"):
                pool_info["overflow"] = pool.overflow()
            if hasattr(pool, "timeout"):
                pool_info["timeout"] = pool.timeout()

            return pool_info
        except Exception as e:
            return {"error": str(e), "pool_class": "unreachable"}

    @classmethod
    def _check_database_pragmas(cls, db: Session, is_sqlite: bool) -> Dict[str, Any]:
        """Inspects SQLite WAL mode, busy timeout, or PostgreSQL server version & connection status."""
        t0 = time.perf_counter()
        diag: Dict[str, Any] = {
            "engine": "sqlite" if is_sqlite else "postgresql",
            "latency_ms": 0.0,
            "healthy": False,
        }

        try:
            db.execute(text("SELECT 1"))
            diag["latency_ms"] = round((time.perf_counter() - t0) * 1000, 2)
            diag["healthy"] = True

            if is_sqlite:
                # Check PRAGMAs
                journal_mode = db.execute(text("PRAGMA journal_mode;")).scalar()
                busy_timeout = db.execute(text("PRAGMA busy_timeout;")).scalar()
                synchronous = db.execute(text("PRAGMA synchronous;")).scalar()
                foreign_keys = db.execute(text("PRAGMA foreign_keys;")).scalar()

                diag["pragmas"] = {
                    "journal_mode": str(journal_mode).lower(),
                    "busy_timeout_ms": int(busy_timeout) if busy_timeout is not None else 0,
                    "synchronous": int(synchronous) if synchronous is not None else 0,
                    "foreign_keys": bool(foreign_keys),
                }
                # WAL or memory is valid
                diag["wal_enabled"] = str(journal_mode).lower() in ("wal", "memory")
            else:
                diag["wal_enabled"] = True
                try:
                    version = db.execute(text("SELECT version();")).scalar()
                    diag["server_version"] = str(version)
                except Exception:
                    diag["server_version"] = "PostgreSQL"
                try:
                    iso = db.execute(text("SHOW transaction_isolation;")).scalar()
                    diag["isolation_level"] = str(iso)
                except Exception:
                    pass
                diag["pragmas"] = {"note": "PostgreSQL managed WAL & multi-version concurrency control (MVCC)"}

        except Exception as e:
            diag["healthy"] = False
            diag["error"] = f"Database probe query failed: {str(e)}"

        return diag

    @classmethod
    def _check_storage_capacity(cls) -> Dict[str, Any]:
        """Checks local disk writability, free space, and storage health."""
        storage_path = Path("./data").resolve()
        storage_path.mkdir(parents=True, exist_ok=True)

        writable = False
        t0 = time.perf_counter()
        try:
            probe = storage_path / "_diag_probe.tmp"
            probe.write_text("ok", encoding="utf-8")
            if probe.exists():
                probe.unlink()
            writable = True
        except Exception:
            writable = False

        write_latency_ms = round((time.perf_counter() - t0) * 1000, 2)

        # Inspect disk usage
        try:
            total, used, free = shutil.disk_usage(storage_path)
            percent_free = round((free / total) * 100, 2) if total > 0 else 0.0
            percent_used = round((used / total) * 100, 2) if total > 0 else 0.0
        except Exception:
            total = used = free = 0
            percent_free = 100.0
            percent_used = 0.0

        return {
            "path": "./data",  # Relative path to prevent system directory leakage
            "writable": writable,
            "write_latency_ms": write_latency_ms,
            "total_bytes": total,
            "free_bytes": free,
            "used_bytes": used,
            "percent_free": percent_free,
            "percent_used": percent_used,
            "low_disk_warning": percent_free < 10.0,
        }

    @classmethod
    def _check_schema_status(cls, db: Session) -> Dict[str, Any]:
        """Checks that core tables and migrations exist."""
        required_tables = [
            "users",
            "projects",
            "assessment_jobs",
            "vulnerability_findings",
            "assets",
            "audit_events",
        ]
        missing_tables = []
        for table in required_tables:
            try:
                db.execute(text(f"SELECT count(*) FROM {table}"))
            except Exception:
                missing_tables.append(table)

        # Check alembic revision if present
        current_revision = None
        try:
            current_revision = db.execute(text("SELECT version_num FROM alembic_version")).scalar()
        except Exception:
            pass

        healthy = len(missing_tables) == 0
        return {
            "healthy": healthy,
            "verified_tables_count": len(required_tables) - len(missing_tables),
            "total_required_tables": len(required_tables),
            "missing_tables": missing_tables,
            "alembic_revision": current_revision or "not_recorded",
        }

    @classmethod
    def _check_backup_status(cls, db: Session) -> Dict[str, Any]:
        """Inspects backup records and local backup directory."""
        backup_dir = Path("./data/backups")
        local_backup_count = 0
        latest_file_age_hours = None

        if backup_dir.exists() and backup_dir.is_dir():
            files = list(backup_dir.glob("*.db")) + list(backup_dir.glob("*.bak")) + list(backup_dir.glob("*.zip"))
            local_backup_count = len(files)
            if files:
                newest = max(files, key=lambda f: f.stat().st_mtime)
                latest_file_age_hours = round((time.time() - newest.stat().st_mtime) / 3600, 1)

        # Query BackupAuditRecord if model exists
        verified_backups_count = 0
        last_outcome = None
        try:
            from app.models.backup import BackupAuditRecord
            verified_backups_count = db.query(BackupAuditRecord).filter(BackupAuditRecord.verification_status == "VERIFIED").count()
            latest_rec = db.query(BackupAuditRecord).order_by(BackupAuditRecord.created_at.desc()).first()
            if latest_rec:
                last_outcome = latest_rec.verification_status
        except Exception:
            pass

        return {
            "local_backup_files_count": local_backup_count,
            "verified_records_count": verified_backups_count,
            "latest_file_age_hours": latest_file_age_hours,
            "last_verification_status": last_outcome or "NONE",
            "backup_configured": local_backup_count > 0 or verified_backups_count > 0,
        }
