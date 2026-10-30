"""
VAPT Platform — Startup Preflight & Safe Deployment Governance Service (Prompt 28).
Provides:
1. Automated startup preflight validation across configuration, database, directories, and crypto.
2. Redacted non-secret configuration diagnostics.
3. Database upgrade readiness pre-checking and backup advisories.
"""
import os
import sys
import hashlib
import hmac
import tempfile
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

from sqlalchemy.orm import Session
from sqlalchemy import text

from app.core.config import settings
from app.core.database import SessionLocal, engine
from app.schemas.deployment import (
    CheckSeverity,
    PreflightCheckItem,
    PreflightReport,
    RedactedConfigResponse,
    UpgradePrecheckResponse,
    ConfigDiagnosticItem,
    ConfigDiagnosticResponse,
)

REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent


class StartupPreflightService:
    def __init__(self):
        self.data_dir = REPO_ROOT / "backend" / "data"
        self.evidence_dir = self.data_dir / "evidence"
        self.backup_dir = self.data_dir / "backups"
        self.logs_dir = self.data_dir / "logs"

    def ensure_data_directories(self) -> None:
        """Creates required application directories safely."""
        for d in [self.data_dir, self.evidence_dir, self.backup_dir, self.logs_dir]:
            try:
                d.mkdir(parents=True, exist_ok=True)
            except Exception:
                pass

    def run_preflight_checks(self, db: Optional[Session] = None) -> PreflightReport:
        checks: List[PreflightCheckItem] = []
        env = settings.ENVIRONMENT.lower()

        # 1. Secret Key Hardening
        secret = settings.SECRET_KEY
        if len(secret) < 32:
            checks.append(
                PreflightCheckItem(
                    name="SECRET_KEY Length Check",
                    category="Cryptography",
                    status=CheckSeverity.FAIL,
                    details=f"SECRET_KEY is only {len(secret)} characters (min 32 required).",
                    remediation_advice="Set SECRET_KEY environment variable to a cryptographically secure 32+ char token.",
                )
            )
        elif env == "production" and any(bad in secret.lower() for bad in ["insecure", "change_in_production", "test"]):
            checks.append(
                PreflightCheckItem(
                    name="Production Secret Hardening",
                    category="Cryptography",
                    status=CheckSeverity.FAIL,
                    details="Insecure default SECRET_KEY detected in production environment.",
                    remediation_advice="Generate a secure random production secret key using secrets.token_hex(32).",
                )
            )
        else:
            checks.append(
                PreflightCheckItem(
                    name="SECRET_KEY Cryptographic Hardening",
                    category="Cryptography",
                    status=CheckSeverity.PASS,
                    details=f"SECRET_KEY meets 32+ character requirement ({len(secret)} chars) for {env} mode.",
                )
            )

        # 2. Database Connectivity & Pragmas
        close_db = False
        if db is None:
            db = SessionLocal()
            close_db = True
        try:
            db.execute(text("SELECT 1")).scalar()
            checks.append(
                PreflightCheckItem(
                    name="Database Engine Connectivity",
                    category="Persistence",
                    status=CheckSeverity.PASS,
                    details=f"Successfully connected to database dialect '{db.bind.dialect.name}'.",
                )
            )

            # Check SQLite Pragmas if sqlite
            if db.bind and db.bind.dialect.name == "sqlite":
                journal_mode = db.execute(text("PRAGMA journal_mode")).scalar()
                fk_status = db.execute(text("PRAGMA foreign_keys")).scalar()
                if str(journal_mode).lower() == "wal":
                    checks.append(
                        PreflightCheckItem(
                            name="SQLite WAL Mode Verification",
                            category="Persistence",
                            status=CheckSeverity.PASS,
                            details="SQLite WAL journal_mode active for high-concurrency read/write safety.",
                        )
                    )
                else:
                    checks.append(
                        PreflightCheckItem(
                            name="SQLite WAL Mode Verification",
                            category="Persistence",
                            status=CheckSeverity.WARN,
                            details=f"SQLite journal_mode is '{journal_mode}' instead of 'wal'.",
                            remediation_advice="Enable WAL mode using PRAGMA journal_mode=WAL.",
                        )
                    )

                if fk_status == 1:
                    checks.append(
                        PreflightCheckItem(
                            name="SQLite Foreign Key Integrity",
                            category="Persistence",
                            status=CheckSeverity.PASS,
                            details="Foreign key constraint enforcement is active.",
                        )
                    )
                else:
                    checks.append(
                        PreflightCheckItem(
                            name="SQLite Foreign Key Integrity",
                            category="Persistence",
                            status=CheckSeverity.FAIL,
                            details="Foreign keys disabled (PRAGMA foreign_keys=0). Relational integrity compromised.",
                            remediation_advice="Enable foreign key enforcement via PRAGMA foreign_keys=ON.",
                        )
                    )
        except Exception as e:
            checks.append(
                PreflightCheckItem(
                    name="Database Connectivity",
                    category="Persistence",
                    status=CheckSeverity.FAIL,
                    details=f"Database connection error: {str(e)}",
                    remediation_advice="Verify database URL and ensure target database path exists and is writable.",
                )
            )
        finally:
            if close_db:
                db.close()

        # 3. Data Directories Writability
        self.ensure_data_directories()
        dir_ok = True
        for name, p in [
            ("data", self.data_dir),
            ("evidence", self.evidence_dir),
            ("backups", self.backup_dir),
            ("logs", self.logs_dir),
        ]:
            try:
                test_file = p / f".write_test_{os.getpid()}"
                test_file.write_text("ok", encoding="utf-8")
                test_file.unlink()
            except Exception as e:
                dir_ok = False
                checks.append(
                    PreflightCheckItem(
                        name=f"Directory Writability ({name})",
                        category="Storage",
                        status=CheckSeverity.FAIL,
                        details=f"Cannot write to designated directory {p}: {str(e)}",
                        remediation_advice=f"Ensure write permissions are granted to {p}.",
                    )
                )
        if dir_ok:
            checks.append(
                PreflightCheckItem(
                    name="Filesystem Data Directories",
                    category="Storage",
                    status=CheckSeverity.PASS,
                    details="All designated storage directories (data, evidence, backups, logs) are writable.",
                )
            )

        # 4. Cryptographic Primitives Health
        try:
            # Test SHA-256 and HMAC
            h = hashlib.sha256(b"test").hexdigest()
            mac = hmac.new(b"key", b"msg", hashlib.sha256).hexdigest()
            checks.append(
                PreflightCheckItem(
                    name="Cryptographic Primitives Health",
                    category="Cryptography",
                    status=CheckSeverity.PASS,
                    details="SHA-256 and HMAC-SHA256 engines operational.",
                )
            )
        except Exception as e:
            checks.append(
                PreflightCheckItem(
                    name="Cryptographic Primitives Health",
                    category="Cryptography",
                    status=CheckSeverity.FAIL,
                    details=f"Crypto failure: {str(e)}",
                    remediation_advice="Verify Python hashlib environment.",
                )
            )

        # 5. CORS Origins Exposure
        origins = settings.cors_origins
        if "*" in origins:
            if env == "production":
                checks.append(
                    PreflightCheckItem(
                        name="CORS Policy Security",
                        category="Network",
                        status=CheckSeverity.FAIL,
                        details="Wildcard '*' in ALLOWED_ORIGINS is forbidden in production.",
                        remediation_advice="Specify explicit trusted origins in ALLOWED_ORIGINS.",
                    )
                )
            else:
                checks.append(
                    PreflightCheckItem(
                        name="CORS Policy Security",
                        category="Network",
                        status=CheckSeverity.WARN,
                        details="Wildcard in ALLOWED_ORIGINS allowed in development but must be restricted for production.",
                    )
                )
        else:
            checks.append(
                PreflightCheckItem(
                    name="CORS Policy Security",
                    category="Network",
                    status=CheckSeverity.PASS,
                    details=f"Strict allowed origins configured: {', '.join(origins)}",
                )
            )

        # 6. Debug Mode Guardrail
        if settings.DEBUG and env == "production":
            checks.append(
                PreflightCheckItem(
                    name="Debug Mode Exposure",
                    category="Configuration",
                    status=CheckSeverity.FAIL,
                    details="DEBUG=True in production environment compromises diagnostic privacy.",
                    remediation_advice="Set DEBUG=False in production.",
                )
            )
        else:
            checks.append(
                PreflightCheckItem(
                    name="Debug Mode Guardrail",
                    category="Configuration",
                    status=CheckSeverity.PASS,
                    details=f"DEBUG is set to {settings.DEBUG} for {env} mode.",
                )
            )

        # Aggregate Verdict
        fail_count = sum(1 for c in checks if c.status == CheckSeverity.FAIL)
        warn_count = sum(1 for c in checks if c.status == CheckSeverity.WARN)
        pass_count = sum(1 for c in checks if c.status == CheckSeverity.PASS)

        if fail_count > 0:
            overall_status = "FATAL_ERROR"
        elif warn_count > 0:
            overall_status = "WARNINGS"
        else:
            overall_status = "PASSED"

        return PreflightReport(
            status=overall_status,
            environment=settings.ENVIRONMENT,
            total_checks=len(checks),
            passed_count=pass_count,
            warning_count=warn_count,
            failure_count=fail_count,
            checks=checks,
        )

    def get_redacted_config(self) -> RedactedConfigResponse:
        """Returns non-secret settings with sensitive tokens redacted."""
        raw_db_url = settings.DATABASE_URL
        if "sqlite" in raw_db_url:
            db_type = "sqlite"
            redacted_db = "sqlite:///***LOCAL_DATA_DIR***/vapt.db"
        elif "@" in raw_db_url:
            db_type = "postgresql"
            redacted_db = raw_db_url.split("@")[-1]  # Omit credentials
            redacted_db = f"postgresql://***REDACTED***@{redacted_db}"
        else:
            db_type = "other"
            redacted_db = "***REDACTED***"

        return RedactedConfigResponse(
            environment=settings.ENVIRONMENT,
            debug=settings.DEBUG,
            app_name=settings.APP_NAME,
            database_type=db_type,
            database_url_redacted=redacted_db,
            allowed_origins=settings.cors_origins,
            audit_strict=settings.AUDIT_LOG_STRICT,
            data_directories={
                "data_dir": str(self.data_dir),
                "evidence_dir": str(self.evidence_dir),
                "backup_dir": str(self.backup_dir),
                "logs_dir": str(self.logs_dir),
            },
            cryptographic_algorithm=settings.ALGORITHM,
            token_expiry_minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES,
            worker_execution_mode=settings.EXECUTION_MODE,
        )

    def get_config_diagnostics(self) -> ConfigDiagnosticResponse:
        """
        Executes deep evaluation of configuration settings and reports cryptographic posture
        and missing/insecure parameters without exposing raw secrets.
        """
        raw_items = settings.get_config_diagnostics()
        diag_items = [
            ConfigDiagnosticItem(
                key=item["key"],
                is_secret=item["is_secret"],
                configured=item["configured"],
                status=item["status"],
                strength=item["strength"],
                redacted_value=item["redacted_value"],
                message=item["message"],
            )
            for item in raw_items
        ]
        passed = sum(1 for d in diag_items if d.status == "PASS")
        warn = sum(1 for d in diag_items if d.status == "WARN")
        fail = sum(1 for d in diag_items if d.status == "FAIL")

        return ConfigDiagnosticResponse(
            environment=settings.ENVIRONMENT,
            total_settings=len(diag_items),
            passed_count=passed,
            warning_count=warn,
            failure_count=fail,
            items=diag_items,
        )

    def check_upgrade_readiness(self, db: Optional[Session] = None) -> UpgradePrecheckResponse:
        """Evaluates database schema status and advises pre-upgrade safety measures."""
        close_db = False
        if db is None:
            db = SessionLocal()
            close_db = True
        try:
            # Query alembic_version table
            current_rev = "none"
            try:
                row = db.execute(text("SELECT version_num FROM alembic_version")).fetchone()
                if row:
                    current_rev = str(row[0])
            except Exception:
                current_rev = "uninitialized"

            migration_head = "e4f5a6b7c8d9"  # Current head from Prompt 26
            pending_count = 0 if current_rev == migration_head else 1

            return UpgradePrecheckResponse(
                current_version="1.0.0",
                target_version="1.1.0",
                migration_head=migration_head,
                current_db_version=current_rev,
                pending_migrations_count=pending_count,
                backup_required=True,
                can_upgrade=True,
                recommended_action="Execute automated backup drill before applying 'alembic upgrade head'."
                if pending_count > 0
                else "Schema is fully up-to-date with migration head.",
            )
        finally:
            if close_db:
                db.close()


startup_preflight_service = StartupPreflightService()
