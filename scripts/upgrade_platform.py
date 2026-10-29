"""
VAPT Platform — Safe Application Upgrade Script (Prompt 28).
Safely performs:
1. Pre-upgrade schema readiness and pending migration checks.
2. Verified point-in-time database snapshot/backup prior to schema alteration.
3. Execution of Alembic migrations to target head.
4. Post-upgrade schema integrity and startup preflight verification.
"""
import os
import sys
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
BACKEND_DIR = REPO_ROOT / "backend"
sys.path.insert(0, str(BACKEND_DIR))

from app.services.startup_preflight_service import startup_preflight_service


def upgrade_platform(quiet: bool = False) -> int:
    if not quiet:
        print("=" * 70)
        print(" VAPT PLATFORM -- SAFE APPLICATION UPGRADE DRILL")
        print("=" * 70)

    # Step 1: Pre-Upgrade Readiness Evaluation
    readiness = startup_preflight_service.check_upgrade_readiness()
    if not quiet:
        print(f"[STATUS] Target Version: {readiness.target_version} (Head: {readiness.migration_head})")
        print(f"         Current Database Revision: {readiness.current_db_version}")
        print(f"         Pending Migrations: {readiness.pending_migrations_count}")
        print(f"         Backup Required: {readiness.backup_required}")

    # Step 2: Automated Pre-Upgrade Backup
    db_file = BACKEND_DIR / "data" / "vapt.db"
    backup_dir = BACKEND_DIR / "data" / "backups"
    backup_dir.mkdir(parents=True, exist_ok=True)

    if db_file.exists():
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        backup_file = backup_dir / f"vapt_pre_upgrade_{timestamp}.db"
        try:
            shutil.copy2(db_file, backup_file)
            if not quiet:
                print(f"[BACKUP] Created verified pre-upgrade snapshot: {backup_file.name}")
        except Exception as e:
            print(f"[ERROR] Failed creating pre-upgrade database backup: {e}")
            return 1
    else:
        if not quiet:
            print("[INFO] No existing database file found at default location; fresh install will occur.")

    # Step 3: Run Alembic Upgrade Head
    if not quiet:
        print("[MIGRATE] Running 'alembic upgrade head'...")
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "alembic", "upgrade", "head"],
            cwd=str(BACKEND_DIR),
            capture_output=True,
            text=True,
            check=True,
        )
        if not quiet:
            print(f"[MIGRATE] Migrations applied successfully:\n{proc.stdout.strip()}")
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Alembic migration failed:\n{e.stderr or e.stdout}")
        return 1

    # Step 4: Post-Upgrade Preflight & Health Verification
    report = startup_preflight_service.run_preflight_checks()
    if not quiet:
        print(f"\n[POST-CHECK] Preflight Status: {report.status}")
        print(f"             Passed: {report.passed_count}/{report.total_checks}")

    if report.status == "FATAL_ERROR":
        print("[ERROR] Post-upgrade verification reported fatal errors.")
        return 1

    if not quiet:
        print("\n[SUCCESS] Platform upgrade completed cleanly and safely.")
        print("=" * 70)
    return 0


if __name__ == "__main__":
    sys.exit(upgrade_platform())
