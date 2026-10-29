"""
VAPT Platform — Idempotent Environment Initialization Script (Prompt 28).
Safe first-run setup:
- Creates required directory tree without modifying existing user data.
- Generates secure random credentials ONLY if .env does not already exist.
- Never silently overwrites or rotates existing valid secrets.
- Configures SQLite pragmas and verifies file writability.
- Emits exit code 0 on success.
"""
import os
import sys
import secrets
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
BACKEND_DIR = REPO_ROOT / "backend"
sys.path.insert(0, str(BACKEND_DIR))

from app.services.startup_preflight_service import startup_preflight_service


def initialize_environment(quiet: bool = False) -> int:
    data_dir = BACKEND_DIR / "data"
    env_file = data_dir / ".env"
    legacy_env = BACKEND_DIR / ".env"
    
    if not quiet:
        print("=" * 70)
        print(" VAPT PLATFORM -- SECURE ENVIRONMENT INITIALIZATION")
        print("=" * 70)

    # 1. Ensure Data Directories
    startup_preflight_service.ensure_data_directories()
    data_dir.mkdir(parents=True, exist_ok=True)
    if not quiet:
        print(f"[OK] Verified data directories under: {data_dir}")

    # 2. Secret & Configuration Preservation
    if legacy_env.exists() and not env_file.exists():
        import shutil
        shutil.move(legacy_env, env_file)
        if not quiet:
            print(f"[MIGRATED] Relocated legacy config from {legacy_env} to {env_file}.")

    if env_file.exists():
        if not quiet:
            print(f"[PRESERVED] Existing configuration found at {env_file}.")
            print("            Preserving existing SECRET_KEY and settings (Idempotent).")
    else:
        new_secret = secrets.token_hex(32)
        default_db = (data_dir / "vapt.db").resolve().as_posix()
        template = f"""# VAPT Platform Environment Configuration (Generated)
PROJECT_NAME="VAPT Security Platform"
ENVIRONMENT="development"
DEBUG=True
SECRET_KEY="{new_secret}"
ALGORITHM="HS256"
ACCESS_TOKEN_EXPIRE_MINUTES=480
DATABASE_URL="sqlite:///{default_db}"
ALLOWED_ORIGINS="http://localhost:5173,http://127.0.0.1:5173"
AUDIT_LOG_STRICT=True
EXECUTION_MODE="bounded"
"""
        env_file.write_text(template, encoding="utf-8")
        if not quiet:
            print(f"[INITIALIZED] Created fresh data/.env with 64-char cryptographically secure SECRET_KEY.")

    # 3. Execute Preflight Verification
    report = startup_preflight_service.run_preflight_checks()
    if not quiet:
        print(f"\n[PREFLIGHT] Overall Status: {report.status}")
        print(f"            Passed: {report.passed_count}/{report.total_checks}")
        print(f"            Warnings: {report.warning_count}")
        print(f"            Failures: {report.failure_count}")

    if report.status == "FATAL_ERROR":
        if not quiet:
            print("\n[FATAL] Startup preflight check failed fatal security invariants:")
            for c in report.checks:
                if c.status.value == "FAIL":
                    print(f"  - {c.name}: {c.details}")
                    if c.remediation_advice:
                        print(f"    Remediation: {c.remediation_advice}")
        return 1

    if not quiet:
        print("\n[SUCCESS] Environment initialization completed safely.")
        print("=" * 70)
    return 0


if __name__ == "__main__":
    sys.exit(initialize_environment())
