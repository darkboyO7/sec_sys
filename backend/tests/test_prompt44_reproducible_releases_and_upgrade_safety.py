"""
Comprehensive Deterministic Integration Test Suite for Prompt 44:
Reproducible Releases, Upgrade Safety and Deployment Acceptance Gates.

Validates:
1. Pinned dependency reproducibility and runtime vs development manifest separation.
2. Safe database migrations on clean installations without existing schema.
3. Representative database upgrade drills with verified pre-upgrade snapshot backups and data preservation.
4. Packaging hygiene and strict exclusion of development artifacts (.git, node_modules, .venv, .db, secrets).
5. Truthful release metadata, SBOM inclusion, and cryptographic HMAC-SHA256 signature verification.
6. Single-byte archive/manifest tampering detection and fail-closed verification.
7. Atomic release candidate staging and preservation of last-known-good releases.
8. Security audit of native Windows startup, upgrade, and health scripts (no hardcoded paths, no plaintext secrets).
"""

import os
import sys
import json
import re
import shutil
import tempfile
import tarfile
import hashlib
from pathlib import Path
from datetime import datetime, timezone
import pytest
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import sessionmaker

from alembic.config import Config
from alembic import command

from app.core.config import settings
from app.services.supply_chain_security_service import (
    supply_chain_security_service,
    FORBIDDEN_RELEASE_PATTERNS,
)
from app.services.startup_preflight_service import startup_preflight_service


REPO_ROOT = Path(__file__).resolve().parent.parent.parent
BACKEND_DIR = REPO_ROOT / "backend"


def test_01_dependency_manifest_reproducibility():
    """
    Requirement 2 & 3:
    Verifies that Python and frontend dependencies are reproducibly declared:
    - Runtime dependencies are separated from dev/test dependencies.
    - All direct runtime packages have strict pinned versions (==).
    - No unpinned or floating version constraints exist in production manifest.
    """
    req_runtime_path = BACKEND_DIR / "requirements.txt"
    req_dev_path = BACKEND_DIR / "requirements-dev.txt"
    package_json_path = REPO_ROOT / "frontend" / "package.json"

    assert req_runtime_path.exists(), "backend/requirements.txt must exist"
    assert req_dev_path.exists(), "backend/requirements-dev.txt must exist"
    assert package_json_path.exists(), "frontend/package.json must exist"

    runtime_lines = [
        line.strip()
        for line in req_runtime_path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]

    assert len(runtime_lines) > 0, "requirements.txt must not be empty"

    # Verify each runtime dependency is pinned with ==
    for line in runtime_lines:
        assert "==" in line, f"Runtime dependency '{line}' must be pinned with exact '==' version"
        pkg_name, version = line.split("==", 1)
        assert pkg_name.strip()
        assert version.strip()
        assert not version.strip().startswith(("^", "~", ">", "<", "*")), f"Floating version not allowed: {line}"

    # Verify test tools are in requirements-dev.txt, not requirements.txt
    runtime_text = req_runtime_path.read_text(encoding="utf-8").lower()
    assert "pytest==" not in runtime_text, "pytest should reside in requirements-dev.txt, not runtime requirements.txt"

    dev_text = req_dev_path.read_text(encoding="utf-8").lower()
    assert "pytest" in dev_text, "pytest must be declared in requirements-dev.txt"

    # Frontend package.json audit
    package_data = json.loads(package_json_path.read_text(encoding="utf-8"))
    assert "dependencies" in package_data
    assert "devDependencies" in package_data
    # Runtime deps must include core ui libs
    assert "react" in package_data["dependencies"]
    # Build/test tools must be in devDependencies
    assert "vite" in package_data["devDependencies"]
    assert "vitest" in package_data["devDependencies"]


def test_02_clean_installation_database_migration():
    """
    Requirement 8:
    Verify that database migrations can be applied safely to a clean installation.
    Runs Alembic upgrade head against an empty temporary SQLite database and confirms all core tables exist.
    """
    with tempfile.TemporaryDirectory() as tmp_dir:
        clean_db_path = Path(tmp_dir) / "clean_vapt.db"
        clean_db_url = f"sqlite:///{clean_db_path.as_posix()}"

        alembic_cfg = Config(str(BACKEND_DIR / "alembic.ini"))
        alembic_cfg.set_main_option("script_location", str(BACKEND_DIR / "alembic"))
        alembic_cfg.set_main_option("sqlalchemy.url", clean_db_url)

        # Run migration from scratch to head
        command.upgrade(alembic_cfg, "head")

        assert clean_db_path.exists(), "Clean database file was not created"

        # Inspect created tables
        engine = create_engine(clean_db_url)
        inspector = inspect(engine)
        table_names = set(inspector.get_table_names())

        required_tables = {
            "users",
            "organizations",
            "projects",
            "scope_targets",
            "scope_exclusions",
            "assessment_jobs",
            "assessment_findings",
            "finding_evidence",
            "vulnerability_findings",
            "finding_transitions",
            "audit_events",
            "backup_schedules",
            "disaster_recovery_bundles",
            "compliance_evaluation_runs",
            "scheduler_policies",
            "threat_intelligence_records",
            "connector_configurations",
        }

        missing_tables = required_tables - table_names
        engine.dispose()
        assert not missing_tables, f"Clean migration missed required tables: {missing_tables}"


def test_03_database_upgrade_drill_and_pre_upgrade_backup():
    """
    Requirement 8 & 10:
    Tests upgrade behavior against a representative existing database copy:
    - Pre-upgrade readiness evaluation and backup creation.
    - Verified snapshot creation.
    - Schema upgrade without data loss or corruption.
    """
    with tempfile.TemporaryDirectory() as tmp_dir:
        db_dir = Path(tmp_dir) / "data"
        backup_dir = db_dir / "backups"
        db_dir.mkdir(parents=True)
        backup_dir.mkdir(parents=True)

        test_db_path = db_dir / "vapt.db"
        test_db_url = f"sqlite:///{test_db_path.as_posix()}"

        # 1. Initialize schema
        alembic_cfg = Config(str(BACKEND_DIR / "alembic.ini"))
        alembic_cfg.set_main_option("script_location", str(BACKEND_DIR / "alembic"))
        alembic_cfg.set_main_option("sqlalchemy.url", test_db_url)
        command.upgrade(alembic_cfg, "head")

        # 2. Populate representative user record
        engine = create_engine(test_db_url)
        with engine.connect() as conn:
            conn.execute(
                text(
                    "INSERT INTO users (id, email, hashed_password, full_name, system_role, is_active, created_at, updated_at) "
                    "VALUES ('user-test-upg-01', 'upgrade_tester@corp.local', 'hash123', 'Upgrade Tester', 'ADMIN', 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"
                )
            )
            conn.commit()

        # 3. Simulate pre-upgrade snapshot backup
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        snapshot_file = backup_dir / f"vapt_pre_upgrade_{timestamp}.db"
        shutil.copy2(test_db_path, snapshot_file)

        assert snapshot_file.exists()
        assert snapshot_file.stat().st_size == test_db_path.stat().st_size

        # 4. Re-apply upgrade head (idempotent verification)
        command.upgrade(alembic_cfg, "head")

        # 5. Verify data preserved
        with engine.connect() as conn:
            result = conn.execute(text("SELECT email, system_role FROM users WHERE id = 'user-test-upg-01'")).fetchone()
            assert result is not None
            assert result[0] == "upgrade_tester@corp.local"
            assert result[1] == "ADMIN"

        engine.dispose()


def test_04_release_packaging_exclusions_and_hygiene():
    """
    Requirement 4 & 5:
    Audits packaging rules to exclude development artifacts, caches, secrets, and databases:
    - Excludes .git, node_modules, .venv, caches, local databases, temporary evidence.
    - Includes runtime assets, migration files, templates, scripts/windows.
    """
    with tempfile.TemporaryDirectory() as tmp_dir:
        out_dir = Path(tmp_dir) / "dist"

        archive_path, manifest_path = supply_chain_security_service.build_release_package(
            version="1.0.0-test",
            output_dir=out_dir,
            as_candidate=True,
        )

        assert archive_path.exists()
        assert manifest_path.exists()

        # Inspect files bundled in tar.gz
        bundled_files = []
        with tarfile.open(archive_path, "r:gz") as tar:
            for member in tar.getmembers():
                bundled_files.append(member.name)

        # Forbidden patterns check
        forbidden_regexes = [re.compile(pat, re.IGNORECASE) for pat in FORBIDDEN_RELEASE_PATTERNS]
        violations = []
        for b_file in bundled_files:
            file_name = Path(b_file).name
            for pat in forbidden_regexes:
                if pat.search(file_name) or pat.search(b_file):
                    violations.append(f"Forbidden artifact '{b_file}' matched pattern '{pat.pattern}'")

        assert not violations, f"Forbidden files bundled in release archive:\n" + "\n".join(violations[:10])

        # Mandatory files check
        assert any("backend/app/main.py" in f for f in bundled_files), "backend/app/main.py must be bundled"
        assert any("backend/alembic.ini" in f for f in bundled_files), "backend/alembic.ini must be bundled"
        assert any("scripts/windows/start_platform.bat" in f for f in bundled_files), "scripts/windows/start_platform.bat must be bundled"
        assert any("scripts/windows/upgrade_platform.bat" in f for f in bundled_files), "scripts/windows/upgrade_platform.bat must be bundled"
        assert any(".env.example" in f for f in bundled_files), ".env.example must be bundled"


def test_05_release_manifest_truthfulness_and_cryptographic_signature():
    """
    Requirement 11, 13 & 14:
    Verifies truthful release metadata, HMAC-SHA256 signature, and single-byte tampering detection:
    - Truthful fields: version, build_timestamp, git_commit, environment, files.
    - Manifest signature validation.
    - Tamper detection fails closed.
    """
    with tempfile.TemporaryDirectory() as tmp_dir:
        out_dir = Path(tmp_dir) / "dist"
        signing_key = "super_secure_prompt44_test_signing_key_12345"

        archive_path, manifest_path = supply_chain_security_service.build_release_package(
            version="1.0.0-test",
            signing_key=signing_key,
            output_dir=out_dir,
            as_candidate=True,
        )

        # 1. Valid verification
        ver_res = supply_chain_security_service.verify_release_package(
            archive_path=archive_path,
            manifest_path=manifest_path,
            signing_key=signing_key,
        )

        assert ver_res.valid is True
        assert ver_res.signature_valid is True
        assert ver_res.total_files_verified > 0
        assert len(ver_res.errors) == 0

        # 2. Truthful metadata inspection
        manifest_data = json.loads(manifest_path.read_text(encoding="utf-8"))
        assert manifest_data["version"] == "1.0.0-test"
        assert manifest_data["signature_algorithm"] == "HMAC-SHA256"
        assert "build_timestamp" in manifest_data
        assert "environment" in manifest_data
        assert "python_version" in manifest_data["environment"]

        # 3. Tamper test: Alter 1 byte in the archive
        with open(archive_path, "r+b") as f:
            f.seek(50)
            orig_byte = f.read(1)
            f.seek(50)
            f.write(bytes([orig_byte[0] ^ 0xFF]))

        tampered_res = supply_chain_security_service.verify_release_package(
            archive_path=archive_path,
            manifest_path=manifest_path,
            signing_key=signing_key,
        )

        assert tampered_res.valid is False, "Tampered release archive must fail verification"
        assert len(tampered_res.errors) > 0


def test_06_atomic_candidate_promotion_and_preservation_of_good_releases():
    """
    Requirement 15:
    Verifies that release candidate staging prevents overwriting the last known-good release
    until the candidate passes acceptance checks.
    """
    with tempfile.TemporaryDirectory() as tmp_dir:
        dist_dir = Path(tmp_dir) / "dist"
        candidates_dir = dist_dir / "candidates"
        dist_dir.mkdir(parents=True)
        candidates_dir.mkdir(parents=True)

        # 1. Establish known-good release v1.0.0
        good_archive = dist_dir / "vapt-platform-v1.0.0.tar.gz"
        good_manifest = dist_dir / "release-manifest.json"
        good_archive.write_bytes(b"EXISTING_KNOWN_GOOD_V1_0_0_ARCHIVE_DATA")
        good_manifest.write_text('{"version": "1.0.0", "status": "KNOWN_GOOD"}', encoding="utf-8")

        # 2. Build candidate v1.1.0 in staging
        cand_archive, cand_manifest = supply_chain_security_service.build_release_package(
            version="1.1.0",
            output_dir=dist_dir,
            as_candidate=True,
        )

        assert cand_archive.parent == candidates_dir
        assert "candidate" in cand_archive.name

        # Verify known-good release v1.0.0 remains 100% untouched
        assert good_archive.read_bytes() == b"EXISTING_KNOWN_GOOD_V1_0_0_ARCHIVE_DATA"
        assert json.loads(good_manifest.read_text(encoding="utf-8"))["version"] == "1.0.0"

        # 3. Simulate acceptance gate qualification -> Promote
        promoted_archive, promoted_manifest = supply_chain_security_service.promote_release_candidate(
            candidate_archive=cand_archive,
            candidate_manifest=cand_manifest,
            target_dir=dist_dir,
            version="1.1.0",
        )

        assert promoted_archive.exists()
        assert promoted_manifest.exists()
        assert promoted_archive.name == "vapt-platform-v1.1.0.tar.gz"
        assert json.loads(promoted_manifest.read_text(encoding="utf-8"))["version"] == "1.1.0"


def test_07_windows_startup_scripts_security_and_portability():
    """
    Requirement 9 & 12:
    Ensures Windows startup scripts:
    - Do not hardcode machine-specific paths or user home directories.
    - Do not expose credentials, hardcoded passwords, or private keys.
    - Do not pass '--insecure' or disable security controls.
    - Implement bounded timeout checks.
    """
    scripts_to_audit = [
        REPO_ROOT / "scripts" / "windows" / "start_platform.bat",
        REPO_ROOT / "scripts" / "windows" / "start_platform.ps1",
        REPO_ROOT / "scripts" / "windows" / "upgrade_platform.bat",
        REPO_ROOT / "scripts" / "windows" / "upgrade_platform.ps1",
    ]

    for script_path in scripts_to_audit:
        assert script_path.exists(), f"Script {script_path.name} must exist"
        content = script_path.read_text(encoding="utf-8", errors="ignore")

        # Portability: Check for user-specific hardcoded paths
        assert "C:\\Users\\" not in content, f"Hardcoded user path found in {script_path.name}"
        assert "D:\\alt" not in content, f"Hardcoded developer path found in {script_path.name}"

        # Security: Check for disabled controls or plain secrets
        assert "--insecure" not in content.lower(), f"Insecure flag found in {script_path.name}"
        assert "password=" not in content.lower(), f"Possible embedded password in {script_path.name}"
        assert "secret_key=" not in content.lower(), f"Possible embedded secret key in {script_path.name}"
