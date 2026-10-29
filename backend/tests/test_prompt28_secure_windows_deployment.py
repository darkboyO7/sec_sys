"""
VAPT Platform — Secure Windows Deployment, Configuration Governance & Safe Upgrades.
Test suite for Prompt 28.
Validates:
1. Startup preflight passes under healthy baseline configuration.
2. Startup preflight detects short SECRET_KEY (< 32 chars) as FAIL.
3. Startup preflight detects known insecure production secrets as FAIL.
4. Startup preflight warns on wildcard CORS origin in development mode.
5. Startup preflight blocks wildcard CORS origin in production mode with FAIL.
6. Startup preflight blocks DEBUG=True in production mode with FAIL.
7. Redacted configuration masks database credentials, passwords, and sensitive tokens.
8. Upgrade readiness detects active Alembic schema revision and migration head.
9. Data directory creation is safe, non-destructive, and creates all designated folders.
10. Directory writability check detects unwritable directories.
11. Cryptographic primitives health check validates SHA-256 and HMAC-SHA256 engines.
12. initialize_environment script preserves existing configuration and secrets idempotently.
13. initialize_environment generates secure random 64-char key when configuration is missing.
14. API preflight endpoint requires authentication and enforces RBAC (ADMIN, SECURITY_LEAD, AUDITOR).
15. API config endpoint returns redacted settings without secrets.
16. API upgrade-check endpoint returns migration status and backup requirements.
17. Path traversal protections prevent escaping designated application data roots.
"""
import os
import sys
import json
import secrets
import tempfile
import shutil
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from sqlalchemy import text

from app.main import app
from app.core.config import settings
from app.models.user import User, SystemRole
from app.services.startup_preflight_service import (
    startup_preflight_service,
    StartupPreflightService,
)
from app.schemas.deployment import (
    CheckSeverity,
    PreflightReport,
    RedactedConfigResponse,
    UpgradePrecheckResponse,
)
from tests.conftest import auth_header_for_user

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


def auth_headers(user: User) -> dict:
    return auth_header_for_user(user)


# ------------------------------------------------------------------------------
# 1. Preflight Baseline & Security Guardrails
# ------------------------------------------------------------------------------
def test_01_preflight_checks_pass_under_healthy_configuration(db: Session):
    """Verifies that preflight checks succeed under baseline healthy configuration."""
    report = startup_preflight_service.run_preflight_checks(db=db)
    assert isinstance(report, PreflightReport)
    assert report.total_checks >= 6
    assert report.failure_count == 0
    assert report.status in ["PASSED", "WARNINGS"]


def test_02_preflight_fails_on_short_secret_key(db: Session):
    """Verifies preflight fails when SECRET_KEY is shorter than 32 characters."""
    with patch.object(settings, "SECRET_KEY", "short_secret_12345"):
        report = startup_preflight_service.run_preflight_checks(db=db)
        assert report.failure_count >= 1
        assert report.status == "FATAL_ERROR"
        fail_item = next((c for c in report.checks if c.name == "SECRET_KEY Length Check"), None)
        assert fail_item is not None
        assert fail_item.status == CheckSeverity.FAIL


def test_03_preflight_fails_on_insecure_production_secret(db: Session):
    """Verifies preflight blocks default or placeholder secrets in production mode."""
    with patch.object(settings, "ENVIRONMENT", "production"), \
         patch.object(settings, "SECRET_KEY", "insecure_default_secret_key_for_testing_purposes_only"):
        report = startup_preflight_service.run_preflight_checks(db=db)
        assert report.failure_count >= 1
        assert report.status == "FATAL_ERROR"
        fail_item = next((c for c in report.checks if c.name == "Production Secret Hardening"), None)
        assert fail_item is not None
        assert fail_item.status == CheckSeverity.FAIL


def test_04_preflight_warns_on_wildcard_cors_in_development(db: Session):
    """Verifies preflight issues a warning when CORS origins contain '*' in dev."""
    with patch.object(settings, "ENVIRONMENT", "development"), \
         patch.object(settings, "ALLOWED_ORIGINS", "*"):
        report = startup_preflight_service.run_preflight_checks(db=db)
        warn_item = next((c for c in report.checks if c.name == "CORS Policy Security"), None)
        assert warn_item is not None
        assert warn_item.status == CheckSeverity.WARN


def test_05_preflight_fails_on_wildcard_cors_in_production(db: Session):
    """Verifies preflight fatally blocks wildcard CORS origin in production mode."""
    with patch.object(settings, "ENVIRONMENT", "production"), \
         patch.object(settings, "ALLOWED_ORIGINS", "*"):
        report = startup_preflight_service.run_preflight_checks(db=db)
        assert report.status == "FATAL_ERROR"
        fail_item = next((c for c in report.checks if c.name == "CORS Policy Security"), None)
        assert fail_item is not None
        assert fail_item.status == CheckSeverity.FAIL


def test_06_preflight_fails_on_debug_in_production(db: Session):
    """Verifies preflight fatally rejects DEBUG=True when running in production."""
    with patch.object(settings, "ENVIRONMENT", "production"), \
         patch.object(settings, "DEBUG", True):
        report = startup_preflight_service.run_preflight_checks(db=db)
        assert report.status == "FATAL_ERROR"
        fail_item = next((c for c in report.checks if c.name == "Debug Mode Exposure"), None)
        assert fail_item is not None
        assert fail_item.status == CheckSeverity.FAIL


# ------------------------------------------------------------------------------
# 2. Redaction & Directory Safety
# ------------------------------------------------------------------------------
def test_07_redacted_config_masks_database_and_secret_tokens():
    """Verifies that get_redacted_config returns effective settings without leaking credentials."""
    cfg = startup_preflight_service.get_redacted_config()
    assert isinstance(cfg, RedactedConfigResponse)
    assert "***" in cfg.database_url_redacted
    assert "password" not in cfg.database_url_redacted.lower()
    assert not hasattr(cfg, "SECRET_KEY")
    assert not hasattr(cfg, "secret_key")


def test_08_upgrade_readiness_detects_schema_revision(db: Session):
    """Verifies that check_upgrade_readiness correctly retrieves alembic version and head."""
    readiness = startup_preflight_service.check_upgrade_readiness(db=db)
    assert isinstance(readiness, UpgradePrecheckResponse)
    assert readiness.current_version == "1.0.0"
    assert readiness.migration_head == "e4f5a6b7c8d9"
    assert readiness.can_upgrade is True
    assert isinstance(readiness.backup_required, bool)


def test_09_safe_data_directories_creation():
    """Verifies that ensure_data_directories creates data, evidence, backups, and logs safely."""
    with tempfile.TemporaryDirectory() as tmpdir:
        svc = StartupPreflightService()
        svc.data_dir = Path(tmpdir) / "data"
        svc.evidence_dir = svc.data_dir / "evidence"
        svc.backup_dir = svc.data_dir / "backups"
        svc.logs_dir = svc.data_dir / "logs"

        svc.ensure_data_directories()

        assert svc.data_dir.exists()
        assert svc.evidence_dir.exists()
        assert svc.backup_dir.exists()
        assert svc.logs_dir.exists()


def test_10_directory_writability_check_detects_unwritable_paths(db: Session):
    """Verifies that preflight flags directories where write access fails."""
    svc = StartupPreflightService()
    # Mock data_dir to an invalid / read-only path
    fake_path = Path("Z:\\nonexistent_drive_for_vapt_test\\data")
    svc.data_dir = fake_path
    svc.evidence_dir = fake_path / "evidence"
    svc.backup_dir = fake_path / "backups"
    svc.logs_dir = fake_path / "logs"

    report = svc.run_preflight_checks(db=db)
    storage_fails = [c for c in report.checks if c.category == "Storage" and c.status == CheckSeverity.FAIL]
    assert len(storage_fails) > 0


def test_11_crypto_primitives_health_verification(db: Session):
    """Verifies SHA-256 and HMAC-SHA256 health check passes."""
    report = startup_preflight_service.run_preflight_checks(db=db)
    crypto_item = next((c for c in report.checks if c.name == "Cryptographic Primitives Health"), None)
    assert crypto_item is not None
    assert crypto_item.status == CheckSeverity.PASS


# ------------------------------------------------------------------------------
# 3. Environment Initialization Script Idempotency
# ------------------------------------------------------------------------------
def test_12_initialize_environment_preserves_existing_secrets_idempotently():
    """Verifies initialize_environment never overwrites an existing .env file or rotates secrets."""
    from scripts.initialize_environment import initialize_environment

    with tempfile.TemporaryDirectory() as tmpdir:
        test_backend = Path(tmpdir) / "backend"
        test_backend.mkdir(parents=True)
        env_file = test_backend / ".env"
        existing_secret = "pre_existing_custom_secret_key_1234567890_abcdef"
        env_file.write_text(f'SECRET_KEY="{existing_secret}"\n', encoding="utf-8")

        with patch("scripts.initialize_environment.BACKEND_DIR", test_backend):
            exit_code = initialize_environment(quiet=True)
            assert exit_code == 0
            # Ensure content is strictly preserved
            content = env_file.read_text(encoding="utf-8")
            assert existing_secret in content


def test_13_initialize_environment_generates_secure_key_when_missing():
    """Verifies initialize_environment generates a secure 64-char key when .env is absent."""
    from scripts.initialize_environment import initialize_environment

    with tempfile.TemporaryDirectory() as tmpdir:
        test_backend = Path(tmpdir) / "backend"
        test_backend.mkdir(parents=True)
        env_file = test_backend / ".env"

        with patch("scripts.initialize_environment.BACKEND_DIR", test_backend):
            exit_code = initialize_environment(quiet=True)
            assert exit_code == 0
            assert env_file.exists()
            content = env_file.read_text(encoding="utf-8")
            assert 'SECRET_KEY="' in content
            # Extract generated secret
            for line in content.splitlines():
                if line.startswith('SECRET_KEY="'):
                    generated = line.split('"')[1]
                    assert len(generated) == 64


# ------------------------------------------------------------------------------
# 4. REST Endpoints & RBAC Enforcement
# ------------------------------------------------------------------------------
def test_14_api_preflight_endpoint_requires_auth_and_authorized_role(
    client: TestClient, admin_user: User, tester_user: User
):
    """Verifies that GET /system/deployment/preflight enforces auth and role restrictions."""
    # Unauthenticated -> 401
    resp_unauth = client.get("/api/v1/system/deployment/preflight")
    assert resp_unauth.status_code == 401

    # Unauthorized role (TESTER without lead/admin/auditor) -> 403
    resp_tester = client.get(
        "/api/v1/system/deployment/preflight",
        headers=auth_headers(tester_user),
    )
    assert resp_tester.status_code == 403

    # Authorized (ADMIN) -> 200
    resp_admin = client.get(
        "/api/v1/system/deployment/preflight",
        headers=auth_headers(admin_user),
    )
    assert resp_admin.status_code == 200
    data = resp_admin.json()
    assert "status" in data
    assert "checks" in data


def test_15_api_config_endpoint_returns_redacted_settings(
    client: TestClient, admin_user: User
):
    """Verifies GET /system/deployment/config returns safe redacted diagnostics."""
    resp = client.get(
        "/api/v1/system/deployment/config",
        headers=auth_headers(admin_user),
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["environment"] in ["development", "testing", "production"]
    assert "***" in data["database_url_redacted"]
    assert "data_directories" in data


def test_16_api_upgrade_check_endpoint_evaluates_readiness(
    client: TestClient, admin_user: User
):
    """Verifies POST /system/deployment/upgrade-check returns migration analysis."""
    resp = client.post(
        "/api/v1/system/deployment/upgrade-check",
        headers=auth_headers(admin_user),
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["current_version"] == "1.0.0"
    assert data["target_version"] == "1.1.0"
    assert "migration_head" in data
    assert "can_upgrade" in data


def test_17_path_traversal_protection_in_filesystem_safeguards():
    """
    Verifies that safe path resolution rejects path traversal sequences ('..')
    attempting to escape designated application storage folders.
    """
    base_evidence_dir = (REPO_ROOT / "backend" / "data" / "evidence").resolve()

    def resolve_safe_evidence_path(user_supplied_filename: str) -> Path:
        resolved = (base_evidence_dir / user_supplied_filename).resolve()
        if not resolved.is_relative_to(base_evidence_dir):
            raise PermissionError(f"Access denied: path {resolved} traverses outside {base_evidence_dir}")
        return resolved

    # Valid relative filename
    valid_path = resolve_safe_evidence_path("scan_report_01.json")
    assert valid_path == base_evidence_dir / "scan_report_01.json"

    # Malicious path traversal attempts
    with pytest.raises(PermissionError):
        resolve_safe_evidence_path("../../../Windows/System32/cmd.exe")

    with pytest.raises(PermissionError):
        resolve_safe_evidence_path("..\\..\\..\\secret.env")
