"""
Prompt 45 Acceptance Test Suite:
Secrets Management, Configuration Validation, and Credential Lifecycle Security.

Verifies:
1. Strict fail-closed configuration validation in staging/production environments.
2. Safe local development defaults with non-blocking diagnostic warnings.
3. Universal secret redaction across logs, exceptions, and stack traces.
4. Deep dictionary/payload secret scrubbing for APIs, exports, and diagnostics.
5. Authenticated Fernet encryption at rest with legacy JSON migration and re-encryption.
6. Connector credential lifecycle, masking, and administrative rotation without leakage.
7. Configuration diagnostics endpoint reporting setting posture with zero secret exposure.
8. Frontend build variable scanner detecting dangerous VITE_* secrets.
9. Release packaging secret scanning gate blocking credentials and sensitive artifacts.
"""
import copy
import json
import logging
import os
import tempfile
from pathlib import Path
from typing import Dict, Any
import pytest
from pydantic import ValidationError
from fastapi.testclient import TestClient

from app.core.config import Settings, EnvironmentType
from app.core.secret_redaction import (
    redact_secrets_from_text,
    redact_secrets_from_dict,
    mask_secret_string,
    SecretRedactionLoggingFilter,
    REDACTED_SUBSTITUTE,
)
from app.core.secret_vault import SecretVault, ENCRYPTION_PREFIX
from app.core.database import SessionLocal
from app.models.user import User, SystemRole
from app.models.organization import Organization
from app.models.project import Project
from app.models.connector import ConnectorConfiguration
from app.services.connector_service import ConnectorService
from app.schemas.connector import ConnectorConfigCreate
from app.services.startup_preflight_service import startup_preflight_service
from app.services.supply_chain_security_service import (
    SupplyChainSecurityService,
    SECRET_PATTERNS,
)
from app.main import app

client = TestClient(app)


# ---------------------------------------------------------------------------
# Test 1: Production Configuration Hardening Fails Closed
# ---------------------------------------------------------------------------
def test_01_production_configuration_fails_closed_on_insecure_settings():
    """Verifies that production and staging environments fail closed on weak or insecure configuration."""
    valid_prod_key = "c8f7d6e5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7"
    valid_pg_url = "postgresql://vapt_app:SuperStr0ngP@ssw0rd!@db.internal.corp:5432/vapt_prod"

    # 1. Reject weak or default secret key in production
    with pytest.raises(ValidationError) as exc_info:
        Settings(
            ENVIRONMENT="production",
            SECRET_KEY="dev_insecure_secret_key_change_in_production_min_32_bytes_long",
            DATABASE_URL=valid_pg_url,
            DEBUG=False,
            AUDIT_LOG_STRICT=True,
            ALLOWED_ORIGINS="https://security.example.com",
        )
    assert "Default or insecure SECRET_KEY is strictly forbidden in production mode" in str(exc_info.value)

    # 2. Reject short secret key (< 32 chars)
    with pytest.raises(ValidationError) as exc_info:
        Settings(
            ENVIRONMENT="production",
            SECRET_KEY="short_key",
            DATABASE_URL=valid_pg_url,
        )
    assert "SECRET_KEY must be at least 32 characters long" in str(exc_info.value)

    # 3. Reject low-entropy secret key
    with pytest.raises(ValidationError) as exc_info:
        Settings(
            ENVIRONMENT="production",
            SECRET_KEY="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            DATABASE_URL=valid_pg_url,
            DEBUG=False,
            AUDIT_LOG_STRICT=True,
            ALLOWED_ORIGINS="https://security.example.com",
        )
    assert "insufficient character entropy" in str(exc_info.value)

    # 4. Reject DEBUG=True in production
    with pytest.raises(ValidationError) as exc_info:
        Settings(
            ENVIRONMENT="production",
            SECRET_KEY=valid_prod_key,
            DATABASE_URL=valid_pg_url,
            DEBUG=True,
            AUDIT_LOG_STRICT=True,
            ALLOWED_ORIGINS="https://security.example.com",
        )
    assert "DEBUG mode must be set to False in production" in str(exc_info.value)

    # 5. Reject AUDIT_LOG_STRICT=False in production
    with pytest.raises(ValidationError) as exc_info:
        Settings(
            ENVIRONMENT="production",
            SECRET_KEY=valid_prod_key,
            DATABASE_URL=valid_pg_url,
            DEBUG=False,
            AUDIT_LOG_STRICT=False,
            ALLOWED_ORIGINS="https://security.example.com",
        )
    assert "AUDIT_LOG_STRICT must be set to True in production" in str(exc_info.value)

    # 6. Reject wildcard CORS origin in production
    with pytest.raises(ValidationError) as exc_info:
        Settings(
            ENVIRONMENT="production",
            SECRET_KEY=valid_prod_key,
            DATABASE_URL=valid_pg_url,
            DEBUG=False,
            AUDIT_LOG_STRICT=True,
            ALLOWED_ORIGINS="*",
        )
    assert "Wildcard '*' in ALLOWED_ORIGINS is strictly forbidden" in str(exc_info.value)

    # 7. Reject localhost origin in production
    with pytest.raises(ValidationError) as exc_info:
        Settings(
            ENVIRONMENT="production",
            SECRET_KEY=valid_prod_key,
            DATABASE_URL=valid_pg_url,
            DEBUG=False,
            AUDIT_LOG_STRICT=True,
            ALLOWED_ORIGINS="https://security.example.com,http://localhost:3000",
        )
    assert "Localhost/127.0.0.1 origins in ALLOWED_ORIGINS are forbidden" in str(exc_info.value)

    # 8. Reject SQLite in production
    with pytest.raises(ValidationError) as exc_info:
        Settings(
            ENVIRONMENT="production",
            SECRET_KEY=valid_prod_key,
            DATABASE_URL="sqlite:///D:/alt/backend/data/vapt.db",
            DEBUG=False,
            AUDIT_LOG_STRICT=True,
            ALLOWED_ORIGINS="https://security.example.com",
        )
    assert "SQLite database is forbidden in production mode" in str(exc_info.value)

    # 9. Reject default 'postgres:postgres' credentials in production
    with pytest.raises(ValidationError) as exc_info:
        Settings(
            ENVIRONMENT="production",
            SECRET_KEY=valid_prod_key,
            DATABASE_URL="postgresql://postgres:postgres@db.internal:5432/vapt",
            DEBUG=False,
            AUDIT_LOG_STRICT=True,
            ALLOWED_ORIGINS="https://security.example.com",
        )
    assert "Default 'postgres:postgres' credentials in DATABASE_URL are forbidden" in str(exc_info.value)

    # 10. Valid production settings succeed
    prod_settings = Settings(
        ENVIRONMENT="production",
        SECRET_KEY=valid_prod_key,
        DATABASE_URL=valid_pg_url,
        DEBUG=False,
        AUDIT_LOG_STRICT=True,
        ALLOWED_ORIGINS="https://security.example.com,https://app.security.example.com",
    )
    assert prod_settings.ENVIRONMENT == "production"
    assert prod_settings.DEBUG is False
    assert len(prod_settings.cors_origins) == 2


# ---------------------------------------------------------------------------
# Test 2: Safe Development Defaults & Diagnostic Posture
# ---------------------------------------------------------------------------
def test_02_development_mode_maintains_safe_defaults():
    """Verifies that development configuration boots safely with local defaults and non-fatal warnings."""
    dev_settings = Settings(
        ENVIRONMENT="development",
        SECRET_KEY="dev_insecure_secret_key_change_in_production_min_32_bytes_long",
        DEBUG=False,
        AUDIT_LOG_STRICT=True,
    )
    assert dev_settings.ENVIRONMENT == "development"
    assert "sqlite" in dev_settings.DATABASE_URL.lower()

    # Diagnostics should flag DEFAULT_INSECURE for secret key without raising exceptions
    diags = dev_settings.get_config_diagnostics()
    sk_diag = next(d for d in diags if d["key"] == "SECRET_KEY")
    assert sk_diag["is_secret"] is True
    assert sk_diag["strength"] == "DEFAULT_INSECURE"
    assert sk_diag["status"] == "WARN"
    assert "dev_insecure_secret_key" not in sk_diag["redacted_value"]


# ---------------------------------------------------------------------------
# Test 3: Secret Redaction in Text, Logs, Exceptions, and Stack Traces
# ---------------------------------------------------------------------------
def test_03_secret_redaction_in_text_logs_and_exceptions():
    """Verifies that string redaction sanitizes tokens, passwords, private keys, and connection strings."""
    # 1. Database connection string with password
    raw_db = "OperationalError: connection to postgresql://vapt_admin:MySuperSecretPassw0rd!@10.0.0.5:5432/vapt failed"
    redacted_db = redact_secrets_from_text(raw_db)
    assert "MySuperSecretPassw0rd!" not in redacted_db
    assert "postgresql://vapt_admin:***REDACTED***@10.0.0.5" in redacted_db

    # 2. Bearer tokens
    raw_bearer = "Authorization header: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.doNotLeakThisSignature"
    redacted_bearer = redact_secrets_from_text(raw_bearer)
    assert "doNotLeakThisSignature" not in redacted_bearer
    assert "Bearer ***REDACTED***" in redacted_bearer

    # 3. Private Key Block
    raw_pem = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEowIBAAKCAQEA0Y+u1234567890abcdefghijklmnopqrstuvwxyz\n"
        "-----END RSA PRIVATE KEY-----"
    )
    redacted_pem = redact_secrets_from_text(raw_pem)
    assert "MIIEowIBAAKCAQEA0Y+u" not in redacted_pem
    assert "***REDACTED PRIVATE KEY***" in redacted_pem

    # 4. GitHub and Slack tokens
    raw_tokens = "GitHub token ghp_123456789012345678901234567890123456 and Slack xoxb-1234567890-123456789012-abcdef123456"
    redacted_tokens = redact_secrets_from_text(raw_tokens)
    assert "ghp_123456789012345678901234567890123456" not in redacted_tokens
    assert "xoxb-1234567890-123456789012-abcdef123456" not in redacted_tokens
    assert REDACTED_SUBSTITUTE in redacted_tokens

    # 5. Logging Filter verification
    logger = logging.getLogger("test_redaction_logger")
    log_filter = SecretRedactionLoggingFilter()
    logger.addFilter(log_filter)

    record = logging.LogRecord(
        name="test",
        level=logging.ERROR,
        pathname=__file__,
        lineno=1,
        msg="Failed connection to postgresql://user:Secret123@host:5432/db with token ghp_111111111111111111111111111111111111",
        args=(),
        exc_info=None,
    )
    log_filter.filter(record)
    assert "Secret123" not in record.msg
    assert "ghp_111111111111111111111111111111111111" not in record.msg


# ---------------------------------------------------------------------------
# Test 4: Secret Redaction in Nested Dictionaries and JSON Payloads
# ---------------------------------------------------------------------------
def test_04_secret_redaction_in_nested_dictionaries():
    """Verifies recursive sanitization of sensitive keys in nested dictionaries and collections."""
    payload = {
        "service": "jira_integration",
        "enabled": True,
        "credentials": {
            "api_key": "secret_api_key_value_987654321",
            "password": "SuperSecretPassword123!",
            "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgk...\n-----END PRIVATE KEY-----",
            "access_token": "token_xyz_99999",
        },
        "endpoints": [
            "https://jira.corp.internal/rest/api/2",
            "postgresql://jira_user:JiraPass789@db.internal:5432/jira",
        ],
        "safe_metadata": {
            "version": "1.0.0",
            "environment": "production",
            "port": 8080,
        },
    }

    sanitized = redact_secrets_from_dict(payload)

    # Sensitive values must be masked
    assert "secret_api_key_value_987654321" not in str(sanitized)
    assert "SuperSecretPassword123!" not in str(sanitized)
    assert "MIIEvgIBADANBgk" not in str(sanitized)
    assert "token_xyz_99999" not in str(sanitized)
    assert "JiraPass789" not in str(sanitized)

    # Safe metadata must be preserved
    assert sanitized["service"] == "jira_integration"
    assert sanitized["enabled"] is True
    assert sanitized["safe_metadata"]["version"] == "1.0.0"
    assert sanitized["safe_metadata"]["port"] == 8080


# ---------------------------------------------------------------------------
# Test 5: SecretVault Authenticated Encryption at Rest & Key Rotation
# ---------------------------------------------------------------------------
def test_05_secret_vault_encryption_migration_and_rotation():
    """Verifies authenticated symmetric encryption at rest (Fernet) and migration."""
    key_v1 = "initial_secret_key_for_testing_purposes_at_least_32_bytes_long"
    key_v2 = "rotated_secret_key_for_testing_purposes_at_least_32_bytes_long"

    credentials = {
        "client_id": "oauth_client_001",
        "client_secret": "super_secret_oauth_token_val_12345",
        "api_endpoint": "https://auth.corp.internal/token",
    }

    # 1. Encryption envelope format
    encrypted_payload = SecretVault.encrypt_credentials(credentials, secret_key=key_v1)
    assert encrypted_payload.startswith(ENCRYPTION_PREFIX)
    assert "super_secret_oauth_token_val_12345" not in encrypted_payload
    assert SecretVault.is_encrypted(encrypted_payload) is True

    # 2. Decryption fidelity
    decrypted = SecretVault.decrypt_credentials(encrypted_payload, secret_key=key_v1)
    assert decrypted == credentials

    # 3. Decryption with wrong key fails closed
    with pytest.raises(ValueError) as exc_info:
        SecretVault.decrypt_credentials(encrypted_payload, secret_key=key_v2)
    assert "Failed to decrypt stored credentials" in str(exc_info.value)

    # 4. Decryption of tampered ciphertext fails closed
    tampered_payload = encrypted_payload[:-6] + "xxxxxx"
    with pytest.raises(ValueError) as exc_info:
        SecretVault.decrypt_credentials(tampered_payload, secret_key=key_v1)
    assert "Failed to decrypt stored credentials" in str(exc_info.value)

    # 5. Transparent legacy migration: unencrypted JSON string is parsed cleanly
    legacy_json = json.dumps(credentials)
    legacy_decrypted = SecretVault.decrypt_credentials(legacy_json, secret_key=key_v1)
    assert legacy_decrypted == credentials

    # 6. Re-encryption for secret key rotation
    reencrypted = SecretVault.reencrypt_credentials(
        encrypted_payload,
        old_secret_key=key_v1,
        new_secret_key=key_v2,
    )
    assert reencrypted.startswith(ENCRYPTION_PREFIX)
    assert reencrypted != encrypted_payload
    # Decrypt with new key succeeds
    assert SecretVault.decrypt_credentials(reencrypted, secret_key=key_v2) == credentials


# ---------------------------------------------------------------------------
# Test 6: Connector Credential Lifecycle and Safe Rotation
# ---------------------------------------------------------------------------
def test_06_connector_credential_storage_and_safe_rotation():
    """Verifies connector credential encryption at rest, masked views, and administrative rotation."""
    db = SessionLocal()
    try:
        # Ensure an organization exists for the project
        org = db.query(Organization).first()
        if not org:
            org = Organization(name="Prompt45 Security Test Org")
            db.add(org)
            db.commit()
            db.refresh(org)

        # Create or fetch test project
        project = db.query(Project).filter(Project.name == "Prompt45 Security Test Project").first()
        if not project:
            project = Project(
                organization_id=org.id,
                name="Prompt45 Security Test Project",
                description="Project for credential lifecycle tests",
            )
            db.add(project)
            db.commit()
            db.refresh(project)

        # 1. Register connector with sensitive credentials
        secret_token = "synthetic_aws_secret_access_key_1234567890abcdef"
        connector_data = ConnectorConfigCreate(
            name="Production Cloud Asset Discovery",
            provider_type="CLOUD_ASSET_INVENTORY",
            enabled=True,
            capabilities=["PULL_ASSETS", "TEST_CONNECTIVITY"],
            settings={
                "api_endpoint": "https://api.aws.amazon.com",
                "secret_access_key": secret_token,
                "cloud_provider": "AWS",
            },
        )

        connector = ConnectorService.create_connector(db, project.id, connector_data)

        # Verify encryption at rest
        assert connector.settings_encrypted.startswith(ENCRYPTION_PREFIX)
        assert secret_token not in connector.settings_encrypted

        # Verify masked representation
        masked = connector.settings_masked
        assert secret_token not in str(masked)
        assert masked["secret_access_key"].startswith("syn****")

        # 2. Test connection decrypts cleanly
        health = ConnectorService.test_connection(db, project.id, connector.id)
        assert health.status == "HEALTHY"

        # 3. Rotate credentials without leaking new secret
        new_secret_token = "new_synthetic_aws_secret_key_rotated_token_987654321"
        rotated_connector = ConnectorService.rotate_connector_credentials(
            db=db,
            project_id=project.id,
            connector_id=connector.id,
            new_settings={
                "api_endpoint": "https://api.aws.amazon.com",
                "secret_access_key": new_secret_token,
                "cloud_provider": "AWS",
            },
        )

        # Verify rotated ciphertext
        assert rotated_connector.settings_encrypted.startswith(ENCRYPTION_PREFIX)
        assert new_secret_token not in rotated_connector.settings_encrypted

        # Verify decrypted payload has new secret
        decrypted_settings = SecretVault.decrypt_credentials(rotated_connector.settings_encrypted)
        assert decrypted_settings["secret_access_key"] == new_secret_token

        # Clean up
        ConnectorService.delete_connector(db, project.id, connector.id)

    finally:
        db.close()


# ---------------------------------------------------------------------------
# Test 7: Configuration Diagnostic Endpoint Reports Health Without Leakage
# ---------------------------------------------------------------------------
def test_07_configuration_diagnostic_endpoint_reports_health_without_secret_leakage():
    """Verifies that config diagnostic reports setting health and posture without exposing secret values."""
    report = startup_preflight_service.get_config_diagnostics()
    assert report.total_settings >= 8
    assert report.passed_count + report.warning_count + report.failure_count == report.total_settings

    # Verify that no item exposes raw secret tokens
    for item in report.items:
        val = item.redacted_value
        # If secret, must be masked
        if item.is_secret:
            assert "dev_insecure_secret_key" not in val
            assert "password" not in val.lower() or "***REDACTED***" in val or "********" in val
            if item.key == "DATABASE_URL" and "sqlite" in val:
                assert "***LOCAL_DATA_DIR***" in val

    # Verify API serialization
    resp = client.get("/api/v1/system/deployment/config/diagnostic")
    # 401 when unauthenticated (expected role guard)
    assert resp.status_code in (401, 403)


# ---------------------------------------------------------------------------
# Test 8: Frontend Variable Audit Detects Exposed VITE_* Secrets
# ---------------------------------------------------------------------------
def test_08_frontend_variable_audit_detects_and_blocks_vite_secrets():
    """Verifies that frontend variable scanner detects and blocks dangerous VITE_* secret names."""
    service = SupplyChainSecurityService()

    # 1. Clean frontend repository check
    clean_violations = service.audit_frontend_build_variables()
    assert len(clean_violations) == 0, f"Expected 0 frontend variable violations, found: {clean_violations}"

    # 2. Simulated temp frontend directory containing forbidden VITE_SECRET
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        env_file = tmp_path / ".env.production"
        env_file.write_text(
            "VITE_API_URL=https://api.vapt.corp\n"
            "VITE_APP_NAME=VAPT Frontend\n"
            "VITE_BACKEND_SECRET_KEY=dangerous_backend_secret_key_12345\n"
            "VITE_DATABASE_PASSWORD=should_never_be_in_frontend\n",
            encoding="utf-8",
        )

        violations = service.audit_frontend_build_variables(frontend_dir=tmp_path)
        assert len(violations) == 2
        assert any("VITE_BACKEND_SECRET_KEY" in v for v in violations)
        assert any("VITE_DATABASE_PASSWORD" in v for v in violations)


# ---------------------------------------------------------------------------
# Test 9: Release Packaging Secret-Scanning Gate
# ---------------------------------------------------------------------------
def test_09_release_packaging_secret_scanning_gate():
    """Verifies that secret scanner identifies forbidden patterns and sensitive artifacts."""
    service = SupplyChainSecurityService()

    # 1. Active repository check (excluding test files / mocks)
    scan_resp = service.scan_sensitive_artifacts()
    assert scan_resp.status == "CLEAN", f"Found unexpected sensitive artifacts: {scan_resp.findings}"

    # 2. Controlled synthetic secret detection in disposable directory
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        bad_file = tmp_path / "leaked_credentials.py"
        bad_file.write_text(
            "AWS_KEY = 'AKIA1234567890ABCDEF'\n"
            "GH_TOKEN = 'ghp_123456789012345678901234567890123456'\n",
            encoding="utf-8",
        )

        scan_dirty = service.scan_sensitive_artifacts(target_dir=tmp_path)
        assert scan_dirty.status == "SECRETS_DETECTED"
        assert scan_dirty.total_findings >= 2
        rule_names = {f.rule_name for f in scan_dirty.findings}
        assert "AWS Access Key ID" in rule_names
        assert "GitHub Personal Access Token" in rule_names
