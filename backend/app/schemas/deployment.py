"""
VAPT Platform — Secure Windows Deployment & Configuration Governance Schemas (Prompt 28).
Typed models for preflight checks, redacted configuration diagnostics, directory health,
and safe application upgrade governance.
"""
from typing import Optional, List, Dict, Any
from datetime import datetime, timezone
import enum
from pydantic import BaseModel, Field


class EnvironmentMode(str, enum.Enum):
    DEVELOPMENT = "development"
    TESTING = "testing"
    PRODUCTION = "production"


class CheckSeverity(str, enum.Enum):
    PASS = "PASS"
    WARN = "WARN"
    FAIL = "FAIL"


class PreflightCheckItem(BaseModel):
    name: str
    category: str
    status: CheckSeverity
    details: str
    remediation_advice: Optional[str] = None


class PreflightReport(BaseModel):
    status: str  # PASSED, WARNINGS, FATAL_ERROR
    environment: str
    total_checks: int
    passed_count: int
    warning_count: int
    failure_count: int
    checks: List[PreflightCheckItem]
    evaluated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class ConfigDiagnosticItem(BaseModel):
    key: str
    is_secret: bool
    configured: bool
    status: str
    strength: str
    redacted_value: str
    message: str


class ConfigDiagnosticResponse(BaseModel):
    environment: str
    total_settings: int
    passed_count: int
    warning_count: int
    failure_count: int
    items: List[ConfigDiagnosticItem]
    evaluated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class RedactedConfigResponse(BaseModel):
    environment: str
    debug: bool
    app_name: str
    database_type: str
    database_url_redacted: str
    allowed_origins: List[str]
    audit_strict: bool
    data_directories: Dict[str, str]
    cryptographic_algorithm: str
    token_expiry_minutes: int
    worker_execution_mode: str
    retrieved_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class UpgradePrecheckResponse(BaseModel):
    current_version: str
    target_version: str
    migration_head: str
    current_db_version: str
    pending_migrations_count: int
    backup_required: bool
    can_upgrade: bool
    recommended_action: str
    checked_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
