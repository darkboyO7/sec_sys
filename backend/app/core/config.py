"""
Application Configuration and Hardening Settings (Prompt 45).
Enforces typed constraints, cryptographic bounds, safe development fallbacks,
and strict fail-closed validation for staging and production deployments.
"""
import enum
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Union
from pydantic import AnyHttpUrl, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_BACKEND_DIR = Path(__file__).resolve().parent.parent.parent
_DEFAULT_DB_FILE = (_BACKEND_DIR / "data" / "vapt.db").resolve().as_posix()
_DATA_ENV_FILE = (_BACKEND_DIR / "data" / ".env").resolve()
_ROOT_ENV_FILE = (_BACKEND_DIR / ".env").resolve()


class EnvironmentType(str, enum.Enum):
    DEVELOPMENT = "development"
    TESTING = "testing"
    STAGING = "staging"
    PRODUCTION = "production"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=(_DATA_ENV_FILE, _ROOT_ENV_FILE, ".env"),
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )

    ENVIRONMENT: str = "development"
    DEBUG: bool = False
    APP_NAME: str = "VAPT Security Platform"
    API_V1_STR: str = "/api/v1"

    # Database: Absolute path anchored to backend/data/vapt.db
    DATABASE_URL: str = f"sqlite:///{_DEFAULT_DB_FILE}"
    POSTGRES_POOL_SIZE: int = 20
    POSTGRES_MAX_OVERFLOW: int = 10
    POSTGRES_POOL_TIMEOUT: int = 30
    POSTGRES_POOL_RECYCLE: int = 1800
    DB_RETRY_MAX_ATTEMPTS: int = 3
    DB_RETRY_BASE_DELAY_SECONDS: float = 0.05

    # Security & Cryptography
    SECRET_KEY: str = "dev_insecure_secret_key_change_in_production_min_32_bytes_long"
    CREDENTIAL_ENCRYPTION_KEY: Optional[str] = None
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30

    # CORS
    ALLOWED_ORIGINS: Union[str, List[str]] = "http://localhost:5173,http://127.0.0.1:5173"

    # Audit & Security Controls
    AUDIT_LOG_STRICT: bool = True
    MAX_SCOPE_TARGETS_PER_PROJECT: int = 500
    SECRET_REDACTION_ENABLED: bool = True
    CONFIG_DIAGNOSTICS_ENABLED: bool = True

    # Phase 7A: Execution Worker Subprocess Configuration
    EXECUTION_MODE: str = "SUBPROCESS"  # "SUBPROCESS" or "IN_PROCESS"
    WORKER_TIMEOUT_GRACE_PERIOD_SECONDS: int = 3
    WORKER_MAX_IPC_PAYLOAD_BYTES: int = 10485760  # 10MB

    # Enterprise Scalability & Distributed Execution (Prompts 53-57)
    WORKER_BACKEND: str = "LOCAL"  # "LOCAL", "DISTRIBUTED", "HYBRID"
    WORKER_BROKER_URL: Optional[str] = None  # Optional redis:// or amqp:// URL
    WORKER_HEARTBEAT_INTERVAL_SECONDS: int = 10
    WORKER_HEARTBEAT_TIMEOUT_SECONDS: int = 30
    WORKER_MAX_CONCURRENT_JOBS: int = 8
    WORKER_MAX_CONCURRENT_JOBS_PER_PROJECT: int = 4
    WORKER_MAX_QUEUE_DEPTH: int = 50
    WORKER_JOB_MAX_RETRIES: int = 3
    WORKER_REGISTRATION_SECRET: Optional[str] = None
    BACKPRESSURE_REJECT_ON_OVERLOAD: bool = True

    # Prompt 49: Evidence Directory Separation
    EVIDENCE_DIR: str = str((_BACKEND_DIR / "data" / "evidence").resolve().as_posix())
    TEST_EVIDENCE_DIR: str = str((_BACKEND_DIR / "data" / "test_evidence").resolve().as_posix())

    # Prompt 52: Fault Injection Controls (Strictly test-only)
    FAULT_INJECTION_ENABLED: bool = False

    @field_validator("ENVIRONMENT")
    @classmethod
    def validate_environment(cls, v: str) -> str:
        norm = v.strip().lower()
        valid = {e.value for e in EnvironmentType}
        if norm not in valid:
            raise ValueError(
                f"Invalid ENVIRONMENT profile '{v}'. Must be one of: {', '.join(sorted(valid))}."
            )
        return norm

    def get_evidence_path(self) -> Path:
        """Returns the appropriate evidence storage directory based on active environment profile."""
        if self.ENVIRONMENT == EnvironmentType.TESTING.value:
            p = Path(self.TEST_EVIDENCE_DIR)
        else:
            p = Path(self.EVIDENCE_DIR)
        p.mkdir(parents=True, exist_ok=True)
        return p

    @field_validator("DATABASE_URL")
    @classmethod
    def validate_database_url(cls, v: str) -> str:
        if v.startswith("sqlite:///./") or v.startswith("sqlite:///data/"):
            filename = Path(v.replace("sqlite:///", "")).name
            anchored = (_BACKEND_DIR / "data" / filename).resolve().as_posix()
            return f"sqlite:///{anchored}"
        return v

    @field_validator("SECRET_KEY")
    @classmethod
    def validate_secret_key(cls, v: str) -> str:
        if len(v.strip()) < 32:
            raise ValueError("SECRET_KEY must be at least 32 characters long for cryptographic security.")
        return v

    @model_validator(mode="after")
    def validate_production_hardening(self) -> "Settings":
        env_lower = self.ENVIRONMENT.lower().strip()
        is_prod_like = env_lower in ("production", "staging")

        # 1. Secret Key Hardening
        forbidden_substrings = [
            "insecure",
            "change_in_production",
            "changeme",
            "test",
            "default",
            "sample",
            "password",
            "admin",
            "123456",
        ]

        if is_prod_like:
            # Reject weak or default secret key
            if any(bad in self.SECRET_KEY.lower() for bad in forbidden_substrings):
                raise ValueError(
                    f"Default or insecure SECRET_KEY is strictly forbidden in {env_lower} mode. "
                    "Generate a cryptographically secure 32+ character key."
                )

            # Ensure minimum entropy (at least 8 distinct characters)
            if len(set(self.SECRET_KEY)) < 8:
                raise ValueError(
                    "SECRET_KEY has insufficient character entropy. Use a high-entropy random token."
                )

            # Reject DEBUG in production
            if self.DEBUG:
                raise ValueError(f"DEBUG mode must be set to False in {env_lower}.")

            # Reject permissive audit logging in production
            if not self.AUDIT_LOG_STRICT:
                raise ValueError(f"AUDIT_LOG_STRICT must be set to True in {env_lower}.")

            # Reject permissive or local CORS origins in production
            origins = self.cors_origins
            if "*" in origins:
                raise ValueError(f"Wildcard '*' in ALLOWED_ORIGINS is strictly forbidden in {env_lower} mode.")
            if any("localhost" in orig.lower() or "127.0.0.1" in orig for orig in origins):
                raise ValueError(
                    f"Localhost/127.0.0.1 origins in ALLOWED_ORIGINS are forbidden in {env_lower} mode."
                )

            # Reject SQLite in production-like environments
            if "sqlite" in self.DATABASE_URL.lower():
                raise ValueError(
                    f"SQLite database is forbidden in {env_lower} mode. A managed enterprise PostgreSQL database is required."
                )

            # Reject Fault Injection in production-like environments (Prompt 52)
            if self.FAULT_INJECTION_ENABLED:
                raise ValueError(
                    f"FAULT_INJECTION_ENABLED must be False in {env_lower} mode. Fault injection is strictly prohibited in production and staging."
                )

            # Validate PostgreSQL connection string credentials
            if "postgres" in self.DATABASE_URL.lower():
                if "postgres:postgres@" in self.DATABASE_URL.lower():
                    raise ValueError(
                        f"Default 'postgres:postgres' credentials in DATABASE_URL are forbidden in {env_lower} mode."
                    )
                # Ensure password is present
                match = re.search(r"postgresql(?:\+[a-z0-9]+)?://([^:]+):([^@]+)@", self.DATABASE_URL)
                if not match or not match.group(2).strip():
                    raise ValueError(
                        f"DATABASE_URL is missing a non-empty database password in {env_lower} mode."
                    )

            # Validate Distributed Worker Authentication Secret (Prompt 53-57)
            if self.WORKER_BACKEND.upper() in ("DISTRIBUTED", "HYBRID"):
                if not self.WORKER_REGISTRATION_SECRET or len(self.WORKER_REGISTRATION_SECRET) < 32:
                    raise ValueError(
                        f"WORKER_REGISTRATION_SECRET must be configured with at least 32 characters in {env_lower} mode when using distributed workers."
                    )

        return self

    @property
    def cors_origins(self) -> List[str]:
        if isinstance(self.ALLOWED_ORIGINS, list):
            return self.ALLOWED_ORIGINS
        return [origin.strip() for origin in self.ALLOWED_ORIGINS.split(",") if origin.strip()]

    def get_config_diagnostics(self) -> List[Dict[str, Any]]:
        """
        Evaluates the health and status of all primary settings without exposing raw secret values.
        Returns diagnostic items suitable for health dashboards and security compliance audits.
        """
        env_lower = self.ENVIRONMENT.lower().strip()
        is_prod = env_lower in ("production", "staging")
        diagnostics = []

        # 1. ENVIRONMENT
        diagnostics.append({
            "key": "ENVIRONMENT",
            "is_secret": False,
            "configured": bool(self.ENVIRONMENT),
            "status": "PASS",
            "strength": "NOT_APPLICABLE",
            "redacted_value": self.ENVIRONMENT,
            "message": f"Operating in '{self.ENVIRONMENT}' profile.",
        })

        # 2. DEBUG
        dbg_status = "PASS" if not self.DEBUG else ("FAIL" if is_prod else "WARN")
        diagnostics.append({
            "key": "DEBUG",
            "is_secret": False,
            "configured": True,
            "status": dbg_status,
            "strength": "NOT_APPLICABLE",
            "redacted_value": str(self.DEBUG),
            "message": "DEBUG disabled" if not self.DEBUG else ("DEBUG enabled (Forbidden in production)" if is_prod else "DEBUG enabled for development"),
        })

        # 3. SECRET_KEY
        sk = self.SECRET_KEY
        sk_len = len(sk)
        is_dev_default = any(b in sk.lower() for b in ["insecure", "change_in_production", "test"])
        if is_dev_default:
            sk_status = "FAIL" if is_prod else "WARN"
            sk_strength = "DEFAULT_INSECURE"
            sk_msg = "Using known development fallback secret key."
        elif sk_len >= 32 and len(set(sk)) >= 8:
            sk_status = "PASS"
            sk_strength = "STRONG"
            sk_msg = f"Cryptographically strong secret key ({sk_len} chars, sufficient entropy)."
        else:
            sk_status = "WARN"
            sk_strength = "ADEQUATE"
            sk_msg = f"Secret key meets minimum length ({sk_len} chars)."

        masked_sk = f"{sk[:3]}****{sk[-3:]}" if sk_len > 8 else "********"
        diagnostics.append({
            "key": "SECRET_KEY",
            "is_secret": True,
            "configured": True,
            "status": sk_status,
            "strength": sk_strength,
            "redacted_value": masked_sk,
            "message": sk_msg,
        })

        # 4. CREDENTIAL_ENCRYPTION_KEY
        cek = self.CREDENTIAL_ENCRYPTION_KEY
        if cek:
            cek_status = "PASS"
            cek_strength = "STRONG" if len(cek) >= 32 else "ADEQUATE"
            cek_msg = "Dedicated credential encryption key configured."
            masked_cek = f"{cek[:3]}****{cek[-3:]}" if len(cek) > 8 else "********"
        else:
            cek_status = "PASS"
            cek_strength = "ADEQUATE"
            cek_msg = "Derived from SECRET_KEY (standard unified vault derivation)."
            masked_cek = "[DERIVED_FROM_SECRET_KEY]"

        diagnostics.append({
            "key": "CREDENTIAL_ENCRYPTION_KEY",
            "is_secret": True,
            "configured": bool(cek),
            "status": cek_status,
            "strength": cek_strength,
            "redacted_value": masked_cek,
            "message": cek_msg,
        })

        # 5. DATABASE_URL
        raw_db = self.DATABASE_URL
        if "sqlite" in raw_db.lower():
            db_status = "FAIL" if is_prod else "PASS"
            db_strength = "ADEQUATE" if not is_prod else "WEAK"
            redacted_db = "sqlite:///***LOCAL_DATA_DIR***/vapt.db"
            db_msg = "Local SQLite database engine (Forbidden in production)" if is_prod else "Local SQLite database configured for development."
        elif "postgres" in raw_db.lower():
            redacted_db = re.sub(r":([^@]+)@", ":***REDACTED***@", raw_db)
            is_default_pg = "postgres:postgres@" in raw_db.lower()
            if is_default_pg:
                db_status = "FAIL" if is_prod else "WARN"
                db_strength = "DEFAULT_INSECURE"
                db_msg = "PostgreSQL using default 'postgres:postgres' credentials."
            else:
                db_status = "PASS"
                db_strength = "STRONG"
                db_msg = "Enterprise PostgreSQL engine configured."
        else:
            redacted_db = "***REDACTED***"
            db_status = "PASS"
            db_strength = "ADEQUATE"
            db_msg = "External database configured."

        diagnostics.append({
            "key": "DATABASE_URL",
            "is_secret": True,
            "configured": True,
            "status": db_status,
            "strength": db_strength,
            "redacted_value": redacted_db,
            "message": db_msg,
        })

        # 6. ALLOWED_ORIGINS
        origins = self.cors_origins
        has_wildcard = "*" in origins
        has_local = any("localhost" in o or "127.0.0.1" in o for o in origins)
        if has_wildcard:
            cors_status = "FAIL" if is_prod else "WARN"
            cors_msg = "Wildcard '*' origin enabled."
        elif is_prod and has_local:
            cors_status = "FAIL"
            cors_msg = "Localhost origins present in production."
        else:
            cors_status = "PASS"
            cors_msg = f"{len(origins)} explicit trusted origin(s) configured."

        diagnostics.append({
            "key": "ALLOWED_ORIGINS",
            "is_secret": False,
            "configured": bool(origins),
            "status": cors_status,
            "strength": "NOT_APPLICABLE",
            "redacted_value": ", ".join(origins),
            "message": cors_msg,
        })

        # 7. AUDIT_LOG_STRICT
        audit_status = "PASS" if self.AUDIT_LOG_STRICT else ("FAIL" if is_prod else "WARN")
        diagnostics.append({
            "key": "AUDIT_LOG_STRICT",
            "is_secret": False,
            "configured": True,
            "status": audit_status,
            "strength": "NOT_APPLICABLE",
            "redacted_value": str(self.AUDIT_LOG_STRICT),
            "message": "Immutable audit hash-chaining strictly enforced." if self.AUDIT_LOG_STRICT else "Strict audit logging disabled.",
        })

        # 8. SECRET_REDACTION_ENABLED
        diagnostics.append({
            "key": "SECRET_REDACTION_ENABLED",
            "is_secret": False,
            "configured": True,
            "status": "PASS" if self.SECRET_REDACTION_ENABLED else "WARN",
            "strength": "STRONG" if self.SECRET_REDACTION_ENABLED else "WEAK",
            "redacted_value": str(self.SECRET_REDACTION_ENABLED),
            "message": "Global secret redaction filter active for logs, exceptions, and diagnostics.",
        })

        # 9. FAULT_INJECTION_ENABLED (Prompt 52)
        fi_status = "FAIL" if (is_prod and self.FAULT_INJECTION_ENABLED) else "PASS"
        diagnostics.append({
            "key": "FAULT_INJECTION_ENABLED",
            "is_secret": False,
            "configured": True,
            "status": fi_status,
            "strength": "STRONG" if not self.FAULT_INJECTION_ENABLED else "WEAK",
            "redacted_value": str(self.FAULT_INJECTION_ENABLED),
            "message": "Fault injection disabled (safe)" if not self.FAULT_INJECTION_ENABLED else "Fault injection enabled (test only)",
        })

        return diagnostics


settings = Settings()
