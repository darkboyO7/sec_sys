from typing import List, Union
from pydantic import AnyHttpUrl, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )

    ENVIRONMENT: str = "development"
    DEBUG: bool = False
    APP_NAME: str = "VAPT Security Platform"
    API_V1_STR: str = "/api/v1"

    # Database
    DATABASE_URL: str = "sqlite:///./data/vapt.db"
    POSTGRES_POOL_SIZE: int = 20
    POSTGRES_MAX_OVERFLOW: int = 10
    POSTGRES_POOL_TIMEOUT: int = 30
    POSTGRES_POOL_RECYCLE: int = 1800
    DB_RETRY_MAX_ATTEMPTS: int = 3
    DB_RETRY_BASE_DELAY_SECONDS: float = 0.05

    # Security & Cryptography
    SECRET_KEY: str = "dev_insecure_secret_key_change_in_production_min_32_bytes_long"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30

    # CORS
    ALLOWED_ORIGINS: Union[str, List[str]] = "http://localhost:5173,http://127.0.0.1:5173"

    # Audit & Security Controls
    AUDIT_LOG_STRICT: bool = True
    MAX_SCOPE_TARGETS_PER_PROJECT: int = 500

    # Phase 7A: Execution Worker Subprocess Configuration
    EXECUTION_MODE: str = "SUBPROCESS"  # "SUBPROCESS" or "IN_PROCESS"
    WORKER_TIMEOUT_GRACE_PERIOD_SECONDS: int = 3
    WORKER_MAX_IPC_PAYLOAD_BYTES: int = 10485760  # 10MB

    @field_validator("SECRET_KEY")
    @classmethod
    def validate_secret_key(cls, v: str, info) -> str:
        if len(v.strip()) < 32:
            raise ValueError("SECRET_KEY must be at least 32 characters long for cryptographic security.")
        return v

    @model_validator(mode="after")
    def validate_production_hardening(self) -> "Settings":
        if self.ENVIRONMENT.lower() == "production":
            if any(bad in self.SECRET_KEY.lower() for bad in ["insecure", "change_in_production", "test"]):
                raise ValueError("Default or development SECRET_KEY is strictly forbidden in production mode.")
            if self.DEBUG:
                raise ValueError("DEBUG mode must be set to False in production.")
            if not self.AUDIT_LOG_STRICT:
                raise ValueError("AUDIT_LOG_STRICT must be set to True in production.")
            origins = self.cors_origins
            if "*" in origins:
                raise ValueError("Wildcard '*' in ALLOWED_ORIGINS is strictly forbidden in production mode.")
        return self

    @property
    def cors_origins(self) -> List[str]:
        if isinstance(self.ALLOWED_ORIGINS, list):
            return self.ALLOWED_ORIGINS
        return [origin.strip() for origin in self.ALLOWED_ORIGINS.split(",") if origin.strip()]


settings = Settings()
