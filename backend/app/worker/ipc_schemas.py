"""Typed IPC Request and Response contracts for isolated worker processes.

Protocol version: 1.0.0
"""
import math
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field, field_validator
from app.services.scanner_adapters.base import RawAdapterFinding, MAX_FINDINGS_PER_JOB


SUPPORTED_PROTOCOL_VERSION = "1.0.0"
MAX_ERRORS_PER_RESPONSE = 50
MAX_STATUS_SUMMARY_CHARS = 1000


class WorkerIPCRequest(BaseModel):
    """
    Structured IPC request delivered from the server process to the worker process.
    """
    protocol_version: str = Field(default=SUPPORTED_PROTOCOL_VERSION)
    job_id: str = Field(min_length=1, max_length=100)
    project_id: str = Field(min_length=1, max_length=100)
    worker_id: str = Field(min_length=1, max_length=100)
    attempt_count: int = Field(ge=1, le=100)
    target_input: str = Field(min_length=1, max_length=2048)
    adapter_name: str = Field(min_length=1, max_length=100)
    adapter_version: str = Field(default="1.0.0", max_length=50)
    policy_version: str = Field(default="2026.1", max_length=50)
    config: Dict[str, Any] = Field(default_factory=dict)
    timeout_seconds: int = Field(default=300, ge=1, le=3600)
    auth_context: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("protocol_version")
    @classmethod
    def validate_protocol_version(cls, v: str) -> str:
        if v != SUPPORTED_PROTOCOL_VERSION:
            raise ValueError(
                f"Unsupported IPC protocol version '{v}'. Supported: '{SUPPORTED_PROTOCOL_VERSION}'"
            )
        return v


class WorkerIPCResponse(BaseModel):
    """
    Structured IPC response emitted by the worker process back to the server process.
    """
    protocol_version: str = Field(default=SUPPORTED_PROTOCOL_VERSION)
    job_id: str = Field(min_length=1, max_length=100)
    project_id: str = Field(min_length=1, max_length=100)
    worker_id: str = Field(min_length=1, max_length=100)
    attempt_count: int = Field(ge=1, le=100)
    success: bool
    status_summary: str = Field(default="", max_length=MAX_STATUS_SUMMARY_CHARS)
    failure_category: Optional[str] = Field(default=None, max_length=100)
    errors: List[str] = Field(default_factory=list)
    findings: List[RawAdapterFinding] = Field(default_factory=list)
    execution_duration_ms: float = Field(default=0.0, ge=0.0)
    is_simulated: bool = Field(default=True)
    process_stats: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("protocol_version")
    @classmethod
    def validate_protocol_version(cls, v: str) -> str:
        if v != SUPPORTED_PROTOCOL_VERSION:
            raise ValueError(
                f"Unsupported IPC protocol version '{v}'. Supported: '{SUPPORTED_PROTOCOL_VERSION}'"
            )
        return v

    @field_validator("findings")
    @classmethod
    def bound_findings(cls, v: List[RawAdapterFinding]) -> List[RawAdapterFinding]:
        if len(v) > MAX_FINDINGS_PER_JOB:
            return v[:MAX_FINDINGS_PER_JOB]
        return v

    @field_validator("errors")
    @classmethod
    def bound_errors(cls, v: List[str]) -> List[str]:
        bounded = [str(err)[:500] for err in v[:MAX_ERRORS_PER_RESPONSE]]
        return bounded

    @field_validator("execution_duration_ms", mode="before")
    @classmethod
    def validate_duration(cls, v: Any) -> float:
        try:
            val = float(v)
            if math.isnan(val) or math.isinf(val) or val < 0.0:
                return 0.0
            return round(val, 2)
        except Exception:
            return 0.0
