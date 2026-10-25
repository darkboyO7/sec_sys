"""Typed IPC Request and Response contracts for isolated worker processes.

Protocol version: 1.0.0
"""
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field, field_validator
from app.services.scanner_adapters.base import RawAdapterFinding


SUPPORTED_PROTOCOL_VERSION = "1.0.0"


class WorkerIPCRequest(BaseModel):
    """
    Structured IPC request delivered from the server process to the worker process.
    """
    protocol_version: str = Field(default=SUPPORTED_PROTOCOL_VERSION)
    job_id: str = Field(min_length=1)
    project_id: str = Field(min_length=1)
    worker_id: str = Field(min_length=1)
    attempt_count: int = Field(ge=1)
    target_input: str = Field(min_length=1)
    adapter_name: str = Field(min_length=1)
    adapter_version: str = Field(default="1.0.0")
    policy_version: str = Field(default="2026.1")
    config: Dict[str, Any] = Field(default_factory=dict)
    timeout_seconds: int = Field(default=300, ge=1)
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
    job_id: str = Field(min_length=1)
    project_id: str = Field(min_length=1)
    worker_id: str = Field(min_length=1)
    attempt_count: int = Field(ge=1)
    success: bool
    status_summary: str = Field(default="")
    failure_category: Optional[str] = None
    errors: List[str] = Field(default_factory=list)
    findings: List[RawAdapterFinding] = Field(default_factory=list)
    execution_duration_ms: float = Field(default=0.0)
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
