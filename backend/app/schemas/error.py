"""
VAPT Platform — Standardized API Error Models (Prompt 24).
Provides predictable, typed error structures across all endpoints with stable error codes,
safe human-readable messages, correlation tracking, and backward-compatible detail fields.
"""
from typing import Optional, List, Dict, Any, Union
from datetime import datetime, timezone
import enum
from pydantic import BaseModel, Field


class APIErrorCode(str, enum.Enum):
    UNAUTHENTICATED = "UNAUTHENTICATED"
    PERMISSION_DENIED = "PERMISSION_DENIED"
    RESOURCE_NOT_FOUND = "RESOURCE_NOT_FOUND"
    VALIDATION_ERROR = "VALIDATION_ERROR"
    RESOURCE_CONFLICT = "RESOURCE_CONFLICT"
    RATE_LIMIT_EXCEEDED = "RATE_LIMIT_EXCEEDED"
    PAYLOAD_TOO_LARGE = "PAYLOAD_TOO_LARGE"
    DESTINATION_RESTRICTED = "DESTINATION_RESTRICTED"
    NETWORK_TIMEOUT = "NETWORK_TIMEOUT"
    DATABASE_BUSY = "DATABASE_BUSY"
    INTERNAL_ERROR = "INTERNAL_ERROR"


class APIErrorDetail(BaseModel):
    field: Optional[str] = Field(None, description="Path to invalid field")
    issue: str = Field(..., description="Validation failure explanation")
    location: Optional[List[str]] = Field(None, description="Location in request (body, query, path, header)")


class APIErrorResponse(BaseModel):
    """
    Standardized API Error Response Model.
    Includes 'detail' and 'correlation_id' for strict backward compatibility with existing tests and clients.
    """
    error_code: str = Field(..., description="Stable programmatic error identifier")
    message: str = Field(..., description="Safe human-readable error description")
    detail: Optional[Union[str, Dict[str, Any], List[Any]]] = Field(..., description="Backward-compatible detail field mirroring message or dictionary payload")
    request_id: str = Field(..., description="Unique request/correlation ID for tracing")
    correlation_id: Optional[str] = Field(None, description="Backward-compatible alias for request_id")
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    details: Optional[List[Dict[str, Any]]] = Field(None, description="Granular field-level validation errors")
    retryable: bool = Field(False, description="Whether client may safely retry request")

    def __init__(self, **data):
        if "request_id" in data and "correlation_id" not in data:
            data["correlation_id"] = data["request_id"]
        super().__init__(**data)
