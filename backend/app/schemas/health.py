from datetime import datetime
from typing import Dict, Any, Optional
from pydantic import BaseModel, Field


class HealthResponse(BaseModel):
    status: str
    version: str
    environment: str
    timestamp: datetime
    uptime_seconds: Optional[float] = None


# Alias for explicit liveness probe
LivenessResponse = HealthResponse


class ReadinessCheck(BaseModel):
    database: bool
    migrations: bool
    storage_writable: bool
    evidence_writable: bool = True
    profile: str = "development"
    profile_valid: bool = True
    details: Dict[str, Any]


class ReadinessResponse(BaseModel):
    status: str  # "ready" or "not_ready"
    timestamp: datetime
    checks: ReadinessCheck
    degraded: bool = False
    message: Optional[str] = None


class DependencyItemCheck(BaseModel):
    name: str
    critical: bool
    status: str  # "healthy", "degraded", "unhealthy", "unknown"
    latency_ms: float
    message: Optional[str] = None
    details: Optional[Dict[str, Any]] = None


class DependencyHealthResponse(BaseModel):
    status: str  # "healthy", "degraded", "unhealthy"
    critical_healthy: bool
    timestamp: datetime
    dependencies: Dict[str, DependencyItemCheck]
    summary: str
