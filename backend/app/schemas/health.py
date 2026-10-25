from datetime import datetime
from typing import Dict, Any
from pydantic import BaseModel


class HealthResponse(BaseModel):
    status: str
    version: str
    environment: str
    timestamp: datetime


class ReadinessCheck(BaseModel):
    database: bool
    migrations: bool
    storage_writable: bool
    details: Dict[str, Any]


class ReadinessResponse(BaseModel):
    status: str  # "ready" or "not_ready"
    timestamp: datetime
    checks: ReadinessCheck
