"""
Pydantic Schemas for Secure Integration Framework and Connector Contracts (Prompt 40).
"""
from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field

from app.models.connector import (
    ConnectorCapability,
    ConnectorStatus,
    SyncStatus,
    ImplementationStatus,
)


class ConnectorInventoryItem(BaseModel):
    provider_type: str
    name: str
    version: str
    supported_capabilities: List[str]
    implementation_status: str
    description: str
    limitations: Optional[str] = None
    config_schema: Dict[str, Any] = Field(default_factory=dict)


class ConnectorConfigCreate(BaseModel):
    name: str = Field(..., min_length=2, max_length=100)
    provider_type: str = Field(...)
    version: str = Field("1.0.0", max_length=20)
    enabled: bool = True
    capabilities: List[str] = Field(default_factory=list)
    settings: Dict[str, Any] = Field(default_factory=dict)
    rate_limit_per_minute: int = Field(60, ge=1, le=10000)
    timeout_seconds: float = Field(10.0, ge=1.0, le=120.0)
    max_retries: int = Field(3, ge=0, le=10)
    max_response_size_kb: int = Field(10240, ge=64, le=102400)


class ConnectorConfigUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=2, max_length=100)
    enabled: Optional[bool] = None
    capabilities: Optional[List[str]] = None
    settings: Optional[Dict[str, Any]] = None
    rate_limit_per_minute: Optional[int] = Field(None, ge=1, le=10000)
    timeout_seconds: Optional[float] = Field(None, ge=1.0, le=120.0)
    max_retries: Optional[int] = Field(None, ge=0, le=10)
    max_response_size_kb: Optional[int] = Field(None, ge=64, le=102400)


class ConnectorConfigRead(BaseModel):
    id: str
    project_id: str
    name: str
    provider_type: str
    version: str
    enabled: bool
    capabilities: List[str]
    config_schema_version: str
    settings_masked: Dict[str, Any]
    rate_limit_per_minute: int
    timeout_seconds: float
    max_retries: int
    max_response_size_kb: int
    last_sync_at: Optional[datetime] = None
    last_sync_watermark: Optional[str] = None
    last_health_status: str
    last_health_message: Optional[str] = None
    consecutive_failures: int
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class ConnectorHealthRead(BaseModel):
    connector_id: str
    name: str
    provider_type: str
    status: str
    latency_ms: float
    message: str
    error_category: Optional[str] = None
    details: Dict[str, Any] = Field(default_factory=dict)


class ConnectorSyncTriggerResponse(BaseModel):
    sync_event_id: str
    connector_id: str
    status: str
    records_pulled: int
    records_normalized: int
    records_ingested: int
    records_tombstoned: int
    raw_payload_digest: Optional[str] = None
    next_watermark: Optional[str] = None
    message: str


class ConnectorSyncEventRead(BaseModel):
    id: str
    connector_id: str
    project_id: str
    started_at: datetime
    finished_at: Optional[datetime] = None
    status: str
    records_pulled: int
    records_normalized: int
    records_ingested: int
    records_tombstoned: int
    error_message: Optional[str] = None
    error_type: Optional[str] = None
    raw_payload_digest: Optional[str] = None
    sync_watermark: Optional[str] = None
    execution_metadata: Optional[Dict[str, Any]] = None

    class Config:
        from_attributes = True
