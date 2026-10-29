from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime


class IntegrationHealthRead(BaseModel):
    name: str
    version: str
    status: str
    details: Dict[str, Any] = Field(default_factory=dict)


class KevEntryRead(BaseModel):
    cve_id: str
    vendor_project: str
    product: str
    vulnerability_name: str
    date_added: str
    short_description: str
    required_action: str
    known_ransomware_campaign_use: bool


class WebhookTestRequest(BaseModel):
    event_type: str = Field("FINDING_CRITICAL_DISCOVERED", description="Type of event to simulate")
    target_url: Optional[str] = Field(None, description="Optional destination URL; defaults to configured webhook")
    custom_payload: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Optional custom event payload")


class WebhookDeliveryRead(BaseModel):
    event_id: str
    event_type: str
    project_id: str
    timestamp: str
    signature: str
    payload_size: int
    payload: Dict[str, Any]
    delivered: bool
    delivered_at: str


class SiemExportResponse(BaseModel):
    project_id: str
    format: str
    total_events: int
    stream: List[str]
    exported_at: datetime


class DestinationValidationRequest(BaseModel):
    url: str = Field(..., description="Destination URL to pre-flight validate against SSRF and network security policy")
    allow_private: bool = Field(False, description="Whether private/internal RFC 1918 addresses are permitted")


class DestinationValidationResponse(BaseModel):
    valid: bool
    url: str
    scheme: str
    hostname: str
    port: int
    resolved_ips: List[str]
    allow_private: bool
