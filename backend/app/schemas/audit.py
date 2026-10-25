from datetime import datetime
from typing import Optional, Dict, Any, List
from pydantic import BaseModel


class AuditEventResponse(BaseModel):
    id: str
    timestamp: datetime
    actor_id: Optional[str] = None
    actor_email: Optional[str] = None
    action: str
    target_type: str
    target_id: Optional[str] = None
    project_id: Optional[str] = None
    ip_address: Optional[str] = None
    outcome: str
    details: Dict[str, Any]

    class Config:
        from_attributes = True


class AuditLedgerResponse(BaseModel):
    total: int
    items: List[AuditEventResponse]
