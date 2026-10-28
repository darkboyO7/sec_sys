from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field
from app.models.monitoring import ScheduleFrequency, ScheduleStatus


class ScheduleCreate(BaseModel):
    name: str = Field(..., min_length=3, max_length=255)
    target_input: str = Field(..., min_length=1, max_length=500)
    adapter_name: str = Field("live_network_auditor_adapter", max_length=100)
    fixture_profile: str = Field("LIVE_WEB_SECURITY_AUDIT", max_length=100)
    frequency: ScheduleFrequency = ScheduleFrequency.DAILY
    interval_seconds: int = Field(86400, ge=60, le=2592000)
    config: Dict[str, Any] = Field(default_factory=dict)


class ScheduleUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=3, max_length=255)
    frequency: Optional[ScheduleFrequency] = None
    interval_seconds: Optional[int] = Field(None, ge=60, le=2592000)
    status: Optional[ScheduleStatus] = None
    config: Optional[Dict[str, Any]] = None


class MonitoringRunResponse(BaseModel):
    id: str
    schedule_id: str
    project_id: str
    job_id: Optional[str] = None
    scheduled_at: datetime
    executed_at: datetime
    status: str
    new_findings_count: int
    recurring_findings_count: int
    resolved_findings_count: int
    summary_notes: Optional[str] = None
    run_metadata: Dict[str, Any] = Field(default_factory=dict)

    class Config:
        from_attributes = True


class ScheduleResponse(BaseModel):
    id: str
    project_id: str
    name: str
    target_input: str
    adapter_name: str
    fixture_profile: str
    frequency: ScheduleFrequency
    interval_seconds: int
    status: ScheduleStatus
    last_run_at: Optional[datetime] = None
    next_run_at: Optional[datetime] = None
    last_job_id: Optional[str] = None
    last_status: Optional[str] = None
    last_error: Optional[str] = None
    run_count: int
    consecutive_failures: int
    max_consecutive_failures: int
    config: Dict[str, Any]
    created_by_id: str
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class MonitoringOverviewResponse(BaseModel):
    total_schedules: int
    active_schedules: int
    paused_schedules: int
    expired_schedules: int
    total_runs_executed: int
    recent_runs: List[MonitoringRunResponse]
