from datetime import datetime
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, ConfigDict, Field
from app.models.report import ReportType, ReportFormat


class ReportGenerateRequest(BaseModel):
    report_type: ReportType = ReportType.EXECUTIVE
    report_format: ReportFormat = ReportFormat.JSON
    title: Optional[str] = Field(default=None, max_length=255)


class ReportRecordRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    project_id: str
    report_type: ReportType
    report_format: ReportFormat
    title: str
    generated_by_id: Optional[str] = None
    report_sha256: str
    item_count: int
    content_bytes: int
    generated_at: datetime
    created_at: datetime
    updated_at: datetime


class ReportExportResponse(BaseModel):
    record: ReportRecordRead
    content: str
    mime_type: str
    filename: str
