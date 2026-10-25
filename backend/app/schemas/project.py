from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, Field
from app.models.project import ProjectRole


class ProjectCreate(BaseModel):
    name: str = Field(min_length=2, max_length=255)
    description: Optional[str] = Field(default="", max_length=1000)
    organization_id: Optional[str] = None  # If omitted, default org is used


class ProjectUpdate(BaseModel):
    name: Optional[str] = Field(default=None, min_length=2, max_length=255)
    description: Optional[str] = Field(default=None, max_length=1000)
    is_active: Optional[bool] = None


class ProjectMemberAdd(BaseModel):
    user_id: str
    role: ProjectRole = ProjectRole.TESTER


class ProjectMemberResponse(BaseModel):
    id: str
    user_id: str
    role: ProjectRole
    created_at: datetime
    user_email: Optional[str] = None
    user_full_name: Optional[str] = None

    class Config:
        from_attributes = True


class ProjectResponse(BaseModel):
    id: str
    organization_id: str
    name: str
    description: str
    is_active: bool
    created_at: datetime
    updated_at: datetime
    member_count: Optional[int] = 0
    scope_target_count: Optional[int] = 0
    scope_exclusion_count: Optional[int] = 0

    class Config:
        from_attributes = True
