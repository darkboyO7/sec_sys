from typing import List, Optional
from pathlib import Path
from fastapi import APIRouter, Depends, HTTPException, status, Request, Query, Response
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.user import User
from app.models.report import ReportType, ReportFormat, ReportRecord
from app.schemas.report import (
    ReportGenerateRequest,
    ReportRecordRead,
    ReportExportResponse,
)
from app.services.report_service import ReportGenerationService
from app.api.deps import get_current_user, verify_project_access, get_client_ip

router = APIRouter()


@router.post(
    "/projects/{project_id}/reports/generate",
    response_model=ReportExportResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Generate and persist security report artifact",
)
def generate_project_report(
    project_id: str,
    body: ReportGenerateRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Generate an Executive, Technical, or Governance security report in JSON, CSV, or HTML.
    Enforces server-side project scoping, formula injection prevention, and HTML escaping.
    """
    verify_project_access(project_id, current_user, db)
    client_ip = get_client_ip(request)

    try:
        record, content, mime_type, filename = ReportGenerationService.generate_report(
            project_id=project_id,
            report_type=body.report_type,
            report_format=body.report_format,
            user=current_user,
            db=db,
            title=body.title,
            client_ip=client_ip,
        )
        return ReportExportResponse(
            record=ReportRecordRead.model_validate(record),
            content=content,
            mime_type=mime_type,
            filename=filename,
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.get(
    "/projects/{project_id}/reports",
    response_model=List[ReportRecordRead],
    summary="List generated report records for project",
)
def list_project_reports(
    project_id: str,
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    verify_project_access(project_id, current_user, db)
    return (
        db.query(ReportRecord)
        .filter(ReportRecord.project_id == project_id)
        .order_by(ReportRecord.generated_at.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )


@router.get(
    "/projects/{project_id}/reports/{report_id}",
    response_model=ReportRecordRead,
    summary="Get report record metadata by ID",
)
def get_report_record(
    project_id: str,
    report_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    verify_project_access(project_id, current_user, db)
    record = (
        db.query(ReportRecord)
        .filter(ReportRecord.id == report_id, ReportRecord.project_id == project_id)
        .first()
    )
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Report record '{report_id}' not found in project '{project_id}'.",
        )
    return record


@router.get(
    "/projects/{project_id}/reports/export/executive",
    summary="Direct export stream for Executive Report",
)
def export_executive_report(
    project_id: str,
    format: ReportFormat = Query(ReportFormat.JSON, description="Output format"),
    request: Request = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    verify_project_access(project_id, current_user, db)
    client_ip = get_client_ip(request) if request else None
    _, content, mime_type, filename = ReportGenerationService.generate_report(
        project_id=project_id,
        report_type=ReportType.EXECUTIVE,
        report_format=format,
        user=current_user,
        db=db,
        client_ip=client_ip,
    )
    return Response(
        content=content,
        media_type=mime_type,
        headers={"Content-Disposition": f'attachment; filename="{Path(filename).name}"'},
    )


@router.get(
    "/projects/{project_id}/reports/export/technical",
    summary="Direct export stream for Technical Report",
)
def export_technical_report(
    project_id: str,
    format: ReportFormat = Query(ReportFormat.JSON, description="Output format"),
    request: Request = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    verify_project_access(project_id, current_user, db)
    client_ip = get_client_ip(request) if request else None
    _, content, mime_type, filename = ReportGenerationService.generate_report(
        project_id=project_id,
        report_type=ReportType.TECHNICAL,
        report_format=format,
        user=current_user,
        db=db,
        client_ip=client_ip,
    )
    return Response(
        content=content,
        media_type=mime_type,
        headers={"Content-Disposition": f'attachment; filename="{Path(filename).name}"'},
    )


@router.get(
    "/projects/{project_id}/reports/export/governance",
    summary="Direct export stream for Governance Report",
)
def export_governance_report(
    project_id: str,
    format: ReportFormat = Query(ReportFormat.JSON, description="Output format"),
    request: Request = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    verify_project_access(project_id, current_user, db)
    client_ip = get_client_ip(request) if request else None
    _, content, mime_type, filename = ReportGenerationService.generate_report(
        project_id=project_id,
        report_type=ReportType.GOVERNANCE,
        report_format=format,
        user=current_user,
        db=db,
        client_ip=client_ip,
    )
    return Response(
        content=content,
        media_type=mime_type,
        headers={"Content-Disposition": f'attachment; filename="{Path(filename).name}"'},
    )
