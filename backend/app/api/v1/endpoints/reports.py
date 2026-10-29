import base64
from typing import List, Optional
from pathlib import Path
from fastapi import APIRouter, Depends, HTTPException, status, Request, Query, Response
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.user import User
from app.models.report import ReportType, ReportFormat, ReportRecord
from app.schemas.report import (
    ReportGenerateRequest,
    ReportRecordRead,
    ReportExportResponse,
)
from app.schemas.canonical_report import (
    AssessmentReportManifest,
    ReportCoverageSummary,
    BundleVerificationResult,
)
from app.services.report_service import ReportGenerationService
from app.services.canonical_report_service import CanonicalReportService
from app.services.audit_service import AuditService
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
            assessment_id=body.assessment_id,
            client_ip=client_ip,
        )
        if isinstance(content, bytes):
            str_content = base64.b64encode(content).decode("ascii")
        else:
            str_content = content

        return ReportExportResponse(
            record=ReportRecordRead.model_validate(record),
            content=str_content,
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


# ==============================================================================
# Prompt 32: Canonical Assessment Reporting, Verifiable Bundles & Safe Inspection
# ==============================================================================

@router.get(
    "/projects/{project_id}/assessments/{assessment_id}/report/canonical",
    response_model=AssessmentReportManifest,
    summary="Get canonical assessment report manifest",
)
def get_canonical_assessment_report(
    project_id: str,
    assessment_id: str,
    title: Optional[str] = Query(None, description="Custom report title"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Retrieve grounded, canonical assessment report manifest constructed from persisted state.
    Includes verified scope, coverage limits, missing evidence flags, and retest outcomes.
    """
    verify_project_access(project_id, current_user, db)
    try:
        return CanonicalReportService.build_assessment_manifest(
            project_id=project_id,
            assessment_id=assessment_id,
            db=db,
            title=title,
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.get(
    "/projects/{project_id}/assessments/{assessment_id}/report/coverage",
    response_model=ReportCoverageSummary,
    summary="Get assessment coverage and limitations summary",
)
def get_assessment_coverage_summary(
    project_id: str,
    assessment_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Retrieve coverage KPIs, probe completion counts, missing evidence, and limitations.
    """
    verify_project_access(project_id, current_user, db)
    try:
        manifest = CanonicalReportService.build_assessment_manifest(
            project_id=project_id,
            assessment_id=assessment_id,
            db=db,
        )
        return manifest.coverage_summary
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.post(
    "/projects/{project_id}/assessments/{assessment_id}/report/generate",
    response_model=ReportExportResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Generate and persist canonical assessment report",
)
def generate_canonical_assessment_report(
    project_id: str,
    assessment_id: str,
    body: ReportGenerateRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Generate, persist, and audit an assessment-level canonical report artifact.
    """
    verify_project_access(project_id, current_user, db)
    client_ip = get_client_ip(request)

    try:
        record, content, mime_type, filename = ReportGenerationService.generate_report(
            project_id=project_id,
            report_type=ReportType.ASSESSMENT_CANONICAL,
            report_format=body.report_format,
            user=current_user,
            db=db,
            title=body.title,
            assessment_id=assessment_id,
            client_ip=client_ip,
        )
        if isinstance(content, bytes):
            str_content = base64.b64encode(content).decode("ascii")
        else:
            str_content = content

        return ReportExportResponse(
            record=ReportRecordRead.model_validate(record),
            content=str_content,
            mime_type=mime_type,
            filename=filename,
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.get(
    "/projects/{project_id}/assessments/{assessment_id}/report/export",
    summary="Direct export stream for canonical assessment report (JSON, HTML, CSV, BUNDLE)",
)
def export_canonical_assessment_report(
    project_id: str,
    assessment_id: str,
    format: ReportFormat = Query(ReportFormat.JSON, description="Output format"),
    title: Optional[str] = Query(None, description="Custom title"),
    request: Request = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Directly streams the rendered assessment report or verifiable bundle archive (.tar.gz).
    """
    verify_project_access(project_id, current_user, db)
    client_ip = get_client_ip(request) if request else None

    try:
        _, content, mime_type, filename = ReportGenerationService.generate_report(
            project_id=project_id,
            report_type=ReportType.ASSESSMENT_CANONICAL,
            report_format=format,
            user=current_user,
            db=db,
            title=title,
            assessment_id=assessment_id,
            client_ip=client_ip,
        )
        return Response(
            content=content,
            media_type=mime_type,
            headers={"Content-Disposition": f'attachment; filename="{Path(filename).name}"'},
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


class BundleVerifyRequest(BaseModel):
    bundle_base64: Optional[str] = None


@router.post(
    "/projects/{project_id}/reports/bundle/verify",
    response_model=BundleVerificationResult,
    summary="Validation-only inspection and integrity verification of an assessment bundle archive",
)
async def verify_bundle_archive(
    project_id: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Inspects an uploaded assessment bundle (.tar.gz) in validation-only mode.
    Accepts raw binary stream (.tar.gz) or JSON payload with base64 encoded archive.
    Verifies:
    1. Schema version and bundle version ('1.0.0').
    2. File count, uncompressed bomb limits, and path traversal safety.
    3. Cryptographic SHA-256 digest consistency against bundle manifest.
    Guarantees: Zero database record mutations or silent overwrites.
    """
    verify_project_access(project_id, current_user, db)
    client_ip = get_client_ip(request)

    content_type = request.headers.get("content-type", "")
    bundle_bytes: bytes = b""

    if "application/json" in content_type:
        try:
            body_json = await request.json()
            b64_str = body_json.get("bundle_base64", "")
            if b64_str:
                bundle_bytes = base64.b64decode(b64_str)
        except Exception as e:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Invalid JSON/base64 payload: {str(e)}")
    else:
        bundle_bytes = await request.body()

    if not bundle_bytes:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No bundle archive payload provided for verification.",
        )

    result = CanonicalReportService.verify_assessment_bundle(bundle_bytes)

    # Audit log verification attempt
    AuditService.log(
        db=db,
        action="ASSESSMENT_BUNDLE_VERIFIED",
        actor_id=current_user.id,
        target_resource=f"bundle:{result.assessment_id or 'unknown'}",
        project_id=project_id,
        client_ip=client_ip,
        details={
            "is_valid": result.is_valid,
            "violations_count": len(result.violations),
            "corrupted_files_count": len(result.corrupted_files),
            "file_count": result.file_count,
            "total_bytes": result.total_decompressed_bytes,
            "inspection_mode": result.inspection_mode,
        },
    )
    db.commit()

    return result
