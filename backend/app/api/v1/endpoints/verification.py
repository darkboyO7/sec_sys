from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Request, Query
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.user import User, SystemRole
from app.models.project import ProjectRole, ProjectMember
from app.schemas.verification import (
    RemediationVerificationCreate,
    RemediationVerificationRead,
    AutomatedVerificationRequest,
)
from app.services.remediation_verification_service import RemediationVerificationService
from app.api.deps import get_current_user, verify_project_access, get_client_ip

router = APIRouter()


@router.post(
    "/projects/{project_id}/findings/{finding_id}/verify",
    response_model=RemediationVerificationRead,
    status_code=status.HTTP_201_CREATED,
    summary="Record independent remediation verification outcome",
)
def record_finding_verification(
    project_id: str,
    finding_id: str,
    body: RemediationVerificationCreate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Record an independent verification outcome (VERIFIED_FIXED, STILL_VULNERABLE, PARTIALLY_REMEDIATED, INCONCLUSIVE).
    Enforces that:
    - Only Project LEAD or System ADMIN can verify closure (VERIFIED_FIXED).
    - Failed/partial verification transitions findings to REOPENED and increments recurrence.
    - Inconclusive results do not close the finding.
    """
    verify_project_access(project_id, current_user, db)
    verifier_role = None
    if current_user.system_role == SystemRole.ADMIN:
        verifier_role = ProjectRole.LEAD
    else:
        member = (
            db.query(ProjectMember)
            .filter(ProjectMember.project_id == project_id, ProjectMember.user_id == current_user.id)
            .first()
        )
        verifier_role = member.role if member else None

    client_ip = get_client_ip(request)
    try:
        return RemediationVerificationService.record_verification(
            project_id=project_id,
            finding_id=finding_id,
            outcome=body.outcome,
            verification_criteria=body.verification_criteria,
            verification_evidence_summary=body.verification_evidence_summary,
            notes=body.notes,
            verifier=current_user,
            verifier_role=verifier_role,
            db=db,
            verification_method=body.verification_method,
            verification_evidence_data=body.verification_evidence_data,
            recommendation_id=body.recommendation_id,
            baseline_evidence_hash=body.baseline_evidence_hash,
            client_ip=client_ip,
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except PermissionError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))


@router.post(
    "/projects/{project_id}/findings/{finding_id}/verify/retest",
    response_model=RemediationVerificationRead,
    status_code=status.HTTP_201_CREATED,
    summary="Execute automated passive re-test to verify remediation",
)
def execute_automated_retest(
    project_id: str,
    finding_id: str,
    body: AutomatedVerificationRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Executes a targeted, passive re-test using an approved adapter against finding target.
    Compares observations to confirm or refute resolution.
    """
    verify_project_access(project_id, current_user, db)
    verifier_role = None
    if current_user.system_role == SystemRole.ADMIN:
        verifier_role = ProjectRole.LEAD
    else:
        member = (
            db.query(ProjectMember)
            .filter(ProjectMember.project_id == project_id, ProjectMember.user_id == current_user.id)
            .first()
        )
        verifier_role = member.role if member else None

    client_ip = get_client_ip(request)
    try:
        return RemediationVerificationService.execute_automated_retest(
            project_id=project_id,
            finding_id=finding_id,
            adapter_name=body.adapter_name,
            config=body.config,
            notes=body.notes,
            verifier=current_user,
            verifier_role=verifier_role,
            db=db,
            client_ip=client_ip,
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except PermissionError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))


@router.get(
    "/projects/{project_id}/findings/{finding_id}/verifications",
    response_model=List[RemediationVerificationRead],
    summary="List verification attempts for finding",
)
def list_finding_verifications(
    project_id: str,
    finding_id: str,
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Retrieves full audit history of verification attempts (both successful and failed) for a finding.
    """
    verify_project_access(project_id, current_user, db)
    return RemediationVerificationService.list_verifications(
        project_id=project_id,
        finding_id=finding_id,
        db=db,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/projects/{project_id}/verifications",
    response_model=List[RemediationVerificationRead],
    summary="List all verifications for project",
)
def list_all_project_verifications(
    project_id: str,
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Retrieves all verification records for a project.
    """
    verify_project_access(project_id, current_user, db)
    return RemediationVerificationService.list_verifications(
        project_id=project_id,
        finding_id=None,
        db=db,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/projects/{project_id}/verifications/{verification_id}",
    response_model=RemediationVerificationRead,
    summary="Get single verification record",
)
def get_verification_by_id(
    project_id: str,
    verification_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    verify_project_access(project_id, current_user, db)
    verification = RemediationVerificationService.get_verification(
        project_id=project_id,
        verification_id=verification_id,
        db=db,
    )
    if not verification:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Verification record '{verification_id}' not found in project '{project_id}'.",
        )
    return verification
