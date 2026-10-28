from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.user import User
from app.models.assessment import AssessmentJob
from app.api.deps import get_current_user, verify_project_access
from app.schemas.integrity import (
    AuditVerificationResponse,
    EvidenceVerificationResponse,
    MerkleProofResponse,
    EntityIntegrityVerificationResponse,
)
from app.services.integrity_service import IntegrityService

router = APIRouter()


@router.get("/projects/{project_id}/audit/verify", response_model=AuditVerificationResponse)
def verify_audit_ledger(
    project_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Verify cryptographic hash chaining and Merkle integrity of the audit ledger
    for the specified project.
    """
    verify_project_access(project_id, current_user, db)
    report = IntegrityService.verify_audit_ledger_integrity(db=db, project_id=project_id)
    return report


@router.get(
    "/projects/{project_id}/assessments/{job_id}/evidence/verify",
    response_model=EvidenceVerificationResponse,
)
def verify_job_evidence(
    project_id: str,
    job_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Verify SHA-256 cryptographic hashes and Merkle root of all evidence records
    belonging to an assessment job.
    """
    verify_project_access(project_id, current_user, db)
    job = (
        db.query(AssessmentJob)
        .filter(AssessmentJob.id == job_id, AssessmentJob.project_id == project_id)
        .first()
    )
    if not job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Assessment job '{job_id}' not found in project '{project_id}'.",
        )

    report = IntegrityService.verify_evidence_integrity(db=db, job_id=job_id)
    return report


@router.get(
    "/projects/{project_id}/assessments/{job_id}/evidence/{evidence_id}/proof",
    response_model=MerkleProofResponse,
)
def get_evidence_proof(
    project_id: str,
    job_id: str,
    evidence_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Generate an independent cryptographic Merkle inclusion proof for a single
    evidence item, enabling non-repudiation and third-party verification.
    """
    verify_project_access(project_id, current_user, db)
    job = (
        db.query(AssessmentJob)
        .filter(AssessmentJob.id == job_id, AssessmentJob.project_id == project_id)
        .first()
    )
    if not job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Assessment job '{job_id}' not found in project '{project_id}'.",
        )

    try:
        proof_report = IntegrityService.get_evidence_merkle_proof(
            db=db,
            job_id=job_id,
            evidence_id=evidence_id,
        )
        return proof_report
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )


@router.get(
    "/projects/{project_id}/integrity/verify-all",
    response_model=EntityIntegrityVerificationResponse,
)
def verify_all_project_entities(
    project_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Comprehensive platform integrity verification across all assessment records,
    findings, evidence items, assets, remediation actions, and verification results.
    """
    verify_project_access(project_id, current_user, db)
    return IntegrityService.verify_platform_entity_integrity(db=db, project_id=project_id)
