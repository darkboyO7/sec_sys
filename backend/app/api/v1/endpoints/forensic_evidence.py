"""
VAPT Platform — Forensic Evidence Preservation & Chain of Custody API Endpoints (Prompt 48).
"""
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.api.deps import (
    get_db,
    get_current_user,
    require_system_roles,
    verify_project_access,
)
from app.models.user import User, SystemRole
from app.models.project import Project, ProjectMember, ProjectRole
from app.models.forensic_evidence import ForensicEvidenceRecord
from app.schemas.forensic_evidence import (
    EvidenceIngestRequest,
    EvidenceNormalizeRequest,
    EvidenceContradictionRequest,
    EvidenceVerificationRequest,
    ForensicVerificationReport,
    ForensicVerificationReportItem,
    ForensicEvidenceRecordRead,
    EvidenceExportBundle,
    EvidenceImportRequest,
    EvidenceImportResult,
)
from app.services.forensic_evidence_service import forensic_evidence_service

router = APIRouter(prefix="/forensic-evidence", tags=["Forensic Evidence Preservation & Chain of Custody"])


@router.post("/records", response_model=ForensicEvidenceRecordRead, status_code=status.HTTP_201_CREATED)
def ingest_forensic_evidence(
    req: EvidenceIngestRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Ingests raw forensic evidence with SHA-256 digest, Ed25519 digital signature, and initial custody hash.
    Requires at least ANALYST role in the project or ADMIN.
    """
    verify_project_access(
        project_id=req.project_id,
        user=current_user,
        db=db,
        required_project_roles=[ProjectRole.LEAD, ProjectRole.TESTER],
    )
    return forensic_evidence_service.ingest_evidence(
        db=db,
        req=req,
        actor_id=current_user.email,
        actor_role=current_user.system_role.value,
    )


@router.get("/records", response_model=List[ForensicEvidenceRecordRead])
def list_forensic_evidence(
    project_id: str = Query(..., description="Project identifier"),
    lifecycle_state: Optional[str] = Query(None),
    is_contradictory: Optional[bool] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Lists forensic evidence records within an authorized project.
    """
    verify_project_access(project_id=project_id, user=current_user, db=db)

    # Determine user's project role
    membership = (
        db.query(ProjectMember)
        .filter(ProjectMember.project_id == project_id, ProjectMember.user_id == current_user.id)
        .first()
    )
    is_viewer = membership and membership.role == ProjectRole.VIEWER and current_user.system_role != SystemRole.ADMIN

    query = db.query(ForensicEvidenceRecord).filter(
        ForensicEvidenceRecord.project_id == project_id,
        ForensicEvidenceRecord.is_deleted == False,
    )
    if lifecycle_state:
        query = query.filter(ForensicEvidenceRecord.lifecycle_state == lifecycle_state)
    if is_contradictory is not None:
        query = query.filter(ForensicEvidenceRecord.is_contradictory == is_contradictory)

    records = query.order_by(ForensicEvidenceRecord.collection_time.desc()).all()

    # Redact raw payloads for viewer role to prevent sensitive leakage
    if is_viewer:
        for r in records:
            r.raw_payload = forensic_evidence_service.sanitize_for_display(r.raw_payload)

    return records


@router.get("/records/{evidence_id}", response_model=ForensicEvidenceRecordRead)
def get_forensic_evidence(
    evidence_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Retrieves a single forensic evidence record and its custody chain.
    """
    record = db.query(ForensicEvidenceRecord).filter(ForensicEvidenceRecord.id == evidence_id).first()
    if not record:
        raise HTTPException(status_code=404, detail=f"Evidence {evidence_id} not found")

    verify_project_access(project_id=record.project_id, user=current_user, db=db)

    membership = (
        db.query(ProjectMember)
        .filter(ProjectMember.project_id == record.project_id, ProjectMember.user_id == current_user.id)
        .first()
    )
    is_viewer = membership and membership.role == ProjectRole.VIEWER and current_user.system_role != SystemRole.ADMIN

    if is_viewer:
        record.raw_payload = forensic_evidence_service.sanitize_for_display(record.raw_payload)

    return record


@router.post("/records/{evidence_id}/normalize", response_model=ForensicEvidenceRecordRead)
def normalize_forensic_evidence(
    evidence_id: str,
    req: EvidenceNormalizeRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Derives normalized representation without overwriting original raw record.
    """
    record = db.query(ForensicEvidenceRecord).filter(ForensicEvidenceRecord.id == evidence_id).first()
    if not record:
        raise HTTPException(status_code=404, detail=f"Evidence {evidence_id} not found")

    verify_project_access(
        project_id=record.project_id,
        user=current_user,
        db=db,
        required_project_roles=[ProjectRole.LEAD, ProjectRole.TESTER],
    )

    return forensic_evidence_service.normalize_evidence(
        db=db,
        evidence_id=evidence_id,
        req=req,
        actor_id=current_user.email,
        actor_role=current_user.system_role.value,
    )


@router.post("/records/{evidence_id}/contradiction", response_model=ForensicEvidenceRecordRead, status_code=status.HTTP_201_CREATED)
def record_evidence_contradiction(
    evidence_id: str,
    req: EvidenceContradictionRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Attaches contradictory observation or correction without rewriting the historical record.
    """
    record = db.query(ForensicEvidenceRecord).filter(ForensicEvidenceRecord.id == evidence_id).first()
    if not record:
        raise HTTPException(status_code=404, detail=f"Evidence {evidence_id} not found")

    verify_project_access(
        project_id=record.project_id,
        user=current_user,
        db=db,
        required_project_roles=[ProjectRole.LEAD, ProjectRole.TESTER],
    )

    return forensic_evidence_service.record_contradiction(
        db=db,
        prior_evidence_id=evidence_id,
        req=req,
        actor_id=current_user.email,
        actor_role=current_user.system_role.value,
    )


@router.post("/records/{evidence_id}/verify", response_model=ForensicVerificationReportItem)
def verify_evidence_record(
    evidence_id: str,
    req: Optional[EvidenceVerificationRequest] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Executes explicit cryptographic verification of raw digest, digital origin signature, and custody chain.
    """
    record = db.query(ForensicEvidenceRecord).filter(ForensicEvidenceRecord.id == evidence_id).first()
    if not record:
        raise HTTPException(status_code=404, detail=f"Evidence {evidence_id} not found")

    verify_project_access(
        project_id=record.project_id,
        user=current_user,
        db=db,
        required_project_roles=[ProjectRole.LEAD, ProjectRole.TESTER],
    )

    return forensic_evidence_service.verify_evidence_record(
        db=db,
        evidence_id=evidence_id,
        actor_id=current_user.email,
        actor_role=current_user.system_role.value,
        req=req,
        persist=True,
    )


@router.post("/verify-batch", response_model=ForensicVerificationReport)
def verify_batch(
    project_id: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    _role=Depends(require_system_roles([SystemRole.ADMIN, SystemRole.SECURITY_LEAD])),
):
    """
    Executes administrative batch verification across evidence records.
    """
    if project_id:
        verify_project_access(project_id=project_id, user=current_user, db=db)

    return forensic_evidence_service.verify_batch(
        db=db,
        project_id=project_id,
        actor_id=current_user.email,
        actor_role=current_user.system_role.value,
        persist=True,
    )


@router.post("/export", response_model=EvidenceExportBundle)
def export_evidence_bundle(
    project_id: str = Query(..., description="Project to export"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Exports verifiable evidence bundle with raw payloads, custody chains, and platform digital signature.
    """
    verify_project_access(
        project_id=project_id,
        user=current_user,
        db=db,
        required_project_roles=[ProjectRole.LEAD],
    )
    return forensic_evidence_service.export_evidence_bundle(
        db=db,
        project_id=project_id,
        actor_id=current_user.email,
        actor_role=current_user.system_role.value,
    )


@router.post("/import", response_model=EvidenceImportResult)
def import_evidence_bundle(
    req: EvidenceImportRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Imports evidence bundle, validating digests and origin signatures before database insertion.
    """
    verify_project_access(
        project_id=req.target_project_id,
        user=current_user,
        db=db,
        required_project_roles=[ProjectRole.LEAD],
    )
    return forensic_evidence_service.import_evidence_bundle(
        db=db,
        bundle=req.bundle,
        target_project_id=req.target_project_id,
        actor_id=current_user.email,
        actor_role=current_user.system_role.value,
    )


@router.delete("/records/{evidence_id}", response_model=ForensicEvidenceRecordRead)
def delete_evidence_record(
    evidence_id: str,
    justification: str = Query(..., min_length=5, description="Auditable deletion rationale"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    _admin=Depends(require_system_roles([SystemRole.ADMIN])),
):
    """
    Authorized evidence deletion workflow enforcing legal holds and tombstoning.
    """
    return forensic_evidence_service.delete_evidence_authorized(
        db=db,
        evidence_id=evidence_id,
        actor_id=current_user.email,
        actor_role=current_user.system_role.value,
        justification=justification,
    )
