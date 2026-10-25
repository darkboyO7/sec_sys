from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Request, Query
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.models.user import User
from app.models.project import ProjectRole
from app.models.assessment import (
    AssessmentJob,
    AssessmentStatus,
    AssessmentFinding,
    FindingEvidence,
)
from app.schemas.assessment import (
    AssessmentJobCreate,
    AssessmentJobResponse,
    AssessmentFindingResponse,
    FindingEvidenceResponse,
)
from app.services.assessment_state_machine import AssessmentStateMachine
from app.services.assessment_engine import AssessmentExecutionEngine
from app.services.scope_engine import ScopeEngine
from app.services.audit_service import AuditService
from app.api.deps import get_current_user, verify_project_access, get_client_ip

router = APIRouter()


@router.get("/projects/{project_id}/assessments/", response_model=List[AssessmentJobResponse])
def list_assessments(
    project_id: str,
    status_filter: Optional[AssessmentStatus] = Query(None, description="Filter by assessment status"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    List all assessment execution jobs belonging to the specified project.
    Strict project boundary isolation enforced.
    """
    verify_project_access(project_id, current_user, db)
    query = db.query(AssessmentJob).filter(AssessmentJob.project_id == project_id)
    if status_filter:
        query = query.filter(AssessmentJob.status == status_filter)
    return query.order_by(AssessmentJob.queued_at.desc()).all()


@router.post("/projects/{project_id}/assessments/", response_model=AssessmentJobResponse, status_code=status.HTTP_201_CREATED)
def create_assessment_job(
    project_id: str,
    job_in: AssessmentJobCreate,
    request: Request,
    auto_execute: bool = Query(True, description="Execute deterministic fixture immediately upon creation"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Create a new assessment job with idempotency support and pre-flight scope validation.
    """
    client_ip = get_client_ip(request)
    verify_project_access(project_id, current_user, db, required_project_roles=[ProjectRole.LEAD, ProjectRole.TESTER])

    # 1. Idempotency Check: prevent duplicate job generation if key is reused
    if job_in.idempotency_key:
        existing_job = (
            db.query(AssessmentJob)
            .filter(
                AssessmentJob.project_id == project_id,
                AssessmentJob.idempotency_key == job_in.idempotency_key.strip(),
            )
            .first()
        )
        if existing_job:
            return existing_job

    # 2. Pre-flight Scope Check: Verify candidate target is authorized before queueing
    scope_eval = ScopeEngine.validate_target_in_scope(
        db=db,
        project_id=project_id,
        target=job_in.target_input.strip(),
    )
    if not scope_eval["is_authorized"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Cannot initiate assessment: Target '{job_in.target_input}' is not authorized ({scope_eval['reason']})",
        )

    # 3. Create persistent assessment job in QUEUED status
    config = dict(job_in.config or {})
    if job_in.fixture_profile:
        config["fixture_profile"] = job_in.fixture_profile

    job = AssessmentJob(
        project_id=project_id,
        target_input=scope_eval["normalized_target"],
        adapter_name=job_in.adapter_name.strip() if job_in.adapter_name else "local_fixture_adapter",
        adapter_version="1.0.0",
        status=AssessmentStatus.QUEUED,
        idempotency_key=job_in.idempotency_key.strip() if job_in.idempotency_key else None,
        progress_pct=0,
        timeout_seconds=job_in.timeout_seconds,
        is_simulated=True,  # Phase 2 operates strictly in deterministic fixture simulation
        created_by_id=current_user.id,
        config=config,
        summary_stats={"status": "QUEUED"},
    )
    db.add(job)
    db.commit()
    db.refresh(job)

    AuditService.record_event(
        db=db,
        action="ASSESSMENT_JOB_CREATE",
        target_type="assessment_job",
        target_id=job.id,
        project_id=project_id,
        actor_id=current_user.id,
        actor_email=current_user.email,
        outcome="SUCCESS",
        ip_address=client_ip,
        details={
            "target_input": job.target_input,
            "adapter_name": job.adapter_name,
            "idempotency_key": job.idempotency_key,
            "is_simulated": job.is_simulated,
        },
    )

    # 4. If auto_execute is True, immediately run through execution engine
    if auto_execute:
        job = AssessmentExecutionEngine.execute_job(
            db=db,
            job_id=job.id,
            client_ip=get_client_ip(request),
        )

    return job


@router.get("/projects/{project_id}/assessments/{job_id}", response_model=AssessmentJobResponse)
def get_assessment_job(
    project_id: str,
    job_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Fetch details of a single assessment job with project boundary validation."""
    verify_project_access(project_id, current_user, db)
    job = (
        db.query(AssessmentJob)
        .filter(AssessmentJob.project_id == project_id, AssessmentJob.id == job_id)
        .first()
    )
    if not job:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Assessment job not found")
    return job


@router.post("/projects/{project_id}/assessments/{job_id}/cancel", response_model=AssessmentJobResponse)
def cancel_assessment_job(
    project_id: str,
    job_id: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Cancel an active or queued assessment job.
    Fails closed if the job has already transitioned to a terminal state.
    """
    client_ip = get_client_ip(request)
    verify_project_access(project_id, current_user, db, required_project_roles=[ProjectRole.LEAD, ProjectRole.TESTER])

    job = (
        db.query(AssessmentJob)
        .filter(AssessmentJob.project_id == project_id, AssessmentJob.id == job_id)
        .first()
    )
    if not job:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Assessment job not found")

    try:
        AssessmentStateMachine.transition(
            job=job,
            new_status=AssessmentStatus.CANCELLED,
            error_message="Assessment cancelled by operator request.",
        )
        db.commit()
        db.refresh(job)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot cancel job in state '{job.status.value}': {str(e)}",
        )

    AuditService.record_event(
        db=db,
        action="ASSESSMENT_JOB_CANCEL",
        target_type="assessment_job",
        target_id=job.id,
        project_id=project_id,
        actor_id=current_user.id,
        actor_email=current_user.email,
        outcome="SUCCESS",
        ip_address=client_ip,
        details={"status": AssessmentStatus.CANCELLED.value},
    )

    return job


@router.get("/projects/{project_id}/assessments/{job_id}/findings", response_model=List[AssessmentFindingResponse])
def list_assessment_findings(
    project_id: str,
    job_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    List all normalized vulnerability findings generated by an assessment execution.
    Includes associated evidence provenance items.
    """
    verify_project_access(project_id, current_user, db)
    job = (
        db.query(AssessmentJob)
        .filter(AssessmentJob.project_id == project_id, AssessmentJob.id == job_id)
        .first()
    )
    if not job:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Assessment job not found")

    findings = (
        db.query(AssessmentFinding)
        .filter(AssessmentFinding.job_id == job_id)
        .order_by(AssessmentFinding.severity.asc())
        .all()
    )
    return findings


@router.get("/projects/{project_id}/assessments/{job_id}/findings/{finding_id}", response_model=AssessmentFindingResponse)
def get_assessment_finding_detail(
    project_id: str,
    job_id: str,
    finding_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Fetch a single finding with full evidence items and cryptographic SHA-256 digests."""
    verify_project_access(project_id, current_user, db)
    finding = (
        db.query(AssessmentFinding)
        .filter(
            AssessmentFinding.project_id == project_id,
            AssessmentFinding.job_id == job_id,
            AssessmentFinding.id == finding_id,
        )
        .first()
    )
    if not finding:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")
    return finding
