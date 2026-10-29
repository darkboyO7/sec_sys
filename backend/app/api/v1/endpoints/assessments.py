import json
import hashlib
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Request, Query
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
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
    AdapterCapabilityResponse,
)
from app.services.assessment_state_machine import AssessmentStateMachine
from app.services.assessment_engine import AssessmentExecutionEngine
import app.services.scanner_adapters  # Ensure all adapters are registered
from app.services.scanner_adapters.base import AdapterRegistry
from app.services.scope_engine import ScopeEngine
from app.services.audit_service import AuditService
from app.api.deps import get_current_user, verify_project_access, get_client_ip

router = APIRouter()


@router.get("/projects/{project_id}/assessments/adapters", response_model=List[AdapterCapabilityResponse])
def list_assessment_adapters(
    project_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    List registered and approved scanner adapters and their declared capabilities.
    Strict project boundary isolation enforced.
    """
    verify_project_access(project_id, current_user, db)
    return AdapterRegistry.list_capabilities()


@router.get("/projects/{project_id}/assessments/", response_model=List[AssessmentJobResponse])
def list_assessments(
    project_id: str,
    status_filter: Optional[AssessmentStatus] = Query(None, description="Filter by assessment status"),
    offset: int = Query(0, ge=0, description="Offset for pagination"),
    limit: int = Query(50, ge=1, le=100, description="Limit for pagination (maximum 100)"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    List all assessment execution jobs belonging to the specified project with bounded pagination.
    Strict project boundary isolation enforced.
    """
    verify_project_access(project_id, current_user, db)
    query = db.query(AssessmentJob).filter(AssessmentJob.project_id == project_id)
    if status_filter:
        query = query.filter(AssessmentJob.status == status_filter)
    return query.order_by(AssessmentJob.queued_at.desc()).offset(offset).limit(limit).all()


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
    Create a new assessment job with idempotency support, typed execution contract,
    and pre-flight scope validation.
    """
    client_ip = get_client_ip(request)
    verify_project_access(project_id, current_user, db, required_project_roles=[ProjectRole.LEAD, ProjectRole.TESTER])

    # 1. Capacity Protection: Limit maximum concurrent active/queued jobs per project
    MAX_ACTIVE_JOBS_PER_PROJECT = 10
    active_jobs_count = (
        db.query(AssessmentJob)
        .filter(
            AssessmentJob.project_id == project_id,
            AssessmentJob.status.in_([
                AssessmentStatus.QUEUED,
                AssessmentStatus.PREFLIGHT,
                AssessmentStatus.READY,
                AssessmentStatus.RUNNING,
            ]),
        )
        .count()
    )
    if active_jobs_count >= MAX_ACTIVE_JOBS_PER_PROJECT:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Project assessment capacity exceeded: maximum {MAX_ACTIVE_JOBS_PER_PROJECT} active jobs allowed. Wait for active jobs to complete.",
        )

    # 2. Scanner Adapter Governance & Validation (Phase 7B)
    clean_target = job_in.target_input.strip()
    is_url_target = clean_target.startswith("http://") or clean_target.startswith("https://")
    default_adapter = "live_network_auditor_adapter" if is_url_target else "local_fixture_adapter"
    adapter_name = (job_in.adapter_name or default_adapter).strip()
    adapter = AdapterRegistry.get(adapter_name)
    if not adapter:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Adapter '{adapter_name}' is not registered in the system.",
        )
    if not AdapterRegistry.is_approved(adapter_name):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Adapter '{adapter_name}' is disabled or not approved for execution.",
        )

    # 3. Pre-flight Scope Check: Verify candidate target is authorized before queueing
    scope_eval = ScopeEngine.validate_target_in_scope(
        db=db,
        project_id=project_id,
        target=clean_target,
    )
    if not scope_eval["is_authorized"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Cannot initiate assessment: Target '{job_in.target_input}' is not authorized ({scope_eval['reason']})",
        )

    # Verify adapter supports the target type
    target_type = scope_eval.get("target_type")
    if target_type:
        valid_type, type_err = adapter.validate_target_type(target_type)
        if not valid_type:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=type_err,
            )

    # 4. Resolve effective profile and validate configuration
    config = dict(job_in.config or {})
    effective_profile = job_in.fixture_profile or config.get("profile") or config.get("fixture_profile") or adapter.supported_profiles[0]
    config["fixture_profile"] = effective_profile
    config["profile"] = effective_profile
    norm_target = scope_eval.get("normalized_target") or clean_target
    if "127.0.0.1" in norm_target or "localhost" in norm_target or scope_eval.get("is_loopback_authorized"):
        config["allow_loopback"] = True
    if scope_eval.get("is_private_authorized"):
        config["allow_private"] = True

    valid_cfg, cfg_err = adapter.validate_config(config)
    if not valid_cfg:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid configuration for adapter '{adapter_name}': {cfg_err}",
        )

    # 5. Validate timeout bounds against adapter policy
    if job_in.timeout_seconds is not None:
        if job_in.timeout_seconds < adapter.min_timeout_seconds or job_in.timeout_seconds > adapter.max_timeout_seconds:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Requested timeout {job_in.timeout_seconds}s is outside permitted range [{adapter.min_timeout_seconds}s, {adapter.max_timeout_seconds}s] for adapter '{adapter_name}'.",
            )

    # 6. Idempotency Check with Canonical Digest Verification
    request_payload = {
        "target_input": job_in.target_input.strip(),
        "adapter_name": adapter_name,
        "fixture_profile": effective_profile,
        "policy_version": (job_in.policy_version or "2026.1").strip(),
        "config": config,
    }
    request_digest = hashlib.sha256(json.dumps(request_payload, sort_keys=True).encode("utf-8")).hexdigest()

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
            # If key is reused with conflicting parameters, reject with 409 Conflict
            if existing_job.idempotency_digest and existing_job.idempotency_digest != request_digest:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Idempotency key already exists for this project with a conflicting request payload.",
                )
            return existing_job

    # 7. Compute immutable scope snapshot & digest
    policy_ver = job_in.policy_version or "2026.1"
    scope_snapshot, scope_snapshot_digest = AssessmentExecutionEngine.compute_scope_snapshot_and_digest(
        scope_eval=scope_eval,
        policy_version=policy_ver,
    )
    rule = scope_eval.get("matched_rule") or {}
    auth_ref = rule.get("id") or scope_eval.get("rule_id") or "SCOPE-PREFLIGHT-RULE"
    auth_status = "AUTHORIZED" if scope_eval.get("is_authorized") else "UNAUTHORIZED"

    # 8. Create persistent assessment job in QUEUED status
    job = AssessmentJob(
        project_id=project_id,
        target_input=scope_eval["normalized_target"],
        adapter_name=adapter.name,
        adapter_version=adapter.version,
        status=AssessmentStatus.QUEUED,
        idempotency_key=job_in.idempotency_key.strip() if job_in.idempotency_key else None,
        idempotency_digest=request_digest,
        lock_version=1,
        progress_pct=0,
        policy_version=policy_ver,
        authorization_reference=auth_ref,
        authorization_status=auth_status,
        scope_snapshot=scope_snapshot,
        scope_snapshot_digest=scope_snapshot_digest,
        attempt_count=1,
        timeout_seconds=job_in.timeout_seconds,
        is_simulated=(adapter.name == "local_fixture_adapter"),
        created_by_id=current_user.id,
        config=config,
        summary_stats={"status": "QUEUED"},
    )
    db.add(job)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        # Concurrent creation race: another request committed with this idempotency key
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
                if existing_job.idempotency_digest and existing_job.idempotency_digest != request_digest:
                    raise HTTPException(
                        status_code=status.HTTP_409_CONFLICT,
                        detail="Idempotency key already exists for this project with a conflicting request payload.",
                    )
                return existing_job
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Database integrity constraint violated during job creation.",
        )
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
            "policy_version": job.policy_version,
            "authorization_reference": job.authorization_reference,
            "scope_snapshot_digest": job.scope_snapshot_digest,
            "is_simulated": job.is_simulated,
        },
    )

    # 5. If auto_execute is True, immediately run through execution engine
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

    # Reject cancellation if already in a terminal state
    if job.status in AssessmentStateMachine.TERMINAL_STATUSES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot cancel job in terminal state '{job.status.value}'",
        )

    # Idempotent: If cancellation was already requested, return job
    if job.status == AssessmentStatus.CANCELLATION_REQUESTED:
        return job

    try:
        if job.status == AssessmentStatus.RUNNING:
            # Running execution: request cancellation; running worker will observe and terminate
            AssessmentStateMachine.transition(
                job=job,
                new_status=AssessmentStatus.CANCELLATION_REQUESTED,
                error_message="Cancellation requested by operator.",
            )
        else:
            # Non-running (QUEUED/PREFLIGHT/READY): confirmed termination immediately
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


@router.post("/projects/{project_id}/assessments/{job_id}/retry", response_model=AssessmentJobResponse)
def retry_assessment_job(
    project_id: str,
    job_id: str,
    request: Request,
    auto_execute: bool = Query(True, description="Execute fixture immediately upon retry"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Retry a failed assessment job within bounded retry limits.
    Enforces role verification and project boundary checks.
    """
    client_ip = get_client_ip(request)
    verify_project_access(project_id, current_user, db, required_project_roles=[ProjectRole.LEAD, ProjectRole.TESTER])

    job = db.query(AssessmentJob).filter(AssessmentJob.project_id == project_id, AssessmentJob.id == job_id).first()
    if not job:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Assessment job not found")

    success, retried_job, msg = AssessmentExecutionEngine.retry_job(db=db, job_id=job.id)
    if not success:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=msg)

    AuditService.record_event(
        db=db,
        action="ASSESSMENT_JOB_RETRY",
        target_type="assessment_job",
        target_id=retried_job.id,
        project_id=project_id,
        actor_id=current_user.id,
        actor_email=current_user.email,
        outcome="SUCCESS",
        ip_address=client_ip,
        details={"attempt_count": retried_job.attempt_count},
    )

    if auto_execute:
        retried_job = AssessmentExecutionEngine.execute_job(db=db, job_id=retried_job.id, client_ip=client_ip)

    return retried_job


@router.post("/projects/{project_id}/assessments/recover-stale")
def recover_stale_assessments(
    project_id: str,
    request: Request,
    max_stale_seconds: int = Query(120, ge=30, le=3600),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Recover abandoned or hung assessment jobs exceeding stale heartbeat thresholds.
    """
    verify_project_access(project_id, current_user, db, required_project_roles=[ProjectRole.LEAD])
    recovered = AssessmentExecutionEngine.recover_abandoned_jobs(
        db=db,
        project_id=project_id,
        max_stale_seconds=max_stale_seconds,
    )
    return {"recovered_count": len(recovered), "recovered_job_ids": [j.id for j in recovered]}


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
        .filter(
            AssessmentFinding.project_id == project_id,
            AssessmentFinding.job_id == job_id,
        )
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


@router.get("/projects/{project_id}/assessments/{job_id}/findings/{finding_id}/evidence/{evidence_id}", response_model=FindingEvidenceResponse)
def get_assessment_evidence_detail(
    project_id: str,
    job_id: str,
    finding_id: str,
    evidence_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Fetch a specific cryptographic evidence item with strict multi-tenant parent-child boundary checks.
    Fails closed with 404 if project_id, job_id, finding_id, or evidence_id do not match.
    """
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

    evidence = (
        db.query(FindingEvidence)
        .filter(
            FindingEvidence.id == evidence_id,
            FindingEvidence.finding_id == finding.id,
        )
        .first()
    )
    if not evidence:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Evidence item not found")
    return evidence
