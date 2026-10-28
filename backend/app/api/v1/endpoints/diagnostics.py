"""
Diagnostics & Controlled Recovery Endpoints for VAPT System.
Provides central system health evaluation, safe read-only project self-diagnostics,
controlled recovery actions with two-phase verification, and continuous improvement intelligence.
"""
from typing import Dict, Any, List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.user import User
from app.models.project import ProjectRole
from app.models.diagnostics import (
    RecoveryActionType,
    DiagnosticRunRecord,
    DiagnosticFindingRecord,
    RecoveryActionRecord,
)
from app.api.deps import get_current_user, verify_project_access
from app.schemas.diagnostics import (
    SystemHealthResponse,
    DiagnosticRunResponse,
    RecoveryActionRequest,
    RecoveryActionResponse,
    ContinuousImprovementResponse,
)
from app.services.health_engine import HealthEngineService
from app.services.diagnostics_engine import DiagnosticsEngineService
from app.services.recovery_engine import RecoveryEngineService
from app.services.continuous_improvement_service import ContinuousImprovementService
from app.services.failure_knowledge_base import FailureKnowledgeBase

router = APIRouter()


# ------------------------------------------------------------------------------
# 1. Central System Health Engine
# ------------------------------------------------------------------------------
@router.get(
    "/health",
    response_model=SystemHealthResponse,
    status_code=status.HTTP_200_OK,
    summary="Evaluate comprehensive health across all 12 platform subsystems",
)
def get_system_health(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Evaluates real functional state across:
    API/Auth, Database/Migrations, Workers, Adapters, Assets/Evidence,
    Risk/Attack-Paths, Verification, Monitoring, Learning, Notifications,
    Backup, and Frontend Connectivity.
    Zero secrets exposed.
    """
    return HealthEngineService.evaluate_system_health(db=db)


# ------------------------------------------------------------------------------
# 2. Failure Knowledge Base
# ------------------------------------------------------------------------------
@router.get(
    "/knowledge-base",
    status_code=status.HTTP_200_OK,
    summary="Query known failure catalog signatures, causes, and safe recovery steps",
)
def get_failure_knowledge_base(
    current_user: User = Depends(get_current_user),
):
    return FailureKnowledgeBase.get_catalog()


# ------------------------------------------------------------------------------
# 3. Project Self-Diagnostics
# ------------------------------------------------------------------------------
@router.post(
    "/{project_id}/run",
    response_model=DiagnosticRunResponse,
    status_code=status.HTTP_200_OK,
    summary="Trigger read-only self-diagnostic checks for a project",
)
def run_project_diagnostics(
    project_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    verify_project_access(project_id, current_user, db)
    return DiagnosticsEngineService.run_project_diagnostics(
        db=db,
        project_id=project_id,
        actor_id=current_user.id,
        trigger_type="MANUAL",
    )


@router.get(
    "/{project_id}/recent",
    status_code=status.HTTP_200_OK,
    summary="Get recent diagnostic run summaries and findings",
)
def get_recent_diagnostics(
    project_id: str,
    limit: int = Query(default=10, ge=1, le=50),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    verify_project_access(project_id, current_user, db)
    runs = (
        db.query(DiagnosticRunRecord)
        .filter(DiagnosticRunRecord.project_id == project_id)
        .order_by(DiagnosticRunRecord.run_timestamp.desc())
        .limit(limit)
        .all()
    )

    result = []
    for r in runs:
        findings = (
            db.query(DiagnosticFindingRecord)
            .filter(DiagnosticFindingRecord.run_id == r.id)
            .all()
        )
        result.append({
            "run_id": r.id,
            "project_id": r.project_id,
            "run_timestamp": r.run_timestamp.isoformat(),
            "trigger_type": r.trigger_type,
            "total_checks": r.total_checks,
            "passed_checks": r.passed_checks,
            "warning_checks": r.warning_checks,
            "failed_checks": r.failed_checks,
            "summary": r.summary,
            "findings": [
                {
                    "id": f.id,
                    "check_id": f.check_id,
                    "category": f.category.value,
                    "severity": f.severity.value,
                    "confidence": f.confidence.value,
                    "title": f.title,
                    "description": f.description,
                    "observed_issue": f.observed_issue,
                    "affected_entities": f.affected_entities,
                    "recommended_action": f.recommended_action,
                    "recovery_action_available": f.recovery_action_available,
                }
                for f in findings
            ],
        })
    return {"project_id": project_id, "recent_runs": result}


# ------------------------------------------------------------------------------
# 4. Controlled Recovery Actions
# ------------------------------------------------------------------------------
@router.post(
    "/{project_id}/recover",
    response_model=RecoveryActionResponse,
    status_code=status.HTTP_200_OK,
    summary="Execute a controlled recovery action with two-phase verification",
)
def execute_recovery_action(
    project_id: str,
    payload: RecoveryActionRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    # Requires LEAD or ADMIN
    verify_project_access(project_id, current_user, db, required_project_roles=[ProjectRole.LEAD])

    try:
        action_enum = RecoveryActionType(payload.action_type)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid recovery action type '{payload.action_type}'.",
        )

    try:
        res = RecoveryEngineService.execute_recovery(
            db=db,
            project_id=project_id,
            action_type=action_enum,
            target_entity_type=payload.target_entity_type,
            target_entity_id=payload.target_entity_id,
            target_resource=payload.target_resource,
            actor=current_user,
            reason=payload.reason,
        )
        return res
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Recovery action execution failed: {str(e)}",
        )


@router.get(
    "/{project_id}/recovery-history",
    status_code=status.HTTP_200_OK,
    summary="Get history of executed recovery actions and verified outcomes",
)
def get_recovery_history(
    project_id: str,
    limit: int = Query(default=20, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    verify_project_access(project_id, current_user, db)
    records = (
        db.query(RecoveryActionRecord)
        .filter(RecoveryActionRecord.project_id == project_id)
        .order_by(RecoveryActionRecord.execution_timestamp.desc())
        .limit(limit)
        .all()
    )
    return {
        "project_id": project_id,
        "total": len(records),
        "records": [
            {
                "id": r.id,
                "action_type": r.action_type.value,
                "target_entity_type": r.target_entity_type,
                "target_entity_id": r.target_entity_id,
                "target_resource": r.target_resource,
                "executed_by_id": r.executed_by_id,
                "execution_timestamp": r.execution_timestamp.isoformat(),
                "reason": r.reason,
                "outcome": r.outcome.value,
                "pre_condition": r.pre_condition,
                "post_condition": r.post_condition,
                "verification_notes": r.verification_notes,
                "verification_timestamp": r.verification_timestamp.isoformat(),
                "ledger_record_id": r.ledger_record_id,
            }
            for r in records
        ],
    }


# ------------------------------------------------------------------------------
# 5. Continuous Improvement & Reliability Intelligence
# ------------------------------------------------------------------------------
@router.get(
    "/{project_id}/patterns",
    response_model=ContinuousImprovementResponse,
    status_code=status.HTTP_200_OK,
    summary="Get repeated failure patterns and continuous improvement recommendations",
)
def get_failure_patterns(
    project_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    verify_project_access(project_id, current_user, db)
    return ContinuousImprovementService.analyze_and_update_patterns(db=db, project_id=project_id)


# ------------------------------------------------------------------------------
# 6. Low-Level Database, Storage, and Operational Diagnostics
# ------------------------------------------------------------------------------
@router.get(
    "/operational-status",
    status_code=status.HTTP_200_OK,
    summary="Get low-level database, storage, WAL, and backup diagnostics",
)
def get_operational_status(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    from app.services.database_diagnostics_service import DatabaseDiagnosticsService
    return DatabaseDiagnosticsService.run_diagnostics(db=db)

