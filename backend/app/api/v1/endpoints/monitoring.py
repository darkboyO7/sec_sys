from typing import List
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.api.deps import get_current_user, verify_project_access, get_client_ip
from app.models.user import User
from app.models.project import ProjectRole
from app.models.monitoring import MonitoringSchedule, MonitoringRun, ScheduleStatus
from app.schemas.monitoring import (
    ScheduleCreate,
    ScheduleUpdate,
    ScheduleResponse,
    MonitoringRunResponse,
    MonitoringOverviewResponse,
)
from app.services.continuous_monitoring_service import ContinuousMonitoringService

router = APIRouter()


@router.post(
    "/projects/{project_id}/monitoring/schedules",
    response_model=ScheduleResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_monitoring_schedule(
    project_id: str,
    schedule_in: ScheduleCreate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Creates a new recurring assessment monitoring schedule for an authorized target.
    Requires Project LEAD or System ADMIN role.
    """
    verify_project_access(project_id, current_user, db, required_project_roles=[ProjectRole.LEAD])
    client_ip = get_client_ip(request)

    try:
        schedule = ContinuousMonitoringService.create_schedule(
            project_id=project_id,
            schedule_in=schedule_in,
            creator=current_user,
            creator_role=ProjectRole.LEAD,
            db=db,
            client_ip=client_ip,
        )
        return schedule
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except PermissionError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))


@router.get(
    "/projects/{project_id}/monitoring/schedules",
    response_model=List[ScheduleResponse],
)
def list_monitoring_schedules(
    project_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Lists all configured monitoring schedules for a project."""
    verify_project_access(project_id, current_user, db)
    return ContinuousMonitoringService.list_schedules(project_id=project_id, db=db)


@router.get(
    "/projects/{project_id}/monitoring/schedules/{schedule_id}",
    response_model=ScheduleResponse,
)
def get_monitoring_schedule(
    project_id: str,
    schedule_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Gets details of a specific monitoring schedule."""
    verify_project_access(project_id, current_user, db)
    schedule = ContinuousMonitoringService.get_schedule(project_id=project_id, schedule_id=schedule_id, db=db)
    if not schedule:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Schedule not found.")
    return schedule


@router.post(
    "/projects/{project_id}/monitoring/schedules/{schedule_id}/pause",
    response_model=ScheduleResponse,
)
def pause_monitoring_schedule(
    project_id: str,
    schedule_id: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Pauses an active monitoring schedule."""
    verify_project_access(project_id, current_user, db, required_project_roles=[ProjectRole.LEAD])
    client_ip = get_client_ip(request)
    try:
        return ContinuousMonitoringService.pause_schedule(
            project_id=project_id,
            schedule_id=schedule_id,
            actor=current_user,
            actor_role=ProjectRole.LEAD,
            db=db,
            client_ip=client_ip,
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.post(
    "/projects/{project_id}/monitoring/schedules/{schedule_id}/resume",
    response_model=ScheduleResponse,
)
def resume_monitoring_schedule(
    project_id: str,
    schedule_id: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Resumes a paused monitoring schedule."""
    verify_project_access(project_id, current_user, db, required_project_roles=[ProjectRole.LEAD])
    client_ip = get_client_ip(request)
    try:
        return ContinuousMonitoringService.resume_schedule(
            project_id=project_id,
            schedule_id=schedule_id,
            actor=current_user,
            actor_role=ProjectRole.LEAD,
            db=db,
            client_ip=client_ip,
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.post(
    "/projects/{project_id}/monitoring/schedules/{schedule_id}/run-now",
    response_model=MonitoringRunResponse,
)
def trigger_monitoring_schedule_run_now(
    project_id: str,
    schedule_id: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Immediately triggers an on-demand execution of an active monitoring schedule."""
    verify_project_access(project_id, current_user, db, required_project_roles=[ProjectRole.LEAD, ProjectRole.TESTER])
    client_ip = get_client_ip(request)
    schedule = ContinuousMonitoringService.get_schedule(project_id=project_id, schedule_id=schedule_id, db=db)
    if not schedule:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Schedule not found.")

    try:
        run = ContinuousMonitoringService.execute_schedule_run(
            schedule_id=schedule_id,
            db=db,
            client_ip=client_ip,
        )
        return run
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.get(
    "/projects/{project_id}/monitoring/runs",
    response_model=List[MonitoringRunResponse],
)
def list_monitoring_runs(
    project_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Lists execution history for all monitoring runs in the project."""
    verify_project_access(project_id, current_user, db)
    runs = (
        db.query(MonitoringRun)
        .filter(MonitoringRun.project_id == project_id)
        .order_by(MonitoringRun.executed_at.desc())
        .limit(100)
        .all()
    )
    return runs


@router.get(
    "/projects/{project_id}/monitoring/overview",
    response_model=MonitoringOverviewResponse,
)
def get_monitoring_overview(
    project_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Aggregates continuous monitoring metrics, status counts, and recent runs."""
    verify_project_access(project_id, current_user, db)
    schedules = db.query(MonitoringSchedule).filter(MonitoringSchedule.project_id == project_id).all()
    recent_runs = (
        db.query(MonitoringRun)
        .filter(MonitoringRun.project_id == project_id)
        .order_by(MonitoringRun.executed_at.desc())
        .limit(10)
        .all()
    )

    total_runs = db.query(MonitoringRun).filter(MonitoringRun.project_id == project_id).count()

    return MonitoringOverviewResponse(
        total_schedules=len(schedules),
        active_schedules=len([s for s in schedules if s.status == ScheduleStatus.ACTIVE]),
        paused_schedules=len([s for s in schedules if s.status == ScheduleStatus.PAUSED]),
        expired_schedules=len([s for s in schedules if s.status == ScheduleStatus.EXPIRED]),
        total_runs_executed=total_runs,
        recent_runs=recent_runs,
    )
