from typing import List, Optional
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, status, Request, Query
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.user import User
from app.models.digital_twin import SecuritySnapshot
from app.schemas.digital_twin import (
    SecuritySnapshotCreate,
    SecuritySnapshotRead,
    SnapshotCompareRequest,
    SnapshotDiffResponse,
    ReconstructStateResponse,
)
from app.services.digital_twin_service import DigitalTwinService
from app.api.deps import get_current_user, verify_project_access, get_client_ip

router = APIRouter()


@router.post(
    "/projects/{project_id}/digital-twin/snapshots",
    response_model=SecuritySnapshotRead,
    status_code=status.HTTP_201_CREATED,
    summary="Capture an immutable point-in-time security digital twin snapshot",
)
def capture_project_snapshot(
    project_id: str,
    body: SecuritySnapshotCreate,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    verify_project_access(project_id, current_user, db)
    client_ip = get_client_ip(request)

    try:
        return DigitalTwinService.capture_snapshot(
            project_id=project_id,
            label=body.snapshot_label,
            user=current_user,
            db=db,
            as_of_time=body.as_of_time,
            client_ip=client_ip,
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.get(
    "/projects/{project_id}/digital-twin/snapshots",
    response_model=List[SecuritySnapshotRead],
    summary="List historical security digital twin snapshots",
)
def list_project_snapshots(
    project_id: str,
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    verify_project_access(project_id, current_user, db)
    return (
        db.query(SecuritySnapshot)
        .filter(SecuritySnapshot.project_id == project_id)
        .order_by(SecuritySnapshot.snapshot_timestamp.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )


@router.get(
    "/projects/{project_id}/digital-twin/snapshots/{snapshot_id}",
    response_model=SecuritySnapshotRead,
    summary="Get single snapshot record by ID",
)
def get_project_snapshot(
    project_id: str,
    snapshot_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    verify_project_access(project_id, current_user, db)
    snapshot = (
        db.query(SecuritySnapshot)
        .filter(SecuritySnapshot.id == snapshot_id, SecuritySnapshot.project_id == project_id)
        .first()
    )
    if not snapshot:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security snapshot '{snapshot_id}' not found in project '{project_id}'.",
        )
    return snapshot


@router.post(
    "/projects/{project_id}/digital-twin/compare",
    response_model=SnapshotDiffResponse,
    summary="Compare two historical security snapshots (A vs B diff)",
)
def compare_snapshots(
    project_id: str,
    body: SnapshotCompareRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    verify_project_access(project_id, current_user, db)
    try:
        return DigitalTwinService.compare_snapshots(
            project_id=project_id,
            snapshot_a_id=body.snapshot_a_id,
            snapshot_b_id=body.snapshot_b_id,
            db=db,
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.get(
    "/projects/{project_id}/digital-twin/reconstruct",
    response_model=ReconstructStateResponse,
    summary="Reconstruct project security state as of a historical timestamp",
)
def reconstruct_historical_state(
    project_id: str,
    as_of: datetime = Query(..., description="Target historical timestamp (ISO 8601)"),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    verify_project_access(project_id, current_user, db)
    try:
        return DigitalTwinService.reconstruct_state_as_of(
            project_id=project_id,
            as_of_time=as_of,
            db=db,
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
