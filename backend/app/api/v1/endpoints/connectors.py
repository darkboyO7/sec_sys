"""
Connectors API Router (Prompt 40).
Provides endpoints for connector inventory discovery, configuration management,
SSRF-protected connection validation, stateful synchronization, and audit history.
"""
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.user import User
from app.api.deps import get_current_user, verify_project_access
from app.services.connector_service import ConnectorService
from app.schemas.connector import (
    ConnectorInventoryItem,
    ConnectorConfigCreate,
    ConnectorConfigUpdate,
    ConnectorConfigRead,
    ConnectorHealthRead,
    ConnectorSyncTriggerResponse,
    ConnectorSyncEventRead,
)

router = APIRouter()


@router.get(
    "/projects/{project_id}/connectors/inventory",
    response_model=List[ConnectorInventoryItem],
    status_code=status.HTTP_200_OK,
    summary="List all registered external integration adapters and capabilities",
)
def get_connector_inventory(
    project_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    verify_project_access(project_id, current_user, db)
    return ConnectorService.get_inventory()


@router.get(
    "/projects/{project_id}/connectors",
    response_model=List[ConnectorConfigRead],
    status_code=status.HTTP_200_OK,
    summary="List all configured enterprise connectors for the active project",
)
def list_connectors(
    project_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    verify_project_access(project_id, current_user, db)
    return ConnectorService.list_connectors(db, project_id)


@router.post(
    "/projects/{project_id}/connectors",
    response_model=ConnectorConfigRead,
    status_code=status.HTTP_201_CREATED,
    summary="Register and configure an external security connector",
)
def create_connector(
    project_id: str,
    data: ConnectorConfigCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    verify_project_access(project_id, current_user, db)
    try:
        return ConnectorService.create_connector(db, project_id, data)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.get(
    "/projects/{project_id}/connectors/{connector_id}",
    response_model=ConnectorConfigRead,
    status_code=status.HTTP_200_OK,
    summary="Get details and truthful health status of a configured connector",
)
def get_connector(
    project_id: str,
    connector_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    verify_project_access(project_id, current_user, db)
    conn = ConnectorService.get_connector(db, project_id, connector_id)
    if not conn:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Connector '{connector_id}' not found",
        )
    return conn


@router.put(
    "/projects/{project_id}/connectors/{connector_id}",
    response_model=ConnectorConfigRead,
    status_code=status.HTTP_200_OK,
    summary="Update connector configuration, capabilities, or rate limits",
)
def update_connector(
    project_id: str,
    connector_id: str,
    data: ConnectorConfigUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    verify_project_access(project_id, current_user, db)
    try:
        return ConnectorService.update_connector(db, project_id, connector_id, data)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.delete(
    "/projects/{project_id}/connectors/{connector_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete a configured connector and its associated sync history",
)
def delete_connector(
    project_id: str,
    connector_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    verify_project_access(project_id, current_user, db)
    try:
        ConnectorService.delete_connector(db, project_id, connector_id)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.post(
    "/projects/{project_id}/connectors/{connector_id}/test",
    response_model=ConnectorHealthRead,
    status_code=status.HTTP_200_OK,
    summary="Perform non-destructive connectivity check with SSRF validation",
)
def test_connection(
    project_id: str,
    connector_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    verify_project_access(project_id, current_user, db)
    try:
        return ConnectorService.test_connection(db, project_id, connector_id)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post(
    "/projects/{project_id}/connectors/{connector_id}/sync",
    response_model=ConnectorSyncTriggerResponse,
    status_code=status.HTTP_200_OK,
    summary="Trigger on-demand idempotent synchronization run",
)
def execute_sync(
    project_id: str,
    connector_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    verify_project_access(project_id, current_user, db)
    try:
        return ConnectorService.execute_sync(db, project_id, connector_id)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.get(
    "/projects/{project_id}/connectors/{connector_id}/history",
    response_model=List[ConnectorSyncEventRead],
    status_code=status.HTTP_200_OK,
    summary="Retrieve sync run execution history and cryptographic provenance digests",
)
def get_sync_history(
    project_id: str,
    connector_id: str,
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    verify_project_access(project_id, current_user, db)
    return ConnectorService.get_sync_history(db, project_id, connector_id, limit=limit)
