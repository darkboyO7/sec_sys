"""
Attack Surface and Exposure Governance API Endpoints (Prompt 46).
Provides endpoints for authorized exposure inventory, timeline feed,
asset-level evidence views, and discovery inclusion approval workflows.
"""
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.user import User, SystemRole
from app.api.deps import get_current_user, verify_project_access, require_system_roles
from app.models.attack_surface import (
    ExposureClassification,
    ExposureFreshness,
    ProposalStatus,
)
from app.schemas.attack_surface import (
    AttackSurfaceExposureRead,
    AttackSurfaceExposureCreate,
    AssetInclusionProposalRead,
    AssetInclusionProposalCreate,
    ProposalApprovalRequest,
    ProposalRejectionRequest,
    AttackSurfaceInventoryResponse,
    AttackSurfaceTimelineResponse,
    AssetExposureEvidenceResponse,
)
from app.services.attack_surface_service import AttackSurfaceService

router = APIRouter()


@router.get(
    "/projects/{project_id}/attack-surface/inventory",
    response_model=AttackSurfaceInventoryResponse,
    status_code=status.HTTP_200_OK,
    summary="Get authorized attack-surface exposure inventory and classification metrics",
)
def get_attack_surface_inventory(
    project_id: str,
    classification: Optional[ExposureClassification] = Query(None),
    freshness: Optional[ExposureFreshness] = Query(None),
    search: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    verify_project_access(project_id, current_user, db)
    return AttackSurfaceService.get_inventory(
        db=db,
        project_id=project_id,
        classification=classification,
        freshness=freshness,
        search=search,
    )


@router.get(
    "/projects/{project_id}/attack-surface/timeline",
    response_model=AttackSurfaceTimelineResponse,
    status_code=status.HTTP_200_OK,
    summary="Get chronological timeline of exposure observations, cert updates, and service changes",
)
def get_attack_surface_timeline(
    project_id: str,
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    verify_project_access(project_id, current_user, db)
    events = AttackSurfaceService.get_timeline(db=db, project_id=project_id, limit=limit)
    return AttackSurfaceTimelineResponse(
        project_id=project_id,
        total_events=len(events),
        events=events,
    )


@router.get(
    "/projects/{project_id}/attack-surface/assets/{asset_id}/evidence",
    response_model=AssetExposureEvidenceResponse,
    status_code=status.HTTP_200_OK,
    summary="Get asset-level exposure evidence breakdown including active services and TLS certs",
)
def get_asset_exposure_evidence(
    project_id: str,
    asset_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    verify_project_access(project_id, current_user, db)
    try:
        return AttackSurfaceService.get_asset_exposure_evidence(
            db=db,
            project_id=project_id,
            asset_id=asset_id,
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.post(
    "/projects/{project_id}/attack-surface/ingest",
    response_model=AttackSurfaceExposureRead,
    status_code=status.HTTP_201_CREATED,
    summary="Ingest an exposure observation with strict preflight scope validation and anti-expansion guard",
)
def ingest_exposure_observation(
    project_id: str,
    data: AttackSurfaceExposureCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    verify_project_access(project_id, current_user, db)
    try:
        exposure, proposal, changes = AttackSurfaceService.ingest_exposure_observation(
            db=db,
            project_id=project_id,
            asset_id=data.asset_id,
            canonical_identifier=data.canonical_identifier,
            service_name=data.service_name,
            port=data.port,
            protocol=data.protocol,
            transport_security=data.transport_security,
            certificate_details=data.certificate_details,
            relevant_hostnames=data.relevant_hostnames,
            exposure_classification=data.exposure_classification,
            provenance_type=data.provenance_type,
            evidence_hash=data.evidence_hash,
            attributes=data.attributes,
            is_simulated=data.is_simulated,
        )
        if proposal:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Target '{data.canonical_identifier}' is not in authorized scope. Routed to discovery inclusion proposal inbox (ID: {proposal.id}).",
            )
        return exposure
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.get(
    "/projects/{project_id}/attack-surface/proposals",
    response_model=List[AssetInclusionProposalRead],
    status_code=status.HTTP_200_OK,
    summary="List proposed discovered assets pending authorization approval",
)
def list_inclusion_proposals(
    project_id: str,
    status_filter: Optional[ProposalStatus] = Query(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    verify_project_access(project_id, current_user, db)
    return AttackSurfaceService.list_proposals(
        db=db,
        project_id=project_id,
        status_filter=status_filter,
    )


@router.post(
    "/projects/{project_id}/attack-surface/proposals/{proposal_id}/approve",
    response_model=AssetInclusionProposalRead,
    status_code=status.HTTP_200_OK,
    summary="Approve a discovered asset for inclusion into active authorized assessment scope",
)
def approve_inclusion_proposal(
    project_id: str,
    proposal_id: str,
    data: ProposalApprovalRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_system_roles([
            SystemRole.ADMIN,
            SystemRole.SECURITY_LEAD,
            SystemRole.SECURITY_TESTER,
        ])
    ),
):
    verify_project_access(project_id, current_user, db)
    try:
        proposal, _ = AttackSurfaceService.approve_inclusion_proposal(
            db=db,
            project_id=project_id,
            proposal_id=proposal_id,
            reviewer=current_user,
            approval_notes=data.approval_notes,
            authorized_evidence=data.authorized_evidence,
        )
        return proposal
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.post(
    "/projects/{project_id}/attack-surface/proposals/{proposal_id}/reject",
    response_model=AssetInclusionProposalRead,
    status_code=status.HTTP_200_OK,
    summary="Reject a discovered asset from active scope inclusion",
)
def reject_inclusion_proposal(
    project_id: str,
    proposal_id: str,
    data: ProposalRejectionRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_system_roles([
            SystemRole.ADMIN,
            SystemRole.SECURITY_LEAD,
            SystemRole.SECURITY_TESTER,
        ])
    ),
):
    verify_project_access(project_id, current_user, db)
    try:
        return AttackSurfaceService.reject_inclusion_proposal(
            db=db,
            project_id=project_id,
            proposal_id=proposal_id,
            reviewer=current_user,
            rejection_reason=data.rejection_reason,
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
