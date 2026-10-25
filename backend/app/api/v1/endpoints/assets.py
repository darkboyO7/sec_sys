from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Request, Query
from sqlalchemy.orm import Session
from sqlalchemy import func, or_

from app.core.database import get_db
from app.models.user import User
from app.models.project import ProjectRole
from app.models.asset import (
    Asset,
    AssetObservation,
    AssetType,
    AssetCriticality,
    AssetStatus,
)
from app.models.finding import VulnerabilityFinding
from app.models.graph import GraphNode, GraphNodeCategory
from app.schemas.asset import (
    AssetRead,
    AssetDetail,
    AssetObservationRead,
    AssetCreateFixtureRequest,
    ResolveAmbiguityRequest,
)
from app.schemas.finding import VulnerabilityFindingRead
from app.services.asset_reconciliation_service import AssetReconciliationService
from app.services.knowledge_graph_service import KnowledgeGraphService
from app.services.audit_service import AuditService
from app.api.deps import get_current_user, verify_project_access, get_client_ip

router = APIRouter()


def _format_asset_detail(asset: Asset, db: Session) -> AssetDetail:
    """Helper to attach observation history, finding count, and graph node reference to an AssetDetail."""
    obs_list = (
        db.query(AssetObservation)
        .filter(AssetObservation.asset_id == asset.id)
        .order_by(AssetObservation.observed_at.desc())
        .limit(50)
        .all()
    )

    finding_count = (
        db.query(func.count(VulnerabilityFinding.id))
        .filter(VulnerabilityFinding.asset_id == asset.id)
        .scalar()
        or 0
    )

    # Locate corresponding graph node if created
    graph_node = (
        db.query(GraphNode)
        .filter(
            GraphNode.project_id == asset.project_id,
            GraphNode.category == GraphNodeCategory.ASSET,
            GraphNode.entity_id == asset.id,
        )
        .first()
    )

    # Count incoming/outgoing relationships connected to this asset node
    related_nodes_count = 0
    if graph_node:
        from app.models.graph import GraphRelationship
        out_cnt = db.query(func.count(GraphRelationship.id)).filter(GraphRelationship.source_node_id == graph_node.id).scalar() or 0
        in_cnt = db.query(func.count(GraphRelationship.id)).filter(GraphRelationship.target_node_id == graph_node.id).scalar() or 0
        related_nodes_count = out_cnt + in_cnt

    detail_data = AssetRead.model_validate(asset).model_dump()
    detail_data["observations"] = [AssetObservationRead.model_validate(o) for o in obs_list]
    detail_data["finding_count"] = finding_count
    detail_data["graph_node_id"] = graph_node.id if graph_node else None
    detail_data["related_nodes_count"] = related_nodes_count
    return AssetDetail(**detail_data)


@router.get("/projects/{project_id}/assets", response_model=List[AssetRead])
def list_project_assets(
    project_id: str,
    asset_type: Optional[AssetType] = Query(None),
    criticality: Optional[AssetCriticality] = Query(None),
    status_filter: Optional[AssetStatus] = Query(None, alias="status"),
    is_ambiguous: Optional[bool] = Query(None),
    search: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    List persistent security assets for a project with bounded pagination and filtering.
    Strict tenant/project isolation enforced.
    """
    verify_project_access(project_id, current_user, db)

    query = db.query(Asset).filter(Asset.project_id == project_id)

    if asset_type:
        query = query.filter(Asset.asset_type == asset_type)
    if criticality:
        query = query.filter(Asset.criticality == criticality)
    if status_filter:
        query = query.filter(Asset.status == status_filter)
    if is_ambiguous is not None:
        query = query.filter(Asset.is_ambiguous == is_ambiguous)
    if search:
        search_term = f"%{search.strip()}%"
        query = query.filter(
            or_(
                Asset.name.ilike(search_term),
                Asset.canonical_identifier.ilike(search_term),
            )
        )

    return (
        query.order_by(Asset.criticality.desc(), Asset.last_seen_at.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )


@router.get("/projects/{project_id}/assets/{asset_id}", response_model=AssetDetail)
def get_asset_detail(
    project_id: str,
    asset_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Retrieve comprehensive asset details, historical observations, and graph linkage.
    """
    verify_project_access(project_id, current_user, db)

    asset = (
        db.query(Asset)
        .filter(Asset.id == asset_id, Asset.project_id == project_id)
        .first()
    )
    if not asset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Asset not found in specified project",
        )

    return _format_asset_detail(asset, db)


@router.get("/projects/{project_id}/assets/{asset_id}/observations", response_model=List[AssetObservationRead])
def list_asset_observations(
    project_id: str,
    asset_id: str,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Retrieve chronological historical observation records supporting the asset.
    """
    verify_project_access(project_id, current_user, db)

    # Verify asset exists in project
    asset = (
        db.query(Asset)
        .filter(Asset.id == asset_id, Asset.project_id == project_id)
        .first()
    )
    if not asset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Asset not found in specified project",
        )

    return (
        db.query(AssetObservation)
        .filter(AssetObservation.asset_id == asset_id)
        .order_by(AssetObservation.observed_at.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )


@router.get("/projects/{project_id}/assets/{asset_id}/findings", response_model=List[VulnerabilityFindingRead])
def list_asset_findings(
    project_id: str,
    asset_id: str,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Retrieve vulnerability findings affecting this specific asset.
    """
    verify_project_access(project_id, current_user, db)

    asset = (
        db.query(Asset)
        .filter(Asset.id == asset_id, Asset.project_id == project_id)
        .first()
    )
    if not asset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Asset not found in specified project",
        )

    return (
        db.query(VulnerabilityFinding)
        .filter(VulnerabilityFinding.asset_id == asset_id, VulnerabilityFinding.project_id == project_id)
        .order_by(VulnerabilityFinding.severity.desc(), VulnerabilityFinding.last_observed_at.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )


@router.post("/projects/{project_id}/assets/fixture", response_model=AssetDetail, status_code=status.HTTP_201_CREATED)
def create_fixture_asset(
    project_id: str,
    asset_in: AssetCreateFixtureRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Ingest a validated synthetic/fixture asset for testing asset inventory and graph modeling.
    Requires Project LEAD or System ADMIN. Active network scanning is NOT performed.
    """
    project = verify_project_access(
        project_id,
        current_user,
        db,
        required_project_roles=[ProjectRole.LEAD],
    )

    # Classify & Normalize identifier
    _, norm_canonical, norm_name = AssetReconciliationService.classify_and_normalize(asset_in.canonical_identifier)

    asset = AssetReconciliationService.reconcile_or_create_asset(
        project_id=project_id,
        organization_id=project.organization_id,
        asset_type=asset_in.asset_type,
        canonical_identifier=norm_canonical,
        name=asset_in.name or norm_name,
        environment=asset_in.environment,
        criticality=asset_in.criticality,
        attributes=asset_in.attributes,
        source=asset_in.source,
        confidence=asset_in.confidence,
        is_ambiguous=asset_in.is_ambiguous,
        ambiguity_reason=asset_in.ambiguity_reason,
        db=db,
    )

    # Record initial observation
    AssetReconciliationService.record_observation(
        asset=asset,
        project_id=project_id,
        observation_source=asset_in.source,
        observed_attributes=asset_in.attributes,
        confidence=asset_in.confidence,
        db=db,
    )

    # Create corresponding graph node
    KnowledgeGraphService.get_or_create_node(
        project_id=project_id,
        category=GraphNodeCategory.ASSET,
        label=asset.name,
        entity_id=asset.id,
        entity_type="Asset",
        properties={
            "asset_type": asset.asset_type.value,
            "canonical_identifier": asset.canonical_identifier,
            "criticality": asset.criticality.value,
            "environment": asset.environment,
        },
        db=db,
    )

    client_ip = get_client_ip(request)
    AuditService.log(
        db=db,
        action="ASSET_FIXTURE_INGEST",
        target_resource=f"asset:{asset.id}",
        actor_id=current_user.id,
        project_id=project_id,
        client_ip=client_ip,
        details={
            "asset_id": asset.id,
            "asset_type": asset.asset_type.value,
            "canonical_identifier": asset.canonical_identifier,
        },
    )
    db.commit()

    return _format_asset_detail(asset, db)


@router.post("/projects/{project_id}/assets/{asset_id}/resolve-ambiguity", response_model=AssetDetail)
def resolve_asset_ambiguity(
    project_id: str,
    asset_id: str,
    resolve_in: ResolveAmbiguityRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Review and resolve an ambiguous asset identity match with explicit justification.
    Requires Project LEAD or System ADMIN.
    """
    verify_project_access(
        project_id,
        current_user,
        db,
        required_project_roles=[ProjectRole.LEAD],
    )

    asset = (
        db.query(Asset)
        .filter(Asset.id == asset_id, Asset.project_id == project_id)
        .first()
    )
    if not asset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Asset not found in specified project",
        )

    asset.is_ambiguous = False
    attrs = dict(asset.attributes or {})
    attrs["_resolution_history"] = attrs.get("_resolution_history", []) + [
        {
            "resolved_at": asset.last_seen_at.isoformat(),
            "actor_id": current_user.id,
            "notes": resolve_in.resolution_notes,
            "previous_ambiguity_reason": asset.ambiguity_reason,
        }
    ]
    asset.attributes = attrs
    asset.ambiguity_reason = None

    client_ip = get_client_ip(request)
    AuditService.log(
        db=db,
        action="ASSET_AMBIGUITY_RESOLVED",
        target_resource=f"asset:{asset.id}",
        actor_id=current_user.id,
        project_id=project_id,
        client_ip=client_ip,
        details={"asset_id": asset.id, "notes": resolve_in.resolution_notes},
    )
    db.commit()

    return _format_asset_detail(asset, db)
