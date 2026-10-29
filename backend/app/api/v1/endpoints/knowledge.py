from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.core.database import get_db
from app.models.user import User
from app.models.project import ProjectRole
from app.models.graph import GraphNode, GraphRelationship, EpistemicStatus
from app.models.finding import VulnerabilityFinding
from app.models.risk import RiskAssessment
from app.models.knowledge import (
    KnowledgeDependencyRecord,
    ExplainableAttackPathRecord,
    KnowledgeReconciliationAudit,
)
from app.schemas.knowledge import (
    KnowledgeDependencyRead,
    ExplainableAttackPathRead,
    KnowledgeReconciliationAuditRead,
    ReconciliationTriggerRequest,
    FindingEpistemicExplanation,
    RelationshipEpistemicExplanation,
)
from app.services.attack_path_service import AttackPathAnalysisService
from app.services.knowledge_reconciliation_service import KnowledgeReconciliationService
from app.api.deps import get_current_user, verify_project_access

router = APIRouter()


@router.get("/projects/{project_id}/knowledge/dependencies", response_model=List[KnowledgeDependencyRead])
def list_knowledge_dependencies(
    project_id: str,
    source_type: Optional[str] = Query(None),
    source_id: Optional[str] = Query(None),
    dependent_type: Optional[str] = Query(None),
    is_valid: Optional[bool] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    List fine-grained dependency records tracking authoritative sources to derived conclusions (Prompt 21).
    """
    verify_project_access(project_id, current_user, db)
    query = db.query(KnowledgeDependencyRecord).filter(KnowledgeDependencyRecord.project_id == project_id)

    if source_type:
        query = query.filter(KnowledgeDependencyRecord.source_entity_type == source_type)
    if source_id:
        query = query.filter(KnowledgeDependencyRecord.source_entity_id == source_id)
    if dependent_type:
        query = query.filter(KnowledgeDependencyRecord.dependent_entity_type == dependent_type)
    if is_valid is not None:
        query = query.filter(KnowledgeDependencyRecord.is_valid == is_valid)

    return query.order_by(desc(KnowledgeDependencyRecord.updated_at)).limit(limit).all()


@router.get("/projects/{project_id}/knowledge/attack-paths", response_model=List[ExplainableAttackPathRead])
def list_explainable_attack_paths(
    project_id: str,
    start_node_id: Optional[str] = Query(None),
    target_node_id: Optional[str] = Query(None),
    finding_id: Optional[str] = Query(None),
    compute_fresh: bool = Query(True),
    max_depth: int = Query(3, ge=1, le=4),
    limit: int = Query(10, ge=1, le=20),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    List or compute explainable, scope-bounded attack paths (Prompt 21).
    """
    verify_project_access(project_id, current_user, db)

    if compute_fresh:
        AttackPathAnalysisService.analyze_attack_paths(
            project_id=project_id,
            db=db,
            start_node_id=start_node_id,
            target_node_id=target_node_id,
            finding_id=finding_id,
            max_depth=max_depth,
            max_paths=limit,
        )
        db.commit()

    query = db.query(ExplainableAttackPathRecord).filter(ExplainableAttackPathRecord.project_id == project_id)
    return query.order_by(desc(ExplainableAttackPathRecord.cumulative_confidence)).limit(limit).all()


@router.get("/projects/{project_id}/knowledge/attack-paths/{path_id}", response_model=ExplainableAttackPathRead)
def get_explainable_attack_path(
    project_id: str,
    path_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Retrieve specific explainable attack path by deterministic fingerprint ID.
    """
    verify_project_access(project_id, current_user, db)
    path = db.query(ExplainableAttackPathRecord).filter(
        ExplainableAttackPathRecord.id == path_id,
        ExplainableAttackPathRecord.project_id == project_id,
    ).first()
    if not path:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Attack path '{path_id}' not found.")
    return path


@router.post("/projects/{project_id}/knowledge/reconcile", response_model=KnowledgeReconciliationAuditRead)
def trigger_knowledge_reconciliation(
    project_id: str,
    req: ReconciliationTriggerRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Execute knowledge graph reconciliation audit and repair.
    Requires Project LEAD or System ADMIN.
    """
    verify_project_access(
        project_id,
        current_user,
        db,
        required_project_roles=[ProjectRole.LEAD],
    )
    audit = KnowledgeReconciliationService.audit_and_reconcile(
        db=db,
        project_id=project_id,
        auto_repair=req.auto_repair,
        run_by_user_id=current_user.id,
    )
    return audit


@router.get("/projects/{project_id}/knowledge/reconcile/audits", response_model=List[KnowledgeReconciliationAuditRead])
def list_reconciliation_audits(
    project_id: str,
    limit: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    List historical knowledge graph reconciliation audits.
    """
    verify_project_access(project_id, current_user, db)
    return (
        db.query(KnowledgeReconciliationAudit)
        .filter(KnowledgeReconciliationAudit.project_id == project_id)
        .order_by(desc(KnowledgeReconciliationAudit.started_at))
        .limit(limit)
        .all()
    )


@router.get("/projects/{project_id}/knowledge/reconcile/audits/{audit_id}", response_model=KnowledgeReconciliationAuditRead)
def get_reconciliation_audit(
    project_id: str,
    audit_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Retrieve specific knowledge reconciliation audit report.
    """
    verify_project_access(project_id, current_user, db)
    audit = db.query(KnowledgeReconciliationAudit).filter(
        KnowledgeReconciliationAudit.id == audit_id,
        KnowledgeReconciliationAudit.project_id == project_id,
    ).first()
    if not audit:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Reconciliation audit '{audit_id}' not found.")
    return audit


@router.get("/projects/{project_id}/knowledge/explain/finding/{finding_id}", response_model=FindingEpistemicExplanation)
def explain_finding_epistemic_history(
    project_id: str,
    finding_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Returns full epistemic explanation of a finding: evidence chain, validation history,
    contextual risk delta breakdown, dependent attack paths, and active dependencies (Prompt 21).
    """
    verify_project_access(project_id, current_user, db)
    finding = db.query(VulnerabilityFinding).filter(
        VulnerabilityFinding.id == finding_id,
        VulnerabilityFinding.project_id == project_id,
    ).first()
    if not finding:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Finding '{finding_id}' not found.")

    # Contextual risk
    risk = db.query(RiskAssessment).filter(
        RiskAssessment.finding_id == finding_id,
        RiskAssessment.is_superseded.is_(False),
    ).order_by(desc(RiskAssessment.calculated_at)).first()

    risk_data = None
    if risk:
        risk_data = {
            "score": risk.score,
            "inherent_score": risk.inherent_score,
            "residual_score": risk.residual_score,
            "priority": risk.priority.value if hasattr(risk.priority, "value") else str(risk.priority),
            "scoring_version": risk.scoring_version,
            "prior_score": getattr(risk, "prior_score", None),
            "score_delta": getattr(risk, "score_delta", None),
            "delta_reasons": getattr(risk, "delta_reasons", []),
            "qualitative_label": getattr(risk, "qualitative_label", "CALCULATED"),
            "unverified_penalty": getattr(risk, "unverified_penalty", 0.0),
            "is_invalidated": getattr(risk, "is_invalidated", False),
            "invalidation_reason": getattr(risk, "invalidation_reason", None),
            "contributing_factors": risk.contributing_factors or [],
            "missing_factors": risk.missing_factors or [],
            "uncertainty_range": risk.uncertainty_range or {},
        }

    # Dependencies
    deps = db.query(KnowledgeDependencyRecord).filter(
        KnowledgeDependencyRecord.project_id == project_id,
        KnowledgeDependencyRecord.source_entity_type == "Finding",
        KnowledgeDependencyRecord.source_entity_id == finding_id,
    ).all()

    # Evidence items
    evidence_list = []
    for raw in getattr(finding, "raw_findings", []):
        for ev in getattr(raw, "evidence_items", []):
            evidence_list.append({
                "id": ev.id,
                "evidence_type": ev.evidence_type.value if hasattr(ev.evidence_type, "value") else str(ev.evidence_type),
                "sha256": ev.sha256_hash,
                "is_valid": ev.is_valid,
                "is_simulated": getattr(ev, "is_simulated", False),
                "created_at": ev.created_at.isoformat() if ev.created_at else None,
            })

    # Validation transitions
    val_history = []
    for vt in getattr(finding, "validation_transitions", []):
        val_history.append({
            "from_status": vt.from_validation_status,
            "to_status": vt.to_validation_status,
            "method": vt.validation_method,
            "reason": vt.validation_reason,
            "timestamp": vt.created_at.isoformat() if vt.created_at else None,
        })

    return FindingEpistemicExplanation(
        finding_id=finding.id,
        title=finding.title,
        severity=finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity),
        lifecycle_status=finding.status.value if hasattr(finding.status, "value") else str(finding.status),
        validation_status=finding.validation_status.value if hasattr(finding.validation_status, "value") else str(finding.validation_status),
        confidence=finding.confidence.value if hasattr(finding.confidence, "value") else str(finding.confidence),
        epistemic_status=getattr(finding, "epistemic_status", "OBSERVED_FACT"),
        is_authoritative=True,
        is_simulated=False,
        evidence_items=evidence_list,
        validation_history=val_history,
        contextual_risk=risk_data,
        dependencies=[KnowledgeDependencyRead.model_validate(d) for d in deps],
    )


@router.get("/projects/{project_id}/knowledge/explain/relationship/{rel_id}", response_model=RelationshipEpistemicExplanation)
def explain_relationship_epistemic_details(
    project_id: str,
    rel_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Returns full epistemic explanation of a graph relationship (provenance, confidence,
    corroboration, assumptions, and invalidation triggers).
    """
    verify_project_access(project_id, current_user, db)
    rel = db.query(GraphRelationship).filter(
        GraphRelationship.id == rel_id,
        GraphRelationship.project_id == project_id,
    ).first()
    if not rel:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Relationship '{rel_id}' not found.")

    src = db.query(GraphNode).filter(GraphNode.id == rel.source_node_id).first()
    tgt = db.query(GraphNode).filter(GraphNode.id == rel.target_node_id).first()

    src_label = src.label if src else rel.source_node_id[:8]
    tgt_label = tgt.label if tgt else rel.target_node_id[:8]

    assumptions = [
        f"Assumes service on '{src_label}' remains active and reachable over '{rel.relationship_type.value}'.",
        f"Assumes target '{tgt_label}' maintains valid network configuration.",
    ]
    unverified = []
    if rel.confidence < 0.8:
        unverified.append(f"Confidence is below 0.80 ({rel.confidence:.2f}); reachability not confirmed.")
    if not getattr(rel, "is_authoritative", True):
        unverified.append("Relationship derived from non-authoritative AI/prose summary.")
    if not rel.evidence_reference:
        unverified.append("No cryptographic evidence reference attached.")

    invalidation_triggers = [
        f"Decommissioning service on '{src_label}' will break this relationship.",
        f"Altering network policy or firewall rules between '{src_label}' and '{tgt_label}' will invalidate this edge.",
    ]

    return RelationshipEpistemicExplanation(
        relationship_id=rel.id,
        source_node={"id": rel.source_node_id, "label": src_label, "category": src.category.value if src else "UNKNOWN"},
        target_node={"id": rel.target_node_id, "label": tgt_label, "category": tgt.category.value if tgt else "UNKNOWN"},
        relationship_type=rel.relationship_type.value,
        status=rel.status.value,
        epistemic_status=getattr(rel, "epistemic_status", rel.status.value),
        confidence=rel.confidence,
        is_authoritative=getattr(rel, "is_authoritative", True),
        is_simulated=getattr(rel, "is_simulated", False),
        provenance=rel.provenance,
        evidence_reference=rel.evidence_reference,
        derivation_rule=getattr(rel, "derivation_rule", None),
        required_assumptions=assumptions,
        unverified_conditions=unverified,
        invalidation_triggers=invalidation_triggers,
        verification_history=list(rel.verification_history or []),
    )
