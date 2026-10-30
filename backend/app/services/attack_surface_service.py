"""
Authorized Attack-Surface Inventory and Exposure Governance Service (Prompt 46).
Manages external attack surface tracking, service & certificate exposures,
strict anti-expansion boundaries, discovery inclusion approval workflows,
provenance tracking, and change intelligence.
"""
import hashlib
import json
import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional, Tuple
from sqlalchemy.orm import Session
from sqlalchemy import desc, and_, or_

from app.models.attack_surface import (
    ExposureClassification,
    ObservationProvenanceType,
    ExposureFreshness,
    ProposalStatus,
    AttackSurfaceExposure,
    AssetInclusionProposal,
)
from app.models.asset import Asset, AssetObservation, AssetType, AssetStatus
from app.models.scope import ScopeTarget, TargetType, AuthorizationStatus
from app.models.project import Project
from app.models.user import User
from app.models.base import utc_now
from app.services.scope_engine import ScopeEngine
from app.services.notification_service import NotificationService
from app.models.notification import NotificationEventType, NotificationSeverity

from sqlalchemy.orm.attributes import flag_modified

logger = logging.getLogger("vapt.attack_surface")


class AttackSurfaceService:
    """
    Core engine for authorized attack-surface inventory and exposure governance.
    Enforces strict preflight scope boundaries, anti-expansion guards,
    provenance classification, deduplication, and change detection.
    """

    @classmethod
    def compute_dedup_hash(
        cls,
        project_id: str,
        canonical_identifier: str,
        port: int,
        protocol: str,
    ) -> str:
        """
        Computes a deterministic SHA-256 fingerprint for unique exposure identification.
        """
        raw_key = f"{project_id.strip()}:{canonical_identifier.strip().lower()}:{port}:{protocol.strip().lower()}"
        return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()

    @classmethod
    def ingest_exposure_observation(
        cls,
        db: Session,
        project_id: str,
        asset_id: str,
        canonical_identifier: str,
        service_name: str = "unknown",
        port: int = 0,
        protocol: str = "tcp",
        transport_security: str = "PLAINTEXT",
        certificate_details: Optional[Dict[str, Any]] = None,
        relevant_hostnames: Optional[List[str]] = None,
        exposure_classification: ExposureClassification = ExposureClassification.INTERNET_FACING,
        provenance_type: ObservationProvenanceType = ObservationProvenanceType.VERIFIED_OBSERVATION,
        evidence_hash: Optional[str] = None,
        attributes: Optional[Dict[str, Any]] = None,
        is_simulated: bool = False,
        now: Optional[datetime] = None,
    ) -> Tuple[Optional[AttackSurfaceExposure], Optional[AssetInclusionProposal], List[str]]:
        """
        Ingests an external exposure observation for an asset.
        1. Preflight Scope Revalidation: Enforces strict boundary check.
           - If target is out of scope or excluded, routes to AssetInclusionProposal (Anti-expansion guard).
        2. Deduplication & Historical Tracking:
           - Updates observation counts, freshness, and evidence digests without erasing history.
        3. Change Detection:
           - Discovers service additions, cert renewals, and hostname mappings.
        """
        if now is None:
            now = utc_now()
        detected_changes: List[str] = []
        cert_data = certificate_details or {}
        hostnames = relevant_hostnames or []
        attrs = attributes or {}

        # ----------------------------------------------------------------------
        # 1. Preflight Scope Authorization & Anti-Expansion Guard (Req 6 & 7)
        # ----------------------------------------------------------------------
        scope_eval = ScopeEngine.validate_target_in_scope(
            db=db,
            project_id=project_id,
            target=canonical_identifier,
            now=now,
        )

        if not scope_eval.get("is_authorized", False):
            # Anti-Expansion Guard: Newly discovered asset CANNOT automatically expand scope
            logger.warning(
                f"Anti-expansion guard triggered: Target '{canonical_identifier}' is not authorized. Routing to proposal inbox."
            )
            proposal = cls.propose_discovered_asset(
                db=db,
                project_id=project_id,
                target_value=canonical_identifier,
                discovery_source=f"PASSIVE_OBSERVATION_{service_name.upper()}",
                provenance_type=provenance_type,
                evidence_hash=evidence_hash,
                rationale=f"Observed on port {port}/{protocol}. Scope validation reason: {scope_eval.get('reason')}",
                is_simulated=is_simulated,
                now=now,
            )
            return None, proposal, ["UNAUTHORIZED_TARGET_PROPOSED_FOR_INCLUSION"]

        # Ensure asset exists in project
        asset = db.query(Asset).filter(Asset.id == asset_id, Asset.project_id == project_id).first()
        if not asset:
            # Look up by canonical identifier
            asset = db.query(Asset).filter(
                Asset.project_id == project_id,
                Asset.canonical_identifier == canonical_identifier,
            ).first()
            if not asset:
                raise ValueError(f"Asset '{asset_id}' or canonical identifier '{canonical_identifier}' not found in project.")

        cert_fp = cert_data.get("fingerprint_sha256")
        dedup_hash = cls.compute_dedup_hash(
            project_id=project_id,
            canonical_identifier=canonical_identifier,
            port=port,
            protocol=protocol,
        )

        # ----------------------------------------------------------------------
        # 2. Query Existing Exposure Point (Deduplication without data loss)
        # ----------------------------------------------------------------------
        exposure = db.query(AttackSurfaceExposure).filter(
            AttackSurfaceExposure.project_id == project_id,
            AttackSurfaceExposure.dedup_hash == dedup_hash,
        ).first()

        if exposure:
            # Check for meaningful changes against previous state
            if exposure.transport_security != transport_security:
                detected_changes.append(f"TRANSPORT_SECURITY_CHANGED: {exposure.transport_security} -> {transport_security}")

            # Check certificate changes
            prev_cert_fp = (exposure.certificate_details or {}).get("fingerprint_sha256")
            if cert_fp and prev_cert_fp and cert_fp != prev_cert_fp:
                detected_changes.append(f"CHANGED_CERTIFICATE: fingerprint renewed {prev_cert_fp[:8]}... -> {cert_fp[:8]}...")

            # Check new hostname mappings
            existing_hostnames = list(exposure.relevant_hostnames or [])
            for h in hostnames:
                if h not in existing_hostnames:
                    detected_changes.append(f"CHANGED_HOSTNAME_ASSOCIATION: Added hostname '{h}'")
                    existing_hostnames.append(h)
            exposure.relevant_hostnames = existing_hostnames

            # Update observation telemetry
            exposure.last_observed_at = now
            exposure.observation_count += 1
            exposure.consecutive_absences = 0
            exposure.freshness = ExposureFreshness.FRESH
            exposure.transport_security = transport_security
            exposure.certificate_details = cert_data
            
            merged_attrs = dict(exposure.attributes or {})
            merged_attrs.update(attrs)
            exposure.attributes = merged_attrs

            merged_hashes = list(exposure.evidence_hashes or [])
            if evidence_hash and evidence_hash not in merged_hashes:
                merged_hashes.append(evidence_hash)
            exposure.evidence_hashes = merged_hashes

            flag_modified(exposure, "attributes")
            flag_modified(exposure, "evidence_hashes")
            flag_modified(exposure, "relevant_hostnames")
            flag_modified(exposure, "certificate_details")

            db.commit()
            db.refresh(exposure)

        else:
            # ------------------------------------------------------------------
            # 3. Create New Attack Surface Exposure
            # ------------------------------------------------------------------
            detected_changes.append(f"NEW_SERVICE: Discovered {service_name} on {canonical_identifier}:{port}/{protocol}")
            evidence_list = [evidence_hash] if evidence_hash else []

            exposure = AttackSurfaceExposure(
                project_id=project_id,
                asset_id=asset.id,
                canonical_identifier=canonical_identifier,
                service_name=service_name,
                port=port,
                protocol=protocol,
                transport_security=transport_security,
                certificate_details=cert_data,
                relevant_hostnames=hostnames,
                exposure_classification=exposure_classification,
                provenance_type=provenance_type,
                freshness=ExposureFreshness.FRESH,
                is_authorized=True,
                first_observed_at=now,
                last_observed_at=now,
                consecutive_absences=0,
                observation_count=1,
                evidence_hashes=evidence_list,
                dedup_hash=dedup_hash,
                attributes=attrs,
            )
            db.add(exposure)
            db.commit()
            db.refresh(exposure)

        # ----------------------------------------------------------------------
        # 4. Alert Integration on Material Changes
        # ----------------------------------------------------------------------
        if detected_changes and not is_simulated:
            for change in detected_changes:
                if "CHANGED_CERTIFICATE" in change or "NEW_SERVICE" in change:
                    try:
                        NotificationService.create_notification(
                            db=db,
                            project_id=project_id,
                            event_type=NotificationEventType.FINDING_DISCOVERED.value,
                            severity=NotificationSeverity.HIGH.value,
                            title=f"Attack Surface Change: {canonical_identifier}:{port}",
                            summary=change,
                            payload={
                                "canonical_identifier": canonical_identifier,
                                "port": port,
                                "protocol": protocol,
                                "change": change,
                                "exposure_id": exposure.id,
                            },
                        )
                    except Exception as e:
                        logger.warning(f"Failed to emit attack surface change notification: {e}")

        return exposure, None, detected_changes

    @classmethod
    def record_exposure_absence(
        cls,
        db: Session,
        project_id: str,
        canonical_identifier: str,
        port: int,
        protocol: str = "tcp",
    ) -> Optional[AttackSurfaceExposure]:
        """
        Records an absence during an assessment run.
        Increments consecutive_absences and updates freshness without falsely declaring
        that the endpoint was removed or decommissioned.
        """
        exposures = db.query(AttackSurfaceExposure).filter(
            AttackSurfaceExposure.project_id == project_id,
            AttackSurfaceExposure.canonical_identifier == canonical_identifier,
            AttackSurfaceExposure.port == port,
            AttackSurfaceExposure.protocol == protocol,
        ).all()

        if not exposures:
            return None

        for exp in exposures:
            exp.consecutive_absences += 1
            if exp.consecutive_absences >= 3:
                # Distinguish disappearance from confirmed removal (Req 5)
                exp.freshness = ExposureFreshness.UNVERIFIED_ABSENT
            elif exp.consecutive_absences >= 1:
                exp.freshness = ExposureFreshness.AGING

        db.commit()
        return exposures[0]

    @classmethod
    def propose_discovered_asset(
        cls,
        db: Session,
        project_id: str,
        target_value: str,
        discovery_source: str,
        provenance_type: ObservationProvenanceType = ObservationProvenanceType.INFERRED_RELATIONSHIP,
        evidence_hash: Optional[str] = None,
        rationale: Optional[str] = None,
        is_simulated: bool = False,
        now: Optional[datetime] = None,
    ) -> AssetInclusionProposal:
        """
        Creates an explicit proposal for adding a newly discovered endpoint or subdomain into scope.
        Idempotent: returns existing proposal if already pending.
        """
        if now is None:
            now = utc_now()
        norm_val = target_value.strip().lower()

        existing = db.query(AssetInclusionProposal).filter(
            AssetInclusionProposal.project_id == project_id,
            AssetInclusionProposal.target_value == norm_val,
        ).first()

        if existing:
            return existing

        # Infer target type
        if "/" in norm_val and not norm_val.startswith("http"):
            t_type = TargetType.CIDR
        elif norm_val.startswith("http://") or norm_val.startswith("https://"):
            t_type = TargetType.URL
        elif any(c.isalpha() for c in norm_val):
            t_type = TargetType.DOMAIN
        else:
            t_type = TargetType.IP_ADDRESS

        proposal = AssetInclusionProposal(
            project_id=project_id,
            target_type=t_type,
            target_value=norm_val,
            discovery_source=discovery_source,
            provenance_type=provenance_type,
            status=ProposalStatus.PENDING,
            rationale=rationale or f"Discovered via {discovery_source}",
            discovered_at=now,
            evidence_hash=evidence_hash,
            is_simulated=is_simulated,
        )
        db.add(proposal)
        db.commit()
        db.refresh(proposal)
        return proposal

    @classmethod
    def approve_inclusion_proposal(
        cls,
        db: Session,
        project_id: str,
        proposal_id: str,
        reviewer: User,
        approval_notes: str,
        authorized_evidence: str,
    ) -> Tuple[AssetInclusionProposal, ScopeTarget]:
        """
        Approves a discovered asset inclusion proposal.
        Atomically creates an AUTHORIZED ScopeTarget and corresponding Asset.
        """
        now = utc_now()
        proposal = db.query(AssetInclusionProposal).filter(
            AssetInclusionProposal.id == proposal_id,
            AssetInclusionProposal.project_id == project_id,
        ).first()

        if not proposal:
            raise ValueError(f"Inclusion proposal '{proposal_id}' not found")

        if proposal.status != ProposalStatus.PENDING:
            raise ValueError(f"Proposal '{proposal_id}' is already {proposal.status.value}")

        # 1. Create ScopeTarget
        scope_target = ScopeTarget(
            project_id=project_id,
            target_type=proposal.target_type,
            target_value=proposal.target_value,
            description=f"Approved discovery from {proposal.discovery_source}",
            authorization_status=AuthorizationStatus.AUTHORIZED,
            authorization_evidence=authorized_evidence,
            authorized_by_id=reviewer.id,
            authorized_at=now,
            created_by_id=reviewer.id,
        )
        db.add(scope_target)
        db.commit()
        db.refresh(scope_target)

        # 2. Create or activate Asset
        existing_asset = db.query(Asset).filter(
            Asset.project_id == project_id,
            Asset.canonical_identifier == proposal.target_value,
        ).first()

        if not existing_asset:
            proj = db.query(Project).filter(Project.id == project_id).first()
            org_id = proj.organization_id if proj and proj.organization_id else "default-org"
            asset_type = AssetType.DOMAIN if proposal.target_type == TargetType.DOMAIN else AssetType.HOST
            new_asset = Asset(
                organization_id=org_id,
                project_id=project_id,
                asset_type=asset_type,
                name=proposal.target_value,
                canonical_identifier=proposal.target_value,
                environment="PRODUCTION",
                status=AssetStatus.ACTIVE,
                source="APPROVED_DISCOVERY",
                confidence=1.0,
            )
            db.add(new_asset)
            db.commit()

        # 3. Update proposal state
        proposal.status = ProposalStatus.APPROVED
        proposal.reviewed_by_id = reviewer.id
        proposal.reviewed_at = now
        proposal.approval_notes = approval_notes
        proposal.resulting_scope_target_id = scope_target.id

        db.commit()
        db.refresh(proposal)
        return proposal, scope_target

    @classmethod
    def reject_inclusion_proposal(
        cls,
        db: Session,
        project_id: str,
        proposal_id: str,
        reviewer: User,
        rejection_reason: str,
    ) -> AssetInclusionProposal:
        """
        Rejects a discovered asset inclusion proposal. Prevents further assessment probes.
        """
        now = utc_now()
        proposal = db.query(AssetInclusionProposal).filter(
            AssetInclusionProposal.id == proposal_id,
            AssetInclusionProposal.project_id == project_id,
        ).first()

        if not proposal:
            raise ValueError(f"Inclusion proposal '{proposal_id}' not found")

        if proposal.status != ProposalStatus.PENDING:
            raise ValueError(f"Proposal '{proposal_id}' is already {proposal.status.value}")

        proposal.status = ProposalStatus.REJECTED
        proposal.reviewed_by_id = reviewer.id
        proposal.reviewed_at = now
        proposal.approval_notes = f"REJECTED: {rejection_reason}"

        db.commit()
        db.refresh(proposal)
        return proposal

    @classmethod
    def list_proposals(
        cls,
        db: Session,
        project_id: str,
        status_filter: Optional[ProposalStatus] = None,
    ) -> List[AssetInclusionProposal]:
        query = db.query(AssetInclusionProposal).filter(AssetInclusionProposal.project_id == project_id)
        if status_filter:
            query = query.filter(AssetInclusionProposal.status == status_filter)
        return query.order_by(AssetInclusionProposal.discovered_at.desc()).all()

    @classmethod
    def get_inventory(
        cls,
        db: Session,
        project_id: str,
        classification: Optional[ExposureClassification] = None,
        freshness: Optional[ExposureFreshness] = None,
        search: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Queries attack surface exposures with filtering and summary metrics.
        """
        query = db.query(AttackSurfaceExposure).filter(AttackSurfaceExposure.project_id == project_id)

        if classification:
            query = query.filter(AttackSurfaceExposure.exposure_classification == classification)
        if freshness:
            query = query.filter(AttackSurfaceExposure.freshness == freshness)
        if search:
            query = query.filter(AttackSurfaceExposure.canonical_identifier.ilike(f"%{search}%"))

        items = query.order_by(AttackSurfaceExposure.last_observed_at.desc()).all()

        all_items = db.query(AttackSurfaceExposure).filter(AttackSurfaceExposure.project_id == project_id).all()
        internet = sum(1 for i in all_items if i.exposure_classification == ExposureClassification.INTERNET_FACING)
        internal = sum(1 for i in all_items if i.exposure_classification == ExposureClassification.INTERNAL_RESTRICTED)
        cloud = sum(1 for i in all_items if i.exposure_classification == ExposureClassification.CLOUD_EDGE)
        fresh = sum(1 for i in all_items if i.freshness == ExposureFreshness.FRESH)
        stale = sum(1 for i in all_items if i.freshness == ExposureFreshness.STALE)
        absent = sum(1 for i in all_items if i.freshness == ExposureFreshness.UNVERIFIED_ABSENT)

        return {
            "project_id": project_id,
            "total_exposures": len(items),
            "internet_facing_count": internet,
            "internal_restricted_count": internal,
            "cloud_edge_count": cloud,
            "fresh_count": fresh,
            "stale_count": stale,
            "unverified_absent_count": absent,
            "items": items,
        }

    @classmethod
    def get_timeline(
        cls,
        db: Session,
        project_id: str,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        """
        Builds a chronological timeline of exposure observations, certificate updates, and service changes.
        """
        exposures = (
            db.query(AttackSurfaceExposure)
            .filter(AttackSurfaceExposure.project_id == project_id)
            .order_by(AttackSurfaceExposure.last_observed_at.desc())
            .limit(limit)
            .all()
        )

        events = []
        for exp in exposures:
            event_type = "NEW_EXPOSURE" if exp.observation_count == 1 else "OBSERVATION_REFRESH"
            if exp.freshness == ExposureFreshness.UNVERIFIED_ABSENT:
                event_type = "EXPOSURE_ABSENCE"

            events.append({
                "event_id": f"evt-{exp.id}-{int(exp.last_observed_at.timestamp())}",
                "event_type": event_type,
                "occurred_at": exp.last_observed_at,
                "canonical_identifier": exp.canonical_identifier,
                "port": exp.port,
                "protocol": exp.protocol,
                "title": f"{exp.service_name.upper()} on {exp.canonical_identifier}:{exp.port}",
                "details": {
                    "transport_security": exp.transport_security,
                    "freshness": exp.freshness.value,
                    "observation_count": exp.observation_count,
                    "consecutive_absences": exp.consecutive_absences,
                },
                "provenance_type": exp.provenance_type.value,
                "evidence_hash": exp.evidence_hashes[-1] if exp.evidence_hashes else None,
            })

        return events

    @classmethod
    def get_asset_exposure_evidence(
        cls,
        db: Session,
        project_id: str,
        asset_id: str,
    ) -> Dict[str, Any]:
        """
        Returns an asset-level evidence breakdown including active services, certificates,
        hostnames, and raw evidence digests.
        """
        asset = db.query(Asset).filter(Asset.id == asset_id, Asset.project_id == project_id).first()
        if not asset:
            raise ValueError(f"Asset '{asset_id}' not found")

        exposures = db.query(AttackSurfaceExposure).filter(
            AttackSurfaceExposure.project_id == project_id,
            AttackSurfaceExposure.asset_id == asset_id,
        ).all()

        services = []
        certificates = []
        hostnames = set()
        evidence_hashes = set()

        for exp in exposures:
            services.append({
                "service_name": exp.service_name,
                "port": exp.port,
                "protocol": exp.protocol,
                "transport_security": exp.transport_security,
                "freshness": exp.freshness.value,
                "last_observed_at": exp.last_observed_at.isoformat(),
            })
            if exp.certificate_details:
                certificates.append(exp.certificate_details)
            for h in exp.relevant_hostnames:
                hostnames.add(h)
            for hsh in exp.evidence_hashes:
                evidence_hashes.add(hsh)

        return {
            "project_id": project_id,
            "asset_id": asset_id,
            "canonical_identifier": asset.canonical_identifier,
            "is_authorized": True,
            "freshness": asset.freshness_status,
            "total_observations": len(exposures),
            "active_services": services,
            "tls_certificates": certificates,
            "associated_hostnames": sorted(list(hostnames)),
            "evidence_digests": sorted(list(evidence_hashes)),
            "last_observed_at": asset.last_successful_observation_at or asset.last_seen_at,
        }
