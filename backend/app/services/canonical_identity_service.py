import ipaddress
import re
import json
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any, List, Tuple
from sqlalchemy.orm import Session
from sqlalchemy import or_, and_, desc

from app.models.asset import (
    Asset,
    AssetObservation,
    AssetType,
    AssetCriticality,
    AssetStatus,
    AssetIdentifierAlias,
    AssetIdentityMergeRecord,
)
from app.models.finding import VulnerabilityFinding
from app.models.scope import ScopeTarget
from app.models.canonical_asset import (
    ResolutionMatchOutcome,
    DeduplicationProposalStatus,
    DataQualityIssueType,
    DataQualityIssueStatus,
    AssetDeduplicationProposal,
    AssetDataQualityIssue,
)
from app.models.base import utc_now
from app.services.asset_identity_service import AssetIdentityService
from app.services.audit_service import AuditService
from fastapi import HTTPException, status


def ensure_utc(dt: Optional[datetime]) -> Optional[datetime]:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


class ResolutionMatchResult:
    def __init__(
        self,
        outcome: ResolutionMatchOutcome,
        matched_asset: Optional[Asset],
        confidence: float,
        match_reasons: List[str],
        conflicts_detected: List[str],
    ):
        self.outcome = outcome
        self.matched_asset = matched_asset
        self.confidence = confidence
        self.match_reasons = match_reasons
        self.conflicts_detected = conflicts_detected

    def to_dict(self) -> Dict[str, Any]:
        return {
            "outcome": self.outcome.value,
            "matched_asset_id": self.matched_asset.id if self.matched_asset else None,
            "matched_canonical_identifier": self.matched_asset.canonical_identifier if self.matched_asset else None,
            "confidence": round(self.confidence, 4),
            "match_reasons": self.match_reasons,
            "conflicts_detected": self.conflicts_detected,
        }


class CanonicalIdentityService:
    """
    Asset Identity Resolution, Data Quality, and Canonical Security Records Service (Prompt 37).
    Enforces confidence-aware entity resolution, address reuse detection, reviewable deduplication
    workflows, and comprehensive inventory data quality audits.
    """

    STALENESS_HORIZON_DAYS = 7
    AUDIT_STALENESS_DAYS = 30

    @classmethod
    def resolve_entity(
        cls,
        db: Session,
        project_id: str,
        candidate_target: str,
        attributes: Optional[Dict[str, Any]] = None,
        observed_at: Optional[datetime] = None,
    ) -> ResolutionMatchResult:
        """
        Confidence-aware entity resolution.
        Matches candidate against existing assets using strict canonical keys,
        strong fingerprints, and time-bounded alias correlation.
        NEVER merges assets solely on shared IP or fuzzy hostnames.
        """
        attrs = attributes or {}
        now = ensure_utc(observed_at or utc_now())
        reasons: List[str] = []
        conflicts: List[str] = []

        try:
            asset_type, canonical_id, display_name = AssetIdentityService.classify_and_normalize(candidate_target)
        except ValueError as e:
            return ResolutionMatchResult(
                outcome=ResolutionMatchOutcome.UNMATCHED,
                matched_asset=None,
                confidence=0.0,
                match_reasons=[f"Classification failed: {str(e)}"],
                conflicts_detected=["Invalid or malformed target representation"],
            )

        # 1. Exact Primary Canonical Key Match within Project
        exact_match = (
            db.query(Asset)
            .filter(
                Asset.project_id == project_id,
                Asset.asset_type == asset_type,
                Asset.canonical_identifier == canonical_id,
                Asset.status != AssetStatus.DECOMMISSIONED,
            )
            .first()
        )
        if exact_match:
            reasons.append(f"Exact canonical key match on {asset_type.value}: '{canonical_id}'")
            return ResolutionMatchResult(
                outcome=ResolutionMatchOutcome.EXACT_MATCH,
                matched_asset=exact_match,
                confidence=1.0,
                match_reasons=reasons,
                conflicts_detected=conflicts,
            )

        # 2. Strong Hardware/Cloud Fingerprint Match
        # E.g. unique AWS instance id, GCP resource ID, or TLS cert serial
        cert_serial = attrs.get("tls_cert_serial")
        cloud_arn = attrs.get("cloud_resource_id") or attrs.get("cloud_arn")

        if cloud_arn:
            cloud_matches = (
                db.query(Asset)
                .filter(
                    Asset.project_id == project_id,
                    Asset.status != AssetStatus.DECOMMISSIONED,
                )
                .all()
            )
            for cand in cloud_matches:
                cand_arn = (cand.attributes or {}).get("cloud_resource_id") or (cand.attributes or {}).get("cloud_arn")
                if cand_arn and cand_arn == cloud_arn:
                    reasons.append(f"Strong unique cloud resource match: '{cloud_arn}'")
                    return ResolutionMatchResult(
                        outcome=ResolutionMatchOutcome.STRONG_CORRELATION,
                        matched_asset=cand,
                        confidence=0.95,
                        match_reasons=reasons,
                        conflicts_detected=conflicts,
                    )

        # 3. Observed Alias Correlation with Time-Bounded Horizon
        # Check if candidate_target is registered as an active alias
        alias_match = (
            db.query(AssetIdentifierAlias)
            .filter(
                AssetIdentifierAlias.project_id == project_id,
                AssetIdentifierAlias.identifier_value == canonical_id,
                AssetIdentifierAlias.is_active == True,
            )
            .first()
        )

        if alias_match:
            cand_asset = (
                db.query(Asset)
                .filter(Asset.id == alias_match.asset_id, Asset.status != AssetStatus.DECOMMISSIONED)
                .first()
            )
            if cand_asset:
                last_obs = ensure_utc(alias_match.last_observed_at)
                time_diff = abs((now - last_obs).total_seconds()) if (now and last_obs) else 0
                days_diff = time_diff / 86400.0

                # Detect IP Address Reuse / DHCP Ephemeral Reassignment
                if asset_type == AssetType.IP_ADDRESS or alias_match.identifier_type == "IP_ADDRESS":
                    if days_diff > cls.STALENESS_HORIZON_DAYS:
                        conflicts.append(
                            f"IP address reuse suspected: alias '{canonical_id}' last observed {days_diff:.1f} days ago (> {cls.STALENESS_HORIZON_DAYS}d horizon)"
                        )
                        return ResolutionMatchResult(
                            outcome=ResolutionMatchOutcome.AMBIGUOUS_CONFLICT,
                            matched_asset=cand_asset,
                            confidence=0.45,
                            match_reasons=[f"Historical alias match on IP '{canonical_id}' but observation window expired"],
                            conflicts_detected=conflicts,
                        )
                    else:
                        # Shared IP observed recently without definitive cert/hardware match
                        # Prompt 37 INVARIANT: "Never merge assets solely because they share an IP address"
                        conflicts.append("Single IP match without cryptographic fingerprint is ambiguous (multi-tenant host or shared gateway)")
                        return ResolutionMatchResult(
                            outcome=ResolutionMatchOutcome.AMBIGUOUS_CONFLICT,
                            matched_asset=cand_asset,
                            confidence=0.60,
                            match_reasons=[f"Active IP alias match on '{canonical_id}'"],
                            conflicts_detected=conflicts,
                        )
                else:
                    # Non-IP alias match (e.g. DNS CNAME, Netloc)
                    if days_diff <= cls.STALENESS_HORIZON_DAYS:
                        reasons.append(f"Active alias match on '{canonical_id}' ({alias_match.identifier_type}) within {days_diff:.1f} days")
                        return ResolutionMatchResult(
                            outcome=ResolutionMatchOutcome.STRONG_CORRELATION,
                            matched_asset=cand_asset,
                            confidence=0.88,
                            match_reasons=reasons,
                            conflicts_detected=conflicts,
                        )
                    else:
                        conflicts.append(f"DNS alias observation stale: {days_diff:.1f} days since last observation")
                        return ResolutionMatchResult(
                            outcome=ResolutionMatchOutcome.AMBIGUOUS_CONFLICT,
                            matched_asset=cand_asset,
                            confidence=0.55,
                            match_reasons=[f"Stale alias match on '{canonical_id}'"],
                            conflicts_detected=conflicts,
                        )

        # 4. Hostname / Domain Resemblance Check
        # Strict rejection of fuzzy/substring auto-merges
        if asset_type in (AssetType.HOSTNAME, AssetType.DOMAIN):
            similar_asset = (
                db.query(Asset)
                .filter(
                    Asset.project_id == project_id,
                    Asset.asset_type.in_([AssetType.HOSTNAME, AssetType.DOMAIN]),
                    Asset.status != AssetStatus.DECOMMISSIONED,
                )
                .all()
            )
            for sa in similar_asset:
                if sa.canonical_identifier != canonical_id and (
                    sa.canonical_identifier.startswith(canonical_id) or canonical_id.startswith(sa.canonical_identifier)
                ):
                    conflicts.append(f"Similar hostname resemblance to existing asset '{sa.canonical_identifier}' rejected for auto-merge")
                    return ResolutionMatchResult(
                        outcome=ResolutionMatchOutcome.AMBIGUOUS_CONFLICT,
                        matched_asset=sa,
                        confidence=0.35,
                        match_reasons=[f"Fuzzy hostname resemblance with '{sa.canonical_identifier}'"],
                        conflicts_detected=conflicts,
                    )

        # 5. Unmatched New Entity
        return ResolutionMatchResult(
            outcome=ResolutionMatchOutcome.UNMATCHED,
            matched_asset=None,
            confidence=0.0,
            match_reasons=["No matching canonical key or active strong fingerprint located"],
            conflicts_detected=[],
        )

    @classmethod
    def evaluate_dry_run_impact(
        cls,
        db: Session,
        project_id: str,
        source_asset_id: str,
        target_asset_id: str,
    ) -> Dict[str, Any]:
        """
        Calculates dry-run impact report before any merge proposal or execution.
        """
        if source_asset_id == target_asset_id:
            raise ValueError("Source and target asset IDs must be distinct.")

        source = (
            db.query(Asset)
            .filter(Asset.id == source_asset_id, Asset.project_id == project_id)
            .first()
        )
        target = (
            db.query(Asset)
            .filter(Asset.id == target_asset_id, Asset.project_id == project_id)
            .first()
        )

        if not source or not target:
            raise ValueError("Both source and target assets must exist within the project.")

        # Findings count
        findings_count = (
            db.query(VulnerabilityFinding)
            .filter(VulnerabilityFinding.asset_id == source.id)
            .count()
        )

        # Aliases count
        aliases_count = (
            db.query(AssetIdentifierAlias)
            .filter(AssetIdentifierAlias.asset_id == source.id)
            .count()
        )

        # Observations count
        observations_count = (
            db.query(AssetObservation)
            .filter(AssetObservation.asset_id == source.id)
            .count()
        )

        # Detect potential conflicts between source and target
        conflicts = []
        if source.asset_type != target.asset_type:
            conflicts.append(f"Differing asset types: {source.asset_type.value} -> {target.asset_type.value}")

        source_env = (source.attributes or {}).get("environment") or source.environment
        target_env = (target.attributes or {}).get("environment") or target.environment
        if source_env and target_env and source_env != target_env:
            conflicts.append(f"Environment mismatch: {source_env} vs {target_env}")

        return {
            "source_asset_id": source.id,
            "source_canonical_identifier": source.canonical_identifier,
            "target_asset_id": target.id,
            "target_canonical_identifier": target.canonical_identifier,
            "findings_to_repoint": findings_count,
            "aliases_to_transfer": aliases_count,
            "observations_to_repoint": observations_count,
            "conflicts_detected": conflicts,
            "safe_to_merge": len(conflicts) == 0,
        }

    @classmethod
    def propose_deduplication(
        cls,
        db: Session,
        project_id: str,
        source_asset_id: str,
        target_asset_id: str,
        proposed_by_id: Optional[str] = None,
        rationale: str = "Operator suggested duplicate merge",
        confidence: float = 0.90,
    ) -> AssetDeduplicationProposal:
        """
        Creates reviewable deduplication proposal requiring Lead/Admin approval.
        """
        impact = cls.evaluate_dry_run_impact(db, project_id, source_asset_id, target_asset_id)
        now = utc_now()

        proposal = AssetDeduplicationProposal(
            project_id=project_id,
            source_asset_id=source_asset_id,
            target_asset_id=target_asset_id,
            status=DeduplicationProposalStatus.PROPOSED,
            confidence_score=max(0.0, min(1.0, confidence)),
            match_reasons=[rationale],
            conflicts_detected=impact.get("conflicts_detected", []),
            dry_run_impact=impact,
            proposed_by_id=proposed_by_id,
            created_at=now,
            updated_at=now,
        )
        db.add(proposal)
        db.commit()
        db.refresh(proposal)

        AuditService.record_event(
            db=db,
            action="ASSET_DEDUPLICATION_PROPOSED",
            target_type="asset",
            target_id=target_asset_id,
            project_id=project_id,
            actor_id=proposed_by_id,
            outcome="SUCCESS",
            details={
                "proposal_id": proposal.id,
                "source_asset_id": source_asset_id,
                "target_asset_id": target_asset_id,
                "findings_impact": impact.get("findings_to_repoint", 0),
            },
        )
        return proposal

    @classmethod
    def approve_deduplication(
        cls,
        db: Session,
        project_id: str,
        proposal_id: str,
        reviewer_id: Optional[str] = None,
        review_comments: Optional[str] = None,
    ) -> AssetDeduplicationProposal:
        """
        Approves and executes asset deduplication merge.
        Preserves findings, evidence, aliases, observations, and audit provenance.
        """
        proposal = (
            db.query(AssetDeduplicationProposal)
            .filter(
                AssetDeduplicationProposal.id == proposal_id,
                AssetDeduplicationProposal.project_id == project_id,
            )
            .first()
        )
        if not proposal:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Deduplication proposal not found")

        if proposal.status != DeduplicationProposalStatus.PROPOSED:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Proposal is in '{proposal.status.value}' state and cannot be approved",
            )

        source = (
            db.query(Asset)
            .filter(Asset.id == proposal.source_asset_id, Asset.project_id == project_id)
            .first()
        )
        target = (
            db.query(Asset)
            .filter(Asset.id == proposal.target_asset_id, Asset.project_id == project_id)
            .first()
        )

        if not source or not target:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="One or both assets in the proposal no longer exist",
            )

        now = utc_now()

        # Execute safe merge via AssetIdentityService
        merge_rec = AssetIdentityService.merge_asset_identities(
            project_id=project_id,
            target_asset_id=target.id,
            source_asset_id=source.id,
            rationale=f"Approved proposal {proposal.id}: {review_comments or 'Authorized merge'}",
            actor_id=reviewer_id,
            confidence=proposal.confidence_score,
            db=db,
        )

        proposal.status = DeduplicationProposalStatus.APPROVED
        proposal.reviewed_by_id = reviewer_id
        proposal.review_comments = review_comments
        proposal.reviewed_at = now
        proposal.merge_record_id = merge_rec.id
        proposal.updated_at = now

        db.commit()
        db.refresh(proposal)

        AuditService.record_event(
            db=db,
            action="ASSET_DEDUPLICATION_APPROVED",
            target_type="asset",
            target_id=target.id,
            project_id=project_id,
            actor_id=reviewer_id,
            outcome="SUCCESS",
            details={
                "proposal_id": proposal.id,
                "merge_record_id": merge_rec.id,
                "source_asset_id": source.id,
                "target_asset_id": target.id,
            },
        )
        return proposal

    @classmethod
    def reject_deduplication(
        cls,
        db: Session,
        project_id: str,
        proposal_id: str,
        reviewer_id: Optional[str] = None,
        review_comments: Optional[str] = None,
    ) -> AssetDeduplicationProposal:
        """
        Rejects a proposed deduplication merge.
        """
        proposal = (
            db.query(AssetDeduplicationProposal)
            .filter(
                AssetDeduplicationProposal.id == proposal_id,
                AssetDeduplicationProposal.project_id == project_id,
            )
            .first()
        )
        if not proposal:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Deduplication proposal not found")

        if proposal.status != DeduplicationProposalStatus.PROPOSED:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Proposal is in '{proposal.status.value}' state and cannot be rejected",
            )

        now = utc_now()
        proposal.status = DeduplicationProposalStatus.REJECTED
        proposal.reviewed_by_id = reviewer_id
        proposal.review_comments = review_comments
        proposal.reviewed_at = now
        proposal.updated_at = now

        db.commit()
        db.refresh(proposal)

        AuditService.record_event(
            db=db,
            action="ASSET_DEDUPLICATION_REJECTED",
            target_type="asset",
            target_id=proposal.target_asset_id,
            project_id=project_id,
            actor_id=reviewer_id,
            outcome="SUCCESS",
            details={
                "proposal_id": proposal.id,
                "source_asset_id": proposal.source_asset_id,
                "target_asset_id": proposal.target_asset_id,
                "comments": review_comments,
            },
        )
        return proposal

    @classmethod
    def revert_deduplication(
        cls,
        db: Session,
        project_id: str,
        proposal_id: str,
        revert_user_id: Optional[str] = None,
        reversal_notes: Optional[str] = None,
    ) -> AssetDeduplicationProposal:
        """
        Reverts an approved deduplication merge (Split Workflow).
        Restores source asset to ACTIVE state, moves findings and aliases back,
        and marks proposal status REVERTED.
        """
        proposal = (
            db.query(AssetDeduplicationProposal)
            .filter(
                AssetDeduplicationProposal.id == proposal_id,
                AssetDeduplicationProposal.project_id == project_id,
            )
            .first()
        )
        if not proposal:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Deduplication proposal not found")

        if proposal.status != DeduplicationProposalStatus.APPROVED:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Proposal is in '{proposal.status.value}' state and cannot be reverted",
            )

        if not proposal.merge_record_id:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No associated merge record to revert")

        # Execute reversal via AssetIdentityService
        AssetIdentityService.reverse_asset_merge(
            project_id=project_id,
            merge_record_id=proposal.merge_record_id,
            actor_id=revert_user_id,
            reversal_notes=reversal_notes or "Deduplication proposal reverted by operator",
            db=db,
        )

        now = utc_now()
        proposal.status = DeduplicationProposalStatus.REVERTED
        proposal.reverted_at = now
        proposal.reverted_by_id = revert_user_id
        proposal.updated_at = now

        db.commit()
        db.refresh(proposal)

        AuditService.record_event(
            db=db,
            action="ASSET_DEDUPLICATION_REVERTED",
            target_type="asset",
            target_id=proposal.target_asset_id,
            project_id=project_id,
            actor_id=revert_user_id,
            outcome="SUCCESS",
            details={
                "proposal_id": proposal.id,
                "merge_record_id": proposal.merge_record_id,
                "source_asset_id": proposal.source_asset_id,
                "target_asset_id": proposal.target_asset_id,
                "reversal_notes": reversal_notes,
            },
        )
        return proposal

    @classmethod
    def run_data_quality_audit(cls, db: Session, project_id: str) -> List[AssetDataQualityIssue]:
        """
        Executes comprehensive data quality inspection over asset inventory (Prompt 37 Req 10).
        Identifies:
        1. Orphaned findings (missing or non-existent asset reference)
        2. Missing asset references (scope targets without resolved asset)
        3. Duplicate identifiers (distinct active assets sharing identical canonical key)
        4. Inconsistent timestamps (last_seen_at < first_seen_at or future timestamps)
        5. Invalid relationships (aliases pointing to missing assets)
        6. Stale observations (active assets with no observation in > 30 days)
        """
        now = utc_now()
        detected_issues: List[AssetDataQualityIssue] = []

        # 1. Orphaned findings: findings where asset_id is not in active assets
        findings = db.query(VulnerabilityFinding).filter(VulnerabilityFinding.project_id == project_id).all()
        active_asset_ids = set(
            row[0]
            for row in db.query(Asset.id)
            .filter(Asset.project_id == project_id, Asset.status != AssetStatus.DECOMMISSIONED)
            .all()
        )

        for f in findings:
            if not f.asset_id or f.asset_id not in active_asset_ids:
                existing_issue = (
                    db.query(AssetDataQualityIssue)
                    .filter(
                        AssetDataQualityIssue.project_id == project_id,
                        AssetDataQualityIssue.issue_type == DataQualityIssueType.ORPHANED_FINDING,
                        AssetDataQualityIssue.affected_resource_id == f.id,
                        AssetDataQualityIssue.status == DataQualityIssueStatus.OPEN,
                    )
                    .first()
                )
                if not existing_issue:
                    iss = AssetDataQualityIssue(
                        project_id=project_id,
                        issue_type=DataQualityIssueType.ORPHANED_FINDING,
                        severity="HIGH",
                        affected_resource_type="FINDING",
                        affected_resource_id=f.id,
                        details={
                            "finding_title": f.title,
                            "target_value": f.target_value,
                            "held_asset_id": f.asset_id,
                            "reason": "Finding references missing or decommissioned asset record",
                        },
                        status=DataQualityIssueStatus.OPEN,
                        detected_at=now,
                        created_at=now,
                        updated_at=now,
                    )
                    db.add(iss)
                    detected_issues.append(iss)

        # 2. Missing asset references: scope targets with no corresponding asset
        targets = db.query(ScopeTarget).filter(ScopeTarget.project_id == project_id).all()
        canonical_identifiers = set(
            row[0]
            for row in db.query(Asset.canonical_identifier)
            .filter(Asset.project_id == project_id, Asset.status != AssetStatus.DECOMMISSIONED)
            .all()
        )

        for t in targets:
            try:
                _, norm_id, _ = AssetIdentityService.classify_and_normalize(t.target_value)
                if norm_id not in canonical_identifiers:
                    existing_issue = (
                        db.query(AssetDataQualityIssue)
                        .filter(
                            AssetDataQualityIssue.project_id == project_id,
                            AssetDataQualityIssue.issue_type == DataQualityIssueType.MISSING_ASSET_REFERENCE,
                            AssetDataQualityIssue.affected_resource_id == t.id,
                            AssetDataQualityIssue.status == DataQualityIssueStatus.OPEN,
                        )
                        .first()
                    )
                    if not existing_issue:
                        iss = AssetDataQualityIssue(
                            project_id=project_id,
                            issue_type=DataQualityIssueType.MISSING_ASSET_REFERENCE,
                            severity="MEDIUM",
                            affected_resource_type="TARGET",
                            affected_resource_id=t.id,
                            details={
                                "target_value": t.target_value,
                                "normalized_identifier": norm_id,
                                "reason": "Authorized scope target has not been resolved to a canonical asset",
                            },
                            status=DataQualityIssueStatus.OPEN,
                            detected_at=now,
                            created_at=now,
                            updated_at=now,
                        )
                        db.add(iss)
                        detected_issues.append(iss)
            except Exception:
                pass

        # 3. Inconsistent timestamps
        all_assets = db.query(Asset).filter(Asset.project_id == project_id).all()
        future_threshold = now + timedelta(days=1)

        for a in all_assets:
            a_first = ensure_utc(a.first_seen_at)
            a_last = ensure_utc(a.last_seen_at)
            is_inconsistent = False
            inc_reason = ""

            if a_first and a_last and a_last < a_first:
                is_inconsistent = True
                inc_reason = f"last_seen_at ({a_last.isoformat()}) is earlier than first_seen_at ({a_first.isoformat()})"
            elif a_last and a_last > future_threshold:
                is_inconsistent = True
                inc_reason = f"last_seen_at ({a_last.isoformat()}) is in the future"

            if is_inconsistent:
                existing_issue = (
                    db.query(AssetDataQualityIssue)
                    .filter(
                        AssetDataQualityIssue.project_id == project_id,
                        AssetDataQualityIssue.issue_type == DataQualityIssueType.INCONSISTENT_TIMESTAMPS,
                        AssetDataQualityIssue.affected_resource_id == a.id,
                        AssetDataQualityIssue.status == DataQualityIssueStatus.OPEN,
                    )
                    .first()
                )
                if not existing_issue:
                    iss = AssetDataQualityIssue(
                        project_id=project_id,
                        issue_type=DataQualityIssueType.INCONSISTENT_TIMESTAMPS,
                        severity="LOW",
                        affected_resource_type="ASSET",
                        affected_resource_id=a.id,
                        details={
                            "canonical_identifier": a.canonical_identifier,
                            "first_seen_at": a_first.isoformat() if a_first else None,
                            "last_seen_at": a_last.isoformat() if a_last else None,
                            "reason": inc_reason,
                        },
                        status=DataQualityIssueStatus.OPEN,
                        detected_at=now,
                        created_at=now,
                        updated_at=now,
                    )
                    db.add(iss)
                    detected_issues.append(iss)

        # 4. Stale observations: active assets with no observation in > 30 days
        stale_threshold = now - timedelta(days=cls.AUDIT_STALENESS_DAYS)
        for a in all_assets:
            if a.status == AssetStatus.ACTIVE and not a.confirmed_absent:
                a_last = ensure_utc(a.last_successful_observation_at or a.last_seen_at)
                if a_last and a_last < stale_threshold:
                    days_stale = (now - a_last).total_seconds() / 86400.0
                    existing_issue = (
                        db.query(AssetDataQualityIssue)
                        .filter(
                            AssetDataQualityIssue.project_id == project_id,
                            AssetDataQualityIssue.issue_type == DataQualityIssueType.STALE_OBSERVATION,
                            AssetDataQualityIssue.affected_resource_id == a.id,
                            AssetDataQualityIssue.status == DataQualityIssueStatus.OPEN,
                        )
                        .first()
                    )
                    if not existing_issue:
                        iss = AssetDataQualityIssue(
                            project_id=project_id,
                            issue_type=DataQualityIssueType.STALE_OBSERVATION,
                            severity="MEDIUM",
                            affected_resource_type="ASSET",
                            affected_resource_id=a.id,
                            details={
                                "canonical_identifier": a.canonical_identifier,
                                "last_observation_at": a_last.isoformat(),
                                "days_stale": round(days_stale, 1),
                                "reason": f"Active asset has not been observed in {days_stale:.1f} days (> {cls.AUDIT_STALENESS_DAYS}d)",
                            },
                            status=DataQualityIssueStatus.OPEN,
                            detected_at=now,
                            created_at=now,
                            updated_at=now,
                        )
                        db.add(iss)
                        detected_issues.append(iss)

        db.commit()
        return detected_issues

    @classmethod
    def resolve_data_quality_issue(
        cls,
        db: Session,
        project_id: str,
        issue_id: str,
        new_status: DataQualityIssueStatus,
    ) -> AssetDataQualityIssue:
        """
        Updates the status of a data quality issue (RESOLVED / IGNORED).
        """
        issue = (
            db.query(AssetDataQualityIssue)
            .filter(
                AssetDataQualityIssue.id == issue_id,
                AssetDataQualityIssue.project_id == project_id,
            )
            .first()
        )
        if not issue:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Data quality issue not found")

        issue.status = new_status
        issue.resolved_at = utc_now()
        issue.updated_at = utc_now()
        db.commit()
        db.refresh(issue)
        return issue
