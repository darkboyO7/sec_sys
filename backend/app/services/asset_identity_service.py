import ipaddress
import re
import json
import hashlib
from datetime import datetime, timezone, timedelta
from typing import Tuple, Optional, Dict, Any, List
from urllib.parse import urlparse
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
from app.models.base import utc_now
from app.services.audit_service import AuditService


def _normalize_dt(dt: Optional[datetime]) -> Optional[datetime]:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


class AssetIdentityService:
    """
    Asset Identity, Resolution, and Lifecycle Service (Prompt 20 / Section 1).
    Distinguishes stable logical asset identity from changeable observed attributes.
    Preserves historical aliases, handles address reuse and ephemeral infrastructure,
    enforces non-destructive identity resolution, and supports reversible merges.
    """

    @classmethod
    def classify_and_normalize(cls, raw_target: str) -> Tuple[AssetType, str, str]:
        """
        Deterministically classifies and normalizes a candidate target string.
        Returns: (AssetType, canonical_identifier, display_name)
        Raises ValueError on malformed, unsafe, or ambiguous representations (e.g. CWE-1288).
        """
        val = (raw_target or "").strip()
        if not val:
            raise ValueError("Target string cannot be empty.")

        # 1. URL / Web Application / API Endpoint
        if val.lower().startswith(("http://", "https://")):
            parsed = urlparse(val)
            scheme = parsed.scheme.lower()
            hostname = (parsed.hostname or "").lower().rstrip(".")
            port = parsed.port

            host_ipv4 = re.match(r"^(\d+)\.(\d+)\.(\d+)\.(\d+)$", hostname)
            if host_ipv4 and any(len(o) > 1 and o.startswith("0") for o in host_ipv4.groups()):
                raise ValueError(
                    f"Ambiguous URL host '{hostname}': IPv4 octets with leading zeros are prohibited (CWE-1288)."
                )

            if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
                netloc = hostname
            elif port:
                netloc = f"{hostname}:{port}"
            else:
                netloc = hostname

            path = parsed.path.rstrip("/") if parsed.path and parsed.path != "/" else ""
            canonical = f"{scheme}://{netloc}{path}"
            asset_type = AssetType.API_ENDPOINT if path else AssetType.WEB_APP
            return asset_type, canonical, netloc

        # 2. Service with Protocol Scheme (e.g. tcp://10.0.0.1:443 or ssh://host:22)
        if re.match(r"^[a-zA-Z0-9_-]+://", val):
            parsed = urlparse(val)
            proto = parsed.scheme.lower()
            host = (parsed.hostname or "").lower().rstrip(".")
            port = parsed.port or ""
            host_ipv4 = re.match(r"^(\d+)\.(\d+)\.(\d+)\.(\d+)$", host)
            if host_ipv4 and any(len(o) > 1 and o.startswith("0") for o in host_ipv4.groups()):
                raise ValueError(
                    f"Ambiguous service host '{host}': IPv4 octets with leading zeros are prohibited (CWE-1288)."
                )
            canonical = f"{proto}://{host}:{port}" if port else f"{proto}://{host}"
            return AssetType.SERVICE, canonical, canonical

        # 3. IPv4 Address
        ipv4_match = re.match(r"^(\d+)\.(\d+)\.(\d+)\.(\d+)$", val)
        if ipv4_match:
            octets = ipv4_match.groups()
            if any(len(o) > 1 and o.startswith("0") for o in octets):
                raise ValueError(
                    f"Ambiguous IPv4 address '{val}': octets with leading zeros are prohibited (CWE-1288)."
                )
            try:
                ip_obj = ipaddress.ip_address(val)
                canonical = ip_obj.compressed.lower()
                return AssetType.IP_ADDRESS, canonical, canonical
            except ValueError as e:
                raise ValueError(f"Invalid IPv4 address '{val}': {e}")

        # 4. IPv6 Address
        if ":" in val and not val.startswith("http") and "/" not in val and not val.split(":")[-1].isdigit():
            try:
                ip_obj = ipaddress.ip_address(val)
                canonical = ip_obj.compressed.lower()
                return AssetType.IP_ADDRESS, canonical, canonical
            except ValueError:
                pass

        # 5. CIDR block
        cidr_match = re.match(r"^(\d+)\.(\d+)\.(\d+)\.(\d+)/(\d+)$", val)
        if cidr_match:
            octets = cidr_match.groups()[:4]
            if any(len(o) > 1 and o.startswith("0") for o in octets):
                raise ValueError(
                    f"Ambiguous IPv4 CIDR '{val}': octets with leading zeros are prohibited (CWE-1288)."
                )

        if "/" in val:
            try:
                net_obj = ipaddress.ip_network(val, strict=False)
                canonical = net_obj.compressed.lower()
                return AssetType.HOST, canonical, f"Network {canonical}"
            except ValueError as e:
                raise ValueError(f"Invalid CIDR network representation '{val}': {e}")

        # 6. Host:Port (e.g. "10.0.0.1:8080" or "db.corp.internal:5432")
        if ":" in val and not val.startswith("["):
            parts = val.split(":")
            if len(parts) == 2 and parts[1].isdigit():
                host = parts[0].strip().lower().rstrip(".")
                port = parts[1]
                host_ipv4 = re.match(r"^(\d+)\.(\d+)\.(\d+)\.(\d+)$", host)
                if host_ipv4 and any(len(o) > 1 and o.startswith("0") for o in host_ipv4.groups()):
                    raise ValueError(
                        f"Ambiguous service host '{host}': IPv4 octets with leading zeros are prohibited (CWE-1288)."
                    )
                canonical = f"tcp://{host}:{port}"
                return AssetType.SERVICE, canonical, f"Service on {val}"

        # 7. Domain or Hostname
        canonical_domain = val.lower().rstrip(".")
        if not re.match(r"^[a-zA-Z0-9*_\-.]+$", canonical_domain):
            raise ValueError(
                f"Invalid domain or hostname identifier: '{val}'. Contains invalid characters."
            )

        asset_type = AssetType.DOMAIN if "." in canonical_domain else AssetType.HOSTNAME
        return asset_type, canonical_domain, canonical_domain

    @classmethod
    def reconcile_or_create_asset(
        cls,
        project_id: str,
        organization_id: str,
        asset_type: AssetType,
        canonical_identifier: str,
        name: Optional[str] = None,
        environment: str = "PRODUCTION",
        criticality: AssetCriticality = AssetCriticality.MEDIUM,
        attributes: Optional[Dict[str, Any]] = None,
        source: str = "ASSESSMENT",
        confidence: float = 1.0,
        is_ambiguous: bool = False,
        ambiguity_reason: Optional[str] = None,
        observed_at: Optional[datetime] = None,
        db: Optional[Session] = None,
    ) -> Asset:
        """
        Reconciles an asset conservatively against existing records within the project.
        Enforces out-of-order observation protection: older observations do not overwrite
        newer authoritative state.
        """
        assert db is not None, "Database session required"
        now = _normalize_dt(observed_at or utc_now())
        display_name = name or canonical_identifier

        # Look up authoritative asset by unique constraint
        existing = (
            db.query(Asset)
            .filter(
                Asset.project_id == project_id,
                Asset.asset_type == asset_type,
                Asset.canonical_identifier == canonical_identifier,
            )
            .first()
        )

        if existing:
            # Out-of-order protection: only update last_seen_at if incoming observation is >= current
            if existing.last_seen_at is None or now >= _normalize_dt(existing.last_seen_at):
                existing.last_seen_at = now

            # If asset was marked confirmed_absent, restore to active upon new observation
            if existing.confirmed_absent:
                existing.confirmed_absent = False
                existing.consecutive_absences = 0
                existing.status = AssetStatus.ACTIVE

            # Non-destructively merge attributes
            if attributes:
                merged = dict(existing.attributes or {})
                for k, v in attributes.items():
                    if k not in merged:
                        merged[k] = v
                    elif merged[k] != v:
                        hist_key = f"_conflict_{k}"
                        if hist_key not in merged:
                            merged[hist_key] = [merged[k]]
                        if v not in merged[hist_key]:
                            merged[hist_key].append(v)
                existing.attributes = merged

            # Ambiguity update
            if is_ambiguous and not existing.is_ambiguous:
                existing.is_ambiguous = True
                existing.ambiguity_reason = ambiguity_reason

            db.flush()
            return existing

        # Create new Asset
        new_asset = Asset(
            project_id=project_id,
            organization_id=organization_id,
            asset_type=asset_type,
            name=display_name,
            canonical_identifier=canonical_identifier,
            environment=environment,
            criticality=criticality,
            status=AssetStatus.ACTIVE,
            attributes=attributes or {},
            source=source,
            confidence=max(0.0, min(1.0, confidence)),
            first_seen_at=now,
            last_seen_at=now,
            last_successful_observation_at=now,
            freshness_status="FRESH",
            completeness_score=1.0,
            consecutive_absences=0,
            confirmed_absent=False,
            is_ambiguous=is_ambiguous,
            ambiguity_reason=ambiguity_reason,
        )

        try:
            with db.begin_nested():
                db.add(new_asset)
                db.flush()
        except Exception:
            existing = (
                db.query(Asset)
                .filter(
                    Asset.project_id == project_id,
                    Asset.asset_type == asset_type,
                    Asset.canonical_identifier == canonical_identifier,
                )
                .first()
            )
            if existing:
                return existing
            raise

        return new_asset

    @classmethod
    def record_alias(
        cls,
        asset: Asset,
        identifier_type: str,
        identifier_value: str,
        is_primary: bool = False,
        confidence: float = 1.0,
        evidence_ref: Optional[str] = None,
        observed_at: Optional[datetime] = None,
        db: Optional[Session] = None,
    ) -> AssetIdentifierAlias:
        """
        Records or updates an alternate identifier association for an asset.
        Handles IP address associations, hostname aliases, and DNS mappings.
        """
        assert db is not None, "Database session required"
        now = observed_at or utc_now()
        norm_val = identifier_value.strip().lower()

        alias = (
            db.query(AssetIdentifierAlias)
            .filter(
                AssetIdentifierAlias.project_id == asset.project_id,
                AssetIdentifierAlias.asset_id == asset.id,
                AssetIdentifierAlias.identifier_type == identifier_type,
                AssetIdentifierAlias.identifier_value == norm_val,
            )
            .first()
        )

        if alias:
            alias.last_observed_at = max(alias.last_observed_at, now)
            alias.is_active = True
            alias.confidence = max(alias.confidence, confidence)
            if evidence_ref:
                alias.evidence_ref = evidence_ref
            if is_primary:
                alias.is_primary = True
            db.flush()
            return alias

        alias = AssetIdentifierAlias(
            asset_id=asset.id,
            project_id=asset.project_id,
            identifier_type=identifier_type,
            identifier_value=norm_val,
            is_primary=is_primary,
            confidence=max(0.0, min(1.0, confidence)),
            evidence_ref=evidence_ref,
            first_observed_at=now,
            last_observed_at=now,
            is_active=True,
            created_at=now,
            updated_at=now,
        )
        db.add(alias)
        db.flush()
        return alias

    @classmethod
    def disassociate_alias(
        cls,
        alias_id: str,
        reason: str,
        db: Session,
    ) -> Optional[AssetIdentifierAlias]:
        """Marks an alias inactive when address reuse or DNS migration occurs."""
        alias = db.query(AssetIdentifierAlias).filter(AssetIdentifierAlias.id == alias_id).first()
        if alias:
            alias.is_active = False
            alias.disassociation_reason = reason
            alias.updated_at = utc_now()
            db.flush()
        return alias

    @classmethod
    def record_observation(
        cls,
        asset: Asset,
        project_id: str,
        observation_source: str,
        observed_attributes: Dict[str, Any],
        assessment_job_id: Optional[str] = None,
        monitoring_run_id: Optional[str] = None,
        adapter_version: str = "1.0.0",
        authorization_context: Optional[Dict[str, Any]] = None,
        confidence: float = 1.0,
        completeness: float = 1.0,
        collection_errors: Optional[List[Dict[str, Any]]] = None,
        is_simulated: bool = False,
        is_successful_absence: bool = False,
        validation_status: str = "VALIDATED",
        evidence_hash: Optional[str] = None,
        observed_at: Optional[datetime] = None,
        db: Optional[Session] = None,
    ) -> Tuple[AssetObservation, bool]:
        """
        Appends an immutable, versioned observation for an asset (Prompt 20).
        Calculates a deterministic dedup_hash over the observation contents to prevent
        duplicate event delivery from creating duplicate logical observations.
        Returns: (observation_record, is_newly_created)
        """
        assert db is not None, "Database session required"
        now = _normalize_dt(observed_at or utc_now())

        computed_hash = evidence_hash
        canonical_json = json.dumps(observed_attributes, sort_keys=True, separators=(",", ":")).encode("utf-8")
        if not computed_hash and observed_attributes:
            computed_hash = hashlib.sha256(canonical_json).hexdigest()

        # Compute dedup_hash over core observation fields
        dedup_seed = f"{asset.id}:{observation_source}:{adapter_version}:{is_successful_absence}:{computed_hash}"
        dedup_hash = hashlib.sha256(dedup_seed.encode("utf-8")).hexdigest()

        # Check for duplicate delivery within recent window (last 5 minutes)
        recent_threshold = now - timedelta(minutes=5)
        existing_duplicate = (
            db.query(AssetObservation)
            .filter(
                AssetObservation.asset_id == asset.id,
                AssetObservation.dedup_hash == dedup_hash,
                AssetObservation.observed_at >= recent_threshold,
            )
            .first()
        )

        if existing_duplicate:
            # Duplicate event delivery suppressed
            return existing_duplicate, False

        obs = AssetObservation(
            asset_id=asset.id,
            project_id=project_id,
            assessment_job_id=assessment_job_id,
            monitoring_run_id=monitoring_run_id,
            observation_source=observation_source,
            adapter_version=adapter_version,
            observed_at=now,
            observed_attributes=observed_attributes,
            evidence_hash=computed_hash,
            confidence=max(0.0, min(1.0, confidence)),
            validation_status=validation_status,
            authorization_context=authorization_context or {},
            is_simulated=is_simulated,
            completeness=max(0.0, min(1.0, completeness)),
            collection_errors=collection_errors or [],
            observation_schema_version="1.0",
            is_successful_absence=is_successful_absence,
            dedup_hash=dedup_hash,
            created_at=now,
        )
        db.add(obs)
        db.flush()

        # Update parent asset state
        if not is_successful_absence and completeness >= 0.8:
            asset.last_successful_observation_at = now
            asset.consecutive_absences = 0
            asset.confirmed_absent = False
            asset.completeness_score = completeness
        elif is_successful_absence:
            asset.consecutive_absences += 1
            if asset.consecutive_absences >= 3:
                asset.confirmed_absent = True
                asset.status = AssetStatus.INACTIVE

        if asset.last_seen_at is None or now >= _normalize_dt(asset.last_seen_at):
            asset.last_seen_at = now

        cls.update_asset_freshness_status(asset, now)
        db.flush()

        return obs, True

    @classmethod
    def update_asset_freshness_status(cls, asset: Asset, now: Optional[datetime] = None) -> str:
        """
        Evaluates and updates asset data freshness:
        - FRESH: observed successfully within last 24h
        - AGING: observed successfully within last 7d
        - STALE: observed > 7d ago
        - EXPIRED: observed > 30d ago
        - UNOBSERVED: no successful observation recorded
        """
        ref_time = _normalize_dt(now or utc_now())
        last_obs = _normalize_dt(asset.last_successful_observation_at)
        if not last_obs:
            asset.freshness_status = "UNOBSERVED"
            return asset.freshness_status

        age = ref_time - last_obs
        if age <= timedelta(hours=24):
            asset.freshness_status = "FRESH"
        elif age <= timedelta(days=7):
            asset.freshness_status = "AGING"
        elif age <= timedelta(days=30):
            asset.freshness_status = "STALE"
        else:
            asset.freshness_status = "EXPIRED"

        return asset.freshness_status

    @classmethod
    def merge_asset_identities(
        cls,
        project_id: str,
        target_asset_id: str,
        source_asset_id: str,
        rationale: str,
        actor_id: Optional[str] = None,
        confidence: float = 1.0,
        db: Optional[Session] = None,
    ) -> AssetIdentityMergeRecord:
        """
        Performs a reversible, auditable merge of two asset identities (Prompt 20 / Section 1).
        Preserves an exact snapshot of source asset state for complete reversibility.
        Moves aliases, observations, and findings to target_asset.
        """
        assert db is not None, "Database session required"
        if target_asset_id == source_asset_id:
            raise ValueError("Cannot merge an asset into itself.")

        target = db.query(Asset).filter(Asset.id == target_asset_id, Asset.project_id == project_id).first()
        source = db.query(Asset).filter(Asset.id == source_asset_id, Asset.project_id == project_id).first()

        if not target or not source:
            raise ValueError("Target or source asset not found in project.")

        # Snapshot source attributes and aliases
        snapshot = {
            "source_id": source.id,
            "asset_type": source.asset_type.value,
            "canonical_identifier": source.canonical_identifier,
            "name": source.name,
            "attributes": dict(source.attributes or {}),
            "status": source.status.value,
            "criticality": source.criticality.value,
            "first_seen_at": source.first_seen_at.isoformat() if source.first_seen_at else None,
            "last_seen_at": source.last_seen_at.isoformat() if source.last_seen_at else None,
            "aliases": [
                {
                    "id": a.id,
                    "identifier_type": a.identifier_type,
                    "identifier_value": a.identifier_value,
                    "is_primary": a.is_primary,
                }
                for a in source.aliases
            ],
            "finding_ids": [f.id for f in source.findings],
        }

        # Create merge record
        now = utc_now()
        merge_rec = AssetIdentityMergeRecord(
            project_id=project_id,
            target_asset_id=target.id,
            merged_asset_id=source.id,
            merged_canonical_identifier=source.canonical_identifier,
            merged_asset_type=source.asset_type.value,
            merged_attributes_snapshot=snapshot,
            merge_rationale=rationale,
            confidence=max(0.0, min(1.0, confidence)),
            actor_id=actor_id,
            is_reversed=False,
            created_at=now,
            updated_at=now,
        )
        db.add(merge_rec)

        # Repoint aliases of source asset as aliases of target asset
        for alias in list(source.aliases):
            alias.asset_id = target.id

        # Repoint observations
        for obs in list(source.observations):
            obs.asset_id = target.id

        # Repoint findings
        for f in list(source.findings):
            f.asset_id = target.id

        # Decommission source asset
        source.status = AssetStatus.DECOMMISSIONED
        source_attrs = dict(source.attributes or {})
        source_attrs["_merged_into"] = target.id
        source_attrs["_merged_at"] = now.isoformat()
        source.attributes = source_attrs

        AuditService.log(
            db=db,
            action="ASSET_IDENTITY_MERGED",
            target_resource=f"asset:{target.id}",
            actor_id=actor_id,
            project_id=project_id,
            details={
                "target_asset_id": target.id,
                "merged_asset_id": source.id,
                "merge_rationale": rationale,
            },
        )
        db.flush()
        return merge_rec

    @classmethod
    def reverse_asset_merge(
        cls,
        project_id: str,
        merge_record_id: str,
        actor_id: Optional[str] = None,
        reversal_notes: Optional[str] = None,
        db: Optional[Session] = None,
    ) -> AssetIdentityMergeRecord:
        """
        Reverses an earlier asset merge operation, restoring the original source asset state (Prompt 20).
        """
        assert db is not None, "Database session required"
        merge_rec = (
            db.query(AssetIdentityMergeRecord)
            .filter(
                AssetIdentityMergeRecord.id == merge_record_id,
                AssetIdentityMergeRecord.project_id == project_id,
            )
            .first()
        )
        if not merge_rec:
            raise ValueError("Merge record not found.")
        if merge_rec.is_reversed:
            raise ValueError("Merge has already been reversed.")

        source = db.query(Asset).filter(Asset.id == merge_rec.merged_asset_id, Asset.project_id == project_id).first()
        if source:
            source.status = AssetStatus.ACTIVE
            attrs = dict(source.attributes or {})
            attrs.pop("_merged_into", None)
            attrs["_unmerged_at"] = utc_now().isoformat()
            source.attributes = attrs

            # Restore aliases recorded in snapshot
            snapshot = merge_rec.merged_attributes_snapshot or {}
            saved_alias_ids = [a["id"] for a in snapshot.get("aliases", [])]
            if saved_alias_ids:
                aliases_to_restore = (
                    db.query(AssetIdentifierAlias)
                    .filter(AssetIdentifierAlias.id.in_(saved_alias_ids))
                    .all()
                )
                for a in aliases_to_restore:
                    a.asset_id = source.id

            # Restore findings recorded in snapshot
            saved_finding_ids = snapshot.get("finding_ids", [])
            if saved_finding_ids:
                from app.models.finding import VulnerabilityFinding
                findings_to_restore = (
                    db.query(VulnerabilityFinding)
                    .filter(VulnerabilityFinding.id.in_(saved_finding_ids))
                    .all()
                )
                for f in findings_to_restore:
                    f.asset_id = source.id

        now = utc_now()
        merge_rec.is_reversed = True
        merge_rec.reversed_at = now
        merge_rec.reversed_by_id = actor_id
        merge_rec.reversal_notes = reversal_notes or "Reversed by operator request."
        merge_rec.updated_at = now

        AuditService.log(
            db=db,
            action="ASSET_IDENTITY_MERGE_REVERSED",
            target_resource=f"asset:{merge_rec.target_asset_id}",
            actor_id=actor_id,
            project_id=project_id,
            details={
                "merge_record_id": merge_rec.id,
                "target_asset_id": merge_rec.target_asset_id,
                "restored_asset_id": merge_rec.merged_asset_id,
                "reversal_notes": merge_rec.reversal_notes,
            },
        )
        db.flush()
        return merge_rec
