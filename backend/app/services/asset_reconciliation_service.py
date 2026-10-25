import ipaddress
import re
from typing import Tuple, Optional, Dict, Any, List
from urllib.parse import urlparse
from sqlalchemy.orm import Session

from app.models.asset import (
    Asset,
    AssetObservation,
    AssetType,
    AssetCriticality,
    AssetStatus,
)
from app.models.base import utc_now
from app.services.audit_service import AuditService


class AssetReconciliationService:
    """
    Conservative asset reconciliation and inventory management service.
    Normalizes identifiers using type-specific rules, separates authoritative asset state
    from supporting historical observations, and preserves conflicting signals.
    """

    @classmethod
    def classify_and_normalize(cls, raw_target: str) -> Tuple[AssetType, str, str]:
        """
        Deterministically classifies and normalizes a candidate target string.
        Returns: (AssetType, canonical_identifier, display_name)
        """
        val = (raw_target or "").strip()

        # 1. Check for URL / Web Application / API Endpoint
        if val.lower().startswith(("http://", "https://")):
            parsed = urlparse(val)
            scheme = parsed.scheme.lower()
            hostname = (parsed.hostname or "").lower().rstrip(".")
            port = parsed.port
            # Strip standard default ports
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

        # 2. Check for Service with Protocol Scheme (e.g. tcp://10.0.0.1:443 or ssh://host:22)
        if re.match(r"^[a-zA-Z0-9_-]+://", val):
            parsed = urlparse(val)
            proto = parsed.scheme.lower()
            host = (parsed.hostname or "").lower()
            port = parsed.port or ""
            canonical = f"{proto}://{host}:{port}" if port else f"{proto}://{host}"
            return AssetType.SERVICE, canonical, canonical

        # 3. Check for IPv4 or IPv6 Address
        # Pre-process potential IPv4 with leading zeros (e.g. 192.168.001.050)
        cleaned_ip_str = val
        ipv4_match = re.match(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$", val)
        if ipv4_match:
            try:
                octets = [int(p) for p in ipv4_match.groups()]
                if all(0 <= o <= 255 for o in octets):
                    cleaned_ip_str = ".".join(str(o) for o in octets)
            except ValueError:
                pass

        try:
            ip_obj = ipaddress.ip_address(cleaned_ip_str)
            canonical = ip_obj.compressed.lower()
            return AssetType.IP_ADDRESS, canonical, canonical
        except ValueError:
            pass

        # 4. Check for CIDR block (treated as Host or IP Range network)
        cleaned_cidr_str = val
        cidr_match = re.match(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})/(\d{1,2})$", val)
        if cidr_match:
            try:
                octets = [int(p) for p in cidr_match.groups()[:4]]
                prefix = int(cidr_match.group(5))
                if all(0 <= o <= 255 for o in octets) and 0 <= prefix <= 32:
                    cleaned_cidr_str = f"{'.'.join(str(o) for o in octets)}/{prefix}"
            except ValueError:
                pass

        try:
            net_obj = ipaddress.ip_network(cleaned_cidr_str, strict=False)
            canonical = net_obj.compressed.lower()
            return AssetType.HOST, canonical, f"Network {canonical}"
        except ValueError:
            pass

        # 5. Check for Host:Port string (e.g. "10.0.0.1:8080" or "db.corp.internal:5432")
        if ":" in val and not val.startswith("["):
            parts = val.split(":")
            if len(parts) == 2 and parts[1].isdigit():
                host = parts[0].strip().lower().rstrip(".")
                port = parts[1]
                canonical = f"tcp://{host}:{port}"
                return AssetType.SERVICE, canonical, f"Service on {val}"

        # 6. Default to Domain / Hostname
        canonical_domain = val.lower().rstrip(".")
        # If looks like simple unpunctuated name, classify as HOSTNAME, else DOMAIN
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
        db: Optional[Session] = None,
    ) -> Asset:
        """
        Reconciles an asset conservatively against existing records within the project.
        If existing asset matches (project_id, asset_type, canonical_identifier):
        - Updates last_seen_at.
        - Merges attributes non-destructively.
        If not found: creates new Asset record.
        """
        assert db is not None, "Database session required for asset reconciliation"
        now = utc_now()
        display_name = name or canonical_identifier

        # Authoritative lookup by unique constraint
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
            existing.last_seen_at = now
            # Non-destructively merge attributes
            if attributes:
                merged = dict(existing.attributes or {})
                for k, v in attributes.items():
                    if k not in merged:
                        merged[k] = v
                    elif merged[k] != v:
                        # Record conflicting attribute observation
                        hist_key = f"_conflict_{k}"
                        if hist_key not in merged:
                            merged[hist_key] = [merged[k]]
                        if v not in merged[hist_key]:
                            merged[hist_key].append(v)
                existing.attributes = merged

            # If newly marked ambiguous, update
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
            is_ambiguous=is_ambiguous,
            ambiguity_reason=ambiguity_reason,
        )

        try:
            with db.begin_nested():
                db.add(new_asset)
                db.flush()
        except Exception:
            # Handle concurrent creation
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
    def record_observation(
        cls,
        asset: Asset,
        project_id: str,
        observation_source: str,
        observed_attributes: Dict[str, Any],
        assessment_job_id: Optional[str] = None,
        adapter_version: str = "1.0.0",
        confidence: float = 1.0,
        validation_status: str = "VALIDATED",
        evidence_hash: Optional[str] = None,
        db: Optional[Session] = None,
    ) -> AssetObservation:
        """
        Appends an immutable, time-stamped observation record for an asset.
        Supports historical change analysis and preserves divergent scanner data.
        """
        assert db is not None, "Database session required"
        now = utc_now()

        obs = AssetObservation(
            asset_id=asset.id,
            project_id=project_id,
            assessment_job_id=assessment_job_id,
            observation_source=observation_source,
            adapter_version=adapter_version,
            observed_at=now,
            observed_attributes=observed_attributes,
            evidence_hash=evidence_hash,
            confidence=max(0.0, min(1.0, confidence)),
            validation_status=validation_status,
            created_at=now,
        )
        db.add(obs)
        db.flush()

        # Update parent asset last seen timestamp
        asset.last_seen_at = now
        return obs
