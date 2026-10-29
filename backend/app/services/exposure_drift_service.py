import hashlib
import json
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional, Tuple
from sqlalchemy.orm import Session
from sqlalchemy import desc, and_

from app.models.asset import Asset, AssetObservation, AssetStatus
from app.models.drift import (
    ExposureDriftRecord,
    DriftType,
    DriftMateriality,
)
from app.models.finding import (
    VulnerabilityFinding,
    FindingLifecycleStatus,
    FindingValidationStatus,
)
from app.models.base import utc_now
from app.services.dependency_invalidation_service import DependencyInvalidationService
from app.services.audit_service import AuditService


class ExposureDriftService:
    """
    Exposure-Drift Detection & Continuous Change Intelligence Service (Prompt 20 / Sections 3 & 4).
    Compares compatible observations to identify:
    - Newly observed authorized assets and services
    - Changes in IP / hostname / port associations
    - Security configuration changes (TLS, headers, banners)
    - Distinguishes real changes from missing data, adapter failures, or partial coverage
    - Classifies drift materiality (MATERIAL, IMMATERIAL, INCONCLUSIVE)
    - Identifies stale findings and invalidates downstream risk/attack-path conclusions
    """

    # Security-sensitive headers whose removal or modification is MATERIAL
    SECURITY_HEADERS = {
        "strict-transport-security",
        "content-security-policy",
        "x-frame-options",
        "x-content-type-options",
        "referrer-policy",
        "permissions-policy",
    }

    # Benign headers whose modifications are IMMATERIAL
    IMMATERIAL_HEADERS = {
        "date",
        "etag",
        "last-modified",
        "cache-control",
        "expires",
        "content-length",
        "age",
        "x-request-id",
        "x-runtime",
    }

    @classmethod
    def evaluate_drift(
        cls,
        project_id: str,
        asset: Asset,
        current_observation: AssetObservation,
        previous_observation: Optional[AssetObservation] = None,
        db: Optional[Session] = None,
    ) -> List[ExposureDriftRecord]:
        """
        Evaluates exposure drift between current observation and historical baseline.
        If previous_observation is omitted, fetches the most recent compatible predecessor.
        Returns a list of created ExposureDriftRecords.
        """
        assert db is not None, "Database session required"
        detected_drifts: List[ExposureDriftRecord] = []
        now = utc_now()

        # Find previous compatible observation if not provided
        if not previous_observation:
            previous_observation = (
                db.query(AssetObservation)
                .filter(
                    AssetObservation.asset_id == asset.id,
                    AssetObservation.project_id == project_id,
                    AssetObservation.id != current_observation.id,
                    AssetObservation.observation_source == current_observation.observation_source,
                )
                .order_by(AssetObservation.observed_at.desc())
                .first()
            )

        # Baseline: First-ever observation of newly authorized asset
        if not previous_observation:
            drift = cls._record_drift(
                project_id=project_id,
                asset_id=asset.id,
                drift_type=DriftType.NEW_AUTHORIZED_ASSET,
                materiality=DriftMateriality.MATERIAL,
                materiality_reason="Newly observed authorized asset ingested into active project inventory.",
                target_resource=asset.canonical_identifier,
                title=f"New Authorized Asset Discovered: {asset.name}",
                previous_observation_id=None,
                current_observation_id=current_observation.id,
                previous_state={},
                new_state=current_observation.observed_attributes or {},
                evidence_references=[current_observation.evidence_hash] if current_observation.evidence_hash else [],
                confidence=current_observation.confidence,
                security_impact_summary="New attack surface discovered; initial security assessment recommended.",
                reassessment_recommended=True,
                now=now,
                db=db,
            )
            if drift:
                detected_drifts.append(drift)
            return detected_drifts

        # Incomplete collection or collection errors check
        is_partial = (
            current_observation.completeness < 0.8
            or bool(current_observation.collection_errors)
        )

        curr_attrs = current_observation.observed_attributes or {}
        prev_attrs = previous_observation.observed_attributes or {}

        # 1. Absence / Disappearance check
        if current_observation.is_successful_absence:
            if asset.consecutive_absences >= 3:
                drift = cls._record_drift(
                    project_id=project_id,
                    asset_id=asset.id,
                    drift_type=DriftType.ASSET_CONFIRMED_ABSENT,
                    materiality=DriftMateriality.MATERIAL,
                    materiality_reason="Target confirmed absent across 3 or more consecutive complete monitoring runs.",
                    target_resource=asset.canonical_identifier,
                    title=f"Asset Confirmed Absent / Decommissioned: {asset.name}",
                    previous_observation_id=previous_observation.id,
                    current_observation_id=current_observation.id,
                    previous_state={"consecutive_absences": asset.consecutive_absences - 1},
                    new_state={"consecutive_absences": asset.consecutive_absences, "confirmed_absent": True},
                    evidence_references=[current_observation.evidence_hash] if current_observation.evidence_hash else [],
                    confidence=0.95,
                    security_impact_summary="Asset no longer exposes live attack surface. Retesting deferred.",
                    reassessment_recommended=False,
                    now=now,
                    db=db,
                )
                if drift:
                    detected_drifts.append(drift)
            else:
                drift = cls._record_drift(
                    project_id=project_id,
                    asset_id=asset.id,
                    drift_type=DriftType.ASSET_UNOBSERVED_WARNING,
                    materiality=DriftMateriality.INCONCLUSIVE,
                    materiality_reason=f"Target unobserved on single run ({asset.consecutive_absences}/3 required for absence confirmation).",
                    target_resource=asset.canonical_identifier,
                    title=f"Asset Temporarily Unobserved: {asset.name}",
                    previous_observation_id=previous_observation.id,
                    current_observation_id=current_observation.id,
                    previous_state={"last_seen": previous_observation.observed_at.isoformat()},
                    new_state={"unobserved_run_at": current_observation.observed_at.isoformat()},
                    evidence_references=[],
                    confidence=0.5,
                    security_impact_summary="Single missed observation. Existing findings preserved; not marked resolved.",
                    reassessment_recommended=False,
                    now=now,
                    db=db,
                )
                if drift:
                    detected_drifts.append(drift)
            return detected_drifts

        # If scan had collection errors or partial coverage, mark any differences as INCONCLUSIVE
        if is_partial:
            drift = cls._record_drift(
                project_id=project_id,
                asset_id=asset.id,
                drift_type=DriftType.EVIDENCE_CONFIDENCE_CHANGED,
                materiality=DriftMateriality.INCONCLUSIVE,
                materiality_reason=f"Partial collection detected (completeness: {current_observation.completeness:.2f}, errors: {len(current_observation.collection_errors)}). Cannot establish reliable drift.",
                target_resource=asset.canonical_identifier,
                title=f"Inconclusive Observation on {asset.name}",
                previous_observation_id=previous_observation.id,
                current_observation_id=current_observation.id,
                previous_state={"completeness": previous_observation.completeness},
                new_state={"completeness": current_observation.completeness, "errors": current_observation.collection_errors},
                evidence_references=[],
                confidence=0.4,
                security_impact_summary="Data collection incomplete. Findings preserved without alteration.",
                reassessment_recommended=False,
                now=now,
                db=db,
            )
            if drift:
                detected_drifts.append(drift)
            return detected_drifts

        # 2. Open Port / Service Changes
        prev_ports = set(prev_attrs.get("open_ports", []))
        curr_ports = set(curr_attrs.get("open_ports", []))

        added_ports = curr_ports - prev_ports
        removed_ports = prev_ports - curr_ports

        if added_ports:
            drift = cls._record_drift(
                project_id=project_id,
                asset_id=asset.id,
                drift_type=DriftType.SERVICE_ADDED,
                materiality=DriftMateriality.MATERIAL,
                materiality_reason=f"New network ports opened: {sorted(list(added_ports))}.",
                target_resource=asset.canonical_identifier,
                title=f"New Network Ports Exposed on {asset.name}: {sorted(list(added_ports))}",
                previous_observation_id=previous_observation.id,
                current_observation_id=current_observation.id,
                previous_state={"open_ports": sorted(list(prev_ports))},
                new_state={"open_ports": sorted(list(curr_ports)), "added_ports": sorted(list(added_ports))},
                evidence_references=[current_observation.evidence_hash] if current_observation.evidence_hash else [],
                confidence=1.0,
                security_impact_summary="Expanded exposure surface. New open ports require security auditing.",
                reassessment_recommended=True,
                now=now,
                db=db,
            )
            if drift:
                detected_drifts.append(drift)

        if removed_ports:
            drift = cls._record_drift(
                project_id=project_id,
                asset_id=asset.id,
                drift_type=DriftType.SERVICE_REMOVED,
                materiality=DriftMateriality.MATERIAL,
                materiality_reason=f"Network ports closed or service stopped: {sorted(list(removed_ports))}.",
                target_resource=asset.canonical_identifier,
                title=f"Services Closed / Removed on {asset.name}: {sorted(list(removed_ports))}",
                previous_observation_id=previous_observation.id,
                current_observation_id=current_observation.id,
                previous_state={"open_ports": sorted(list(prev_ports))},
                new_state={"open_ports": sorted(list(curr_ports)), "removed_ports": sorted(list(removed_ports))},
                evidence_references=[current_observation.evidence_hash] if current_observation.evidence_hash else [],
                confidence=0.95,
                security_impact_summary="Service withdrawn. Associated findings on these ports may be stale.",
                reassessment_recommended=False,
                now=now,
                db=db,
            )
            if drift:
                detected_drifts.append(drift)
            # Evaluate stale findings for removed ports
            cls._evaluate_stale_findings_for_removed_ports(asset, removed_ports, db)

        # 3. IP / Hostname Association Changes
        prev_ip = prev_attrs.get("ip_address")
        curr_ip = curr_attrs.get("ip_address")
        if curr_ip and prev_ip and curr_ip != prev_ip:
            drift = cls._record_drift(
                project_id=project_id,
                asset_id=asset.id,
                drift_type=DriftType.IP_ASSOCIATION_CHANGED,
                materiality=DriftMateriality.MATERIAL,
                materiality_reason=f"Resolved IP changed from {prev_ip} to {curr_ip} (DNS migration or IP reassignment).",
                target_resource=asset.canonical_identifier,
                title=f"IP Address Reassignment on {asset.name}: {prev_ip} -> {curr_ip}",
                previous_observation_id=previous_observation.id,
                current_observation_id=current_observation.id,
                previous_state={"ip_address": prev_ip},
                new_state={"ip_address": curr_ip},
                evidence_references=[current_observation.evidence_hash] if current_observation.evidence_hash else [],
                confidence=1.0,
                security_impact_summary="Network endpoint reassigned. Target scope re-authorization required.",
                reassessment_recommended=True,
                now=now,
                db=db,
            )
            if drift:
                detected_drifts.append(drift)

        # 4. Security Configuration Changes (Headers, TLS)
        prev_headers = {k.lower(): v for k, v in prev_attrs.get("headers", {}).items()}
        curr_headers = {k.lower(): v for k, v in curr_attrs.get("headers", {}).items()}

        removed_sec_headers = [h for h in cls.SECURITY_HEADERS if h in prev_headers and h not in curr_headers]
        added_sec_headers = [h for h in cls.SECURITY_HEADERS if h not in prev_headers and h in curr_headers]

        if removed_sec_headers:
            drift = cls._record_drift(
                project_id=project_id,
                asset_id=asset.id,
                drift_type=DriftType.SECURITY_CONFIG_CHANGED,
                materiality=DriftMateriality.MATERIAL,
                materiality_reason=f"Defensive security headers removed: {removed_sec_headers}.",
                target_resource=asset.canonical_identifier,
                title=f"Security Posture Regression: Headers Removed on {asset.name}",
                previous_observation_id=previous_observation.id,
                current_observation_id=current_observation.id,
                previous_state={"headers": {h: prev_headers[h] for h in removed_sec_headers}},
                new_state={"headers": {h: None for h in removed_sec_headers}},
                evidence_references=[current_observation.evidence_hash] if current_observation.evidence_hash else [],
                confidence=1.0,
                security_impact_summary="Security control dismantled. Previous remediation invalidated.",
                reassessment_recommended=True,
                now=now,
                db=db,
            )
            if drift:
                detected_drifts.append(drift)

        elif added_sec_headers:
            drift = cls._record_drift(
                project_id=project_id,
                asset_id=asset.id,
                drift_type=DriftType.SECURITY_CONFIG_CHANGED,
                materiality=DriftMateriality.MATERIAL,
                materiality_reason=f"Hardened security headers introduced: {added_sec_headers}.",
                target_resource=asset.canonical_identifier,
                title=f"Security Hardening Detected: Headers Added on {asset.name}",
                previous_observation_id=previous_observation.id,
                current_observation_id=current_observation.id,
                previous_state={"headers": {h: None for h in added_sec_headers}},
                new_state={"headers": {h: curr_headers[h] for h in added_sec_headers}},
                evidence_references=[current_observation.evidence_hash] if current_observation.evidence_hash else [],
                confidence=1.0,
                security_impact_summary="Hardening controls applied. Associated findings eligible for verification retest.",
                reassessment_recommended=False,
                now=now,
                db=db,
            )
            if drift:
                detected_drifts.append(drift)

        # Check for cosmetic/immaterial changes
        other_header_diffs = {
            k: curr_headers[k]
            for k in curr_headers
            if k in cls.IMMATERIAL_HEADERS and curr_headers.get(k) != prev_headers.get(k)
        }
        if other_header_diffs and not removed_sec_headers and not added_sec_headers:
            drift = cls._record_drift(
                project_id=project_id,
                asset_id=asset.id,
                drift_type=DriftType.SECURITY_CONFIG_CHANGED,
                materiality=DriftMateriality.IMMATERIAL,
                materiality_reason="Non-security headers modified (e.g. timestamp, ETag, or cache control).",
                target_resource=asset.canonical_identifier,
                title=f"Immaterial Header Updates on {asset.name}",
                previous_observation_id=previous_observation.id,
                current_observation_id=current_observation.id,
                previous_state={"immaterial_diff": {k: prev_headers.get(k) for k in other_header_diffs}},
                new_state={"immaterial_diff": other_header_diffs},
                evidence_references=[],
                confidence=1.0,
                security_impact_summary="No material security impact. No reassessment warranted.",
                reassessment_recommended=False,
                now=now,
                db=db,
            )
            if drift:
                detected_drifts.append(drift)

        # 5. Application / Software Version Changes
        prev_version = prev_attrs.get("server_banner") or prev_attrs.get("component_version")
        curr_version = curr_attrs.get("server_banner") or curr_attrs.get("component_version")
        if curr_version and prev_version and curr_version != prev_version:
            drift = cls._record_drift(
                project_id=project_id,
                asset_id=asset.id,
                drift_type=DriftType.VERSION_CHANGED,
                materiality=DriftMateriality.MATERIAL,
                materiality_reason=f"Software component or server version changed: '{prev_version}' -> '{curr_version}'.",
                target_resource=asset.canonical_identifier,
                title=f"Software Version Upgrade / Transition on {asset.name}",
                previous_observation_id=previous_observation.id,
                current_observation_id=current_observation.id,
                previous_state={"version": prev_version},
                new_state={"version": curr_version},
                evidence_references=[current_observation.evidence_hash] if current_observation.evidence_hash else [],
                confidence=1.0,
                security_impact_summary="Underlying software modified. Vulnerability catalog must be re-evaluated.",
                reassessment_recommended=True,
                now=now,
                db=db,
            )
            if drift:
                detected_drifts.append(drift)

        # Invalidate derived graph & risk state if any MATERIAL drift occurred
        if any(d.materiality == DriftMateriality.MATERIAL for d in detected_drifts):
            DependencyInvalidationService.invalidate_for_asset_change(
                db=db,
                project_id=project_id,
                asset_id=asset.id,
                now=now,
            )

        return detected_drifts

    @classmethod
    def _record_drift(
        cls,
        project_id: str,
        asset_id: Optional[str],
        drift_type: DriftType,
        materiality: DriftMateriality,
        materiality_reason: str,
        target_resource: str,
        title: str,
        previous_observation_id: Optional[str],
        current_observation_id: Optional[str],
        previous_state: Dict[str, Any],
        new_state: Dict[str, Any],
        evidence_references: List[str],
        confidence: float,
        security_impact_summary: str,
        reassessment_recommended: bool,
        now: datetime,
        db: Session,
    ) -> Optional[ExposureDriftRecord]:
        """Idempotently records an exposure drift event using a deterministic dedup_key."""
        dedup_seed = f"{project_id}:{asset_id}:{drift_type.value}:{json.dumps(new_state, sort_keys=True)}"
        dedup_key = hashlib.sha256(dedup_seed.encode("utf-8")).hexdigest()

        # Suppress duplicate drift within recent 1 hour window
        recent_threshold = now - timedelta(hours=1)
        existing = (
            db.query(ExposureDriftRecord)
            .filter(
                ExposureDriftRecord.project_id == project_id,
                ExposureDriftRecord.dedup_key == dedup_key,
                ExposureDriftRecord.detected_at >= recent_threshold,
            )
            .first()
        )
        if existing:
            return None

        record = ExposureDriftRecord(
            project_id=project_id,
            asset_id=asset_id,
            drift_type=drift_type,
            materiality=materiality,
            materiality_reason=materiality_reason,
            target_resource=target_resource,
            title=title,
            previous_observation_id=previous_observation_id,
            current_observation_id=current_observation_id,
            previous_state=previous_state,
            new_state=new_state,
            evidence_references=evidence_references,
            confidence=max(0.0, min(1.0, confidence)),
            security_impact_summary=security_impact_summary,
            reassessment_recommended=reassessment_recommended,
            dedup_key=dedup_key,
            detected_at=now,
            evaluated_at=now,
            created_at=now,
            updated_at=now,
        )
        db.add(record)
        db.flush()

        AuditService.log(
            db=db,
            action="EXPOSURE_DRIFT_DETECTED",
            target_resource=target_resource,
            project_id=project_id,
            details={
                "drift_id": record.id,
                "drift_type": drift_type.value,
                "materiality": materiality.value,
                "reassessment_recommended": reassessment_recommended,
            },
        )
        return record

    @classmethod
    def _evaluate_stale_findings_for_removed_ports(
        cls,
        asset: Asset,
        removed_ports: set,
        db: Session,
    ) -> None:
        """Flags vulnerability findings whose underlying port or service was closed."""
        findings = db.query(VulnerabilityFinding).filter(
            VulnerabilityFinding.asset_id == asset.id,
            VulnerabilityFinding.status.in_([
                FindingLifecycleStatus.DETECTED,
                FindingLifecycleStatus.CONFIRMED,
                FindingLifecycleStatus.NEEDS_VALIDATION,
                FindingLifecycleStatus.REOPENED,
            ]),
        ).all()

        for f in findings:
            port_match = False
            matched_port = None
            for p in removed_ports:
                if f":{p}" in (f.target_value or ""):
                    port_match = True
                    matched_port = p
                    break

            if port_match:
                # Note finding as candidate stale without prematurely closing it
                f.validation_notes = f"[STALE CANDIDATE]: Underlying port {matched_port} was closed during drift evaluation."
                db.flush()
