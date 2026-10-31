import os
import json
import hashlib
import re
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional, Tuple
from sqlalchemy.orm import Session
from sqlalchemy import or_, and_

from app.models.threat_intel import (
    FeedSyncStatus,
    MatchClassification,
    ThreatIntelSource,
    ThreatIntelFeedRecord,
    ThreatIntelligenceRecord,
    ThreatCorrelationRecord,
)
from app.models.finding import VulnerabilityFinding, FindingLifecycleStatus
from app.models.assessment import FindingSeverity
from app.models.asset import Asset, AssetCriticality
from app.models.user import User

FIXTURES_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "fixtures", "threat_intel")
MAX_PAYLOAD_BYTES = 10 * 1024 * 1024  # 10 MB payload safety limit


def ensure_utc(dt: Optional[datetime]) -> Optional[datetime]:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def parse_version_tuple(v_str: str) -> Tuple[int, ...]:
    """Parse version string into tuple of integers for comparison, stripping build tags."""
    if not v_str:
        return ()
    # Extract only digit components separated by dots or dashes
    cleaned = re.split(r"[-_+~]", v_str.strip())[0]
    parts = re.findall(r"\d+", cleaned)
    try:
        return tuple(int(p) for p in parts)
    except Exception:
        return ()


def is_version_in_range(
    target_version: str,
    start_inc: Optional[str] = None,
    end_exc: Optional[str] = None,
    end_inc: Optional[str] = None,
    explicit_list: Optional[List[Any]] = None,
) -> bool:
    """Evaluate whether target_version falls within affected range."""
    if not target_version:
        return False
    if explicit_list:
        for entry in explicit_list:
            if isinstance(entry, str) and entry == target_version:
                return True
            elif isinstance(entry, dict):
                if is_version_in_range(
                    target_version,
                    start_inc=entry.get("version_start_including"),
                    end_exc=entry.get("version_end_excluding"),
                    end_inc=entry.get("version_end_including"),
                ):
                    return True

    t_tuple = parse_version_tuple(target_version)
    if not t_tuple:
        return False

    if start_inc:
        s_tuple = parse_version_tuple(start_inc)
        if s_tuple and t_tuple < s_tuple:
            return False

    if end_exc:
        e_tuple = parse_version_tuple(end_exc)
        if e_tuple and t_tuple >= e_tuple:
            return False

    if end_inc:
        ei_tuple = parse_version_tuple(end_inc)
        if ei_tuple and t_tuple > ei_tuple:
            return False

    # If bounds were specified and passed, return True
    return bool(start_inc or end_exc or end_inc)


def check_version_match(target_version: str, intel: ThreatIntelligenceRecord) -> bool:
    """Check if target_version matches primary range columns or any range in affected_versions_list."""
    if not target_version:
        return False
    if is_version_in_range(
        target_version,
        start_inc=intel.version_start_including,
        end_exc=intel.version_end_excluding,
        end_inc=intel.version_end_including,
    ):
        return True
    if intel.affected_versions_list and is_version_in_range(
        target_version,
        explicit_list=intel.affected_versions_list,
    ):
        return True
    return False


class ThreatIntelService:

    @staticmethod
    def get_or_create_feeds(db: Session) -> List[ThreatIntelFeedRecord]:
        """Seed default authoritative feeds if they do not exist."""
        defaults = [
            {
                "feed_name": "CISA_KEV",
                "feed_url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
                "is_authoritative": True,
                "stale_after_days": 7,
            },
            {
                "feed_name": "NVD_CVE",
                "feed_url": "https://services.nvd.nist.gov/rest/json/cves/2.0",
                "is_authoritative": True,
                "stale_after_days": 7,
            },
            {
                "feed_name": "EPSS",
                "feed_url": "https://api.first.org/data/v1/epss",
                "is_authoritative": True,
                "stale_after_days": 7,
            },
        ]
        feeds = []
        for d in defaults:
            feed = db.query(ThreatIntelFeedRecord).filter(ThreatIntelFeedRecord.feed_name == d["feed_name"]).first()
            if not feed:
                feed = ThreatIntelFeedRecord(
                    feed_name=d["feed_name"],
                    feed_url=d["feed_url"],
                    is_authoritative=d["is_authoritative"],
                    sync_status=FeedSyncStatus.STALE,
                    stale_after_days=d["stale_after_days"],
                    record_count=0,
                )
                db.add(feed)
                db.commit()
                db.refresh(feed)
            feeds.append(feed)
        return feeds

    @staticmethod
    def check_feed_freshness(feed: ThreatIntelFeedRecord) -> bool:
        """Evaluate if feed is stale based on last_synced_at and stale_after_days."""
        if not feed.last_synced_at:
            return True
        now = datetime.now(timezone.utc)
        synced_at = ensure_utc(feed.last_synced_at)
        diff = now - synced_at
        return diff.total_seconds() > (feed.stale_after_days * 86400)

    @classmethod
    def sync_feed(
        cls,
        db: Session,
        feed_name: str,
        force_local: bool = True,
        custom_payload: Optional[Dict[str, Any]] = None,
        max_bytes: int = MAX_PAYLOAD_BYTES,
    ) -> Dict[str, Any]:
        """
        Synchronize threat intelligence feed with validation, checksumming, size enforcement, and deduplication.
        """
        feed = db.query(ThreatIntelFeedRecord).filter(ThreatIntelFeedRecord.feed_name == feed_name).first()
        if not feed:
            cls.get_or_create_feeds(db)
            feed = db.query(ThreatIntelFeedRecord).filter(ThreatIntelFeedRecord.feed_name == feed_name).first()

        now = datetime.now(timezone.utc)
        feed.last_sync_started_at = now
        feed.sync_status = FeedSyncStatus.SYNCING
        db.commit()

        try:
            # 1. Acquire payload
            raw_bytes: bytes
            data: Dict[str, Any]

            if custom_payload is not None:
                raw_bytes = json.dumps(custom_payload).encode("utf-8")
                data = custom_payload
            elif force_local or not feed.feed_url:
                fixture_map = {
                    "CISA_KEV": "cisa_kev.json",
                    "NVD_CVE": "nvd_cve.json",
                    "EPSS": "epss_sample.json",
                }
                filename = fixture_map.get(feed_name)
                if not filename:
                    raise ValueError(f"No local fixture available for feed {feed_name}")
                filepath = os.path.join(FIXTURES_DIR, filename)
                if not os.path.exists(filepath):
                    raise FileNotFoundError(f"Fixture file missing: {filepath}")
                with open(filepath, "rb") as f:
                    raw_bytes = f.read()

                # Prompt 52: Deterministic Fault Injection Hooks (Test-Only)
                from app.core.fault_injection import FaultInjector
                FaultInjector.maybe_inject("provider:threat_feed", {"feed_name": feed_name})
                malformed_feed = FaultInjector.maybe_inject("provider:malformed_feed", {"feed_name": feed_name})
                if malformed_feed is not None:
                    raw_bytes = malformed_feed.encode("utf-8") if isinstance(malformed_feed, str) else malformed_feed

                data = json.loads(raw_bytes.decode("utf-8"))
            else:
                raise NotImplementedError("Direct live external network requests prohibited in isolated test gate")

            # 2. Check payload size limit
            if len(raw_bytes) > max_bytes:
                raise ValueError(f"Payload size {len(raw_bytes)} bytes exceeds limit {max_bytes} bytes")

            # 3. Compute SHA-256 Checksum
            checksum = hashlib.sha256(raw_bytes).hexdigest()

            # 4. Ingest according to schema
            records_ingested = 0
            records_updated = 0

            if feed_name == "CISA_KEV":
                vulns = data.get("vulnerabilities", [])
                for v in vulns:
                    cve_id = v.get("cveID", "").strip()
                    if not cve_id:
                        continue
                    vendor = v.get("vendorProject")
                    product = v.get("product")
                    title = v.get("vulnerabilityName")
                    desc = v.get("shortDescription")
                    action = v.get("requiredAction")
                    due_date_str = v.get("dueDate")
                    due_date = None
                    if due_date_str:
                        try:
                            due_date = datetime.strptime(due_date_str, "%Y-%m-%d").replace(tzinfo=timezone.utc)
                        except Exception:
                            pass

                    existing = db.query(ThreatIntelligenceRecord).filter(
                        ThreatIntelligenceRecord.cve_id == cve_id,
                        ThreatIntelligenceRecord.source == "CISA_KEV",
                    ).first()

                    if existing:
                        existing.title = title
                        existing.description = desc
                        existing.vendor = vendor
                        existing.product = product
                        existing.is_known_exploited = True
                        existing.cisa_kev_due_date = due_date
                        existing.cisa_kev_action = action
                        existing.raw_payload = v
                        existing.raw_payload_checksum = hashlib.sha256(json.dumps(v).encode("utf-8")).hexdigest()
                        existing.retrieved_at = now
                        records_updated += 1
                    else:
                        rec = ThreatIntelligenceRecord(
                            cve_id=cve_id,
                            source="CISA_KEV",
                            title=title,
                            description=desc,
                            vendor=vendor,
                            product=product,
                            is_known_exploited=True,
                            cisa_kev_due_date=due_date,
                            cisa_kev_action=action,
                            confidence=1.0,
                            provenance_url=v.get("notes"),
                            raw_payload=v,
                            raw_payload_checksum=hashlib.sha256(json.dumps(v).encode("utf-8")).hexdigest(),
                            retrieved_at=now,
                        )
                        db.add(rec)
                        records_ingested += 1

                    # Cross-enrich any existing NVD records for this CVE
                    nvd_matches = db.query(ThreatIntelligenceRecord).filter(
                        ThreatIntelligenceRecord.cve_id == cve_id,
                        ThreatIntelligenceRecord.source == "NVD_CVE",
                    ).all()
                    for nm in nvd_matches:
                        nm.is_known_exploited = True
                        nm.cisa_kev_due_date = due_date
                        nm.cisa_kev_action = action

            elif feed_name == "NVD_CVE":
                items = data.get("vulnerabilities", [])
                for item in items:
                    cve_obj = item.get("cve", {})
                    cve_id = cve_obj.get("id", "").strip()
                    if not cve_id:
                        continue
                    descs = cve_obj.get("descriptions", [])
                    desc_text = descs[0].get("value") if descs else ""

                    # Metrics & CVSS
                    cvss_score = None
                    cvss_vector = None
                    metrics = cve_obj.get("metrics", {})
                    v31 = metrics.get("cvssMetricV31", [])
                    if v31:
                        cdata = v31[0].get("cvssData", {})
                        cvss_score = cdata.get("baseScore")
                        cvss_vector = cdata.get("vectorString")

                    # CPE and affected range
                    vendor = None
                    product = None
                    cpe_str = None
                    version_start_inc = None
                    version_end_exc = None
                    version_end_inc = None
                    all_ranges = []

                    configs = cve_obj.get("configurations", [])
                    for conf in configs:
                        for node in conf.get("nodes", []):
                            for match in node.get("cpeMatch", []):
                                cpe = match.get("criteria", "")
                                if cpe and not cpe_str:
                                    cpe_str = cpe
                                    # parse cpe:2.3:part:vendor:product:...
                                    cpe_parts = cpe.split(":")
                                    if len(cpe_parts) >= 5:
                                        vendor = cpe_parts[3]
                                        product = cpe_parts[4]
                                s_inc = match.get("versionStartIncluding")
                                e_exc = match.get("versionEndExcluding")
                                e_inc = match.get("versionEndIncluding")
                                if s_inc or e_exc or e_inc:
                                    all_ranges.append({
                                        "version_start_including": s_inc,
                                        "version_end_excluding": e_exc,
                                        "version_end_including": e_inc,
                                    })
                                if not version_start_inc and s_inc:
                                    version_start_inc = s_inc
                                if not version_end_exc and e_exc:
                                    version_end_exc = e_exc
                                if not version_end_inc and e_inc:
                                    version_end_inc = e_inc

                    existing = db.query(ThreatIntelligenceRecord).filter(
                        ThreatIntelligenceRecord.cve_id == cve_id,
                        ThreatIntelligenceRecord.source == "NVD_CVE",
                    ).first()

                    # Check if already marked KEV in CISA
                    cisa_rec = db.query(ThreatIntelligenceRecord).filter(
                        ThreatIntelligenceRecord.cve_id == cve_id,
                        ThreatIntelligenceRecord.source == "CISA_KEV",
                    ).first()
                    is_kev = bool(cisa_rec and cisa_rec.is_known_exploited)

                    if existing:
                        existing.title = f"NVD Vulnerability {cve_id}"
                        existing.description = desc_text
                        existing.vendor = vendor or existing.vendor
                        existing.product = product or existing.product
                        existing.cpe = cpe_str or existing.cpe
                        existing.version_start_including = version_start_inc
                        existing.version_end_excluding = version_end_exc
                        existing.version_end_including = version_end_inc
                        existing.affected_versions_list = all_ranges
                        existing.cvss_score = cvss_score
                        existing.cvss_vector = cvss_vector
                        if is_kev:
                            existing.is_known_exploited = True
                            existing.cisa_kev_due_date = cisa_rec.cisa_kev_due_date
                            existing.cisa_kev_action = cisa_rec.cisa_kev_action
                        existing.raw_payload = item
                        existing.raw_payload_checksum = hashlib.sha256(json.dumps(item).encode("utf-8")).hexdigest()
                        existing.retrieved_at = now
                        records_updated += 1
                    else:
                        rec = ThreatIntelligenceRecord(
                            cve_id=cve_id,
                            source="NVD_CVE",
                            title=f"NVD Vulnerability {cve_id}",
                            description=desc_text,
                            vendor=vendor,
                            product=product,
                            cpe=cpe_str,
                            version_start_including=version_start_inc,
                            version_end_excluding=version_end_exc,
                            version_end_including=version_end_inc,
                            affected_versions_list=all_ranges,
                            cvss_score=cvss_score,
                            cvss_vector=cvss_vector,
                            is_known_exploited=is_kev,
                            cisa_kev_due_date=cisa_rec.cisa_kev_due_date if cisa_rec else None,
                            cisa_kev_action=cisa_rec.cisa_kev_action if cisa_rec else None,
                            confidence=1.0,
                            provenance_url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                            raw_payload=item,
                            raw_payload_checksum=hashlib.sha256(json.dumps(item).encode("utf-8")).hexdigest(),
                            retrieved_at=now,
                        )
                        db.add(rec)
                        records_ingested += 1

            elif feed_name == "EPSS":
                entries = data.get("data", [])
                for entry in entries:
                    cve_id = entry.get("cve", "").strip()
                    if not cve_id:
                        continue
                    try:
                        epss_score = float(entry.get("epss", 0.0))
                        epss_pct = float(entry.get("percentile", 0.0))
                    except (ValueError, TypeError):
                        continue

                    # Enrich all records matching cve_id
                    matches = db.query(ThreatIntelligenceRecord).filter(
                        ThreatIntelligenceRecord.cve_id == cve_id
                    ).all()
                    if matches:
                        for m in matches:
                            m.epss_score = epss_score
                            m.epss_percentile = epss_pct
                            records_updated += 1
                    else:
                        # Record EPSS entry standalone
                        rec = ThreatIntelligenceRecord(
                            cve_id=cve_id,
                            source="EPSS",
                            title=f"EPSS Score {cve_id}",
                            description=f"EPSS score: {epss_score}, percentile: {epss_pct}",
                            epss_score=epss_score,
                            epss_percentile=epss_pct,
                            confidence=1.0,
                            provenance_url="https://www.first.org/epss",
                            raw_payload=entry,
                            raw_payload_checksum=hashlib.sha256(json.dumps(entry).encode("utf-8")).hexdigest(),
                            retrieved_at=now,
                        )
                        db.add(rec)
                        records_ingested += 1

            # 5. Update feed record
            feed.feed_checksum = checksum
            feed.last_synced_at = now
            feed.sync_status = FeedSyncStatus.SYNCED
            feed.last_sync_error = None
            total_count = db.query(ThreatIntelligenceRecord).filter(
                ThreatIntelligenceRecord.source == feed_name
            ).count()
            feed.record_count = total_count

            db.commit()
            db.refresh(feed)

            return {
                "feed_name": feed_name,
                "records_ingested": records_ingested,
                "records_updated": records_updated,
                "sync_status": feed.sync_status,
                "checksum": checksum,
                "message": f"Successfully synced feed {feed_name}: {records_ingested} ingested, {records_updated} updated",
            }

        except Exception as e:
            db.rollback()
            feed.sync_status = FeedSyncStatus.ERROR
            feed.last_sync_error = str(e)
            db.commit()
            raise e

    @classmethod
    def evaluate_correlation(
        cls,
        finding: VulnerabilityFinding,
        intel: ThreatIntelligenceRecord,
        asset: Optional[Asset] = None,
    ) -> Tuple[MatchClassification, float, Dict[str, Any], float, Dict[str, Any]]:
        """
        Evidence-grounded correlation engine (Prompt 35).
        Enforces strict product identity and version boundaries.
        Rejects fuzzy product resemblance (Requirement 7).
        Calculates non-destructive risk enrichment factors without altering finding.severity.
        """
        evidence_grounding: Dict[str, Any] = {
            "matched_cve": intel.cve_id,
            "intel_source": intel.source,
            "intel_product": intel.product,
            "intel_vendor": intel.vendor,
            "vulnerable_range": {
                "version_start_including": intel.version_start_including,
                "version_end_excluding": intel.version_end_excluding,
                "version_end_including": intel.version_end_including,
            },
        }

        # 1. Product Identity and Resemblance Check (Requirement 7)
        # Extract product evidence from finding, asset attributes, or reproduction steps
        observed_product = None
        observed_version = None
        has_contradictions = bool(finding.has_contradictions)

        if asset and asset.attributes:
            observed_product = asset.attributes.get("product") or asset.attributes.get("service") or asset.attributes.get("software")
            observed_version = asset.attributes.get("version")

        if not observed_product and finding.target_value:
            # Check if target_value contains product hints
            tv = finding.target_value.lower()
            if intel.product and intel.product.lower() in tv:
                observed_product = intel.product

        # Strict Resemblance Check:
        # If product is similar/resembles (e.g. prefix/suffix/variation) but NOT an exact product match:
        # REJECT! Do NOT infer asset is vulnerable.
        intel_p_norm = (intel.product or "").lower().strip()
        obs_p_norm = (observed_product or "").lower().strip()

        resemblance_rejected = False
        resemblance_reason = "Product matches authoritative record"

        if obs_p_norm and intel_p_norm:
            # Check for false resemblance like 'openssl' vs 'libssl-wrapper' or 'java' vs 'javascript'
            if obs_p_norm != intel_p_norm:
                if (intel_p_norm in obs_p_norm or obs_p_norm in intel_p_norm) and abs(len(obs_p_norm) - len(intel_p_norm)) >= 3:
                    resemblance_rejected = True
                    resemblance_reason = f"Rejected resemblance: observed product '{observed_product}' is not an exact match for '{intel.product}'"

        evidence_grounding["resemblance_check"] = {
            "observed_product": observed_product,
            "authoritative_product": intel.product,
            "resemblance_rejected": resemblance_rejected,
            "resemblance_reason": resemblance_reason,
        }

        # 2. Match Classification Determination
        match_classification: MatchClassification
        confidence_score: float

        # Direct CVE match on finding.vuln_id
        is_direct_cve = bool(finding.vuln_id and finding.vuln_id.strip().upper() == intel.cve_id.strip().upper())

        if resemblance_rejected:
            match_classification = MatchClassification.UNKNOWN_MATCH
            confidence_score = 0.0
        elif has_contradictions:
            match_classification = MatchClassification.CONFLICTING_DATA
            confidence_score = 0.35
            evidence_grounding["conflict_details"] = finding.contradiction_notes or ["Conflicting scan adapter evidence reported on target"]
        elif is_direct_cve:
            has_bounds = bool(
                intel.version_start_including
                or intel.version_end_excluding
                or intel.version_end_including
                or intel.affected_versions_list
            )
            if observed_version and has_bounds:
                in_range = check_version_match(observed_version, intel)
                if in_range:
                    match_classification = MatchClassification.CONFIRMED_MATCH
                    confidence_score = 0.98
                    evidence_grounding["version_evidence"] = {
                        "observed_version": observed_version,
                        "in_range": True,
                        "status": "CONFIRMED_AFFECTED",
                    }
                else:
                    match_classification = MatchClassification.CONFLICTING_DATA
                    confidence_score = 0.40
                    evidence_grounding["version_evidence"] = {
                        "observed_version": observed_version,
                        "in_range": False,
                        "status": "VERSION_OUTSIDE_VULNERABLE_RANGE",
                    }
            else:
                # Direct CVE, but version bounds not defined on intel, or observed_version unconfirmed
                if getattr(intel, "is_known_exploited", False):
                    match_classification = MatchClassification.CONFIRMED_MATCH
                    confidence_score = 0.95
                    evidence_grounding["version_evidence"] = {
                        "observed_version": observed_version,
                        "in_range": True,
                        "status": "KEV_EXPLOITED_CVE_DIRECT_MATCH",
                    }
                else:
                    match_classification = MatchClassification.POSSIBLE_MATCH
                    confidence_score = 0.75
                    evidence_grounding["version_evidence"] = {
                        "observed_version": observed_version,
                        "status": "VERSION_UNSPECIFIED_IN_EVIDENCE" if not observed_version else "VERSION_BOUNDS_UNSPECIFIED_IN_INTEL",
                    }
        elif obs_p_norm and obs_p_norm == intel_p_norm:
            if observed_version:
                in_range = check_version_match(observed_version, intel)
                if in_range:
                    match_classification = MatchClassification.CONFIRMED_MATCH
                    confidence_score = 0.90
                    evidence_grounding["version_evidence"] = {
                        "observed_version": observed_version,
                        "in_range": True,
                        "status": "PRODUCT_AND_VERSION_MATCH_VULNERABLE_RANGE",
                    }
                else:
                    match_classification = MatchClassification.UNKNOWN_MATCH
                    confidence_score = 0.10
                    evidence_grounding["version_evidence"] = {
                        "observed_version": observed_version,
                        "in_range": False,
                        "status": "VERSION_NOT_VULNERABLE",
                    }
            else:
                match_classification = MatchClassification.POSSIBLE_MATCH
                confidence_score = 0.55
                evidence_grounding["version_evidence"] = {
                    "observed_version": None,
                    "status": "PRODUCT_MATCH_VERSION_MISSING",
                }
        else:
            match_classification = MatchClassification.UNKNOWN_MATCH
            confidence_score = 0.0
            evidence_grounding["status"] = "NO_PRODUCT_OR_CVE_AFFINITY"

        # 3. Non-Destructive Risk Enrichment Calculation (Requirement 8 & 9)
        # Authoritative finding.severity is strictly preserved and never mutated!
        base_sev_map = {
            FindingSeverity.CRITICAL: 80.0,
            FindingSeverity.HIGH: 60.0,
            FindingSeverity.MEDIUM: 40.0,
            FindingSeverity.LOW: 20.0,
            FindingSeverity.INFO: 5.0,
        }
        base_score = base_sev_map.get(finding.severity, 40.0)

        # Verified in-the-wild exploitation boost (CISA KEV)
        kev_boost = 25.0 if intel.is_known_exploited else 0.0

        # EPSS boost
        epss_boost = 0.0
        if intel.epss_score is not None:
            epss_boost = round(min(15.0, intel.epss_score * 15.0), 2)

        # Asset Criticality boost
        asset_boost = 0.0
        if asset:
            crit_map = {
                AssetCriticality.CRITICAL: 15.0,
                AssetCriticality.HIGH: 10.0,
                AssetCriticality.MEDIUM: 5.0,
                AssetCriticality.LOW: 0.0,
                AssetCriticality.INFO: 0.0,
            }
            asset_boost = crit_map.get(asset.criticality, 0.0)

        # Exposure boost (production environment or public internet)
        exposure_boost = 0.0
        if asset and asset.environment == "PRODUCTION":
            exposure_boost = 10.0

        # Match multiplier
        mult_map = {
            MatchClassification.CONFIRMED_MATCH: 1.0,
            MatchClassification.POSSIBLE_MATCH: 0.70,
            MatchClassification.CONFLICTING_DATA: 0.40,
            MatchClassification.UNKNOWN_MATCH: 0.10,
        }
        mult = mult_map.get(match_classification, 0.10)

        raw_enriched_score = (base_score + kev_boost + epss_boost + asset_boost + exposure_boost) * mult
        enriched_risk_score = round(max(0.0, min(100.0, raw_enriched_score)), 2)

        risk_enrichment_factors = {
            "base_finding_severity": finding.severity.value,
            "base_score": base_score,
            "is_known_exploited": intel.is_known_exploited,
            "cisa_kev_boost": kev_boost,
            "epss_score": intel.epss_score,
            "epss_boost": epss_boost,
            "asset_criticality": asset.criticality.value if asset else "UNKNOWN",
            "asset_criticality_boost": asset_boost,
            "exposure_boost": exposure_boost,
            "match_multiplier": mult,
            "unaltered_finding_severity": finding.severity.value,
            "explanation": (
                f"Finding severity remains '{finding.severity.value}'. Enriched risk score {enriched_risk_score}/100 "
                f"incorporates match classification '{match_classification.value}', "
                f"{'known in-the-wild exploitation (+25)' if intel.is_known_exploited else 'no verified active exploit'}, "
                f"EPSS score {intel.epss_score or 'N/A'} (+{epss_boost}), and asset context (+{asset_boost + exposure_boost})."
            ),
        }

        return match_classification, confidence_score, evidence_grounding, enriched_risk_score, risk_enrichment_factors

    @classmethod
    def correlate_project_findings(
        cls,
        db: Session,
        project_id: str,
        user: User,
        force_recorrelate: bool = False,
    ) -> Dict[str, Any]:
        """
        Correlate all active findings in a project with threat intelligence records.
        Creates or updates ThreatCorrelationRecord entries.
        """
        # Ensure feeds and fixtures exist
        cls.get_or_create_feeds(db)

        findings = db.query(VulnerabilityFinding).filter(
            VulnerabilityFinding.project_id == project_id,
            VulnerabilityFinding.status != FindingLifecycleStatus.VERIFIED_CLOSED,
        ).all()

        correlations_created = 0
        confirmed_count = 0
        possible_count = 0
        conflicting_count = 0
        unknown_rejected_count = 0

        now = datetime.now(timezone.utc)

        for finding in findings:
            # Query candidate threat records: by vuln_id, or by exact product in asset
            candidate_intels: List[ThreatIntelligenceRecord] = []

            if finding.vuln_id:
                direct_cves = db.query(ThreatIntelligenceRecord).filter(
                    ThreatIntelligenceRecord.cve_id == finding.vuln_id.strip()
                ).all()
                candidate_intels.extend(direct_cves)

            asset = finding.asset
            if asset and asset.attributes:
                p = asset.attributes.get("product") or asset.attributes.get("service")
                if p:
                    prod_matches = db.query(ThreatIntelligenceRecord).filter(
                        ThreatIntelligenceRecord.product == p.strip()
                    ).all()
                    for pm in prod_matches:
                        if pm not in candidate_intels:
                            candidate_intels.append(pm)

            for intel in candidate_intels:
                match_class, conf, evidence, enriched_score, factors = cls.evaluate_correlation(
                    finding, intel, asset
                )

                if match_class == MatchClassification.CONFIRMED_MATCH:
                    confirmed_count += 1
                elif match_class == MatchClassification.POSSIBLE_MATCH:
                    possible_count += 1
                elif match_class == MatchClassification.CONFLICTING_DATA:
                    conflicting_count += 1
                else:
                    unknown_rejected_count += 1

                # Idempotent upsert of correlation record
                corr = db.query(ThreatCorrelationRecord).filter(
                    ThreatCorrelationRecord.finding_id == finding.id,
                    ThreatCorrelationRecord.threat_intel_id == intel.id,
                ).first()

                if corr:
                    corr.match_classification = match_class
                    corr.confidence_score = conf
                    corr.evidence_grounding = evidence
                    corr.enriched_risk_score = enriched_score
                    corr.risk_enrichment_factors = factors
                    corr.correlated_at = now
                    corr.is_active = True
                else:
                    corr = ThreatCorrelationRecord(
                        project_id=project_id,
                        finding_id=finding.id,
                        threat_intel_id=intel.id,
                        match_classification=match_class,
                        confidence_score=conf,
                        evidence_grounding=evidence,
                        enriched_risk_score=enriched_score,
                        risk_enrichment_factors=factors,
                        correlated_at=now,
                        is_active=True,
                    )
                    db.add(corr)
                    correlations_created += 1

        db.commit()

        return {
            "project_id": project_id,
            "findings_evaluated": len(findings),
            "correlations_created": correlations_created,
            "confirmed_matches": confirmed_count,
            "possible_matches": possible_count,
            "conflicting_data": conflicting_count,
            "unknown_or_rejected": unknown_rejected_count,
            "message": f"Evaluated {len(findings)} findings: {confirmed_count} confirmed, {possible_count} possible, {conflicting_count} conflicting",
        }
