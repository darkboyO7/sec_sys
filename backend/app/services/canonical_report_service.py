"""
Canonical Assessment Report Service (Prompt 32).
Evidence-backed report generation, multi-format export, verifiable bundle packaging,
and validation-only archive inspection.
"""
import csv
import hashlib
import html
import io
import json
import re
import tarfile
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple
from sqlalchemy.orm import Session

from app.models.project import Project
from app.models.scope import ScopeTarget, ScopeExclusion
from app.models.assessment import AssessmentJob, AssessmentFinding, FindingEvidence, AssessmentStatus
from app.models.finding import VulnerabilityFinding, FindingLifecycleStatus
from app.models.asset import Asset
from app.models.risk import RemediationRecommendation
from app.models.verification import RemediationVerification
from app.models.audit import AuditEvent
from app.models.report import ReportType, ReportFormat, ReportRecord
from app.models.user import User
from app.models.base import utc_now
from app.services.audit_service import AuditService
from app.schemas.canonical_report import (
    CanonicalEvidenceRef,
    CanonicalFindingRecord,
    CanonicalAssetRecord,
    CanonicalRemediationRecord,
    CanonicalRetestRecord,
    ReportCoverageSummary,
    AssessmentReportManifest,
    AssessmentBundleManifest,
    BundleVerificationResult,
)


# Security limits for bundle import & inspection
MAX_BUNDLE_BYTES = 50 * 1024 * 1024            # 50 MB
MAX_FILE_BYTES = 20 * 1024 * 1024              # 20 MB per file
MAX_TOTAL_DECOMPRESSED_BYTES = 100 * 1024 * 1024  # 100 MB decompressed total (zip bomb protection)
MAX_FILE_COUNT = 50                            # max files in bundle


def sanitize_csv_cell(value: Any) -> str:
    """Neutralizes spreadsheet formula injection by prefixing triggering characters with a single quote."""
    if value is None:
        return ""
    s = str(value)
    if s and s[0] in ("=", "+", "-", "@", "\t", "\r"):
        return f"'{s}"
    return s


def sanitize_html(value: Any) -> str:
    """Escapes HTML control characters to prevent XSS in report rendering."""
    if value is None:
        return ""
    return html.escape(str(value), quote=True)


def redact_sensitive_strings(text: str) -> Tuple[str, bool]:
    """
    Explicitly redacts common secret tokens and authentication material.
    Returns (sanitized_text, was_redacted).
    """
    if not text:
        return "", False

    redacted = False
    patterns = [
        (r"(Bearer\s+)[A-Za-z0-9\-._~+/]+=*", r"\1[REDACTED_BEARER_TOKEN]"),
        (r"(api[_-]?key\s*[=:]\s*['\"]?)[A-Za-z0-9\-_]{8,}['\"]?", r"\1[REDACTED_API_KEY]"),
        (r"(password\s*[=:]\s*['\"]?)[^\s'\"]+['\"]?", r"\1[REDACTED_PASSWORD]"),
        (r"(secret\s*[=:]\s*['\"]?)[^\s'\"]+['\"]?", r"\1[REDACTED_SECRET]"),
        (r"-----BEGIN [A-Z ]+ PRIVATE KEY-----[\s\S]*?-----END [A-Z ]+ PRIVATE KEY-----", "[REDACTED_PRIVATE_KEY]"),
    ]

    sanitized = text
    for pattern, repl in patterns:
        new_text, count = re.subn(pattern, repl, sanitized, flags=re.IGNORECASE)
        if count > 0:
            sanitized = new_text
            redacted = True

    return sanitized, redacted


class CanonicalReportService:
    """
    Grounded Assessment Report Generation & Export Intelligence.
    Ensures:
    1. Truthful reflection of assessment coverage, missing evidence, and failed checks.
    2. Protection against CSV formula injection and HTML script execution.
    3. Portable assessment bundle packaging with cryptographic SHA-256 manifests.
    4. Safe, non-destructive (validation-only) bundle inspection with traversal and bomb defenses.
    """

    REPORT_DISCLAIMER = (
        "CONFIDENTIAL DEFENSIVE SECURITY ASSESSMENT REPORT. "
        "Findings and risk scores represent point-in-time observations derived strictly from recorded evidence. "
        "Absence of findings on an evaluated asset indicates that no matching vulnerability was observed during "
        "the authorized assessment window; unassessed components and surfaces are not certified secure."
    )

    @classmethod
    def build_assessment_manifest(
        cls,
        project_id: str,
        assessment_id: str,
        db: Session,
        title: Optional[str] = None,
    ) -> AssessmentReportManifest:
        """
        Builds the canonical report manifest from persisted DB entities.
        Verifies scope, coverage, missing evidence, and retest outcomes.
        """
        job = (
            db.query(AssessmentJob)
            .filter(AssessmentJob.id == assessment_id, AssessmentJob.project_id == project_id)
            .first()
        )
        if not job:
            raise ValueError(f"Assessment job '{assessment_id}' not found in project '{project_id}'.")

        project = db.query(Project).filter(Project.id == project_id).first()
        report_title = title or f"{project.name} Assessment Report - {job.target_input}"

        # 1. Scope & exclusions
        scope_targets = db.query(ScopeTarget).filter(ScopeTarget.project_id == project_id).all()
        exclusions = db.query(ScopeExclusion).filter(ScopeExclusion.project_id == project_id).all()

        scope_summary = {
            "target_input": job.target_input,
            "target_id": job.target_id,
            "policy_version": job.policy_version,
            "authorization_status": job.authorization_status,
            "authorized_targets_count": len(scope_targets),
            "exclusions_count": len(exclusions),
            "exclusions": [{"pattern": e.exclusion_pattern, "reason": e.reason} for e in exclusions],
        }

        # 2. Findings & Evidence
        raw_findings = (
            db.query(AssessmentFinding)
            .filter(AssessmentFinding.job_id == assessment_id)
            .all()
        )

        # Fallback/merge with project-level vulnerability findings for the target
        linked_vuln_findings = (
            db.query(VulnerabilityFinding)
            .filter(
                VulnerabilityFinding.project_id == project_id,
                VulnerabilityFinding.target_value == job.target_input,
            )
            .all()
        )

        remediations = db.query(RemediationRecommendation).filter(RemediationRecommendation.project_id == project_id).all()
        verifications = db.query(RemediationVerification).filter(RemediationVerification.project_id == project_id).all()
        assets = db.query(Asset).filter(Asset.project_id == project_id).all()

        canonical_findings: List[CanonicalFindingRecord] = []
        evidence_manifest: List[CanonicalEvidenceRef] = []
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        missing_evidence_count = 0

        # Build map of verifications by finding
        retest_map = {v.finding_id: v for v in verifications}
        remediation_map = {r.finding_id: r for r in remediations}

        # Process job assessment findings
        for f in raw_findings:
            sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            if sev in severity_counts:
                severity_counts[sev] += 1

            evidence_items = (
                db.query(FindingEvidence)
                .filter(FindingEvidence.finding_id == f.id)
                .all()
            )
            evidence_refs: List[str] = []
            has_missing = len(evidence_items) == 0
            if has_missing:
                missing_evidence_count += 1

            for ev in evidence_items:
                _, was_redacted = redact_sensitive_strings(ev.payload or "")
                ev_digest = (
                    getattr(ev, "sha256_hash", None)
                    or getattr(ev, "evidence_sha256", None)
                    or hashlib.sha256((ev.payload or "").encode("utf-8")).hexdigest()
                )
                ev_time = (
                    ev.observed_at.isoformat()
                    if hasattr(ev, "observed_at") and ev.observed_at
                    else (ev.collected_at.isoformat() if hasattr(ev, "collected_at") and ev.collected_at else utc_now().isoformat())
                )
                ev_ref = CanonicalEvidenceRef(
                    evidence_id=ev.id,
                    finding_id=f.id,
                    evidence_type=ev.evidence_type,
                    sha256_digest=ev_digest,
                    collected_at=ev_time,
                    source=f"assessment_probe:{job.adapter_name}",
                    redacted=was_redacted,
                )
                evidence_manifest.append(ev_ref)
                evidence_refs.append(ev.id)

            canonical_fid = getattr(f, "canonical_finding_id", None)
            retest = retest_map.get(f.id) or (retest_map.get(canonical_fid) if canonical_fid else None)
            remediation = remediation_map.get(f.id) or (remediation_map.get(canonical_fid) if canonical_fid else None)

            c_finding = CanonicalFindingRecord(
                id=f.id,
                fingerprint=getattr(f, "fingerprint", f"fp-{f.id[:8]}"),
                title=f.title,
                description=f.description or "",
                severity=sev,
                confidence=f.confidence.value if hasattr(f.confidence, "value") else str(f.confidence),
                cvss_score=f.cvss_score,
                target=f.target_value or job.target_input,
                status=getattr(f, "status", "DETECTED"),
                remediation_status=remediation.execution_governance_stage if remediation else None,
                retest_outcome=retest.outcome.value if retest and hasattr(retest.outcome, "value") else (str(retest.outcome) if retest else None),
                is_simulated=job.is_simulated,
                evidence_refs=evidence_refs,
                has_missing_evidence=has_missing,
                contradictory_evidence_noted=False,
                uncertainty_rationale=None,
                first_detected_at=job.started_at.isoformat() if job.started_at else None,
                last_observed_at=job.completed_at.isoformat() if job.completed_at else None,
            )
            canonical_findings.append(c_finding)

        # Merge linked vulnerability findings if no direct job findings existed
        if not canonical_findings and linked_vuln_findings:
            for vf in linked_vuln_findings:
                sev = vf.severity.value if hasattr(vf.severity, "value") else str(vf.severity)
                if sev in severity_counts:
                    severity_counts[sev] += 1
                retest = retest_map.get(vf.id)
                remediation = remediation_map.get(vf.id)
                c_finding = CanonicalFindingRecord(
                    id=vf.id,
                    fingerprint=vf.fingerprint,
                    title=vf.title,
                    description=vf.description or "",
                    severity=sev,
                    confidence=vf.confidence.value if hasattr(vf.confidence, "value") else str(vf.confidence),
                    cvss_score=vf.cvss_score,
                    target=vf.target_value,
                    status=vf.status.value if hasattr(vf.status, "value") else str(vf.status),
                    remediation_status=remediation.execution_governance_stage if remediation else None,
                    retest_outcome=retest.outcome.value if retest and hasattr(retest.outcome, "value") else (str(retest.outcome) if retest else None),
                    is_simulated=vf.is_simulated,
                    evidence_refs=[],
                    has_missing_evidence=True,
                    contradictory_evidence_noted=False,
                    uncertainty_rationale="Retrieved from project vulnerability ledger without direct job probe binding.",
                    first_detected_at=vf.first_detected_at.isoformat() if vf.first_detected_at else None,
                    last_observed_at=vf.last_observed_at.isoformat() if vf.last_observed_at else None,
                )
                canonical_findings.append(c_finding)
                missing_evidence_count += 1

        # 3. Coverage Analysis
        stats = job.summary_stats or {}
        attempted = stats.get("checks_attempted", len(canonical_findings) if len(canonical_findings) > 0 else 1)
        completed = stats.get("checks_completed", attempted if job.status == AssessmentStatus.COMPLETED else max(0, attempted - 1))
        failed_count = stats.get("checks_failed", 1 if job.status in (AssessmentStatus.FAILED, AssessmentStatus.TIMED_OUT) else 0)
        skipped = stats.get("skipped_checks", [])

        is_incomplete = job.status not in (AssessmentStatus.COMPLETED, AssessmentStatus.READY)
        coverage_gap = is_incomplete or failed_count > 0 or len(skipped) > 0 or missing_evidence_count > 0

        coverage = ReportCoverageSummary(
            assessment_id=job.id,
            target_input=job.target_input,
            status=job.status.value if hasattr(job.status, "value") else str(job.status),
            total_targets_assessed=1,
            total_checks_attempted=attempted,
            total_checks_completed=completed,
            checks_failed_count=failed_count,
            skipped_checks=skipped,
            missing_evidence_count=missing_evidence_count,
            coverage_gap_identified=coverage_gap,
            is_incomplete=is_incomplete,
            disclaimer=cls.REPORT_DISCLAIMER,
        )

        # 4. Canonical Assets
        canonical_assets: List[CanonicalAssetRecord] = []
        for a in assets:
            target_val = getattr(a, "canonical_identifier", None) or getattr(a, "target_value", None) or a.name or ""
            is_target_asset = bool(job.target_input and (job.target_input in a.name or job.target_input in target_val))
            canonical_assets.append(
                CanonicalAssetRecord(
                    id=a.id,
                    name=a.name,
                    target_value=target_val,
                    asset_type=a.asset_type.value if hasattr(a.asset_type, "value") else str(a.asset_type),
                    criticality=a.criticality.value if hasattr(a.criticality, "value") else str(a.criticality),
                    has_active_findings=any(f.target == target_val for f in canonical_findings),
                    assessment_covered=is_target_asset,
                )
            )

        # 5. Canonical Remediations and Retests
        finding_id_set = {cf.id for cf in canonical_findings}
        for f in raw_findings:
            if getattr(f, "canonical_finding_id", None):
                finding_id_set.add(f.canonical_finding_id)

        canonical_remediations = [
            CanonicalRemediationRecord(
                id=r.id,
                finding_id=r.finding_id or "",
                title=r.title,
                action_type=r.action_type,
                governance_stage=r.execution_governance_stage,
                status=r.status.value if hasattr(r.status, "value") else str(r.status),
            )
            for r in remediations
            if r.finding_id in finding_id_set
        ]

        canonical_retests = [
            CanonicalRetestRecord(
                id=v.id,
                finding_id=v.finding_id,
                outcome=v.outcome.value if hasattr(v.outcome, "value") else str(v.outcome),
                verification_method=v.verification_method.value if hasattr(v.verification_method, "value") else str(v.verification_method),
                verified_at=v.verified_at.isoformat() if v.verified_at else None,
            )
            for v in verifications
            if v.finding_id in finding_id_set
        ]

        # 6. Limitations Statement
        limitations: List[str] = []
        if is_incomplete:
            limitations.append(f"Assessment execution is incomplete with status '{coverage.status}'.")
        if failed_count > 0:
            limitations.append(f"{failed_count} assessment probes or verification steps encountered execution errors.")
        if skipped:
            limitations.append(f"The following probes were skipped due to scope/timing rules: {', '.join(skipped)}.")
        if missing_evidence_count > 0:
            limitations.append(f"{missing_evidence_count} finding(s) lack direct raw cryptographic evidence payloads.")
        limitations.append(
            "Defensive posture assurance is limited to evaluated target endpoints and the specified probe window."
        )

        # 7. Compute Deterministic Provenance Digest
        provenance_payload = {
            "project_id": project_id,
            "assessment_id": assessment_id,
            "status": coverage.status,
            "finding_count": len(canonical_findings),
            "severity_counts": severity_counts,
            "evidence_count": len(evidence_manifest),
            "coverage_gap": coverage_gap,
        }
        provenance_digest = hashlib.sha256(
            json.dumps(provenance_payload, sort_keys=True).encode("utf-8")
        ).hexdigest()

        methodology = {
            "adapter_name": job.adapter_name,
            "adapter_version": job.adapter_version,
            "policy_version": job.policy_version,
            "scoring_system": "CVSS_v3.1",
            "epistemic_validation_model": "deterministic-evidence-v2.1",
            "is_simulated": job.is_simulated,
        }

        return AssessmentReportManifest(
            schema_version="1.0.0",
            report_id=f"rep-{hashlib.sha256(f'{assessment_id}-{utc_now().isoformat()}'.encode('utf-8')).hexdigest()[:16]}",
            project_id=project_id,
            assessment_id=assessment_id,
            title=report_title,
            assessment_status=coverage.status,
            started_at=job.started_at.isoformat() if job.started_at else None,
            completed_at=job.completed_at.isoformat() if job.completed_at else None,
            generated_at=utc_now().isoformat(),
            methodology=methodology,
            scope_summary=scope_summary,
            coverage_summary=coverage,
            finding_counts_by_severity=severity_counts,
            findings=canonical_findings,
            assets=canonical_assets,
            remediation_summary=canonical_remediations,
            retest_verifications=canonical_retests,
            evidence_manifest=evidence_manifest,
            limitations=limitations,
            provenance_digest=provenance_digest,
        )

    @classmethod
    def render_json(cls, manifest: AssessmentReportManifest) -> str:
        """Renders deterministic, sorted JSON serialization of canonical report."""
        return json.dumps(manifest.model_dump(), indent=2, sort_keys=True, default=str)

    @classmethod
    def render_html(cls, manifest: AssessmentReportManifest) -> str:
        """Renders self-contained, sanitized HTML report with clear badges and coverage notice."""
        safe_title = sanitize_html(manifest.title)
        safe_disclaimer = sanitize_html(manifest.coverage_summary.disclaimer)
        cov = manifest.coverage_summary

        status_badge_color = "#10b981" if not cov.is_incomplete else "#f59e0b"
        if cov.status in ("FAILED", "TIMED_OUT"):
            status_badge_color = "#ef4444"

        # Findings table rows
        finding_rows = ""
        for f in manifest.findings:
            sev_color = {
                "CRITICAL": "#ef4444",
                "HIGH": "#f97316",
                "MEDIUM": "#eab308",
                "LOW": "#3b82f6",
                "INFO": "#64748b",
            }.get(f.severity, "#64748b")

            ev_status = (
                f'<span style="color:#10b981;">{len(f.evidence_refs)} items</span>'
                if not f.has_missing_evidence
                else '<span style="color:#ef4444;font-weight:600;">Missing</span>'
            )

            finding_rows += f"""<tr>
                <td><strong>{sanitize_html(f.title)}</strong><br><small style="color:#64748b;">FP: {sanitize_html(f.fingerprint)}</small></td>
                <td><span style="background:{sev_color};color:#ffffff;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700;">{sanitize_html(f.severity)}</span></td>
                <td>{sanitize_html(f.cvss_score or 'N/A')}</td>
                <td><code>{sanitize_html(f.target)}</code></td>
                <td>{sanitize_html(f.status)}</td>
                <td>{ev_status}</td>
                <td>{sanitize_html(f.retest_outcome or 'Not Retested')}</td>
            </tr>"""

        # Assets table rows
        asset_rows = ""
        for a in manifest.assets:
            cov_badge = (
                '<span style="color:#10b981;">Assessed</span>'
                if a.assessment_covered
                else '<span style="color:#94a3b8;">Out of Scope</span>'
            )
            asset_rows += f"""<tr>
                <td>{sanitize_html(a.name)}</td>
                <td><code>{sanitize_html(a.target_value)}</code></td>
                <td>{sanitize_html(a.asset_type)}</td>
                <td><strong>{sanitize_html(a.criticality)}</strong></td>
                <td>{cov_badge}</td>
            </tr>"""

        limitations_html = "".join([f"<li>{sanitize_html(l)}</li>" for l in manifest.limitations])

        incomplete_banner = ""
        if cov.is_incomplete or cov.coverage_gap_identified:
            incomplete_banner = f"""
            <div style="background:#fffbeb;border:1px solid #fef3c7;border-left:4px solid #f59e0b;padding:12px;margin:16px 0;border-radius:6px;color:#92400e;">
                <strong>Notice of Assessment Constraints:</strong> This assessment has status <code>{sanitize_html(cov.status)}</code>.
                Probes completed: {cov.total_checks_completed}/{cov.total_checks_attempted}. Missing evidence count: {cov.missing_evidence_count}.
                Do not interpret partial completion as certification of security posture.
            </div>"""

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{safe_title}</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; margin: 30px; color: #1e293b; background: #f8fafc; line-height: 1.5; }}
  .header {{ border-bottom: 2px solid #0284c7; padding-bottom: 16px; margin-bottom: 24px; }}
  .title {{ font-size: 24px; font-weight: bold; color: #0f172a; margin: 0 0 6px 0; }}
  .meta {{ font-size: 13px; color: #64748b; }}
  .kpi-container {{ display: flex; gap: 16px; margin: 20px 0; }}
  .kpi-card {{ flex: 1; background: #ffffff; padding: 14px; border-radius: 8px; border: 1px solid #e2e8f0; }}
  .kpi-val {{ font-size: 22px; font-weight: bold; color: #0f172a; }}
  .kpi-label {{ font-size: 12px; color: #64748b; text-transform: uppercase; margin-top: 4px; }}
  .disclaimer {{ background: #eff6ff; border-left: 4px solid #3b82f6; padding: 12px; margin: 16px 0; font-size: 13px; color: #1e40af; border-radius: 4px; }}
  table {{ width: 100%; border-collapse: collapse; margin-top: 16px; background: #ffffff; border-radius: 6px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,0.06); }}
  th, td {{ padding: 10px 14px; text-align: left; border-bottom: 1px solid #e2e8f0; font-size: 13px; }}
  th {{ background: #f1f5f9; font-weight: 600; color: #334155; }}
  code {{ background: #f1f5f9; padding: 2px 5px; border-radius: 4px; font-family: monospace; font-size: 12px; }}
  .section-title {{ font-size: 16px; font-weight: 700; color: #0f172a; margin-top: 32px; }}
  ul {{ padding-left: 20px; font-size: 13px; color: #475569; }}
</style>
</head>
<body>
<div class="header">
  <div class="title">{safe_title}</div>
  <div class="meta">
    Project: {sanitize_html(manifest.project_id)} | Assessment: {sanitize_html(manifest.assessment_id)} | 
    Status: <span style="background:{status_badge_color};color:#ffffff;padding:2px 6px;border-radius:4px;font-size:11px;">{sanitize_html(cov.status)}</span> | 
    Generated: {sanitize_html(manifest.generated_at)}
  </div>
</div>

{incomplete_banner}

<div class="disclaimer">
  <strong>Coverage Statement:</strong> {safe_disclaimer}
</div>

<div class="kpi-container">
  <div class="kpi-card">
    <div class="kpi-val">{len(manifest.findings)}</div>
    <div class="kpi-label">Total Findings</div>
  </div>
  <div class="kpi-card">
    <div class="kpi-val" style="color:#ef4444;">{manifest.finding_counts_by_severity.get('CRITICAL', 0)}</div>
    <div class="kpi-label">Critical Findings</div>
  </div>
  <div class="kpi-card">
    <div class="kpi-val" style="color:#f97316;">{manifest.finding_counts_by_severity.get('HIGH', 0)}</div>
    <div class="kpi-label">High Findings</div>
  </div>
  <div class="kpi-card">
    <div class="kpi-val">{cov.total_checks_completed}/{cov.total_checks_attempted}</div>
    <div class="kpi-label">Probes Completed</div>
  </div>
  <div class="kpi-card">
    <div class="kpi-val">{len(manifest.evidence_manifest)}</div>
    <div class="kpi-label">Evidence Artifacts</div>
  </div>
</div>

<div class="section-title">Verified Assessment Findings</div>
<table>
  <thead>
    <tr>
      <th>Finding / Fingerprint</th>
      <th>Severity</th>
      <th>CVSS</th>
      <th>Target Resource</th>
      <th>Status</th>
      <th>Evidence Items</th>
      <th>Retest Outcome</th>
    </tr>
  </thead>
  <tbody>
    {finding_rows if finding_rows else '<tr><td colspan="7">No vulnerabilities detected for this target during evaluation.</td></tr>'}
  </tbody>
</table>

<div class="section-title">Asset Inventory & Evaluation Scope</div>
<table>
  <thead>
    <tr>
      <th>Asset Name</th>
      <th>Target Endpoint</th>
      <th>Asset Type</th>
      <th>Criticality</th>
      <th>Assessment Coverage</th>
    </tr>
  </thead>
  <tbody>
    {asset_rows if asset_rows else '<tr><td colspan="5">No assets registered for this project.</td></tr>'}
  </tbody>
</table>

<div class="section-title">Known Limitations & Epistemic Boundaries</div>
<ul>
  {limitations_html}
</ul>

<div style="margin-top:40px;font-size:11px;color:#94a3b8;font-family:monospace;border-top:1px solid #e2e8f0;padding-top:12px;">
  Cryptographic Provenance Digest: {sanitize_html(manifest.provenance_digest)} | Exporter: VAPT-Report-Gen-3.2
</div>
</body>
</html>"""

    @classmethod
    def render_findings_csv(cls, manifest: AssessmentReportManifest) -> str:
        """Renders sanitized CSV export for findings, preventing formula injection."""
        output = io.StringIO()
        writer = csv.writer(output)

        writer.writerow(["REPORT_ID", sanitize_csv_cell(manifest.report_id)])
        writer.writerow(["ASSESSMENT_ID", sanitize_csv_cell(manifest.assessment_id)])
        writer.writerow(["TARGET", sanitize_csv_cell(manifest.coverage_summary.target_input)])
        writer.writerow(["GENERATED_AT", sanitize_csv_cell(manifest.generated_at)])
        writer.writerow([])
        writer.writerow([
            "FINDING_ID",
            "FINGERPRINT",
            "TITLE",
            "SEVERITY",
            "CONFIDENCE",
            "CVSS",
            "TARGET",
            "STATUS",
            "EVIDENCE_ITEMS_COUNT",
            "HAS_MISSING_EVIDENCE",
            "RETEST_OUTCOME",
            "SIMULATED",
            "FIRST_DETECTED",
            "LAST_OBSERVED",
        ])

        for f in manifest.findings:
            writer.writerow([
                sanitize_csv_cell(f.id),
                sanitize_csv_cell(f.fingerprint),
                sanitize_csv_cell(f.title),
                sanitize_csv_cell(f.severity),
                sanitize_csv_cell(f.confidence),
                sanitize_csv_cell(f.cvss_score),
                sanitize_csv_cell(f.target),
                sanitize_csv_cell(f.status),
                sanitize_csv_cell(len(f.evidence_refs)),
                sanitize_csv_cell(f.has_missing_evidence),
                sanitize_csv_cell(f.retest_outcome or "NOT_RETESTED"),
                sanitize_csv_cell(f.is_simulated),
                sanitize_csv_cell(f.first_detected_at),
                sanitize_csv_cell(f.last_observed_at),
            ])

        return output.getvalue()

    @classmethod
    def render_assets_csv(cls, manifest: AssessmentReportManifest) -> str:
        """Renders sanitized CSV export for assets, preventing formula injection."""
        output = io.StringIO()
        writer = csv.writer(output)

        writer.writerow(["REPORT_ID", sanitize_csv_cell(manifest.report_id)])
        writer.writerow(["ASSESSMENT_ID", sanitize_csv_cell(manifest.assessment_id)])
        writer.writerow(["GENERATED_AT", sanitize_csv_cell(manifest.generated_at)])
        writer.writerow([])
        writer.writerow([
            "ASSET_ID",
            "NAME",
            "TARGET_VALUE",
            "ASSET_TYPE",
            "CRITICALITY",
            "HAS_ACTIVE_FINDINGS",
            "ASSESSMENT_COVERED",
        ])

        for a in manifest.assets:
            writer.writerow([
                sanitize_csv_cell(a.id),
                sanitize_csv_cell(a.name),
                sanitize_csv_cell(a.target_value),
                sanitize_csv_cell(a.asset_type),
                sanitize_csv_cell(a.criticality),
                sanitize_csv_cell(a.has_active_findings),
                sanitize_csv_cell(a.assessment_covered),
            ])

        return output.getvalue()

    @classmethod
    def create_assessment_bundle(
        cls,
        manifest: AssessmentReportManifest,
    ) -> Tuple[bytes, AssessmentBundleManifest]:
        """
        Creates a verifiable portable assessment bundle (.tar.gz) containing:
        - report.json: Canonical assessment manifest
        - findings.json: Findings list with evidence pointers
        - evidence_manifest.json: Cryptographic digests and collection times of evidence
        - assets.json: Evaluated asset inventory
        - verifications.json: Retest and verification outcomes
        - sha256sums.txt: Standard checksum file
        - manifest.json: Bundle metadata and file integrity mapping
        """
        report_json_bytes = cls.render_json(manifest).encode("utf-8")
        findings_json_bytes = json.dumps([f.model_dump() for f in manifest.findings], indent=2, sort_keys=True).encode("utf-8")
        evidence_json_bytes = json.dumps([e.model_dump() for e in manifest.evidence_manifest], indent=2, sort_keys=True).encode("utf-8")
        assets_json_bytes = json.dumps([a.model_dump() for a in manifest.assets], indent=2, sort_keys=True).encode("utf-8")
        verifications_json_bytes = json.dumps([v.model_dump() for v in manifest.retest_verifications], indent=2, sort_keys=True).encode("utf-8")

        # Map files to contents and SHA-256 digests
        file_map = {
            "report.json": report_json_bytes,
            "findings.json": findings_json_bytes,
            "evidence_manifest.json": evidence_json_bytes,
            "assets.json": assets_json_bytes,
            "verifications.json": verifications_json_bytes,
        }

        digests: Dict[str, str] = {}
        sha256sums_lines = []
        for fname in sorted(file_map.keys()):
            h = hashlib.sha256(file_map[fname]).hexdigest()
            digests[fname] = h
            sha256sums_lines.append(f"{h}  {fname}")

        sha256sums_bytes = ("\n".join(sha256sums_lines) + "\n").encode("utf-8")
        file_map["sha256sums.txt"] = sha256sums_bytes
        digests["sha256sums.txt"] = hashlib.sha256(sha256sums_bytes).hexdigest()

        # Bundle manifest
        bundle_manifest = AssessmentBundleManifest(
            manifest_version="1.0.0",
            bundle_version="1.0.0",
            report_id=manifest.report_id,
            assessment_id=manifest.assessment_id,
            project_id=manifest.project_id,
            exported_at=utc_now().isoformat(),
            exporter_version="vapt-bundle-exporter-3.2.0",
            files=digests,
            integrity_digest=digests["sha256sums.txt"],
        )
        bundle_manifest_bytes = json.dumps(bundle_manifest.model_dump(), indent=2, sort_keys=True).encode("utf-8")
        file_map["manifest.json"] = bundle_manifest_bytes
        digests["manifest.json"] = hashlib.sha256(bundle_manifest_bytes).hexdigest()

        # Write to in-memory tar.gz archive
        archive_buffer = io.BytesIO()
        with tarfile.open(fileobj=archive_buffer, mode="w:gz") as tar:
            for fname in sorted(file_map.keys()):
                data = file_map[fname]
                ti = tarfile.TarInfo(name=fname)
                ti.size = len(data)
                ti.mtime = int(datetime.now(timezone.utc).timestamp())
                ti.mode = 0o644
                ti.uid = 0
                ti.gid = 0
                ti.uname = "vapt"
                ti.gname = "vapt"
                tar.addfile(ti, io.BytesIO(data))

        return archive_buffer.getvalue(), bundle_manifest

    @classmethod
    def verify_assessment_bundle(
        cls,
        bundle_bytes: bytes,
    ) -> BundleVerificationResult:
        """
        Safe, validation-only inspection of an assessment bundle archive.
        Checks:
        1. Size limits (archive, decompressed total, per-file).
        2. Path traversal attempts (relative paths with .., absolute paths, leading slashes).
        3. File count limits (zip bomb defense).
        4. Schema & bundle versions.
        5. Cryptographic SHA-256 digest consistency against manifest.
        6. Guarantees zero side-effects on existing database records.
        """
        violations: List[str] = []
        corrupted_files: List[str] = []
        missing_files: List[str] = []
        checked_files: List[str] = []

        if len(bundle_bytes) > MAX_BUNDLE_BYTES:
            return BundleVerificationResult(
                is_valid=False,
                violations=[f"Archive size ({len(bundle_bytes)} bytes) exceeds limit ({MAX_BUNDLE_BYTES} bytes)."],
            )

        try:
            archive_stream = io.BytesIO(bundle_bytes)
            with tarfile.open(fileobj=archive_stream, mode="r:gz") as tar:
                members = tar.getmembers()

                if len(members) > MAX_FILE_COUNT:
                    return BundleVerificationResult(
                        is_valid=False,
                        violations=[f"Archive member count ({len(members)}) exceeds limit ({MAX_FILE_COUNT})."],
                    )

                total_decompressed = 0
                file_contents: Dict[str, bytes] = {}

                for m in members:
                    # Traversal defense: no absolute paths, no .. segments, no drive letters
                    norm_name = m.name.replace("\\", "/")
                    if (
                        norm_name.startswith("/")
                        or norm_name.startswith("../")
                        or "/../" in norm_name
                        or norm_name.endswith("/..")
                        or ":" in norm_name
                    ):
                        violations.append(f"Illegal path traversal detected in member: '{m.name}'.")
                        continue

                    if m.size > MAX_FILE_BYTES:
                        violations.append(f"Member '{m.name}' size ({m.size} bytes) exceeds limit ({MAX_FILE_BYTES} bytes).")
                        continue

                    total_decompressed += m.size
                    if total_decompressed > MAX_TOTAL_DECOMPRESSED_BYTES:
                        return BundleVerificationResult(
                            is_valid=False,
                            violations=[f"Decompressed archive size exceeds safety limit ({MAX_TOTAL_DECOMPRESSED_BYTES} bytes)."],
                        )

                    if m.isfile():
                        f = tar.extractfile(m)
                        if f:
                            file_contents[norm_name] = f.read()

                if violations:
                    return BundleVerificationResult(
                        is_valid=False,
                        file_count=len(file_contents),
                        total_decompressed_bytes=total_decompressed,
                        violations=violations,
                    )

                # Check required files
                if "manifest.json" not in file_contents:
                    return BundleVerificationResult(
                        is_valid=False,
                        violations=["Missing mandatory 'manifest.json' in bundle root."],
                        file_count=len(file_contents),
                        total_decompressed_bytes=total_decompressed,
                    )

                # Parse manifest.json
                try:
                    manifest_data = json.loads(file_contents["manifest.json"].decode("utf-8"))
                except Exception as e:
                    return BundleVerificationResult(
                        is_valid=False,
                        violations=[f"Malformed 'manifest.json' JSON syntax: {str(e)}"],
                        file_count=len(file_contents),
                        total_decompressed_bytes=total_decompressed,
                    )

                schema_version = manifest_data.get("manifest_version")
                bundle_version = manifest_data.get("bundle_version")
                if schema_version != "1.0.0" or bundle_version != "1.0.0":
                    violations.append(
                        f"Unsupported bundle/manifest schema version ('{schema_version}', '{bundle_version}'). Expected '1.0.0'."
                    )

                expected_files: Dict[str, str] = manifest_data.get("files", {})

                # Verify each file against manifest digest
                for fname, expected_hash in expected_files.items():
                    if fname == "manifest.json":
                        continue  # manifest contains digest of others
                    checked_files.append(fname)
                    if fname not in file_contents:
                        missing_files.append(fname)
                        continue

                    actual_hash = hashlib.sha256(file_contents[fname]).hexdigest()
                    if actual_hash != expected_hash:
                        corrupted_files.append(fname)

                # Summary info from report.json if present
                assessment_summary = None
                if "report.json" in file_contents:
                    try:
                        rep_data = json.loads(file_contents["report.json"].decode("utf-8"))
                        assessment_summary = {
                            "report_id": rep_data.get("report_id"),
                            "assessment_id": rep_data.get("assessment_id"),
                            "status": rep_data.get("assessment_status"),
                            "title": rep_data.get("title"),
                            "findings_count": len(rep_data.get("findings", [])),
                            "severity_distribution": rep_data.get("finding_counts_by_severity", {}),
                            "coverage_gap": rep_data.get("coverage_summary", {}).get("coverage_gap_identified", False),
                        }
                    except Exception:
                        pass

                is_valid = (len(violations) == 0 and len(corrupted_files) == 0 and len(missing_files) == 0)

                return BundleVerificationResult(
                    is_valid=is_valid,
                    manifest_version=schema_version,
                    bundle_version=bundle_version,
                    assessment_id=manifest_data.get("assessment_id"),
                    project_id=manifest_data.get("project_id"),
                    file_count=len(file_contents),
                    total_decompressed_bytes=total_decompressed,
                    checked_files=checked_files,
                    corrupted_files=corrupted_files,
                    missing_files=missing_files,
                    violations=violations,
                    assessment_summary=assessment_summary,
                    inspection_mode="validation_only",
                )

        except tarfile.TarError as e:
            return BundleVerificationResult(
                is_valid=False,
                violations=[f"Corrupted or invalid tar.gz archive stream: {str(e)}"],
            )
        except Exception as e:
            return BundleVerificationResult(
                is_valid=False,
                violations=[f"Verification failed with unexpected error: {str(e)}"],
            )
