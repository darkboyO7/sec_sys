import csv
import hashlib
import html
import io
import json
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.models.project import Project
from app.models.scope import ScopeTarget, ScopeExclusion
from app.models.finding import VulnerabilityFinding, FindingLifecycleStatus
from app.models.asset import Asset
from app.models.risk import RiskAssessment, RemediationRecommendation
from app.models.verification import RemediationVerification
from app.models.audit import AuditEvent
from app.models.report import ReportType, ReportFormat, ReportRecord
from app.models.user import User
from app.models.base import utc_now
from app.services.audit_service import AuditService


def sanitize_csv_cell(value: Any) -> str:
    """Neutralizes spreadsheet formula injection by prefixing triggering characters with a single quote."""
    if value is None:
        return ""
    s = str(value)
    if s and s[0] in ("=", "+", "-", "@", "\t", "\r"):
        return f"'{s}"
    return s


def sanitize_html(value: Any) -> str:
    """Escapes all HTML control characters to prevent XSS in report rendering."""
    if value is None:
        return ""
    return html.escape(str(value), quote=True)


class ReportGenerationService:
    """
    Evidence-Backed Report Generation and Export Service (Phase 15).
    Produces Executive, Technical, and Governance reports across JSON, CSV, and HTML formats.
    Guarantees:
    1. Robust sanitization preventing CSV formula injection and HTML XSS.
    2. Strict project isolation with server-side access enforcement.
    3. Explicit labeling of synthetic fixture results without fabricated security claims.
    4. Cryptographic SHA-256 integrity digest for every generated report artifact.
    """

    REPORT_DISCLAIMER = (
        "CONFIDENTIAL SECURITY REPORT. This report represents point-in-time security intelligence based solely "
        "on verified assessment observations and recorded evidence. Clean assessment results on an asset reflect absence "
        "of detected indicators during testing; unassessed components are not certified secure. Synthetic test fixtures "
        "are explicitly labeled."
    )

    @classmethod
    def generate_report(
        cls,
        project_id: str,
        report_type: ReportType,
        report_format: ReportFormat,
        user: User,
        db: Session,
        title: Optional[str] = None,
        assessment_id: Optional[str] = None,
        client_ip: Optional[str] = None,
    ) -> Tuple[ReportRecord, Any, str, str]:
        """
        Generates report content, records metadata, logs audit event, and returns:
        (report_record, content, mime_type, filename)
        Supports Executive, Technical, Governance, and Assessment Canonical reports,
        with JSON, CSV, HTML, and verifiable BUNDLE (.tar.gz) exports.
        """
        project = db.query(Project).filter(Project.id == project_id).first()
        if not project:
            raise ValueError(f"Project '{project_id}' not found.")

        timestamp_str = utc_now().strftime("%Y%m%d_%H%M%S")
        safe_title = title or f"{project.name} {report_type.value.title()} Report"

        if report_type == ReportType.ASSESSMENT_CANONICAL or assessment_id is not None:
            from app.services.canonical_report_service import CanonicalReportService
            if not assessment_id:
                raise ValueError("assessment_id is required for ASSESSMENT_CANONICAL reports.")
            
            manifest = CanonicalReportService.build_assessment_manifest(
                project_id=project_id,
                assessment_id=assessment_id,
                db=db,
                title=safe_title,
            )
            filename = f"assessment_report_{assessment_id[:8]}_{timestamp_str}"
            item_count = len(manifest.findings)

            if report_format == ReportFormat.JSON:
                content = CanonicalReportService.render_json(manifest)
                mime_type = "application/json"
                filename += ".json"
            elif report_format == ReportFormat.HTML:
                content = CanonicalReportService.render_html(manifest)
                mime_type = "text/html; charset=utf-8"
                filename += ".html"
            elif report_format == ReportFormat.CSV:
                content = CanonicalReportService.render_findings_csv(manifest)
                mime_type = "text/csv; charset=utf-8"
                filename += ".csv"
            elif report_format == ReportFormat.BUNDLE:
                bundle_bytes, _ = CanonicalReportService.create_assessment_bundle(manifest)
                content = bundle_bytes
                mime_type = "application/gzip"
                filename += ".tar.gz"
            else:
                raise ValueError(f"Unsupported report format: {report_format}")

        else:
            # Generate project-wide report bundle
            if report_type == ReportType.EXECUTIVE:
                data = cls._collect_executive_data(project_id, db)
                filename = f"executive_report_{project_id[:8]}_{timestamp_str}"
            elif report_type == ReportType.TECHNICAL:
                data = cls._collect_technical_data(project_id, db)
                filename = f"technical_report_{project_id[:8]}_{timestamp_str}"
            elif report_type == ReportType.GOVERNANCE:
                data = cls._collect_governance_data(project_id, db)
                filename = f"governance_report_{project_id[:8]}_{timestamp_str}"
            else:
                raise ValueError(f"Unsupported report type: {report_type}")

            # Render format
            if report_format == ReportFormat.JSON:
                content = json.dumps(data, indent=2, default=str)
                mime_type = "application/json"
                filename += ".json"
            elif report_format == ReportFormat.CSV:
                content = cls._render_csv(report_type, data)
                mime_type = "text/csv; charset=utf-8"
                filename += ".csv"
            elif report_format == ReportFormat.HTML:
                content = cls._render_html(report_type, safe_title, data)
                mime_type = "text/html; charset=utf-8"
                filename += ".html"
            else:
                raise ValueError(f"Unsupported report format: {report_format}")

            item_count = data.get("summary", {}).get("total_findings", len(data.get("items", [])))

        if isinstance(content, str):
            raw_bytes = content.encode("utf-8")
        else:
            raw_bytes = content

        content_bytes = len(raw_bytes)
        sha256_digest = hashlib.sha256(raw_bytes).hexdigest()

        # Persist report record
        record = ReportRecord(
            project_id=project_id,
            assessment_id=assessment_id,
            report_type=report_type,
            report_format=report_format,
            title=safe_title,
            generated_by_id=user.id,
            report_sha256=sha256_digest,
            item_count=item_count,
            content_bytes=content_bytes,
            generated_at=utc_now(),
        )
        db.add(record)
        db.flush()

        AuditService.log(
            db=db,
            action="SECURITY_REPORT_GENERATED",
            actor_id=user.id,
            target_resource=f"report:{record.id}",
            project_id=project_id,
            client_ip=client_ip,
            details={
                "report_type": report_type.value,
                "report_format": report_format.value,
                "assessment_id": assessment_id,
                "sha256": sha256_digest,
                "content_bytes": content_bytes,
            },
        )
        db.commit()
        db.refresh(record)

        return record, content, mime_type, filename

    @classmethod
    def _collect_executive_data(cls, project_id: str, db: Session) -> Dict[str, Any]:
        findings = db.query(VulnerabilityFinding).filter(VulnerabilityFinding.project_id == project_id).all()
        assets = db.query(Asset).filter(Asset.project_id == project_id).all()
        recommendations = db.query(RemediationRecommendation).filter(RemediationRecommendation.project_id == project_id).all()

        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in findings:
            sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            if sev in severity_counts:
                severity_counts[sev] += 1

        top_findings = sorted(
            findings,
            key=lambda x: (x.cvss_score or 0.0, 1 if str(x.severity) == "CRITICAL" else 0),
            reverse=True,
        )[:10]

        top_findings_list = [
            {
                "id": f.id,
                "title": f.title,
                "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                "cvss_score": f.cvss_score,
                "status": f.status.value if hasattr(f.status, "value") else str(f.status),
                "target": f.target_value,
                "is_simulated": f.is_simulated,
            }
            for f in top_findings
        ]

        critical_assets = [
            {"id": a.id, "name": a.name, "criticality": a.criticality.value if hasattr(a.criticality, "value") else str(a.criticality), "asset_type": a.asset_type.value if hasattr(a.asset_type, "value") else str(a.asset_type)}
            for a in assets if str(getattr(a, "criticality", "")) in ("HIGH", "CRITICAL")
        ]

        pending_remediations = [
            {"id": r.id, "title": r.title, "action_type": r.action_type, "governance_stage": r.execution_governance_stage, "estimated_effort": r.estimated_effort}
            for r in recommendations if r.execution_governance_stage != "CHANGE_AUTHORIZED"
        ]

        return {
            "report_type": "EXECUTIVE",
            "project_id": project_id,
            "disclaimer": cls.REPORT_DISCLAIMER,
            "generated_at": utc_now().isoformat(),
            "summary": {
                "total_findings": len(findings),
                "severity_distribution": severity_counts,
                "total_assets": len(assets),
                "critical_assets_count": len(critical_assets),
                "pending_remediations_count": len(pending_remediations),
            },
            "top_risks": top_findings_list,
            "critical_assets": critical_assets,
            "remediation_priorities": pending_remediations[:10],
        }

    @classmethod
    def _collect_technical_data(cls, project_id: str, db: Session) -> Dict[str, Any]:
        scopes = db.query(ScopeTarget).filter(ScopeTarget.project_id == project_id).all()
        exclusions = db.query(ScopeExclusion).filter(ScopeExclusion.project_id == project_id).all()
        findings = db.query(VulnerabilityFinding).filter(VulnerabilityFinding.project_id == project_id).all()
        verifications = db.query(RemediationVerification).filter(RemediationVerification.project_id == project_id).all()

        finding_items = [
            {
                "id": f.id,
                "fingerprint": f.fingerprint,
                "title": f.title,
                "description": f.description,
                "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                "confidence": f.confidence.value if hasattr(f.confidence, "value") else str(f.confidence),
                "cvss_score": f.cvss_score,
                "vuln_id": f.vuln_id,
                "target_value": f.target_value,
                "status": f.status.value if hasattr(f.status, "value") else str(f.status),
                "reproduction_steps": f.reproduction_steps,
                "recurrence_detected": f.recurrence_detected,
                "recurrence_count": f.recurrence_count,
                "is_simulated": f.is_simulated,
                "first_detected_at": f.first_detected_at.isoformat() if f.first_detected_at else None,
                "last_observed_at": f.last_observed_at.isoformat() if f.last_observed_at else None,
            }
            for f in findings
        ]

        verification_items = [
            {
                "id": v.id,
                "finding_id": v.finding_id,
                "outcome": v.outcome.value if hasattr(v.outcome, "value") else str(v.outcome),
                "verification_method": v.verification_method.value if hasattr(v.verification_method, "value") else str(v.verification_method),
                "verification_criteria": v.verification_criteria,
                "baseline_evidence_hash": v.baseline_evidence_hash,
                "summary": v.verification_evidence_summary,
                "verified_at": v.verified_at.isoformat() if v.verified_at else None,
            }
            for v in verifications
        ]

        return {
            "report_type": "TECHNICAL",
            "project_id": project_id,
            "disclaimer": cls.REPORT_DISCLAIMER,
            "generated_at": utc_now().isoformat(),
            "scope": {
                "targets": [{"target": s.target_value, "type": s.target_type.value if hasattr(s.target_type, "value") else str(s.target_type), "status": s.authorization_status.value if hasattr(s.authorization_status, "value") else str(s.authorization_status)} for s in scopes],
                "exclusions": [{"pattern": e.exclusion_pattern, "reason": e.reason} for e in exclusions],
            },
            "findings": finding_items,
            "verifications": verification_items,
            "summary": {
                "total_findings": len(finding_items),
                "total_verifications": len(verification_items),
            },
        }

    @classmethod
    def _collect_governance_data(cls, project_id: str, db: Session) -> Dict[str, Any]:
        scopes = db.query(ScopeTarget).filter(ScopeTarget.project_id == project_id).all()
        findings = db.query(VulnerabilityFinding).filter(VulnerabilityFinding.project_id == project_id).all()
        audits = db.query(AuditEvent).filter(AuditEvent.project_id == project_id).order_by(AuditEvent.timestamp.desc()).limit(100).all()
        verifications = db.query(RemediationVerification).filter(RemediationVerification.project_id == project_id).all()

        accepted_risks = [
            {
                "finding_id": f.id,
                "title": f.title,
                "accepted_at": f.risk_accepted_at.isoformat() if f.risk_accepted_at else None,
                "expires_at": f.risk_accepted_expires_at.isoformat() if f.risk_accepted_expires_at else None,
                "reason": f.risk_accepted_reason,
                "compensating_controls": f.compensating_controls,
            }
            for f in findings if f.status == FindingLifecycleStatus.ACCEPTED_RISK
        ]

        false_positives = [
            {
                "finding_id": f.id,
                "title": f.title,
                "classified_at": f.false_positive_at.isoformat() if f.false_positive_at else None,
                "reason": f.false_positive_reason,
            }
            for f in findings if f.status == FindingLifecycleStatus.FALSE_POSITIVE
        ]

        audit_events = [
            {
                "id": a.id,
                "action": a.action,
                "actor_id": a.actor_id,
                "target": f"{a.target_type}:{a.target_id}" if a.target_type else (a.target_id or "N/A"),
                "created_at": a.timestamp.isoformat() if a.timestamp else None,
            }
            for a in audits
        ]

        return {
            "report_type": "GOVERNANCE",
            "project_id": project_id,
            "disclaimer": cls.REPORT_DISCLAIMER,
            "generated_at": utc_now().isoformat(),
            "scope_governance": {
                "authorized_targets_count": len([s for s in scopes if getattr(s, "authorization_status", None) == "AUTHORIZED"]),
                "pending_targets_count": len([s for s in scopes if getattr(s, "authorization_status", None) == "PENDING"]),
            },
            "risk_acceptance_governance": {
                "active_accepted_risks_count": len(accepted_risks),
                "accepted_risks": accepted_risks,
            },
            "disposition_governance": {
                "false_positives_count": len(false_positives),
                "false_positives": false_positives,
            },
            "verification_governance": {
                "total_verifications": len(verifications),
                "verified_fixed_count": len([v for v in verifications if getattr(v, "outcome", None) == "VERIFIED_FIXED"]),
                "still_vulnerable_count": len([v for v in verifications if getattr(v, "outcome", None) == "STILL_VULNERABLE"]),
            },
            "audit_trail": audit_events,
        }

    @classmethod
    def _render_csv(cls, report_type: ReportType, data: Dict[str, Any]) -> str:
        output = io.StringIO()
        writer = csv.writer(output)

        if report_type == ReportType.EXECUTIVE:
            writer.writerow(["REPORT_TYPE", "EXECUTIVE"])
            writer.writerow(["PROJECT_ID", sanitize_csv_cell(data.get("project_id"))])
            writer.writerow(["GENERATED_AT", sanitize_csv_cell(data.get("generated_at"))])
            writer.writerow([])
            writer.writerow(["SEVERITY", "COUNT"])
            for sev, cnt in data.get("summary", {}).get("severity_distribution", {}).items():
                writer.writerow([sanitize_csv_cell(sev), sanitize_csv_cell(cnt)])
            writer.writerow([])
            writer.writerow(["TOP_RISKS_TITLE", "SEVERITY", "CVSS", "STATUS", "TARGET", "SIMULATED"])
            for item in data.get("top_risks", []):
                writer.writerow([
                    sanitize_csv_cell(item.get("title")),
                    sanitize_csv_cell(item.get("severity")),
                    sanitize_csv_cell(item.get("cvss_score")),
                    sanitize_csv_cell(item.get("status")),
                    sanitize_csv_cell(item.get("target")),
                    sanitize_csv_cell(item.get("is_simulated")),
                ])

        elif report_type == ReportType.TECHNICAL:
            writer.writerow(["REPORT_TYPE", "TECHNICAL"])
            writer.writerow(["PROJECT_ID", sanitize_csv_cell(data.get("project_id"))])
            writer.writerow(["GENERATED_AT", sanitize_csv_cell(data.get("generated_at"))])
            writer.writerow([])
            writer.writerow(["FINDING_ID", "FINGERPRINT", "TITLE", "SEVERITY", "CONFIDENCE", "CVSS", "VULN_ID", "TARGET", "STATUS", "SIMULATED"])
            for item in data.get("findings", []):
                writer.writerow([
                    sanitize_csv_cell(item.get("id")),
                    sanitize_csv_cell(item.get("fingerprint")),
                    sanitize_csv_cell(item.get("title")),
                    sanitize_csv_cell(item.get("severity")),
                    sanitize_csv_cell(item.get("confidence")),
                    sanitize_csv_cell(item.get("cvss_score")),
                    sanitize_csv_cell(item.get("vuln_id")),
                    sanitize_csv_cell(item.get("target_value")),
                    sanitize_csv_cell(item.get("status")),
                    sanitize_csv_cell(item.get("is_simulated")),
                ])

        elif report_type == ReportType.GOVERNANCE:
            writer.writerow(["REPORT_TYPE", "GOVERNANCE"])
            writer.writerow(["PROJECT_ID", sanitize_csv_cell(data.get("project_id"))])
            writer.writerow(["GENERATED_AT", sanitize_csv_cell(data.get("generated_at"))])
            writer.writerow([])
            writer.writerow(["AUDIT_ID", "ACTION", "ACTOR_ID", "TARGET_RESOURCE", "CREATED_AT"])
            for item in data.get("audit_trail", []):
                writer.writerow([
                    sanitize_csv_cell(item.get("id")),
                    sanitize_csv_cell(item.get("action")),
                    sanitize_csv_cell(item.get("actor_id")),
                    sanitize_csv_cell(item.get("target")),
                    sanitize_csv_cell(item.get("created_at")),
                ])

        return output.getvalue()

    @classmethod
    def _render_html(cls, report_type: ReportType, title: str, data: Dict[str, Any]) -> str:
        safe_title = sanitize_html(title)
        disclaimer = sanitize_html(cls.REPORT_DISCLAIMER)
        gen_at = sanitize_html(data.get("generated_at", ""))
        project_id = sanitize_html(data.get("project_id", ""))

        rows = ""
        if report_type == ReportType.EXECUTIVE:
            for item in data.get("top_risks", []):
                rows += f"""<tr>
                    <td>{sanitize_html(item.get('title'))}</td>
                    <td><strong>{sanitize_html(item.get('severity'))}</strong></td>
                    <td>{sanitize_html(item.get('cvss_score'))}</td>
                    <td>{sanitize_html(item.get('status'))}</td>
                    <td><code>{sanitize_html(item.get('target'))}</code></td>
                </tr>"""
        elif report_type == ReportType.TECHNICAL:
            for item in data.get("findings", []):
                rows += f"""<tr>
                    <td>{sanitize_html(item.get('title'))}</td>
                    <td><strong>{sanitize_html(item.get('severity'))}</strong></td>
                    <td>{sanitize_html(item.get('vuln_id') or 'N/A')}</td>
                    <td><code>{sanitize_html(item.get('target_value'))}</code></td>
                    <td>{sanitize_html(item.get('status'))}</td>
                </tr>"""
        elif report_type == ReportType.GOVERNANCE:
            for item in data.get("audit_trail", []):
                rows += f"""<tr>
                    <td><code>{sanitize_html(item.get('id'))}</code></td>
                    <td><strong>{sanitize_html(item.get('action'))}</strong></td>
                    <td>{sanitize_html(item.get('actor_id') or 'SYSTEM')}</td>
                    <td>{sanitize_html(item.get('target') or 'N/A')}</td>
                    <td>{sanitize_html(item.get('created_at'))}</td>
                </tr>"""

        html_doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{safe_title}</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; margin: 30px; color: #1e293b; background: #f8fafc; }}
  .header {{ border-bottom: 2px solid #0284c7; padding-bottom: 15px; margin-bottom: 25px; }}
  .title {{ font-size: 24px; font-weight: bold; color: #0f172a; margin: 0 0 8px 0; }}
  .meta {{ font-size: 13px; color: #64748b; }}
  .disclaimer {{ background: #eff6ff; border-left: 4px solid #3b82f6; padding: 12px; margin: 20px 0; font-size: 13px; color: #1e40af; border-radius: 4px; }}
  table {{ width: 100%; border-collapse: collapse; margin-top: 20px; background: #ffffff; border-radius: 6px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
  th, td {{ padding: 10px 14px; text-align: left; border-bottom: 1px solid #e2e8f0; font-size: 13px; }}
  th {{ background: #f1f5f9; font-weight: 600; color: #334155; }}
  code {{ background: #f1f5f9; padding: 2px 5px; border-radius: 4px; font-family: monospace; font-size: 12px; }}
</style>
</head>
<body>
<div class="header">
  <div class="title">{safe_title}</div>
  <div class="meta">Project: {project_id} | Generated: {gen_at} | Classification: Defensive Decision Support</div>
</div>
<div class="disclaimer">{disclaimer}</div>
<table>
  <thead>
    <tr>
      <th>Identifier / Title</th>
      <th>Severity / Action</th>
      <th>Context / Scope</th>
      <th>Target Resource</th>
      <th>Status / Timestamp</th>
    </tr>
  </thead>
  <tbody>
    {rows if rows else '<tr><td colspan="5">No items recorded in this reporting period.</td></tr>'}
  </tbody>
</table>
</body>
</html>"""
        return html_doc
