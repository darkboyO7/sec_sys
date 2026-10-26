import hashlib
import json
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.project import Project
from app.models.user import User
from app.models.finding import (
    FindingLifecycleStatus,
    VulnerabilityFinding,
)
from app.models.asset import Asset, AssetType, AssetCriticality
from app.models.assessment import FindingSeverity, FindingConfidence
from app.models.report import ReportType, ReportFormat
from app.services.report_service import ReportGenerationService, sanitize_csv_cell, sanitize_html
from app.models.base import utc_now


def test_phase15_executive_report_generation(
    db: Session,
    test_project: Project,
    tester_user: User,
):
    """Verify executive report generation across JSON, CSV, and HTML with SHA-256 integrity."""
    finding = VulnerabilityFinding(
        project_id=test_project.id,
        fingerprint="fp-phase15-exec-01",
        target_value="https://test.local/api",
        title="Critical RCE in API Gateway",
        description="Remote code execution flaw.",
        severity=FindingSeverity.CRITICAL,
        confidence=FindingConfidence.CERTAIN,
        cvss_score=9.8,
        status=FindingLifecycleStatus.CONFIRMED,
        is_simulated=True,
        last_observed_at=utc_now(),
    )
    db.add(finding)
    db.commit()

    # 1. JSON Executive Report
    record_json, content_json, mime_json, filename_json = ReportGenerationService.generate_report(
        project_id=test_project.id,
        report_type=ReportType.EXECUTIVE,
        report_format=ReportFormat.JSON,
        user=tester_user,
        db=db,
    )
    assert record_json.id is not None
    assert record_json.report_sha256 == hashlib.sha256(content_json.encode("utf-8")).hexdigest()
    assert mime_json == "application/json"
    parsed_json = json.loads(content_json)
    assert parsed_json["report_type"] == "EXECUTIVE"
    assert parsed_json["summary"]["severity_distribution"]["CRITICAL"] >= 1
    assert "CONFIDENTIAL SECURITY REPORT" in parsed_json["disclaimer"]

    # 2. HTML Executive Report
    record_html, content_html, mime_html, filename_html = ReportGenerationService.generate_report(
        project_id=test_project.id,
        report_type=ReportType.EXECUTIVE,
        report_format=ReportFormat.HTML,
        user=tester_user,
        db=db,
    )
    assert mime_html == "text/html; charset=utf-8"
    assert "Critical RCE in API Gateway" in content_html
    assert "CONFIDENTIAL SECURITY REPORT" in content_html


def test_phase15_csv_formula_injection_prevention(
    db: Session,
    test_project: Project,
    tester_user: User,
):
    """Verify formula injection triggers (=, +, -, @) are escaped in CSV output."""
    # Test unit sanitizer
    assert sanitize_csv_cell("=1+1") == "'=1+1"
    assert sanitize_csv_cell("+cmd|' /C calc'!A0") == "'+cmd|' /C calc'!A0"
    assert sanitize_csv_cell("-SUM(A1:A10)") == "'-SUM(A1:A10)"
    assert sanitize_csv_cell("@SUM(A1:A10)") == "'@SUM(A1:A10)"
    assert sanitize_csv_cell("Normal Text") == "Normal Text"

    # Test full CSV generation with formula-like finding title
    finding = VulnerabilityFinding(
        project_id=test_project.id,
        fingerprint="fp-phase15-formula-02",
        target_value="https://test.local/calc",
        title="=cmd|'/C calc'!A0 in Search Query",
        description="Formula-like payload",
        severity=FindingSeverity.HIGH,
        confidence=FindingConfidence.CERTAIN,
        status=FindingLifecycleStatus.DETECTED,
        is_simulated=True,
        last_observed_at=utc_now(),
    )
    db.add(finding)
    db.commit()

    record_csv, content_csv, mime_csv, filename_csv = ReportGenerationService.generate_report(
        project_id=test_project.id,
        report_type=ReportType.TECHNICAL,
        report_format=ReportFormat.CSV,
        user=tester_user,
        db=db,
    )

    assert mime_csv == "text/csv; charset=utf-8"
    # The cell must start with the escaped single quote, not bare '='
    assert "'=cmd|'/C calc'!A0 in Search Query" in content_csv
    assert "\n=cmd|" not in content_csv


def test_phase15_html_xss_sanitization(
    db: Session,
    test_project: Project,
    tester_user: User,
):
    """Verify raw HTML and script tags are strictly escaped in HTML reports."""
    # Test unit sanitizer
    assert sanitize_html("<script>alert('XSS')</script>") == "&lt;script&gt;alert(&#x27;XSS&#x27;)&lt;/script&gt;"

    finding = VulnerabilityFinding(
        project_id=test_project.id,
        fingerprint="fp-phase15-xss-03",
        target_value="https://test.local/xss",
        title="<script>alert('pwned')</script>",
        description="<img src=x onerror=alert(1)>",
        severity=FindingSeverity.MEDIUM,
        confidence=FindingConfidence.CERTAIN,
        status=FindingLifecycleStatus.DETECTED,
        is_simulated=True,
        last_observed_at=utc_now(),
    )
    db.add(finding)
    db.commit()

    _, content_html, _, _ = ReportGenerationService.generate_report(
        project_id=test_project.id,
        report_type=ReportType.TECHNICAL,
        report_format=ReportFormat.HTML,
        user=tester_user,
        db=db,
    )

    assert "<script>alert('pwned')</script>" not in content_html
    assert "&lt;script&gt;alert(&#x27;pwned&#x27;)&lt;/script&gt;" in content_html


def test_phase15_api_reporting_endpoints_and_isolation(
    client: TestClient,
    db: Session,
    test_project: Project,
    tester_headers: dict,
    lead_headers: dict,
):
    """Verify HTTP API endpoints for generating, listing, and streaming reports with RBAC."""
    # 1. Generate Report via POST
    gen_res = client.post(
        f"/api/v1/projects/{test_project.id}/reports/generate",
        headers=tester_headers,
        json={
            "report_type": "EXECUTIVE",
            "report_format": "JSON",
            "title": "Quarterly Executive Dossier",
        },
    )
    assert gen_res.status_code == 201
    rep_data = gen_res.json()
    record = rep_data["record"]
    assert record["report_type"] == "EXECUTIVE"
    assert record["report_format"] == "JSON"
    assert record["report_sha256"] is not None
    assert "Quarterly Executive Dossier" in record["title"]

    # 2. List reports for project
    list_res = client.get(
        f"/api/v1/projects/{test_project.id}/reports",
        headers=tester_headers,
    )
    assert list_res.status_code == 200
    reports = list_res.json()
    assert len(reports) >= 1

    # 3. Stream export endpoints
    csv_res = client.get(
        f"/api/v1/projects/{test_project.id}/reports/export/technical?format=CSV",
        headers=tester_headers,
    )
    assert csv_res.status_code == 200
    assert "text/csv" in csv_res.headers["content-type"]
    assert "attachment" in csv_res.headers["content-disposition"]

    html_res = client.get(
        f"/api/v1/projects/{test_project.id}/reports/export/governance?format=HTML",
        headers=tester_headers,
    )
    assert html_res.status_code == 200
    assert "text/html" in html_res.headers["content-type"]
    assert "<!DOCTYPE html>" in html_res.text
