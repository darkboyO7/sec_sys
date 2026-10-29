"""
VAPT Platform — Automated API Contract Verification & Drift Detection Gate (Prompt 24).
Validates OpenAPI 3.1 schema integrity, matches frontend TypeScript client call-sites
to registered backend route definitions, and verifies enumeration consistency.
Outputs: api_contract_verification_report.json
"""
import sys
import os
import re
import json
from pathlib import Path
from typing import Dict, Any, List, Set

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "backend"))

REPORT_FILE = REPO_ROOT / "api_contract_verification_report.json"


def normalize_route_template(path: str) -> str:
    """Normalizes both FastAPI {param} and TypeScript ${param} into :param for matching."""
    # Remove query string interpolation expressions: ${qs...}, ${query...}, ${q...}
    path = re.sub(r"\$\{(?:qs|query|q)[^}]*\}", "", path)
    # Remove ${qs ? ...} style ternary expressions
    path = re.sub(r"\$\{[^}]*\?[^}]*\}", "", path)
    # Replace ${param} with :param
    normalized = re.sub(r"\$\{([^}]+)\}", r":\1", path)
    # Replace {param} with :param
    normalized = re.sub(r"\{([^}]+)\}", r":\1", normalized)
    # Remove query string if present
    normalized = normalized.split("?")[0]
    return normalized.rstrip("/")


def extract_frontend_api_calls(api_ts_path: Path) -> List[Dict[str, Any]]:
    """Extracts endpoint paths from frontend/src/services/api.ts."""
    content = api_ts_path.read_text(encoding="utf-8")
    calls = []

    # Match patterns like: this.request<Type>('/endpoint'...) or this.request(`/endpoint...`)
    pattern = re.compile(r"this\.request(?:<[^>]+>)?\(\s*[`'\"]([^`'\"]+)", re.MULTILINE)
    for match in pattern.finditer(content):
        raw_path = match.group(1)
        # Clean any trailing ternary or interpolation fragment
        raw_path = re.split(r"\$\{\s*(?:qs|query|q)\b", raw_path)[0]
        # Prepend /api/v1 if not present
        full_path = raw_path if raw_path.startswith("/api/v1") else f"/api/v1{raw_path}"
        calls.append({
            "raw": match.group(1),
            "normalized": normalize_route_template(full_path),
            "line": content[:match.start()].count("\n") + 1,
        })

    return calls


def extract_frontend_enums(types_ts_path: Path) -> Dict[str, Set[str]]:
    """Extracts type union enumerations from frontend/src/types/index.ts."""
    content = types_ts_path.read_text(encoding="utf-8")
    enums = {}

    target_types = [
        "SystemRole",
        "ProjectRole",
        "AssessmentStatus",
        "FindingSeverity",
        "FindingConfidence",
        "ApprovalWorkflowType",
        "GovernanceApprovalStatus",
        "TargetType",
        "AuthorizationStatus",
        "AssetCriticality",
        "AssetStatus",
        "ReportType",
        "ReportFormat",
        "AlertLifecycleStatus",
        "NotificationSeverity",
        "CaseSeverity",
        "CaseStatus",
        "ConnectorStatus",
        "ConnectorCapability",
        "ScheduleRunStatus",
        "RecoveryBundleStatus",
        "ThreatIntelSource",
        "ExperimentDecision",
        "SplitStrategy",
    ]

    for type_name in target_types:
        pattern = re.compile(rf"export type {type_name}\s*=\s*([^;]+);", re.MULTILINE)
        match = pattern.search(content)
        if match:
            raw_union = match.group(1)
            members = set(re.findall(r"['\"]([^'\"]+)['\"]", raw_union))
            enums[type_name] = members

    return enums


def main():
    print("=" * 80)
    print("   VAPT PLATFORM -- API CONTRACT & DRIFT VERIFICATION GATE")
    print("=" * 80)

    from app.main import app
    from app.models.user import SystemRole
    from app.models.project import ProjectRole
    from app.models.assessment import AssessmentStatus, FindingSeverity, FindingConfidence
    from app.models.governance import ApprovalWorkflowType, GovernanceApprovalStatus
    from app.models.scope import TargetType, AuthorizationStatus
    from app.models.asset import AssetCriticality, AssetStatus
    from app.models.report import ReportType, ReportFormat
    from app.models.notification import NotificationSeverity, AlertLifecycleStatus
    from app.models.incident import CaseSeverity, CaseStatus
    from app.models.connector import ConnectorStatus, ConnectorCapability
    from app.models.recovery import ScheduleRunStatus, RecoveryBundleStatus
    from app.models.threat_intel import ThreatIntelSource
    from app.models.model_experiment import ExperimentDecision, SplitStrategy

    # 1. Generate and inspect OpenAPI spec
    openapi_spec = app.openapi()
    paths = openapi_spec.get("paths", {})
    registered_routes = set()

    for path, methods in paths.items():
        norm = normalize_route_template(path)
        registered_routes.add(norm)

    print(f"[*] Registered backend OpenAPI routes: {len(paths)} endpoints")

    # 2. Inspect Frontend Call-Sites
    frontend_api_ts = REPO_ROOT / "frontend" / "src" / "services" / "api.ts"
    frontend_types_ts = REPO_ROOT / "frontend" / "src" / "types" / "index.ts"

    frontend_calls = extract_frontend_api_calls(frontend_api_ts)
    print(f"[*] Frontend client call-sites discovered: {len(frontend_calls)}")

    # 3. Match Call-Sites to Backend Routes
    unmatched_calls = []
    # Known exceptions or parameterized variations
    for call in frontend_calls:
        norm = call["normalized"]
        # Check direct match or parameter placeholder match
        matched = False
        if norm in registered_routes:
            matched = True
        else:
            # Fuzzy match parameter patterns (:id vs :project_id)
            call_segments = norm.split("/")
            for reg in registered_routes:
                reg_segments = reg.split("/")
                if len(call_segments) == len(reg_segments):
                    if all(c == r or (c.startswith(":") and r.startswith(":")) for c, r in zip(call_segments, reg_segments)):
                        matched = True
                        break

        if not matched:
            unmatched_calls.append(call)

    # 4. Verify Enums Consistency
    frontend_enums = extract_frontend_enums(frontend_types_ts)
    backend_enums = {
        "SystemRole": {r.value for r in SystemRole},
        "ProjectRole": {r.value for r in ProjectRole},
        "AssessmentStatus": {s.value for s in AssessmentStatus},
        "FindingSeverity": {s.value for s in FindingSeverity},
        "FindingConfidence": {c.value for c in FindingConfidence},
        "ApprovalWorkflowType": {w.value for w in ApprovalWorkflowType},
        "GovernanceApprovalStatus": {s.value for s in GovernanceApprovalStatus},
        "TargetType": {t.value for t in TargetType},
        "AuthorizationStatus": {a.value for a in AuthorizationStatus},
        "AssetCriticality": {c.value for c in AssetCriticality},
        "AssetStatus": {a.value for a in AssetStatus},
        "ReportType": {r.value for r in ReportType},
        "ReportFormat": {r.value for r in ReportFormat},
        "NotificationSeverity": {s.value for s in NotificationSeverity},
        "AlertLifecycleStatus": {s.value for s in AlertLifecycleStatus},
        "CaseSeverity": {s.value for s in CaseSeverity},
        "CaseStatus": {s.value for s in CaseStatus},
        "ConnectorStatus": {s.value for s in ConnectorStatus},
        "ConnectorCapability": {c.value for c in ConnectorCapability},
        "ScheduleRunStatus": {s.value for s in ScheduleRunStatus},
        "RecoveryBundleStatus": {s.value for s in RecoveryBundleStatus},
        "ThreatIntelSource": {s.value for s in ThreatIntelSource},
        "ExperimentDecision": {d.value for d in ExperimentDecision},
        "SplitStrategy": {s.value for s in SplitStrategy},
    }

    enum_mismatches = {}
    for enum_name, b_values in backend_enums.items():
        f_values = frontend_enums.get(enum_name, set())
        diff_b_not_f = b_values - f_values
        diff_f_not_b = f_values - b_values
        if diff_b_not_f or diff_f_not_b:
            enum_mismatches[enum_name] = {
                "in_backend_missing_in_frontend": list(diff_b_not_f),
                "in_frontend_missing_in_backend": list(diff_f_not_b),
            }

    # Summary
    passed = len(unmatched_calls) == 0 and len(enum_mismatches) == 0

    report = {
        "openapi_version": openapi_spec.get("openapi", "3.1.0"),
        "total_backend_routes": len(paths),
        "total_frontend_calls": len(frontend_calls),
        "unmatched_frontend_calls": unmatched_calls,
        "enum_mismatches": enum_mismatches,
        "status": "PASSED" if passed else "FAILED",
    }

    with open(REPORT_FILE, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print(f"[*] OpenAPI Schema Version: {report['openapi_version']}")
    print(f"[*] Route matching: {len(frontend_calls) - len(unmatched_calls)}/{len(frontend_calls)} verified")
    print(f"[*] Enumeration checks: {len(backend_enums) - len(enum_mismatches)}/{len(backend_enums)} verified")

    if unmatched_calls:
        print("[!] Unmatched Frontend API Calls:")
        for u in unmatched_calls:
            print(f"    - line {u['line']}: {u['raw']} -> {u['normalized']}")

    if enum_mismatches:
        print("[!] Enumeration Mismatches:")
        for k, v in enum_mismatches.items():
            print(f"    - {k}: {v}")

    print("=" * 80)
    decision = "PASSED" if passed else "FAILED"
    print(f"CONTRACT VERIFICATION RESULT: {decision}")
    print(f"Report written to: {REPORT_FILE}")
    print("=" * 80)

    sys.exit(0 if passed else 1)


if __name__ == "__main__":
    main()
