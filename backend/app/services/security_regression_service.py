"""
VAPT Platform — Security Regression & Control Verification Service (Prompt 47).
Manages execution, machine-readable reporting, and evidence tracking for the
automated security regression suite and security control coverage catalog.
"""
import os
import sys
import json
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
from pathlib import Path
from pydantic import BaseModel, Field

from app.schemas.verification_assurance import (
    ControlCategory,
    SecurityControlRecord,
    SecurityControlsCatalogResponse,
)
from app.services.security_control_verification_service import security_control_verification_service

logger = logging.getLogger("vapt.security_regression")

REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent


class SecurityTestResultRecord(BaseModel):
    test_id: str
    control_id: str
    category: str
    description: str
    outcome: str  # PASSED, FAILED, SKIPPED
    execution_time_ms: float
    evidence_digest: Optional[str] = None
    notes: Optional[str] = None


class SecurityRegressionSuiteReport(BaseModel):
    suite_id: str
    generated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    total_controls_mapped: int
    total_tests_executed: int
    passed_count: int
    failed_count: int
    skipped_count: int
    coverage_pct: float
    mutation_kill_pct: float
    verdict: str  # QUALIFIED, DEFECT_DETECTED
    tests: List[SecurityTestResultRecord]
    limitations: List[str]
    skipped_checks: List[Dict[str, str]]


class SecurityRegressionService:
    """
    Coordinates security regression reporting, machine-readable export generation,
    and control mapping verification.
    """

    @classmethod
    def export_security_controls_inventory(cls, output_path: Optional[Path] = None) -> Path:
        """
        Exports the canonical security control catalog to reports/security_controls_inventory.json.
        """
        if output_path is None:
            output_path = REPO_ROOT / "reports" / "security_controls_inventory.json"
        
        output_path.parent.mkdir(parents=True, exist_ok=True)
        catalog = security_control_verification_service.get_security_controls_catalog()
        
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(catalog.model_dump(), f, indent=2)
            
        logger.info(f"Exported security controls inventory to {output_path}")
        return output_path

    @classmethod
    def generate_regression_report(
        cls,
        test_results: List[SecurityTestResultRecord],
        suite_id: str = "reg-suite-prompt47",
        output_path: Optional[Path] = None,
    ) -> SecurityRegressionSuiteReport:
        """
        Synthesizes machine-readable security regression report and writes to reports/security_regression_results.json.
        """
        if output_path is None:
            output_path = REPO_ROOT / "reports" / "security_regression_results.json"

        output_path.parent.mkdir(parents=True, exist_ok=True)
        catalog = security_control_verification_service.get_security_controls_catalog()
        mutation_drill = security_control_verification_service.run_mutation_drill()

        passed = sum(1 for t in test_results if t.outcome == "PASSED")
        failed = sum(1 for t in test_results if t.outcome == "FAILED")
        skipped = sum(1 for t in test_results if t.outcome == "SKIPPED")
        total = len(test_results)

        cov_pct = round((catalog.verified_controls / catalog.total_controls) * 100.0, 1) if catalog.total_controls > 0 else 0.0
        verdict = "QUALIFIED" if failed == 0 and mutation_drill.kill_ratio_pct == 100.0 else "DEFECT_DETECTED"

        # Explicitly document testing constraints and unavailable hardware checks
        limitations = [
            "Hardware Security Module (HSM) PKCS#11 keys are emulated in software via Fernet symmetric vaults.",
            "Live internet BGP routing anomalies cannot be simulated in offline sandbox test suites.",
            "Live external cloud provider IAM privilege escalation is restricted to local mock contracts.",
            "Raw L2 packet-level flooding and physical hardware tampering checks are unavailable.",
        ]

        skipped_checks = [
            {
                "check_id": "CHK-HW-HSM-01",
                "reason": "Hardware cryptographic module not attached in CI/CD environment; software Fernet AES-128 used.",
                "mitigation": "Automated AES-128-CBC + HMAC-SHA256 authenticated encryption tested in SEC-VAULT-01.",
            },
            {
                "check_id": "CHK-NET-BGP-01",
                "reason": "Upstream AS path hijacking cannot be safely executed against production IP ranges.",
                "mitigation": "Strict preflight ScopeEngine boundary verification tested in SEC-SCOPE-01.",
            },
        ]

        report = SecurityRegressionSuiteReport(
            suite_id=suite_id,
            total_controls_mapped=catalog.total_controls,
            total_tests_executed=total,
            passed_count=passed,
            failed_count=failed,
            skipped_count=skipped,
            coverage_pct=cov_pct,
            mutation_kill_pct=mutation_drill.kill_ratio_pct,
            verdict=verdict,
            tests=test_results,
            limitations=limitations,
            skipped_checks=skipped_checks,
        )

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report.model_dump(), f, indent=2)

        logger.info(f"Exported security regression results to {output_path}")
        return report


security_regression_service = SecurityRegressionService()
