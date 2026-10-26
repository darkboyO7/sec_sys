import time
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Callable, Tuple
from app.models.assessment import FindingSeverity, FindingConfidence
from app.services.scanner_adapters.base import (
    BaseScannerAdapter,
    AdapterResult,
    RawAdapterFinding,
    RawAdapterEvidence,
    PreflightResult,
    AdapterRegistry,
)


class PassiveHeaderAuditAdapter(BaseScannerAdapter):
    """
    Deterministic Passive HTTP Security Header Scanner Adapter (Phase 7B).
    Audits HTTP response headers against OWASP Secure Headers Project standards.
    Operates strictly within memory using verifiable local test fixtures.
    Does NOT initiate external raw network sockets or real HTTP connections.
    Flags all observations with is_simulated = True.
    """

    @property
    def name(self) -> str:
        return "passive_header_adapter"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def declared_capabilities(self) -> List[str]:
        return [
            "HTTP_HEADER_INSPECTION",
            "FRAME_PROTECTION_CHECK",
            "COOKIE_SECURITY_CHECK",
            "CONTENT_TYPE_OPTIONS_CHECK",
        ]

    @property
    def supported_profiles(self) -> List[str]:
        return [
            "OWASP_SECURE_HEADERS",
            "STRICT_TRANSPORT_AUDIT",
            "COOKIE_SECURITY_CHECK",
        ]

    @property
    def permitted_check_categories(self) -> List[str]:
        return [
            "CONFIGURATION",
            "INFORMATION_DISCLOSURE",
        ]

    @property
    def supported_target_types(self) -> List[str]:
        return ["URL", "DOMAIN"]

    @property
    def required_permissions(self) -> List[str]:
        return ["READ_ONLY", "PASSIVE_AUDIT"]

    @property
    def default_timeout_seconds(self) -> int:
        return 60

    @property
    def min_timeout_seconds(self) -> int:
        return 5

    @property
    def max_timeout_seconds(self) -> int:
        return 600

    @property
    def config_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "fixture_profile": {
                    "type": "string",
                    "enum": self.supported_profiles,
                    "default": "OWASP_SECURE_HEADERS",
                    "description": "Target passive header audit profile",
                },
                "include_informational": {
                    "type": "boolean",
                    "default": True,
                    "description": "Whether to report low/informational hardening findings",
                },
            },
            "additionalProperties": True,
        }

    @property
    def status(self) -> str:
        return "ACTIVE"

    def validate_config(self, config: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        profile = config.get("fixture_profile", "OWASP_SECURE_HEADERS")
        if profile not in self.supported_profiles:
            return False, f"Profile '{profile}' is not supported by adapter '{self.name}' (supported: {self.supported_profiles})."
        return True, None

    def preflight_check(self, target: str, config: Dict[str, Any]) -> PreflightResult:
        valid, err = self.validate_config(config)
        return PreflightResult(
            adapter_name=self.name,
            adapter_version=self.version,
            target=target,
            target_type="URL" if "://" in target else "DOMAIN",
            is_ready=valid,
            preflight_error=err,
            mode="SIMULATED_FIXTURE",
        )

    def get_health(self) -> Dict[str, Any]:
        return {
            "status": "HEALTHY",
            "driver": "passive_header_synthetic_evaluator",
            "active_workers": 1,
            "max_concurrency": 8,
            "network_scanning_enabled": False,
        }

    def execute(
        self,
        target: str,
        config: Dict[str, Any],
        cancellation_check: Optional[Callable[[], bool]] = None,
    ) -> AdapterResult:
        start_time = time.perf_counter()
        profile = config.get("fixture_profile", "OWASP_SECURE_HEADERS")
        include_info = config.get("include_informational", True)

        if cancellation_check and cancellation_check():
            duration = (time.perf_counter() - start_time) * 1000
            return AdapterResult(
                adapter_name=self.name,
                adapter_version=self.version,
                target=target,
                is_simulated=True,
                success=False,
                status_summary="Execution cancelled prior to header inspection.",
                failure_category="JOB_CANCELLED",
                errors=["Cancelled by operator or timeout."],
                findings=[],
                execution_duration_ms=duration,
            )

        findings: List[RawAdapterFinding] = []
        errors: List[str] = []

        if profile == "OWASP_SECURE_HEADERS":
            # Finding 1: Missing Strict-Transport-Security
            findings.append(
                RawAdapterFinding(
                    title="Missing Strict-Transport-Security (HSTS) Header",
                    description="The server did not return a Strict-Transport-Security HTTP header, leaving connections susceptible to downgrade attacks.",
                    severity=FindingSeverity.MEDIUM,
                    confidence=FindingConfidence.CERTAIN,
                    vuln_id="CWE-319",
                    cvss_score=4.3,
                    reproduction_steps=f"Perform synthetic HEAD request against {target} and check for 'Strict-Transport-Security' in headers.",
                    evidence_items=[
                        RawAdapterEvidence(
                            evidence_type="HTTP_RESPONSE_HEADERS",
                            payload=f"HTTP/1.1 200 OK\nHost: {target}\nContent-Type: text/html\nServer: nginx\nStrict-Transport-Security: [ABSENT]",
                        )
                    ],
                )
            )

            # Finding 2: Missing Content-Security-Policy
            findings.append(
                RawAdapterFinding(
                    title="Missing Content-Security-Policy Header",
                    description="The web resource does not enforce a Content-Security-Policy, increasing susceptibility to Cross-Site Scripting (XSS).",
                    severity=FindingSeverity.MEDIUM,
                    confidence=FindingConfidence.FIRM,
                    vuln_id="CWE-693",
                    cvss_score=3.5,
                    reproduction_steps=f"Inspect response headers for {target} for absence of Content-Security-Policy.",
                    evidence_items=[
                        RawAdapterEvidence(
                            evidence_type="HTTP_HEADER_ANALYSIS",
                            payload=f"HTTP/1.1 200 OK\nContent-Security-Policy: [ABSENT]\nX-XSS-Protection: 0",
                        )
                    ],
                )
            )

            # Finding 3: Missing X-Content-Type-Options
            if include_info:
                findings.append(
                    RawAdapterFinding(
                        title="Missing X-Content-Type-Options Header",
                        description="The X-Content-Type-Options: nosniff header is missing, allowing legacy browsers to perform MIME-type sniffing.",
                        severity=FindingSeverity.LOW,
                        confidence=FindingConfidence.CERTAIN,
                        vuln_id="CWE-16",
                        cvss_score=2.6,
                        reproduction_steps="Verify absence of X-Content-Type-Options header.",
                        evidence_items=[
                            RawAdapterEvidence(
                                evidence_type="HTTP_RESPONSE_HEADERS",
                                payload=f"HTTP/1.1 200 OK\nX-Content-Type-Options: [ABSENT]",
                            )
                        ],
                    )
                )

        elif profile == "STRICT_TRANSPORT_AUDIT":
            findings.append(
                RawAdapterFinding(
                    title="HSTS Missing includeSubDomains Directive",
                    description="HSTS header is present but lacks the 'includeSubDomains' and 'preload' directives.",
                    severity=FindingSeverity.LOW,
                    confidence=FindingConfidence.FIRM,
                    vuln_id="CWE-319",
                    cvss_score=2.9,
                    reproduction_steps="Verify HSTS max-age directive without includeSubDomains.",
                    evidence_items=[
                        RawAdapterEvidence(
                            evidence_type="HTTP_RESPONSE_HEADERS",
                            payload=f"Strict-Transport-Security: max-age=31536000\n[Directive 'includeSubDomains' missing]",
                        )
                    ],
                )
            )

        elif profile == "COOKIE_SECURITY_CHECK":
            findings.append(
                RawAdapterFinding(
                    title="Session Cookie Lacks Secure and HttpOnly Attributes",
                    description="Simulated session identifier cookie is transmitted without 'Secure' and 'HttpOnly' flags.",
                    severity=FindingSeverity.MEDIUM,
                    confidence=FindingConfidence.CERTAIN,
                    vuln_id="CWE-614",
                    cvss_score=5.0,
                    reproduction_steps="Inspect Set-Cookie headers in HTTP response.",
                    evidence_items=[
                        RawAdapterEvidence(
                            evidence_type="HTTP_RESPONSE_HEADERS",
                            payload="Set-Cookie: session_id=abc123456789; Path=/; SameSite=Lax\n[Missing: Secure, HttpOnly]",
                        )
                    ],
                )
            )

        duration = (time.perf_counter() - start_time) * 1000
        return AdapterResult(
            adapter_name=self.name,
            adapter_version=self.version,
            target=target,
            is_simulated=True,
            success=len(errors) == 0,
            status_summary=f"Passive header audit completed ({profile}): {len(findings)} findings identified.",
            findings=findings,
            errors=errors,
            execution_duration_ms=duration,
        )


# Register adapter in global registry
AdapterRegistry.register(PassiveHeaderAuditAdapter())
