import time
from datetime import datetime, timezone
from typing import Dict, Any, List
from app.models.assessment import FindingSeverity, FindingConfidence
from app.services.scanner_adapters.base import (
    BaseScannerAdapter,
    AdapterResult,
    RawAdapterFinding,
    RawAdapterEvidence,
)


class LocalFixtureAdapter(BaseScannerAdapter):
    """
    Deterministic Local Fixture Scanner Adapter.
    Operates strictly within memory using verifiable local test fixtures.
    Does NOT initiate external raw network sockets or real scanner commands.
    Flags all observations with is_simulated = True.
    """

    @property
    def name(self) -> str:
        return "local_fixture_adapter"

    @property
    def version(self) -> str:
        return "1.0.0"

    def execute(self, target: str, config: Dict[str, Any]) -> AdapterResult:
        start_time = time.perf_counter()
        profile = config.get("fixture_profile", "WEB_APPLICATION_BASELINE")

        findings: List[RawAdapterFinding] = []
        errors: List[str] = []
        status_summary = ""

        # Check for simulated fault injection in config
        if config.get("simulate_error") is True:
            duration = (time.perf_counter() - start_time) * 1000
            return AdapterResult(
                adapter_name=self.name,
                adapter_version=self.version,
                target=target,
                is_simulated=True,
                success=False,
                status_summary="Simulated adapter failure triggered by configuration flag.",
                findings=[],
                errors=["SIMULATED_INTERNAL_FAULT: Local fixture simulated driver error"],
                execution_duration_ms=duration,
            )

        if profile == "HARDENED_HOST_BASELINE":
            status_summary = f"Evaluated target '{target}' against baseline security controls. Zero findings detected."

        elif profile == "TLS_CONFIGURATION_CHECK":
            status_summary = f"Evaluated cryptographic transport configuration on '{target}'."
            findings.append(
                RawAdapterFinding(
                    title="Deprecation of TLS 1.0 and TLS 1.1 Protocols",
                    description=f"Target service on '{target}' offers legacy TLS 1.0 / 1.1 protocol handshakes, vulnerable to downgrade attacks.",
                    severity=FindingSeverity.MEDIUM,
                    confidence=FindingConfidence.CERTAIN,
                    vuln_id="CWE-326",
                    cvss_score=5.3,
                    reproduction_steps="Initiate ClientHello handshake explicitly setting TLSv1.0 version bytes (0x0301).",
                    evidence_items=[
                        RawAdapterEvidence(
                            evidence_type="HANDSHAKE_TRANSCRIPT",
                            payload=f"ClientHello: TLSv1.0 (0x0301)\nServerHello: Accepted TLSv1.0\nCipherSuite: TLS_RSA_WITH_AES_128_CBC_SHA\nTarget: {target}",
                        )
                    ],
                )
            )
            findings.append(
                RawAdapterFinding(
                    title="Strict-Transport-Security (HSTS) Header Absent",
                    description="HTTP response headers do not enforce the HSTS policy directive, permitting unencrypted fallback.",
                    severity=FindingSeverity.LOW,
                    confidence=FindingConfidence.CERTAIN,
                    vuln_id="CWE-523",
                    cvss_score=3.7,
                    reproduction_steps="Send HTTP GET request to port 443 and inspect response header set.",
                    evidence_items=[
                        RawAdapterEvidence(
                            evidence_type="HTTP_RESPONSE_HEADERS",
                            payload=f"HTTP/1.1 200 OK\nDate: {datetime.now(timezone.utc).isoformat()}\nServer: nginx/1.24.0\nStrict-Transport-Security: [MISSING]",
                        )
                    ],
                )
            )

        elif profile == "PARTIAL_FAILURE_PROFILE":
            status_summary = f"Partial assessment completion for '{target}'. Some auxiliary test suites failed."
            errors.append("TIMEOUT_SUB_MODULE: Auxiliary API endpoint probes timed out after 3000ms.")
            findings.append(
                RawAdapterFinding(
                    title="Information Disclosure via Server Header",
                    description="The web server exposes detailed software name and version number in the Server HTTP header.",
                    severity=FindingSeverity.INFO,
                    confidence=FindingConfidence.CERTAIN,
                    vuln_id="CWE-200",
                    cvss_score=0.0,
                    reproduction_steps="Inspect Server response header.",
                    evidence_items=[
                        RawAdapterEvidence(
                            evidence_type="HTTP_RESPONSE_HEADERS",
                            payload="Server: Apache/2.4.52 (Ubuntu) OpenSSL/3.0.2",
                        )
                    ],
                )
            )

        elif profile == "SIMULATED_CRITICAL_EXPOSURE":
            status_summary = f"Identified high-impact security findings on '{target}'."
            findings.append(
                RawAdapterFinding(
                    title="Unauthenticated SQL Injection in Authentication Endpoint",
                    description="SQL parameter concatenation permits arbitrary database query manipulation via the username field.",
                    severity=FindingSeverity.CRITICAL,
                    confidence=FindingConfidence.CERTAIN,
                    vuln_id="CWE-89",
                    cvss_score=9.8,
                    reproduction_steps="Submit single-quote character in login payload to induce syntax error and boolean true condition.",
                    evidence_items=[
                        RawAdapterEvidence(
                            evidence_type="HTTP_REQUEST_RESPONSE",
                            payload=f"POST /api/v1/auth HTTP/1.1\nHost: {target}\nContent-Type: application/json\n\n{{\"user\": \"admin' OR '1'='1\"}}\n\n--- RESPONSE ---\nHTTP/1.1 200 OK\nSet-Cookie: session=simulated_admin_bypass",
                        )
                    ],
                )
            )

        else:  # Default: WEB_APPLICATION_BASELINE
            status_summary = f"Deterministic baseline web evaluation executed for '{target}'."
            findings.append(
                RawAdapterFinding(
                    title="Missing Content-Security-Policy (CSP) Header",
                    description="The application does not declare a Content-Security-Policy header, reducing defense-in-depth against cross-site scripting.",
                    severity=FindingSeverity.LOW,
                    confidence=FindingConfidence.CERTAIN,
                    vuln_id="CWE-693",
                    cvss_score=3.5,
                    reproduction_steps="Examine HTTP response headers on root path.",
                    evidence_items=[
                        RawAdapterEvidence(
                            evidence_type="HTTP_HEADER_ANALYSIS",
                            payload=f"HTTP/1.1 200 OK\nHost: {target}\nContent-Type: text/html\nContent-Security-Policy: [ABSENT]",
                        )
                    ],
                )
            )
            findings.append(
                RawAdapterFinding(
                    title="Anti-Clickjacking X-Frame-Options Header Missing",
                    description="The web page does not supply X-Frame-Options or frame-ancestors CSP directive, allowing the page to be framed.",
                    severity=FindingSeverity.LOW,
                    confidence=FindingConfidence.FIRM,
                    vuln_id="CWE-1021",
                    cvss_score=3.1,
                    reproduction_steps="Attempt to embed target URL within HTML <iframe> element.",
                    evidence_items=[
                        RawAdapterEvidence(
                            evidence_type="FRAME_TEST",
                            payload=f"<iframe> src=\"{target}\" loaded without CSP frame-ancestors or X-Frame-Options restriction.",
                        )
                    ],
                )
            )

        duration = (time.perf_counter() - start_time) * 1000

        # Validate through Pydantic model
        return AdapterResult(
            adapter_name=self.name,
            adapter_version=self.version,
            target=target,
            is_simulated=True,
            success=len(errors) == 0,
            status_summary=status_summary,
            findings=findings,
            errors=errors,
            execution_duration_ms=duration,
        )
