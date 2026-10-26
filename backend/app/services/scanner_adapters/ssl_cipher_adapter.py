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


class SslTlsCipherAuditAdapter(BaseScannerAdapter):
    """
    Deterministic TLS Protocol and Cipher Suite Audit Adapter (Phase 7B).
    Audits cryptographic posture including obsolete TLS protocols and weak cipher suites.
    Operates strictly in memory using deterministic test fixtures.
    Does NOT initiate external raw network sockets or real TLS handshakes.
    Flags all observations with is_simulated = True.
    """

    @property
    def name(self) -> str:
        return "ssl_cipher_adapter"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def declared_capabilities(self) -> List[str]:
        return [
            "TLS_PROTOCOL_AUDIT",
            "CIPHER_SUITE_EVALUATION",
            "CERTIFICATE_VALIDATION",
        ]

    @property
    def supported_profiles(self) -> List[str]:
        return [
            "TLS_MODERN_CIPHERS",
            "LEGACY_DEPRECATION_AUDIT",
            "CERTIFICATE_EXPIRY_CHECK",
        ]

    @property
    def permitted_check_categories(self) -> List[str]:
        return [
            "CRYPTOGRAPHY",
            "CONFIGURATION",
        ]

    @property
    def supported_target_types(self) -> List[str]:
        return ["DOMAIN", "IP_ADDRESS", "IPV4", "URL"]

    @property
    def required_permissions(self) -> List[str]:
        return ["READ_ONLY", "PASSIVE_AUDIT"]

    @property
    def default_timeout_seconds(self) -> int:
        return 120

    @property
    def min_timeout_seconds(self) -> int:
        return 10

    @property
    def max_timeout_seconds(self) -> int:
        return 900

    @property
    def config_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "fixture_profile": {
                    "type": "string",
                    "enum": self.supported_profiles,
                    "default": "TLS_MODERN_CIPHERS",
                    "description": "Simulation TLS assessment profile",
                },
                "port": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 65535,
                    "default": 443,
                    "description": "Target port for TLS negotiation check",
                },
            },
            "additionalProperties": True,
        }

    @property
    def status(self) -> str:
        return "ACTIVE"

    def validate_config(self, config: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        profile = config.get("fixture_profile", "TLS_MODERN_CIPHERS")
        if profile not in self.supported_profiles:
            return False, f"Profile '{profile}' is not supported by adapter '{self.name}' (supported: {self.supported_profiles})."
        port = config.get("port", 443)
        if not isinstance(port, int) or port < 1 or port > 65535:
            return False, f"Port must be an integer between 1 and 65535, got {port}."
        return True, None

    def preflight_check(self, target: str, config: Dict[str, Any]) -> PreflightResult:
        valid, err = self.validate_config(config)
        return PreflightResult(
            adapter_name=self.name,
            adapter_version=self.version,
            target=target,
            target_type="DOMAIN" if not any(c.isdigit() for c in target.split(".")) else "IPV4",
            is_ready=valid,
            preflight_error=err,
            mode="SIMULATED_FIXTURE",
            metadata={"port": config.get("port", 443)},
        )

    def get_health(self) -> Dict[str, Any]:
        return {
            "status": "HEALTHY",
            "driver": "tls_cipher_synthetic_evaluator",
            "active_workers": 1,
            "max_concurrency": 4,
            "network_scanning_enabled": False,
        }

    def execute(
        self,
        target: str,
        config: Dict[str, Any],
        cancellation_check: Optional[Callable[[], bool]] = None,
    ) -> AdapterResult:
        start_time = time.perf_counter()
        profile = config.get("fixture_profile", "TLS_MODERN_CIPHERS")
        port = config.get("port", 443)

        if cancellation_check and cancellation_check():
            duration = (time.perf_counter() - start_time) * 1000
            return AdapterResult(
                adapter_name=self.name,
                adapter_version=self.version,
                target=target,
                is_simulated=True,
                success=False,
                status_summary="Execution cancelled prior to TLS handshake evaluation.",
                failure_category="JOB_CANCELLED",
                errors=["Cancelled by operator or timeout."],
                findings=[],
                execution_duration_ms=duration,
            )

        findings: List[RawAdapterFinding] = []
        errors: List[str] = []

        if profile == "LEGACY_DEPRECATION_AUDIT":
            # Finding 1: Deprecated TLS 1.0 and 1.1 Support
            findings.append(
                RawAdapterFinding(
                    title="Deprecated TLS 1.0 and TLS 1.1 Protocols Enabled",
                    description="The target server accepts connections utilizing TLS 1.0 and TLS 1.1, which suffer from known cryptographic weaknesses.",
                    severity=FindingSeverity.HIGH,
                    confidence=FindingConfidence.CERTAIN,
                    vuln_id="CWE-326",
                    cvss_score=7.4,
                    reproduction_steps=f"Initiate synthetic ClientHello specifying TLS 1.0 to {target}:{port}.",
                    evidence_items=[
                        RawAdapterEvidence(
                            evidence_type="HANDSHAKE_TRANSCRIPT",
                            payload=f"ClientHello: TLSv1.0 (0x0301) -> ServerHello: TLSv1.0 accepted.\nServer cipher chosen: TLS_RSA_WITH_AES_128_CBC_SHA",
                        )
                    ],
                )
            )

            # Finding 2: Weak 3DES Cipher Suite Accepted
            findings.append(
                RawAdapterFinding(
                    title="Sweet32 Vulnerable 64-bit Block Cipher (3DES) Accepted",
                    description="The server supports Triple-DES (3DES) ciphers which are vulnerable to Sweet32 collision attacks (CVE-2016-2183).",
                    severity=FindingSeverity.MEDIUM,
                    confidence=FindingConfidence.FIRM,
                    vuln_id="CWE-327",
                    cvss_score=5.9,
                    reproduction_steps=f"Offer cipher TLS_RSA_WITH_3DES_EDE_CBC_SHA in ClientHello to {target}:{port}.",
                    evidence_items=[
                        RawAdapterEvidence(
                            evidence_type="CONFIG_AUDIT",
                            payload=f"Target: {target}:{port}\nCipher: TLS_RSA_WITH_3DES_EDE_CBC_SHA (0x000A)\nBlock size: 64 bits (Sweet32 vulnerable)",
                        )
                    ],
                )
            )

        elif profile == "CERTIFICATE_EXPIRY_CHECK":
            findings.append(
                RawAdapterFinding(
                    title="X.509 Certificate Approaching Expiration (< 14 Days)",
                    description="The presented server certificate expires in 9 days, posing a high risk of service disruption.",
                    severity=FindingSeverity.MEDIUM,
                    confidence=FindingConfidence.CERTAIN,
                    vuln_id="CWE-298",
                    cvss_score=5.3,
                    reproduction_steps=f"Inspect simulated certificate NotAfter field on {target}:{port}.",
                    evidence_items=[
                        RawAdapterEvidence(
                            evidence_type="CONFIG_AUDIT",
                            payload=f"Subject: CN={target}\nIssuer: R3\nNotBefore: 2026-08-01 00:00:00 UTC\nNotAfter: 2026-11-04 12:00:00 UTC\nDays Remaining: 9",
                        )
                    ],
                )
            )

        elif profile == "TLS_MODERN_CIPHERS":
            # Modern configuration: All baseline checks pass, zero vulnerabilities
            pass

        duration = (time.perf_counter() - start_time) * 1000
        return AdapterResult(
            adapter_name=self.name,
            adapter_version=self.version,
            target=target,
            is_simulated=True,
            success=len(errors) == 0,
            status_summary=f"TLS cipher evaluation completed ({profile}): {len(findings)} findings identified.",
            findings=findings,
            errors=errors,
            execution_duration_ms=duration,
        )


# Register adapter in global registry
AdapterRegistry.register(SslTlsCipherAuditAdapter())
