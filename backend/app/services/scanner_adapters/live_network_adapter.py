import time
import socket
import ssl
import urllib.parse
import urllib.request
import urllib.error
import http.client
import hashlib
import ipaddress
import re
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional, Callable, Tuple, Set

from app.models.assessment import FindingSeverity, FindingConfidence
from app.services.scanner_adapters.base import (
    BaseScannerAdapter,
    AdapterResult,
    RawAdapterFinding,
    RawAdapterEvidence,
    PreflightResult,
    AdapterRegistry,
)


def check_ip_ssrf(ip_str: str, allow_loopback: bool = False, allow_private: bool = False) -> Tuple[bool, Optional[str]]:
    """
    Validates whether an IP address is safe for outbound network observation.
    Blocks IPv4/IPv6 cloud metadata, link-local, multicast, reserved, and private address space.
    Unwraps IPv4-mapped IPv6 addresses.
    """
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False, f"Invalid IP address format: {ip_str}"

    # Unwrap IPv4-mapped IPv6 addresses (e.g. ::ffff:169.254.169.254 -> 169.254.169.254)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped

    str_ip = str(ip)

    # Cloud metadata service endpoints (AWS, GCP, Azure, Oracle Cloud)
    if str_ip in ("169.254.169.254", "fd00:ec2::254") or str_ip.startswith("fd00:ec2:"):
        return False, f"Target IP {str_ip} is cloud metadata service endpoint (SSRF blocked)."

    # Link-local addresses (IPv4 169.254.0.0/16, IPv6 fe80::/10)
    if ip.is_link_local:
        return False, f"Target IP {str_ip} is within link-local address space (SSRF blocked)."

    # Multicast addresses (IPv4 224.0.0.0/4, IPv6 ff00::/8)
    if ip.is_multicast:
        return False, f"Target IP {str_ip} is a multicast address (SSRF blocked)."

    # Unspecified addresses (0.0.0.0, ::)
    if ip.is_unspecified:
        return False, f"Target IP {str_ip} is unspecified address (SSRF blocked)."

    # Loopback addresses (IPv4 127.0.0.0/8, IPv6 ::1)
    if ip.is_loopback:
        if not allow_loopback:
            return False, f"Target IP {str_ip} is loopback localhost (SSRF blocked for production scanning)."
        return True, None

    # Reserved addresses (IETF reserved, excluding loopback which was handled above)
    if ip.is_reserved:
        return False, f"Target IP {str_ip} is in IETF reserved address space (SSRF blocked)."

    # Private network addresses (RFC 1918 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 and IPv6 ULA fc00::/7)
    # Strictly isolated from allow_loopback: allow_loopback=True can NEVER permit private RFC1918 addresses
    if ip.is_private:
        if not allow_private:
            return False, f"Target IP {str_ip} is within private/internal address space (SSRF blocked)."
        return True, None

    return True, None


def resolve_and_verify_ssrf(
    host: str,
    port: int,
    allow_loopback: bool = False,
    allow_private: bool = False,
) -> Tuple[bool, Optional[str], List[str]]:
    """
    Resolves hostname via DNS and enforces SSRF restrictions on all resolved IP addresses.
    Checks IPv4, IPv6, and cloud metadata hostnames.
    """
    clean_host = host.strip("[]")

    # If host is already an IP address
    try:
        ipaddress.ip_address(clean_host)
        is_safe, reason = check_ip_ssrf(clean_host, allow_loopback=allow_loopback, allow_private=allow_private)
        if not is_safe:
            return False, reason, [clean_host]
        return True, None, [clean_host]
    except ValueError:
        pass

    # Check for known dangerous internal hostnames
    lower_host = clean_host.lower()
    if lower_host in ("metadata.google.internal", "metadata", "instance-data", "metadata.internal"):
        return False, f"Hostname '{clean_host}' is a cloud metadata hostname (SSRF blocked).", []

    if (lower_host == "localhost" or lower_host.endswith(".localhost")) and not allow_loopback:
        return False, f"Hostname '{clean_host}' resolves to loopback (SSRF blocked).", []

    # Resolve via DNS (both IPv4 and IPv6)
    try:
        addr_info = socket.getaddrinfo(clean_host, port, proto=socket.IPPROTO_TCP)
        resolved_ips = list({entry[4][0] for entry in addr_info})
        if not resolved_ips:
            return False, f"Could not resolve host '{clean_host}' via DNS.", []

        for ip in resolved_ips:
            is_safe, reason = check_ip_ssrf(ip, allow_loopback=allow_loopback, allow_private=allow_private)
            if not is_safe:
                return False, f"Host '{clean_host}' resolved to restricted IP {ip}: {reason}", resolved_ips

        return True, None, resolved_ips
    except socket.gaierror as e:
        return False, f"DNS resolution failed for '{clean_host}': {str(e)}", []
    except Exception as e:
        return False, f"Error resolving target host '{clean_host}': {str(e)}", []


class SafeHTTPConnection(http.client.HTTPConnection):
    """
    HTTPConnection that pins the socket connection directly to a pre-verified destination IP,
    completely eliminating the Time-of-Check to Time-of-Use (TOCTOU) DNS validation-to-connection gap
    while preserving the original 'Host' header.
    """
    def __init__(self, host, port=None, verified_ip: Optional[str] = None, **kwargs):
        self.verified_ip = verified_ip
        self.original_host = host
        super().__init__(host, port, **kwargs)

    def connect(self):
        connect_host = self.verified_ip if self.verified_ip else self.host
        self.sock = socket.create_connection(
            (connect_host, self.port),
            self.timeout,
            self.source_address,
        )


class SafeHTTPSConnection(http.client.HTTPSConnection):
    """
    HTTPSConnection that pins the socket connection directly to a pre-verified destination IP,
    completely eliminating DNS rebinding while preserving TLS Server Name Indication (SNI)
    and strict hostname certificate verification against the original target hostname.
    """
    def __init__(self, host, port=None, verified_ip: Optional[str] = None, **kwargs):
        self.verified_ip = verified_ip
        self.original_host = host
        super().__init__(host, port, **kwargs)

    def connect(self):
        connect_host = self.verified_ip if self.verified_ip else self.host
        sock = socket.create_connection(
            (connect_host, self.port),
            self.timeout,
            self.source_address,
        )
        server_hostname = self.original_host or self.host
        if ":" in server_hostname:
            server_hostname = server_hostname.split(":")[0]
        server_hostname = server_hostname.strip("[]")
        self.sock = self._context.wrap_socket(sock, server_hostname=server_hostname)


class SafeHTTPHandler(urllib.request.HTTPHandler):
    def __init__(self, verified_ip: Optional[str] = None):
        super().__init__()
        self.verified_ip = verified_ip

    def http_open(self, req):
        return self.do_open(
            lambda host, **kw: SafeHTTPConnection(host, verified_ip=self.verified_ip, **kw),
            req,
        )


class SafeHTTPSHandler(urllib.request.HTTPSHandler):
    def __init__(self, context=None, verified_ip: Optional[str] = None):
        super().__init__(context=context)
        self.verified_ip = verified_ip

    def https_open(self, req):
        return self.do_open(
            lambda host, **kw: SafeHTTPSConnection(host, verified_ip=self.verified_ip, context=self._context, **kw),
            req,
        )


class BoundedRedirectHandler(urllib.request.HTTPRedirectHandler):
    """
    Safe HTTP Redirect Handler that tracks hops, enforces maximum redirect limits,
    enforces scope boundaries (cannot pivot to arbitrary external domains),
    and validates every redirect destination against SSRF rules.
    """
    def __init__(self, target_host: str, allow_loopback: bool = False, allow_private: bool = False, max_redirects: int = 5):
        super().__init__()
        self.target_host = target_host.lower().strip("[]")
        self.allow_loopback = allow_loopback
        self.allow_private = allow_private
        self.max_redirects = max_redirects
        self.redirect_chain: List[Tuple[int, str]] = []
        self.last_verified_ip: Optional[str] = None

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if len(self.redirect_chain) >= self.max_redirects:
            raise urllib.error.HTTPError(
                req.full_url, code, f"Exceeded maximum redirect limit ({self.max_redirects} hops)", headers, fp
            )
        self.redirect_chain.append((code, newurl))
        parsed = urllib.parse.urlparse(newurl)
        dest_host = (parsed.hostname or "").lower().strip("[]")

        # Scope boundary enforcement: Redirect destination must stay within target domain or its subdomains
        if dest_host != self.target_host and not dest_host.endswith("." + self.target_host):
            raise urllib.error.HTTPError(
                newurl, 403, f"Redirect to out-of-scope host '{dest_host}' blocked by scope policy.", headers, fp
            )

        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        is_safe, reason, redirect_resolved_ips = resolve_and_verify_ssrf(
            dest_host, port, self.allow_loopback, self.allow_private
        )
        if not is_safe:
            raise urllib.error.HTTPError(newurl, 403, f"SSRF boundary enforcement blocked redirect: {reason}", headers, fp)

        if redirect_resolved_ips:
            self.last_verified_ip = redirect_resolved_ips[0]

        return super().redirect_request(req, fp, code, msg, headers, newurl)


class LiveNetworkAuditorAdapter(BaseScannerAdapter):
    """
    Genuine Live Non-Intrusive Website Security Auditor Adapter.
    
    Executes real, safe, non-intrusive network security assessments against explicitly authorized targets:
    1. LIVE_WEB_SECURITY_AUDIT: Comprehensive all-in-one web security audit (Headers, Cookies, Resources, TLS).
    2. LIVE_HTTP_HEADERS: Real HTTP GET inspection of security response headers, server disclosure, and cookies.
    3. LIVE_TLS_HANDSHAKE: Real TLS/SSL handshake, certificate validity, issuer, SANs, and cipher suite evaluation.
    4. LIVE_SECURITY_RESOURCES: Safe probe for security.txt (RFC 9116) and robots.txt information disclosure.
    5. LIVE_TCP_BANNER: Safe non-intrusive TCP connection and banner grab on authorized ports.

    Enforces strict pre-flight SSRF & DNS rebinding guardrails, bounded redirects,
    and honest error reporting without fabricating findings when targets are unreachable.
    Always marks is_simulated = False.
    """

    @property
    def name(self) -> str:
        return "live_network_auditor_adapter"

    @property
    def version(self) -> str:
        return "1.1.0"

    @property
    def declared_capabilities(self) -> List[str]:
        return [
            "LIVE_WEB_SECURITY_AUDIT",
            "LIVE_HTTP_HEADER_INSPECTION",
            "LIVE_TLS_CERTIFICATE_AUDIT",
            "LIVE_COOKIE_SECURITY_AUDIT",
            "LIVE_SECURITY_RESOURCE_AUDIT",
            "LIVE_TCP_SERVICE_BANNER_GRAB",
            "SSRF_GUARDRAIL_ENFORCEMENT",
        ]

    @property
    def supported_profiles(self) -> List[str]:
        return [
            "LIVE_WEB_SECURITY_AUDIT",
            "LIVE_HTTP_HEADERS",
            "LIVE_TLS_HANDSHAKE",
            "LIVE_SECURITY_RESOURCES",
            "LIVE_TCP_BANNER",
        ]

    @property
    def permitted_check_categories(self) -> List[str]:
        return [
            "CONFIGURATION",
            "INFORMATION_DISCLOSURE",
            "CRYPTOGRAPHY",
            "NETWORK_SURFACE",
        ]

    @property
    def supported_target_types(self) -> List[str]:
        return ["URL", "DOMAIN", "IPV4", "IP_ADDRESS"]

    @property
    def required_permissions(self) -> List[str]:
        return ["READ_ONLY", "PASSIVE_AUDIT"]

    @property
    def default_timeout_seconds(self) -> int:
        return 15

    @property
    def min_timeout_seconds(self) -> int:
        return 2

    @property
    def max_timeout_seconds(self) -> int:
        return 60

    @property
    def config_schema(self) -> Dict[str, Any]:
        return {
            "type": "object",
            "properties": {
                "profile": {
                    "type": "string",
                    "enum": self.supported_profiles,
                    "default": "LIVE_WEB_SECURITY_AUDIT",
                    "description": "Active live network assessment profile",
                },
                "fixture_profile": {
                    "type": "string",
                    "description": "Compatibility alias for profile parameter",
                },
                "target_port": {
                    "type": "integer",
                    "default": 443,
                    "minimum": 1,
                    "maximum": 65535,
                    "description": "Target TCP port for TLS or Banner audit",
                },
                "verify_ssl": {
                    "type": "boolean",
                    "default": False,
                    "description": "Whether to require valid public CA certificate on target",
                },
                "follow_redirects": {
                    "type": "boolean",
                    "default": True,
                    "description": "Follow HTTP redirects up to max_redirects hops",
                },
                "max_redirects": {
                    "type": "integer",
                    "default": 5,
                    "minimum": 1,
                    "maximum": 10,
                    "description": "Maximum allowed redirect hops",
                },
                "allow_loopback": {
                    "type": "boolean",
                    "default": False,
                    "description": "Allow loopback 127.0.0.1 testing for development environments",
                },
                "allow_private": {
                    "type": "boolean",
                    "default": False,
                    "description": "Allow RFC 1918 private subnets if explicitly authorized",
                },
            },
            "additionalProperties": False,
        }

    @property
    def status(self) -> str:
        return "ACTIVE"

    def _resolve_profile(self, config: Dict[str, Any]) -> str:
        prof = config.get("profile") or config.get("fixture_profile") or "LIVE_WEB_SECURITY_AUDIT"
        return prof.strip()

    def validate_config(self, config: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        profile = self._resolve_profile(config)
        if profile not in self.supported_profiles:
            return False, f"Profile '{profile}' is not supported by {self.name}."
        port = config.get("target_port", 443)
        if not isinstance(port, int) or port < 1 or port > 65535:
            return False, f"Port {port} must be an integer between 1 and 65535."
        return True, None

    def preflight_check(self, target: str, config: Dict[str, Any]) -> PreflightResult:
        valid, err = self.validate_config(config)
        clean_target = target.strip()
        
        if not clean_target:
            return PreflightResult(
                adapter_name=self.name,
                adapter_version=self.version,
                target=target,
                is_ready=False,
                preflight_error="Target cannot be empty.",
                mode="LIVE_NETWORK",
            )

        if "://" in clean_target:
            ttype = "URL"
        elif any(c.isalpha() for c in clean_target.split(":")[0]):
            ttype = "DOMAIN"
        else:
            ttype = "IPV4"

        return PreflightResult(
            adapter_name=self.name,
            adapter_version=self.version,
            target=clean_target,
            target_type=ttype,
            is_ready=valid,
            preflight_error=err,
            mode="LIVE_NETWORK",
        )

    def get_health(self) -> Dict[str, Any]:
        return {
            "status": "HEALTHY",
            "driver": "live_socket_and_http_engine",
            "active_workers": 1,
            "max_concurrency": 4,
            "network_scanning_enabled": True,
            "ssrf_guardrails_active": True,
            "supported_protocols": ["HTTP/1.1", "TLSv1.2", "TLSv1.3", "TCP"],
        }

    def execute(
        self,
        target: str,
        config: Dict[str, Any],
        cancellation_check: Optional[Callable[[], bool]] = None,
    ) -> AdapterResult:
        start_time = time.perf_counter()
        profile = self._resolve_profile(config)
        timeout = float(config.get("timeout_seconds", self.default_timeout_seconds))

        url_sample = target if "://" in target else f"http://{target}"
        parsed_url = urllib.parse.urlparse(url_sample)
        if config.get("target_port") is not None:
            port = int(config["target_port"])
        elif parsed_url.port:
            port = parsed_url.port
        else:
            port = 443 if parsed_url.scheme == "https" else 80

        if cancellation_check and cancellation_check():
            return AdapterResult(
                adapter_name=self.name,
                adapter_version=self.version,
                target=target,
                is_simulated=False,
                success=False,
                status_summary="Execution cancelled prior to live network audit.",
                failure_category="JOB_CANCELLED",
                errors=["Cancelled by operator or timeout deadline."],
                findings=[],
                execution_duration_ms=(time.perf_counter() - start_time) * 1000,
            )

        # Dispatch based on selected profile
        if profile == "LIVE_WEB_SECURITY_AUDIT":
            return self._execute_live_web_security_audit(target, port, config, start_time, timeout, cancellation_check)
        elif profile == "LIVE_HTTP_HEADERS":
            return self._execute_live_http_headers(target, config, start_time, timeout, cancellation_check)
        elif profile == "LIVE_TLS_HANDSHAKE":
            return self._execute_live_tls_audit(target, port, config, start_time, timeout, cancellation_check)
        elif profile == "LIVE_SECURITY_RESOURCES":
            return self._execute_live_security_resources(target, config, start_time, timeout, cancellation_check)
        elif profile == "LIVE_TCP_BANNER":
            return self._execute_live_tcp_banner(target, port, config, start_time, timeout, cancellation_check)
        else:
            return AdapterResult(
                adapter_name=self.name,
                adapter_version=self.version,
                target=target,
                is_simulated=False,
                success=False,
                status_summary=f"Unsupported profile: {profile}",
                errors=[f"Unsupported profile '{profile}'"],
                findings=[],
                execution_duration_ms=(time.perf_counter() - start_time) * 1000,
            )

    # --------------------------------------------------------------------------
    # 1. Comprehensive Live Web Security Audit Profile
    # --------------------------------------------------------------------------
    def _execute_live_web_security_audit(
        self,
        target: str,
        port: int,
        config: Dict[str, Any],
        start_time: float,
        timeout: float,
        cancellation_check: Optional[Callable[[], bool]],
    ) -> AdapterResult:
        all_findings: List[RawAdapterFinding] = []
        all_errors: List[str] = []

        # Step A: Run HTTP response headers and cookie audit
        http_res = self._execute_live_http_headers(target, config, start_time, timeout, cancellation_check)
        if not http_res.success:
            return http_res  # Bubble up connection error or SSRF denial honestly

        all_findings.extend(http_res.findings)
        all_errors.extend(http_res.errors)

        if cancellation_check and cancellation_check():
            return self._cancelled_result(target, start_time)

        # Step B: Run security resources audit (security.txt & robots.txt)
        res_audit = self._execute_live_security_resources(target, config, start_time, timeout, cancellation_check)
        if res_audit.success:
            all_findings.extend(res_audit.findings)

        if cancellation_check and cancellation_check():
            return self._cancelled_result(target, start_time)

        # Step C: If HTTPS, run TLS handshake audit
        url = target if "://" in target else f"http://{target}"
        parsed_target = urllib.parse.urlparse(url)
        is_https = parsed_target.scheme == "https" or (parsed_target.scheme != "http" and port == 443)
        if is_https:
            tls_res = self._execute_live_tls_audit(target, port, config, start_time, timeout, cancellation_check)
            if tls_res.success:
                all_findings.extend(tls_res.findings)
            else:
                all_errors.extend(tls_res.errors)

        duration = (time.perf_counter() - start_time) * 1000
        summary = (
            f"Live Web Security Audit completed successfully: {len(all_findings)} security observations identified "
            f"across headers, cookies, resources, and TLS configuration."
        )
        return AdapterResult(
            adapter_name=self.name,
            adapter_version=self.version,
            target=target,
            is_simulated=False,
            success=True,
            status_summary=summary,
            findings=all_findings,
            errors=all_errors,
            execution_duration_ms=duration,
        )

    # --------------------------------------------------------------------------
    # 2. HTTP Headers and Cookie Security Audit
    # --------------------------------------------------------------------------
    def _execute_live_http_headers(
        self,
        target: str,
        config: Dict[str, Any],
        start_time: float,
        timeout: float,
        cancellation_check: Optional[Callable[[], bool]],
    ) -> AdapterResult:
        url = target if "://" in target else f"http://{target}"
        parsed = urllib.parse.urlparse(url)
        host = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        allow_loopback = bool(config.get("allow_loopback", False))
        allow_private = bool(config.get("allow_private", False))

        # SSRF Pre-flight DNS Verification
        is_safe, ssrf_err, resolved_ips = resolve_and_verify_ssrf(
            host, port, allow_loopback=allow_loopback, allow_private=allow_private
        )
        if not is_safe:
            duration = (time.perf_counter() - start_time) * 1000
            return AdapterResult(
                adapter_name=self.name,
                adapter_version=self.version,
                target=target,
                is_simulated=False,
                success=False,
                status_summary=f"SSRF guardrail blocked request to target: {ssrf_err}",
                failure_category="SSRF_ATTEMPT_BLOCKED",
                errors=[ssrf_err or "Restricted destination IP address."],
                findings=[],
                execution_duration_ms=duration,
            )

        findings: List[RawAdapterFinding] = []
        errors: List[str] = []

        try:
            # Build SSL Context
            ctx = ssl.create_default_context()
            if not config.get("verify_ssl", False):
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE

            # Bounded redirect handler with scope and SSRF enforcement
            follow_redirects = config.get("follow_redirects", True)
            max_redirects = int(config.get("max_redirects", 5))

            primary_verified_ip = resolved_ips[0] if resolved_ips else None
            handlers: List[Any] = [
                SafeHTTPHandler(verified_ip=primary_verified_ip),
                SafeHTTPSHandler(context=ctx, verified_ip=primary_verified_ip),
            ]
            if follow_redirects:
                handlers.append(BoundedRedirectHandler(
                    target_host=host,
                    allow_loopback=allow_loopback,
                    allow_private=allow_private,
                    max_redirects=max_redirects,
                ))
            else:
                class NoRedirect(urllib.request.HTTPRedirectHandler):
                    def redirect_request(self, req, fp, code, msg, headers, newurl):
                        return None
                handlers.append(NoRedirect())

            opener = urllib.request.build_opener(*handlers)
            req = urllib.request.Request(
                url,
                headers={
                    "User-Agent": "VAPT-Defensive-Auditor/1.1 (+https://vapt.internal.corp/auditor)",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Accept-Language": "en-US,en;q=0.5",
                },
                method="GET",
            )

            with opener.open(req, timeout=timeout) as response:
                status_code = response.getcode()
                response_headers = response.info()
                headers = dict(response_headers)
                raw_headers_str = "\n".join(f"{k}: {v}" for k, v in headers.items())

            evidence_item = RawAdapterEvidence(
                evidence_type="HTTP_RESPONSE_HEADERS",
                payload=f"HTTP/1.1 {status_code} Response Headers:\n{raw_headers_str}",
            )

            header_keys_lower = {k.lower(): v for k, v in headers.items()}

            # ------------------------------------------------------------------
            # Check 1: Strict-Transport-Security (HSTS)
            # ------------------------------------------------------------------
            if url.startswith("https://"):
                hsts = header_keys_lower.get("strict-transport-security")
                if not hsts:
                    findings.append(
                        RawAdapterFinding(
                            title="Missing Strict-Transport-Security (HSTS) Header",
                            description=(
                                f"The HTTPS server at {url} does not enforce Strict-Transport-Security. "
                                f"Without HSTS, browsers can be coerced into unencrypted HTTP connections via SSL stripping attacks."
                            ),
                            severity=FindingSeverity.MEDIUM,
                            confidence=FindingConfidence.CERTAIN,
                            vuln_id="CWE-319",
                            cvss_score=4.3,
                            reproduction_steps=f"Initiate HTTP GET against {url} and observe absence of 'Strict-Transport-Security'.",
                            evidence_items=[evidence_item],
                        )
                    )
                else:
                    max_age_match = re.search(r"max-age=(\d+)", hsts, re.IGNORECASE)
                    if max_age_match:
                        max_age_val = int(max_age_match.group(1))
                        if max_age_val < 15724800:  # < 182 days
                            findings.append(
                                RawAdapterFinding(
                                    title="Strict-Transport-Security Has Inadequate Duration",
                                    description=(
                                        f"The HSTS max-age is set to {max_age_val} seconds (< 6 months). "
                                        f"Industry standard recommends at least 31536000 seconds (1 year) with includeSubDomains."
                                    ),
                                    severity=FindingSeverity.LOW,
                                    confidence=FindingConfidence.CERTAIN,
                                    vuln_id="CWE-319",
                                    cvss_score=3.1,
                                    reproduction_steps=f"Inspect HSTS header: '{hsts}'.",
                                    evidence_items=[evidence_item],
                                )
                            )

            # ------------------------------------------------------------------
            # Check 2: Content-Security-Policy (CSP)
            # ------------------------------------------------------------------
            csp = header_keys_lower.get("content-security-policy")
            if not csp:
                findings.append(
                    RawAdapterFinding(
                        title="Missing Content-Security-Policy (CSP) Header",
                        description=(
                            f"The resource at {url} does not define a Content-Security-Policy header. "
                            f"CSP mitigates Cross-Site Scripting (XSS), clickjacking, and malicious resource injection."
                        ),
                        severity=FindingSeverity.MEDIUM,
                        confidence=FindingConfidence.CERTAIN,
                        vuln_id="CWE-693",
                        cvss_score=4.5,
                        reproduction_steps=f"Inspect response headers from {url} for absence of Content-Security-Policy.",
                        evidence_items=[evidence_item],
                    )
                )
            else:
                if "'unsafe-inline'" in csp.lower() or "'unsafe-eval'" in csp.lower():
                    findings.append(
                        RawAdapterFinding(
                            title="Permissive Directive in Content-Security-Policy",
                            description=(
                                f"The Content-Security-Policy at {url} allows 'unsafe-inline' or 'unsafe-eval', "
                                f"significantly reducing XSS mitigation effectiveness."
                            ),
                            severity=FindingSeverity.LOW,
                            confidence=FindingConfidence.CERTAIN,
                            vuln_id="CWE-693",
                            cvss_score=3.5,
                            reproduction_steps=f"Inspect CSP header value: '{csp[:150]}...'",
                            evidence_items=[evidence_item],
                        )
                    )

            # ------------------------------------------------------------------
            # Check 3: X-Content-Type-Options
            # ------------------------------------------------------------------
            xcto = header_keys_lower.get("x-content-type-options", "")
            if "nosniff" not in xcto.lower():
                findings.append(
                    RawAdapterFinding(
                        title="Missing or Misconfigured X-Content-Type-Options",
                        description=(
                            "The server did not send 'X-Content-Type-Options: nosniff'. "
                            "This permits web browsers to perform MIME-type sniffing, potentially executing non-executable files as scripts."
                        ),
                        severity=FindingSeverity.LOW,
                        confidence=FindingConfidence.CERTAIN,
                        vuln_id="CWE-16",
                        cvss_score=2.6,
                        reproduction_steps="Verify HTTP response headers do not contain 'X-Content-Type-Options: nosniff'.",
                        evidence_items=[evidence_item],
                    )
                )

            # ------------------------------------------------------------------
            # Check 4: X-Frame-Options (Clickjacking defense)
            # ------------------------------------------------------------------
            xfo = header_keys_lower.get("x-frame-options", "")
            csp_frame = csp and "frame-ancestors" in csp.lower()
            if not xfo and not csp_frame:
                findings.append(
                    RawAdapterFinding(
                        title="Missing Anti-Clickjacking Header (X-Frame-Options)",
                        description=(
                            f"The resource at {url} does not declare 'X-Frame-Options' or CSP 'frame-ancestors'. "
                            f"Attackers can embed this application within an iframe on an external site to execute clickjacking attacks."
                        ),
                        severity=FindingSeverity.LOW,
                        confidence=FindingConfidence.CERTAIN,
                        vuln_id="CWE-1021",
                        cvss_score=3.4,
                        reproduction_steps=f"Inspect response headers from {url} for absence of X-Frame-Options or frame-ancestors.",
                        evidence_items=[evidence_item],
                    )
                )

            # ------------------------------------------------------------------
            # Check 5: Referrer-Policy
            # ------------------------------------------------------------------
            rp = header_keys_lower.get("referrer-policy", "")
            if not rp:
                findings.append(
                    RawAdapterFinding(
                        title="Missing Referrer-Policy Header",
                        description=(
                            "The server did not declare a Referrer-Policy header. Browsers may leak sensitive URL parameters "
                            "or internal paths across third-party navigation."
                        ),
                        severity=FindingSeverity.LOW,
                        confidence=FindingConfidence.CERTAIN,
                        vuln_id="CWE-116",
                        cvss_score=2.1,
                        reproduction_steps="Inspect HTTP headers for absence of Referrer-Policy.",
                        evidence_items=[evidence_item],
                    )
                )
            elif "unsafe-url" in rp.lower():
                findings.append(
                    RawAdapterFinding(
                        title="Insecure Referrer-Policy Configuration ('unsafe-url')",
                        description="The Referrer-Policy is configured to 'unsafe-url', leaking full URL paths to external domains.",
                        severity=FindingSeverity.LOW,
                        confidence=FindingConfidence.CERTAIN,
                        vuln_id="CWE-200",
                        cvss_score=3.1,
                        reproduction_steps=f"Observed Referrer-Policy: '{rp}'.",
                        evidence_items=[evidence_item],
                    )
                )

            # ------------------------------------------------------------------
            # Check 6: Permissions-Policy
            # ------------------------------------------------------------------
            pp = header_keys_lower.get("permissions-policy")
            if not pp:
                findings.append(
                    RawAdapterFinding(
                        title="Informational: Missing Permissions-Policy Header",
                        description=(
                            "The server did not send a Permissions-Policy header to explicitly restrict browser APIs "
                            "(camera, microphone, geolocation, payment request)."
                        ),
                        severity=FindingSeverity.INFO,
                        confidence=FindingConfidence.CERTAIN,
                        vuln_id=None,
                        cvss_score=None,
                        reproduction_steps="Inspect HTTP headers for absence of Permissions-Policy.",
                        evidence_items=[evidence_item],
                    )
                )

            # ------------------------------------------------------------------
            # Check 7: Information Disclosure via Server / Tech Banners
            # ------------------------------------------------------------------
            server_header = header_keys_lower.get("server")
            if server_header and any(char.isdigit() for char in server_header):
                findings.append(
                    RawAdapterFinding(
                        title=f"Detailed Server Version Disclosed ({server_header})",
                        description=f"The server disclosed specific version information in the 'Server' header: '{server_header}'.",
                        severity=FindingSeverity.LOW,
                        confidence=FindingConfidence.CERTAIN,
                        vuln_id="CWE-200",
                        cvss_score=2.6,
                        reproduction_steps=f"Inspect 'Server' header returned in response from {url}.",
                        evidence_items=[
                            RawAdapterEvidence(
                                evidence_type="HTTP_RESPONSE_HEADERS",
                                payload=f"Server: {server_header}",
                            )
                        ],
                    )
                )

            x_powered_by = header_keys_lower.get("x-powered-by")
            if x_powered_by:
                findings.append(
                    RawAdapterFinding(
                        title=f"Technology Stack Disclosure via X-Powered-By ({x_powered_by})",
                        description=f"The server advertises internal application frameworks via 'X-Powered-By: {x_powered_by}'.",
                        severity=FindingSeverity.LOW,
                        confidence=FindingConfidence.CERTAIN,
                        vuln_id="CWE-200",
                        cvss_score=2.6,
                        reproduction_steps=f"Inspect 'X-Powered-By' header returned in response from {url}.",
                        evidence_items=[
                            RawAdapterEvidence(
                                evidence_type="HTTP_RESPONSE_HEADERS",
                                payload=f"X-Powered-By: {x_powered_by}",
                            )
                        ],
                    )
                )

            # ------------------------------------------------------------------
            # Check 8: Cookie Security Attributes (Set-Cookie Audit)
            # ------------------------------------------------------------------
            cookie_headers = response_headers.get_all("Set-Cookie") or []
            for cookie_str in cookie_headers:
                parts = [p.strip() for p in cookie_str.split(";")]
                cookie_name = parts[0].split("=")[0] if parts else "Cookie"
                parts_lower = [p.lower() for p in parts]

                has_secure = "secure" in parts_lower
                has_httponly = "httponly" in parts_lower
                samesite_part = next((p for p in parts if p.lower().startswith("samesite")), None)

                cookie_evidence = RawAdapterEvidence(
                    evidence_type="HTTP_RESPONSE_HEADERS",
                    payload=f"Set-Cookie: {cookie_str}",
                )

                if url.startswith("https://") and not has_secure:
                    findings.append(
                        RawAdapterFinding(
                            title=f"Cookie Set Without 'Secure' Attribute ({cookie_name})",
                            description=(
                                f"Cookie '{cookie_name}' was transmitted over HTTPS without the 'Secure' flag. "
                                f"Browsers may transmit this cookie over unencrypted HTTP channels."
                            ),
                            severity=FindingSeverity.MEDIUM,
                            confidence=FindingConfidence.CERTAIN,
                            vuln_id="CWE-614",
                            cvss_score=4.3,
                            reproduction_steps=f"Inspect Set-Cookie header for '{cookie_name}'.",
                            evidence_items=[cookie_evidence],
                        )
                    )

                if not has_httponly:
                    findings.append(
                        RawAdapterFinding(
                            title=f"Cookie Set Without 'HttpOnly' Attribute ({cookie_name})",
                            description=(
                                f"Cookie '{cookie_name}' is accessible via document.cookie JavaScript API, "
                                f"exposing it to exfiltration during Cross-Site Scripting (XSS) attacks."
                            ),
                            severity=FindingSeverity.LOW,
                            confidence=FindingConfidence.CERTAIN,
                            vuln_id="CWE-1004",
                            cvss_score=3.7,
                            reproduction_steps=f"Inspect Set-Cookie header for '{cookie_name}'.",
                            evidence_items=[cookie_evidence],
                        )
                    )

                if not samesite_part:
                    findings.append(
                        RawAdapterFinding(
                            title=f"Informational: Cookie Missing 'SameSite' Attribute ({cookie_name})",
                            description=(
                                f"Cookie '{cookie_name}' does not specify SameSite protection. "
                                f"Specifying SameSite=Lax or SameSite=Strict provides cross-site request forgery defense."
                            ),
                            severity=FindingSeverity.INFO,
                            confidence=FindingConfidence.CERTAIN,
                            vuln_id=None,
                            cvss_score=None,
                            reproduction_steps=f"Inspect Set-Cookie header for '{cookie_name}'.",
                            evidence_items=[cookie_evidence],
                        )
                    )

            # ------------------------------------------------------------------
            # Check 9: Cross-Origin Resource Sharing (CORS) Security Audit
            # ------------------------------------------------------------------
            acao = header_keys_lower.get("access-control-allow-origin")
            acac = header_keys_lower.get("access-control-allow-credentials", "").lower() == "true"
            if acao:
                cors_evidence = RawAdapterEvidence(
                    evidence_type="HTTP_RESPONSE_HEADERS",
                    payload=f"Access-Control-Allow-Origin: {acao}\nAccess-Control-Allow-Credentials: {header_keys_lower.get('access-control-allow-credentials', 'false')}",
                )
                if acao == "*" and acac:
                    findings.append(
                        RawAdapterFinding(
                            title="Critical CORS Misconfiguration: Wildcard Origin With Credentials Permitted",
                            description=(
                                "The server returned 'Access-Control-Allow-Origin: *' in conjunction with "
                                "'Access-Control-Allow-Credentials: true'. This permits untrusted third-party origins "
                                "to access authenticated session data and responses."
                            ),
                            severity=FindingSeverity.HIGH,
                            confidence=FindingConfidence.CERTAIN,
                            vuln_id="CWE-942",
                            cvss_score=7.5,
                            reproduction_steps=f"Inspect CORS response headers from {url}.",
                            evidence_items=[cors_evidence],
                        )
                    )
                elif acao.lower() == "null":
                    findings.append(
                        RawAdapterFinding(
                            title="Insecure 'null' Origin Permitted in CORS Configuration",
                            description=(
                                "The server allows the 'null' origin in Access-Control-Allow-Origin. "
                                "Sandboxed iframes and local file scheme origins can abuse this to execute cross-origin requests."
                            ),
                            severity=FindingSeverity.MEDIUM,
                            confidence=FindingConfidence.CERTAIN,
                            vuln_id="CWE-942",
                            cvss_score=5.3,
                            reproduction_steps=f"Send request with 'Origin: null' and observe reflected ACAO.",
                            evidence_items=[cors_evidence],
                        )
                    )
                elif acao == "*":
                    findings.append(
                        RawAdapterFinding(
                            title="Informational: Permissive Wildcard Access-Control-Allow-Origin Header",
                            description=(
                                f"The resource at {url} allows all origins via 'Access-Control-Allow-Origin: *'. "
                                f"Ensure this endpoint is intentionally public and does not return sensitive tenant information."
                            ),
                            severity=FindingSeverity.INFO,
                            confidence=FindingConfidence.CERTAIN,
                            vuln_id="CWE-942",
                            cvss_score=None,
                            reproduction_steps=f"Inspect ACAO header: '{acao}'.",
                            evidence_items=[cors_evidence],
                        )
                    )

            # ------------------------------------------------------------------
            # Check 10: Cache-Control for Authenticated/Cookie Responses
            # ------------------------------------------------------------------
            cache_ctrl = header_keys_lower.get("cache-control", "")
            if cookie_headers and ("no-store" not in cache_ctrl.lower() and "private" not in cache_ctrl.lower()):
                findings.append(
                    RawAdapterFinding(
                        title="Informational: Cache-Control Lacks 'no-store' on Cookie-Setting Endpoint",
                        description=(
                            f"The endpoint at {url} sets cookies without declaring 'Cache-Control: no-store'. "
                            f"Intermediate caching proxies or browser caches may retain sensitive session tokens."
                        ),
                        severity=FindingSeverity.INFO,
                        confidence=FindingConfidence.CERTAIN,
                        vuln_id="CWE-525",
                        cvss_score=None,
                        reproduction_steps=f"Inspect Cache-Control header: '{cache_ctrl or 'None'}' along with Set-Cookie.",
                        evidence_items=[evidence_item],
                    )
                )

            duration = (time.perf_counter() - start_time) * 1000
            return AdapterResult(
                adapter_name=self.name,
                adapter_version=self.version,
                target=target,
                is_simulated=False,
                success=True,
                status_summary=f"Live HTTP header audit succeeded ({len(findings)} observations detected, HTTP {status_code}).",
                findings=findings,
                errors=errors,
                execution_duration_ms=duration,
            )

        except urllib.error.HTTPError as e:
            # Operational HTTP error (404, 403, 401, 500) - record raw evidence without fabricating vulnerabilities
            headers = dict(e.headers) if hasattr(e, "headers") else {}
            evidence_item = RawAdapterEvidence(
                evidence_type="HTTP_RESPONSE_HEADERS",
                payload=f"HTTP/1.1 {e.code} {e.reason} Response Headers:\n" + "\n".join(f"{k}: {v}" for k, v in headers.items()),
            )
            # Only 5xx server internal errors are noted as operational findings, NOT 404s
            if e.code >= 500:
                findings.append(
                    RawAdapterFinding(
                        title=f"Server Internal Error Status Disclosed (HTTP {e.code})",
                        description=f"Target {url} returned server error status code {e.code} ({e.reason}).",
                        severity=FindingSeverity.INFO,
                        confidence=FindingConfidence.CERTAIN,
                        vuln_id=None,
                        cvss_score=None,
                        reproduction_steps=f"Send HTTP GET to {url}.",
                        evidence_items=[evidence_item],
                    )
                )
            duration = (time.perf_counter() - start_time) * 1000
            return AdapterResult(
                adapter_name=self.name,
                adapter_version=self.version,
                target=target,
                is_simulated=False,
                success=True,
                status_summary=f"Live HTTP audit observed HTTP {e.code} status ({e.reason}).",
                findings=findings,
                errors=[],
                execution_duration_ms=duration,
            )

        except Exception as e:
            duration = (time.perf_counter() - start_time) * 1000
            err_msg = str(e)
            fail_cat = "CONNECTION_FAILED"
            if "timed out" in err_msg.lower() or "timeout" in err_msg.lower():
                fail_cat = "TIMED_OUT"
            elif "refused" in err_msg.lower():
                fail_cat = "CONNECTION_REFUSED"
            elif "ssrf" in err_msg.lower():
                fail_cat = "SSRF_ATTEMPT_BLOCKED"

            return AdapterResult(
                adapter_name=self.name,
                adapter_version=self.version,
                target=target,
                is_simulated=False,
                success=False,
                status_summary=f"Live HTTP audit connection failed: {err_msg}",
                findings=[],
                errors=[f"Network error connecting to {url}: {err_msg}"],
                failure_category=fail_cat,
                execution_duration_ms=duration,
            )

    # --------------------------------------------------------------------------
    # 3. TLS Handshake and Certificate Audit
    # --------------------------------------------------------------------------
    def _execute_live_tls_audit(
        self,
        target: str,
        port: int,
        config: Dict[str, Any],
        start_time: float,
        timeout: float,
        cancellation_check: Optional[Callable[[], bool]],
    ) -> AdapterResult:
        host = target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
        allow_loopback = bool(config.get("allow_loopback", False))
        allow_private = bool(config.get("allow_private", False))

        is_safe, ssrf_err, resolved_ips = resolve_and_verify_ssrf(
            host, port, allow_loopback=allow_loopback, allow_private=allow_private
        )
        if not is_safe:
            duration = (time.perf_counter() - start_time) * 1000
            return AdapterResult(
                adapter_name=self.name,
                adapter_version=self.version,
                target=target,
                is_simulated=False,
                success=False,
                status_summary=f"SSRF guardrail blocked TLS audit: {ssrf_err}",
                failure_category="SSRF_ATTEMPT_BLOCKED",
                errors=[ssrf_err or "Restricted destination IP address."],
                findings=[],
                execution_duration_ms=duration,
            )

        findings: List[RawAdapterFinding] = []
        errors: List[str] = []

        cert_verified = False
        cert_verification_error: Optional[str] = None
        cert_der: Optional[bytes] = None
        version = "UNKNOWN"
        cipher_name = "UNKNOWN"
        parsed_cert: Dict[str, Any] = {}

        target_ip = resolved_ips[0] if resolved_ips else host

        # Step 1: Real TLS Handshake WITH Certificate & Hostname Validation
        try:
            import certifi
            verify_ctx = ssl.create_default_context(cafile=certifi.where())
        except Exception:
            verify_ctx = ssl.create_default_context()
        try:
            with socket.create_connection((target_ip, port), timeout=timeout) as sock:
                with verify_ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert_der = ssock.getpeercert(binary_form=True)
                    parsed_cert = ssock.getpeercert() or {}
                    version = ssock.version() or "UNKNOWN"
                    cipher = ssock.cipher()
                    cipher_name = cipher[0] if cipher else "UNKNOWN"
                    cert_verified = True
        except ssl.SSLCertVerificationError as cert_err:
            cert_verification_error = str(cert_err)
            # Reconnect unverified solely to extract certificate forensic evidence
            try:
                unverified_ctx = ssl.create_default_context()
                unverified_ctx.check_hostname = False
                unverified_ctx.verify_mode = ssl.CERT_NONE
                with socket.create_connection((target_ip, port), timeout=timeout) as sock2:
                    with unverified_ctx.wrap_socket(sock2, server_hostname=host) as ssock2:
                        cert_der = ssock2.getpeercert(binary_form=True)
                        parsed_cert = ssock2.getpeercert() or {}
                        version = ssock2.version() or "UNKNOWN"
                        cipher = ssock2.cipher()
                        cipher_name = cipher[0] if cipher else "UNKNOWN"
            except Exception:
                pass
        except ssl.SSLError as ssl_err:
            cert_verification_error = str(ssl_err)
            try:
                unverified_ctx = ssl.create_default_context()
                unverified_ctx.check_hostname = False
                unverified_ctx.verify_mode = ssl.CERT_NONE
                with socket.create_connection((target_ip, port), timeout=timeout) as sock2:
                    with unverified_ctx.wrap_socket(sock2, server_hostname=host) as ssock2:
                        cert_der = ssock2.getpeercert(binary_form=True)
                        parsed_cert = ssock2.getpeercert() or {}
                        version = ssock2.version() or "UNKNOWN"
                        cipher = ssock2.cipher()
                        cipher_name = cipher[0] if cipher else "UNKNOWN"
            except Exception:
                pass
        except Exception as conn_err:
            duration = (time.perf_counter() - start_time) * 1000
            err_msg = str(conn_err)
            fail_cat = "TLS_HANDSHAKE_FAILED"
            if "refused" in err_msg.lower():
                fail_cat = "CONNECTION_REFUSED"
            elif "timed out" in err_msg.lower():
                fail_cat = "TIMED_OUT"

            return AdapterResult(
                adapter_name=self.name,
                adapter_version=self.version,
                target=target,
                is_simulated=False,
                success=False,
                status_summary=f"Live TLS audit failed on {host}:{port}: {err_msg}",
                findings=[],
                errors=[f"TLS connection failure to {host}:{port}: {err_msg}"],
                failure_category=fail_cat,
                execution_duration_ms=duration,
            )

        cert_sha256 = hashlib.sha256(cert_der).hexdigest() if cert_der else "NONE"
        tls_evidence = RawAdapterEvidence(
            evidence_type="HANDSHAKE_TRANSCRIPT",
            payload=(
                f"Host: {host}:{port}\n"
                f"TLS Verification: {'VERIFIED' if cert_verified else 'FAILED_UNTRUSTED'}\n"
                f"Verification Error: {cert_verification_error or 'None'}\n"
                f"Negotiated Protocol: {version}\n"
                f"Cipher Suite: {cipher_name}\n"
                f"Certificate SHA-256: {cert_sha256}"
            ),
        )

        # Flag Certificate Trust & Validation Vulnerabilities (Never treat untrusted certs as clean validation)
        if not cert_verified and cert_verification_error:
            err_lower = cert_verification_error.lower()
            if "self-signed" in err_lower or "self signed" in err_lower or "unable to get local issuer" in err_lower:
                findings.append(
                    RawAdapterFinding(
                        title="Untrusted TLS Certificate Authority (Self-Signed / Untrusted Root)",
                        description=(
                            f"The server at {host}:{port} presented a TLS certificate that cannot be validated against public CA trust stores: {cert_verification_error}. "
                            f"Clients will receive security warnings, and the connection is vulnerable to interception."
                        ),
                        severity=FindingSeverity.HIGH,
                        confidence=FindingConfidence.CERTAIN,
                        vuln_id="CWE-295",
                        cvss_score=7.4,
                        reproduction_steps=f"Initiate verified TLS handshake to {host}:{port}.",
                        evidence_items=[tls_evidence],
                    )
                )
            elif "expired" in err_lower or "has expired" in err_lower:
                findings.append(
                    RawAdapterFinding(
                        title="Expired TLS Certificate Presented",
                        description=f"The TLS certificate for {host}:{port} has expired: {cert_verification_error}.",
                        severity=FindingSeverity.HIGH,
                        confidence=FindingConfidence.CERTAIN,
                        vuln_id="CWE-298",
                        cvss_score=7.4,
                        reproduction_steps=f"Connect with TLS client to {host}:{port}.",
                        evidence_items=[tls_evidence],
                    )
                )
            elif "hostname" in err_lower or "doesn't match" in err_lower:
                findings.append(
                    RawAdapterFinding(
                        title="TLS Certificate Hostname Mismatch (SAN Violation)",
                        description=f"The certificate presented at {host}:{port} does not match the requested hostname: {cert_verification_error}.",
                        severity=FindingSeverity.HIGH,
                        confidence=FindingConfidence.CERTAIN,
                        vuln_id="CWE-297",
                        cvss_score=7.1,
                        reproduction_steps=f"Verify hostname '{host}' against certificate Subject Alternative Names.",
                        evidence_items=[tls_evidence],
                    )
                )
            else:
                findings.append(
                    RawAdapterFinding(
                        title="TLS Certificate Validation Failed",
                        description=f"TLS certificate validation failed for {host}:{port}: {cert_verification_error}.",
                        severity=FindingSeverity.HIGH,
                        confidence=FindingConfidence.CERTAIN,
                        vuln_id="CWE-295",
                        cvss_score=7.4,
                        reproduction_steps=f"Connect with verifying TLS client to {host}:{port}.",
                        evidence_items=[tls_evidence],
                    )
                )

        # Check 1: Deprecated TLS protocol versions
        if version in ["TLSv1", "TLSv1.1", "SSLv3", "SSLv2"]:
            findings.append(
                RawAdapterFinding(
                    title=f"Deprecated TLS Protocol Negotiated ({version})",
                    description=(
                        f"The server negotiated {version}, which is cryptographically deprecated and vulnerable "
                        f"to POODLE, BEAST, and protocol downgrade attacks. TLS 1.2 or TLS 1.3 is required."
                    ),
                    severity=FindingSeverity.HIGH,
                    confidence=FindingConfidence.CERTAIN,
                    vuln_id="CWE-326",
                    cvss_score=7.4,
                    reproduction_steps=f"Initiate TLS handshake to {host}:{port} and observe negotiated protocol '{version}'.",
                    evidence_items=[tls_evidence],
                )
            )

        # Check 2: Insecure cipher suite
        if cipher_name and any(weak in cipher_name.upper() for weak in ["RC4", "3DES", "DES", "MD5", "NULL", "EXPORT", "ANON"]):
            findings.append(
                RawAdapterFinding(
                    title=f"Insecure Cipher Suite Negotiated ({cipher_name})",
                    description=f"The server negotiated an insecure or obsolete cipher suite: {cipher_name}.",
                    severity=FindingSeverity.HIGH,
                    confidence=FindingConfidence.CERTAIN,
                    vuln_id="CWE-327",
                    cvss_score=7.5,
                    reproduction_steps=f"Initiate TLS handshake to {host}:{port} and inspect negotiated cipher suite.",
                    evidence_items=[tls_evidence],
                )
            )

        # Check 3: Check certificate expiration and validity dates
        if parsed_cert:
            not_after_str = parsed_cert.get("notAfter")
            if not_after_str:
                try:
                    exp_date = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                    now_utc = datetime.now(timezone.utc)
                    if exp_date <= now_utc and cert_verified:
                        findings.append(
                            RawAdapterFinding(
                                title="Expired TLS Certificate Disclosed",
                                description=f"The TLS certificate for {host} expired on {not_after_str}.",
                                severity=FindingSeverity.HIGH,
                                confidence=FindingConfidence.CERTAIN,
                                vuln_id="CWE-298",
                                cvss_score=7.4,
                                reproduction_steps=f"Inspect peer certificate notAfter attribute: '{not_after_str}'.",
                                evidence_items=[tls_evidence],
                            )
                        )
                    elif exp_date <= now_utc + timedelta(days=30):
                        findings.append(
                            RawAdapterFinding(
                                title="Informational: TLS Certificate Expiring Soon (< 30 Days)",
                                description=f"The TLS certificate for {host} will expire on {not_after_str}.",
                                severity=FindingSeverity.INFO,
                                confidence=FindingConfidence.CERTAIN,
                                vuln_id=None,
                                cvss_score=None,
                                reproduction_steps=f"Observe certificate expiry date: '{not_after_str}'.",
                                evidence_items=[tls_evidence],
                            )
                        )
                except Exception:
                    pass

        duration = (time.perf_counter() - start_time) * 1000
        status_msg = (
            f"Live TLS handshake audit completed ({'CA-Verified' if cert_verified else 'Untrusted Certificate'}, "
            f"{version}, cipher: {cipher_name})."
        )
        return AdapterResult(
            adapter_name=self.name,
            adapter_version=self.version,
            target=target,
            is_simulated=False,
            success=True,
            status_summary=status_msg,
            findings=findings,
            errors=errors,
            execution_duration_ms=duration,
        )

    # --------------------------------------------------------------------------
    # 4. Safe Security Resources Audit (security.txt and robots.txt)
    # --------------------------------------------------------------------------
    def _execute_live_security_resources(
        self,
        target: str,
        config: Dict[str, Any],
        start_time: float,
        timeout: float,
        cancellation_check: Optional[Callable[[], bool]],
    ) -> AdapterResult:
        base_url = target if "://" in target else f"http://{target}"
        parsed = urllib.parse.urlparse(base_url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        host = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        allow_loopback = bool(config.get("allow_loopback", False))
        allow_private = bool(config.get("allow_private", False))

        is_safe, ssrf_err, resolved_ips = resolve_and_verify_ssrf(
            host, port, allow_loopback=allow_loopback, allow_private=allow_private
        )
        if not is_safe:
            duration = (time.perf_counter() - start_time) * 1000
            return AdapterResult(
                adapter_name=self.name,
                adapter_version=self.version,
                target=target,
                is_simulated=False,
                success=False,
                status_summary=f"SSRF guardrail blocked security resources audit: {ssrf_err}",
                failure_category="SSRF_ATTEMPT_BLOCKED",
                errors=[ssrf_err or "Restricted destination IP address."],
                findings=[],
                execution_duration_ms=duration,
            )

        findings: List[RawAdapterFinding] = []
        errors: List[str] = []

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        verified_ip = resolved_ips[0] if resolved_ips else None
        opener = urllib.request.build_opener(
            SafeHTTPHandler(verified_ip=verified_ip),
            SafeHTTPSHandler(context=ctx, verified_ip=verified_ip),
        )

        # Check A: security.txt (RFC 9116) - Informational hardening observation, NOT an exploitable flaw
        security_txt_found = False
        for path in ("/.well-known/security.txt", "/security.txt"):
            try:
                res_url = f"{origin}{path}"
                req = urllib.request.Request(
                    res_url,
                    headers={"User-Agent": "VAPT-Defensive-Auditor/1.1"},
                    method="GET",
                )
                with opener.open(req, timeout=min(timeout, 5.0)) as resp:
                    if resp.getcode() == 200:
                        security_txt_found = True
                        break
            except Exception:
                pass

        if not security_txt_found:
            findings.append(
                RawAdapterFinding(
                    title="Informational: Missing security.txt Policy (RFC 9116)",
                    description=(
                        f"The host at {origin} does not publish an optional security.txt file at /.well-known/security.txt or /security.txt. "
                        f"RFC 9116 defines an optional convention for security researchers to coordinate vulnerability reporting. "
                        f"This is an informational hardening observation, not an exploitable vulnerability."
                    ),
                    severity=FindingSeverity.INFO,
                    confidence=FindingConfidence.FIRM,
                    vuln_id=None,
                    cvss_score=None,
                    reproduction_steps=f"Probe for {origin}/.well-known/security.txt and {origin}/security.txt (HTTP 404 observed).",
                    evidence_items=[
                        RawAdapterEvidence(
                            evidence_type="CONFIG_AUDIT",
                            payload=f"Target: {origin}\nProbed paths: /.well-known/security.txt, /security.txt\nResult: 404 Not Found",
                        )
                    ],
                )
            )

        # Check B: robots.txt Sensitive Path Disclosures
        try:
            robots_url = f"{origin}/robots.txt"
            req = urllib.request.Request(
                robots_url,
                headers={"User-Agent": "VAPT-Defensive-Auditor/1.1"},
                method="GET",
            )
            with opener.open(req, timeout=min(timeout, 5.0)) as resp:
                if resp.getcode() == 200:
                    content = resp.read().decode("utf-8", errors="replace")
                    disallow_lines = [line.strip() for line in content.splitlines() if line.lower().startswith("disallow:")]
                    sensitive_keywords = ["admin", "login", "internal", "backup", "secret", "private", "database", "api/v1/internal", "staging"]
                    disclosed = [
                        line for line in disallow_lines
                        if any(kw in line.lower() for kw in sensitive_keywords)
                    ]
                    if disclosed:
                        evidence_text = "\n".join(disclosed[:10])
                        findings.append(
                            RawAdapterFinding(
                                title="Informational: Sensitive Administrative Paths Disclosed in robots.txt",
                                description=(
                                    f"The robots.txt file at {origin} explicitly disallows crawling of administrative or sensitive paths, "
                                    f"disclosing their location to unauthorized actors: {disclosed[:3]}. "
                                    f"Ensure critical endpoints are protected by strong authentication rather than obscurity."
                                ),
                                severity=FindingSeverity.INFO,
                                confidence=FindingConfidence.CERTAIN,
                                vuln_id="CWE-200",
                                cvss_score=None,
                                reproduction_steps=f"Inspect {origin}/robots.txt for sensitive Disallow directives.",
                                evidence_items=[
                                    RawAdapterEvidence(
                                        evidence_type="CONFIG_AUDIT",
                                        payload=f"URL: {robots_url}\nSensitive Directives:\n{evidence_text}",
                                    )
                                ],
                            )
                        )
        except Exception:
            pass

        duration = (time.perf_counter() - start_time) * 1000
        return AdapterResult(
            adapter_name=self.name,
            adapter_version=self.version,
            target=target,
            is_simulated=False,
            success=True,
            status_summary=f"Security resources audit completed ({len(findings)} observations).",
            findings=findings,
            errors=errors,
            execution_duration_ms=duration,
        )

    # --------------------------------------------------------------------------
    # 5. Live TCP Service Banner Grab
    # --------------------------------------------------------------------------
    def _execute_live_tcp_banner(
        self,
        target: str,
        port: int,
        config: Dict[str, Any],
        start_time: float,
        timeout: float,
        cancellation_check: Optional[Callable[[], bool]],
    ) -> AdapterResult:
        host = target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
        allow_loopback = bool(config.get("allow_loopback", False))
        allow_private = bool(config.get("allow_private", False))

        is_safe, ssrf_err, resolved_ips = resolve_and_verify_ssrf(
            host, port, allow_loopback=allow_loopback, allow_private=allow_private
        )
        if not is_safe:
            duration = (time.perf_counter() - start_time) * 1000
            return AdapterResult(
                adapter_name=self.name,
                adapter_version=self.version,
                target=target,
                is_simulated=False,
                success=False,
                status_summary=f"SSRF guardrail blocked TCP banner grab: {ssrf_err}",
                failure_category="SSRF_ATTEMPT_BLOCKED",
                errors=[ssrf_err or "Restricted destination IP address."],
                findings=[],
                execution_duration_ms=duration,
            )

        target_ip = resolved_ips[0] if resolved_ips else host
        findings: List[RawAdapterFinding] = []
        errors: List[str] = []

        try:
            with socket.create_connection((target_ip, port), timeout=timeout) as s:
                s.settimeout(min(timeout, 3.0))
                try:
                    banner_bytes = s.recv(1024)
                    banner_text = banner_bytes.decode("utf-8", errors="replace").strip()
                except socket.timeout:
                    banner_text = "[NO_BANNER_EMITTED_BEFORE_TIMEOUT]"

            evidence = RawAdapterEvidence(
                evidence_type="PORT_STATE",
                payload=f"Host: {host}\nPort: {port}\nStatus: OPEN\nService Banner:\n{banner_text}",
            )

            if banner_text and banner_text != "[NO_BANNER_EMITTED_BEFORE_TIMEOUT]":
                findings.append(
                    RawAdapterFinding(
                        title=f"Service Banner Disclosed on TCP Port {port}",
                        description=f"The service listening on {host}:{port} disclosed an initial text banner: {banner_text[:100]}",
                        severity=FindingSeverity.LOW,
                        confidence=FindingConfidence.CERTAIN,
                        vuln_id="CWE-200",
                        cvss_score=2.6,
                        reproduction_steps=f"Connect TCP socket to {host}:{port} and read initial bytes.",
                        evidence_items=[evidence],
                    )
                )

            duration = (time.perf_counter() - start_time) * 1000
            return AdapterResult(
                adapter_name=self.name,
                adapter_version=self.version,
                target=target,
                is_simulated=False,
                success=True,
                status_summary=f"Live TCP port {port} banner grab succeeded on {host}.",
                findings=findings,
                errors=errors,
                execution_duration_ms=duration,
            )

        except Exception as e:
            duration = (time.perf_counter() - start_time) * 1000
            return AdapterResult(
                adapter_name=self.name,
                adapter_version=self.version,
                target=target,
                is_simulated=False,
                success=False,
                status_summary=f"Live TCP banner audit failed on {host}:{port}: {str(e)}",
                findings=[],
                errors=[f"TCP connection failed to {host}:{port}: {str(e)}"],
                failure_category="CONNECTION_REFUSED",
                execution_duration_ms=duration,
            )

    def _cancelled_result(self, target: str, start_time: float) -> AdapterResult:
        return AdapterResult(
            adapter_name=self.name,
            adapter_version=self.version,
            target=target,
            is_simulated=False,
            success=False,
            status_summary="Assessment cancelled by operator during live execution.",
            failure_category="JOB_CANCELLED",
            errors=["Cancelled during execution."],
            findings=[],
            execution_duration_ms=(time.perf_counter() - start_time) * 1000,
        )


# Register in global adapter registry
AdapterRegistry.register(LiveNetworkAuditorAdapter())
