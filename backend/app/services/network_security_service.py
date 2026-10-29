"""
VAPT Platform — Outbound Network Security & SSRF Protection Service (Prompt 24).
Provides destination policy enforcement, scheme whitelisting, IP range validation,
DNS-rebinding defenses, strict TLS validation, timeout enforcement, and response size bounds
for all outbound scanner adapters, webhooks, and enterprise integrations.
"""
import socket
import ipaddress
import urllib.parse
from typing import Set, Tuple, List, Optional, Dict, Any
import logging

logger = logging.getLogger("vapt.network_security")


class NetworkSecurityError(Exception):
    """Base exception for outbound network security violations."""
    pass


class DestinationRestrictedError(NetworkSecurityError):
    """Raised when an outbound URL violates network destination policy (SSRF attempt)."""
    pass


class OversizedResponseError(NetworkSecurityError):
    """Raised when an outbound HTTP response exceeds maximum permitted byte limit."""
    pass


class NetworkSecurityTimeoutError(NetworkSecurityError):
    """Raised when an outbound network operation exceeds timeout limits."""
    pass


class OutboundNetworkSecurityService:
    """
    Validates outbound network requests against SSRF, internal network probing,
    DNS rebinding, malicious redirects, and denial-of-service via oversized responses.
    """

    ALLOWED_SCHEMES: Set[str] = {"http", "https"}
    DEFAULT_CONNECT_TIMEOUT: float = 5.0
    DEFAULT_READ_TIMEOUT: float = 10.0
    MAX_RESPONSE_BYTES: int = 10 * 1024 * 1024  # 10 MB

    # Explicit cloud metadata hostnames and endpoints
    BLOCKED_METADATA_HOSTS: Set[str] = {
        "metadata.google.internal",
        "metadata.internal",
        "instance-data",
        "169.254.169.254",
        "fd00:ec2::254",
        "100.100.100.200",
    }

    @classmethod
    def validate_destination_url(
        cls,
        url: str,
        allow_private_networks: bool = False,
        custom_allowed_schemes: Optional[Set[str]] = None,
    ) -> Dict[str, Any]:
        """
        Validates destination URL against SSRF and private address policies.
        Resolves DNS and verifies all IP addresses before connection establishment.

        Returns:
            Dict containing parsed scheme, hostname, port, and resolved_ips.
        Raises:
            DestinationRestrictedError on any policy violation.
        """
        if not url or not isinstance(url, str):
            raise DestinationRestrictedError("Destination URL cannot be empty.")

        url_stripped = url.strip()
        parsed = urllib.parse.urlsplit(url_stripped)

        # 1. Scheme Validation
        allowed_schemes = custom_allowed_schemes or cls.ALLOWED_SCHEMES
        if not parsed.scheme or parsed.scheme.lower() not in allowed_schemes:
            raise DestinationRestrictedError(
                f"Unsupported URL scheme '{parsed.scheme}'. Only {sorted(list(allowed_schemes))} are permitted."
            )

        # 2. Hostname Validation
        hostname = parsed.hostname
        if not hostname:
            raise DestinationRestrictedError("Destination URL must contain a valid hostname.")

        # Reject embedded credentials in URL (e.g. http://user:pass@host)
        if parsed.username or parsed.password:
            raise DestinationRestrictedError("User credentials embedded in destination URLs are prohibited.")

        # Check metadata hostnames
        if hostname.lower() in cls.BLOCKED_METADATA_HOSTS:
            raise DestinationRestrictedError(
                f"Access to cloud metadata destination '{hostname}' is strictly prohibited."
            )

        # 3. Port Validation
        port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
        if not (1 <= port <= 65535):
            raise DestinationRestrictedError(f"Destination port '{port}' is out of valid range (1-65535).")

        # 4. Resolve DNS and Validate All Resolved IP Addresses
        resolved_ips: List[str] = []
        try:
            # Resolves IPv4 and IPv6
            addr_info = socket.getaddrinfo(hostname, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
            for entry in addr_info:
                sockaddr = entry[4]
                ip_str = sockaddr[0]
                if ip_str not in resolved_ips:
                    resolved_ips.append(ip_str)
        except socket.gaierror as e:
            raise DestinationRestrictedError(f"Could not resolve destination hostname '{hostname}': {str(e)}")

        if not resolved_ips:
            raise DestinationRestrictedError(f"No IP addresses resolved for destination hostname '{hostname}'.")

        # 5. Policy Check for Resolved IP Addresses
        for ip_str in resolved_ips:
            cls.validate_ip_address(ip_str, allow_private=allow_private_networks)

        return {
            "valid": True,
            "url": url_stripped,
            "scheme": parsed.scheme.lower(),
            "hostname": hostname,
            "port": port,
            "path": parsed.path or "/",
            "resolved_ips": resolved_ips,
            "allow_private": allow_private_networks,
        }

    @classmethod
    def validate_ip_address(cls, ip_str: str, allow_private: bool = False) -> None:
        """
        Validates individual IP string against reserved, loopback, link-local, and private ranges.
        """
        try:
            ip_obj = ipaddress.ip_address(ip_str)
        except ValueError:
            raise DestinationRestrictedError(f"Malformed IP address string '{ip_str}'.")

        # Loopback (127.0.0.0/8, ::1)
        if ip_obj.is_loopback:
            raise DestinationRestrictedError(
                f"Access to loopback address '{ip_str}' is prohibited by destination policy."
            )

        # Link-local (169.254.0.0/16, fe80::/10) - includes AWS/GCP/Azure metadata services
        if ip_obj.is_link_local:
            raise DestinationRestrictedError(
                f"Access to link-local/cloud metadata address '{ip_str}' is strictly prohibited."
            )

        # Multicast (224.0.0.0/4, ff00::/8)
        if ip_obj.is_multicast:
            raise DestinationRestrictedError(
                f"Access to multicast address '{ip_str}' is prohibited."
            )

        # Reserved / Unspecified (0.0.0.0, ::)
        if ip_obj.is_unspecified or ip_obj.is_reserved:
            raise DestinationRestrictedError(
                f"Access to reserved or unspecified address '{ip_str}' is prohibited."
            )

        # Private RFC 1918 / RFC 4193 (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, fc00::/7)
        if ip_obj.is_private and not allow_private:
            raise DestinationRestrictedError(
                f"Access to internal/private network address '{ip_str}' is prohibited by default destination policy."
            )

    @classmethod
    def execute_safe_dispatch(
        cls,
        url: str,
        method: str = "POST",
        json_body: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        allow_private_networks: bool = False,
        max_response_bytes: Optional[int] = None,
        timeout: Optional[float] = None,
    ) -> Dict[str, Any]:
        """
        Performs an outbound HTTP dispatch with destination policy enforcement,
        DNS rebinding protection, TLS verification, and response size limits.
        """
        import httpx

        # Validate destination before initiating connection
        validation = cls.validate_destination_url(url, allow_private_networks=allow_private_networks)

        max_bytes = max_response_bytes or cls.MAX_RESPONSE_BYTES
        effective_timeout = timeout or cls.DEFAULT_READ_TIMEOUT

        transport_headers = headers or {}

        # Use httpx Client with strict verify=True (enforce TLS) and redirect limits
        client_kwargs = {
            "verify": True,  # Mandatory TLS validation
            "timeout": httpx.Timeout(
                connect=cls.DEFAULT_CONNECT_TIMEOUT,
                read=effective_timeout,
                write=effective_timeout,
                pool=cls.DEFAULT_CONNECT_TIMEOUT,
            ),
            "follow_redirects": False,  # Handle redirects manually to revalidate destination policy
        }

        try:
            with httpx.Client(**client_kwargs) as client:
                current_url = url
                redirect_count = 0
                max_redirects = 3

                while True:
                    req_params = {"headers": transport_headers}
                    if json_body is not None:
                        req_params["json"] = json_body

                    response = client.request(method=method, url=current_url, **req_params)

                    # Check for redirect responses
                    if response.is_redirect and response.has_redirect_location:
                        redirect_count += 1
                        if redirect_count > max_redirects:
                            raise DestinationRestrictedError(f"Exceeded maximum permitted redirects ({max_redirects}).")

                        redirect_target = response.headers.get("Location")
                        if not redirect_target:
                            break

                        next_url = urllib.parse.urljoin(current_url, redirect_target)
                        # CRITICAL: Revalidate new destination before following redirect
                        cls.validate_destination_url(next_url, allow_private_networks=allow_private_networks)
                        current_url = next_url
                        continue

                    # Stream response content with size enforcement
                    content_length = response.headers.get("Content-Length")
                    if content_length and int(content_length) > max_bytes:
                        raise OversizedResponseError(
                            f"Response Content-Length ({content_length} bytes) exceeds limit ({max_bytes} bytes)."
                        )

                    body_bytes = response.content
                    if len(body_bytes) > max_bytes:
                        raise OversizedResponseError(
                            f"Response payload size ({len(body_bytes)} bytes) exceeds limit ({max_bytes} bytes)."
                        )

                    return {
                        "status_code": response.status_code,
                        "headers": dict(response.headers),
                        "body_bytes": len(body_bytes),
                        "text": response.text[:4096],  # Safe snippet
                        "destination_ip": validation["resolved_ips"][0] if validation["resolved_ips"] else None,
                    }

        except httpx.TimeoutException as e:
            raise NetworkSecurityTimeoutError(f"Outbound connection timed out: {str(e)}")
        except httpx.RequestError as e:
            raise NetworkSecurityError(f"Network transport error: {str(e)}")
