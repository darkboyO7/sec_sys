import ipaddress
import re
import socket
from datetime import datetime, timezone
from typing import Optional, Tuple, Dict, Any, List
from urllib.parse import urlparse
from sqlalchemy.orm import Session
from app.models.scope import ScopeTarget, ScopeExclusion, TargetType, AuthorizationStatus

DOMAIN_REGEX = re.compile(
    r"^(?:(?:\*|[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)\.)+[a-zA-Z]{2,}$"
)

CLOUD_METADATA_IPS = {
    "169.254.169.254",   # AWS, GCP, Azure, DO, OpenStack IMDS
    "169.254.0.2",       # Oracle Cloud IMDS link-local
    "fd00:ec2::254",     # AWS IPv6 IMDS
    "100.100.100.200",   # Alibaba Cloud IMDS
    "147.75.204.1",      # Equinix Metal metadata
}

DANGEROUS_METADATA_HOSTNAMES = {
    "metadata.google.internal",
    "api.metadata.google.internal",
    "metadata",
    "instance-data",
    "metadata.internal",
    "kubernetes.default",
    "kubernetes.default.svc",
    "kubernetes.default.svc.cluster.local",
}


class ScopeTargetParseException(Exception):
    """Raised when candidate or registered target cannot be parsed or validated."""
    pass


class ScopeEngine:
    """
    Non-invasive Scope Validation Engine.
    Strictly evaluates targets in memory against database rules without network calls.
    Fails closed: Any target not explicitly covered by an active, unexpired, authorized
    rule or matching an exclusion is strictly DENIED.
    """

    @staticmethod
    def normalize_target(raw_target: str, expected_type: Optional[TargetType] = None) -> Tuple[TargetType, str]:
        """
        Detect type (if not specified) and normalize target value.
        Throws ScopeTargetParseException on invalid inputs.
        """
        if not raw_target or not raw_target.strip():
            raise ScopeTargetParseException("Target value cannot be empty.")

        val = raw_target.strip()
        lower_val = val.lower()

        # Check if URL
        if lower_val.startswith("http://") or lower_val.startswith("https://"):
            try:
                parsed = urlparse(val)
                if not parsed.scheme or not parsed.netloc:
                    raise ValueError()
                # Normalized URL: lowercased scheme + lowercased netloc + path/params
                normalized_url = f"{parsed.scheme.lower()}://{parsed.netloc.lower()}{parsed.path}"
                if parsed.query:
                    normalized_url += f"?{parsed.query}"
                return TargetType.URL, normalized_url
            except Exception:
                raise ScopeTargetParseException(f"Invalid URL target: {val}")

        # Check if CIDR
        if "/" in val:
            try:
                network = ipaddress.ip_network(val, strict=False)
                return TargetType.CIDR, str(network)
            except ValueError:
                raise ScopeTargetParseException(f"Invalid CIDR notation: {val}")

        # Check if Single IP Address (IPv4 or IPv6)
        try:
            ip = ipaddress.ip_address(val)
            return TargetType.IP_ADDRESS, str(ip)
        except ValueError:
            pass

        # Check Domain
        clean_domain = val.lower()
        if clean_domain.startswith("www."):
            pass  # preserve www if explicitly passed
        # Handle wildcard domains e.g. *.example.com
        if clean_domain.startswith("*."):
            suffix = clean_domain[2:]
            if not DOMAIN_REGEX.match(clean_domain) and not DOMAIN_REGEX.match(suffix):
                raise ScopeTargetParseException(f"Invalid wildcard domain: {val}")
            return TargetType.DOMAIN, clean_domain
        elif DOMAIN_REGEX.match(clean_domain):
            return TargetType.DOMAIN, clean_domain

        raise ScopeTargetParseException(
            f"Target '{val}' is not a valid IPv4/IPv6 address, CIDR range, domain name, or HTTP/HTTPS URL."
        )

    @classmethod
    def matches_ip_rule(cls, candidate_ip: ipaddress._BaseAddress, rule_type: TargetType, rule_value: str) -> bool:
        """Check if candidate IP matches an IP or CIDR rule."""
        try:
            if rule_type == TargetType.IP_ADDRESS:
                rule_ip = ipaddress.ip_address(rule_value)
                return candidate_ip == rule_ip
            elif rule_type == TargetType.CIDR:
                rule_net = ipaddress.ip_network(rule_value, strict=False)
                return candidate_ip in rule_net
        except Exception:
            return False
        return False

    @classmethod
    def matches_domain_rule(cls, candidate_domain: str, rule_value: str) -> bool:
        """Check if candidate domain matches domain rule or wildcard."""
        candidate = candidate_domain.lower()
        rule = rule_value.lower()

        # Exact match
        if candidate == rule:
            return True

        # Wildcard rule, e.g. *.example.com
        if rule.startswith("*."):
            base = rule[2:]
            return candidate == base or candidate.endswith("." + base)

        # Standard domain rule, e.g. example.com covers sub.example.com
        if candidate.endswith("." + rule):
            return True

        return False

    @classmethod
    def is_cloud_metadata_destination(cls, target_str: str) -> bool:
        """Checks if a candidate destination resolves or points to a cloud metadata service."""
        clean = target_str.strip().lower()
        if "://" in clean:
            parsed = urlparse(clean)
            host = (parsed.hostname or clean).strip("[]")
        else:
            host = clean.split("/")[0].split(":")[0].strip("[]")

        if host in DANGEROUS_METADATA_HOSTNAMES or host in CLOUD_METADATA_IPS:
            return True

        try:
            ip = ipaddress.ip_address(host)
            if str(ip) in CLOUD_METADATA_IPS:
                return True
            if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
                if str(ip.ipv4_mapped) in CLOUD_METADATA_IPS:
                    return True
            if ip.is_link_local:
                return True
        except ValueError:
            pass

        return False

    @classmethod
    def target_matches_rule(
        cls,
        cand_type: TargetType,
        cand_val: str,
        rule_type: TargetType,
        rule_val: str,
        allow_dns_resolution: bool = False,
    ) -> bool:
        """Evaluate if candidate target matches the specified rule."""
        if cand_type == TargetType.IP_ADDRESS:
            cand_ip = ipaddress.ip_address(cand_val)
            return cls.matches_ip_rule(cand_ip, rule_type, rule_val)

        elif cand_type == TargetType.CIDR:
            cand_net = ipaddress.ip_network(cand_val, strict=False)
            if rule_type == TargetType.CIDR:
                rule_net = ipaddress.ip_network(rule_val, strict=False)
                # Candidate network must be fully inside rule network
                return cand_net.subnet_of(rule_net)
            return False

        elif cand_type == TargetType.DOMAIN:
            if rule_type == TargetType.DOMAIN:
                return cls.matches_domain_rule(cand_val, rule_val)
            elif rule_type in (TargetType.IP_ADDRESS, TargetType.CIDR):
                if allow_dns_resolution:
                    try:
                        addr_info = socket.getaddrinfo(cand_val, None, proto=socket.IPPROTO_TCP)
                        for entry in addr_info:
                            entry_ip = ipaddress.ip_address(entry[4][0])
                            if cls.matches_ip_rule(entry_ip, rule_type, rule_val):
                                return True
                    except Exception:
                        pass
                return False

        elif cand_type == TargetType.URL:
            parsed = urlparse(cand_val)
            cand_host = parsed.hostname or ""
            # If rule is a URL
            if rule_type == TargetType.URL:
                rule_parsed = urlparse(rule_val)
                # Scheme, host, and path prefix must align
                if parsed.scheme.lower() == rule_parsed.scheme.lower() and cand_host.lower() == (rule_parsed.hostname or "").lower():
                    cand_path = parsed.path or "/"
                    rule_path = rule_parsed.path or "/"
                    return cand_path.startswith(rule_path)
                return False
            # If rule is a Domain
            elif rule_type == TargetType.DOMAIN:
                return cls.matches_domain_rule(cand_host, rule_val)
            # If rule is an IP or CIDR and candidate URL host is an IP
            elif rule_type in (TargetType.IP_ADDRESS, TargetType.CIDR):
                try:
                    host_ip = ipaddress.ip_address(cand_host)
                    return cls.matches_ip_rule(host_ip, rule_type, rule_val)
                except ValueError:
                    if allow_dns_resolution:
                        try:
                            addr_info = socket.getaddrinfo(cand_host, None, proto=socket.IPPROTO_TCP)
                            for entry in addr_info:
                                entry_ip = ipaddress.ip_address(entry[4][0])
                                if cls.matches_ip_rule(entry_ip, rule_type, rule_val):
                                    return True
                        except Exception:
                            pass
                    return False

        return False

    @classmethod
    def evaluate_target_ip_characteristics(cls, target_str: str, allow_dns_resolution: bool = False) -> Dict[str, bool]:
        """
        Determines if a target (URL, IP, CIDR, or Hostname) points to loopback or private IP ranges.
        Enables authorized internal network and staging environment assessments.
        """
        clean = target_str.strip()
        if "://" in clean:
            parsed = urlparse(clean)
            host = parsed.hostname or clean
        else:
            try:
                parsed = urlparse(f"http://{clean}")
                host = parsed.hostname or clean.split("/")[0].split(":")[0]
            except Exception:
                host = clean.split("/")[0].split(":")[0]

        host_clean = host.strip("[]")
        is_loopback = False
        is_private = False

        if host_clean.lower() in ("localhost", "127.0.0.1", "::1") or host_clean.lower().endswith(".localhost"):
            is_loopback = True

        cgnat_net = ipaddress.ip_network("100.64.0.0/10")

        try:
            ip = ipaddress.ip_address(host_clean)
            if ip.is_loopback:
                is_loopback = True
            if ip.is_private or (ip.version == 4 and ip in cgnat_net) or not ip.is_global:
                is_private = True
            return {"is_loopback": is_loopback, "is_private": is_private}
        except ValueError:
            try:
                net = ipaddress.ip_network(target_str.strip(), strict=False)
                if net.is_loopback:
                    is_loopback = True
                if net.is_private:
                    is_private = True
                return {"is_loopback": is_loopback, "is_private": is_private}
            except ValueError:
                pass

        if allow_dns_resolution:
            try:
                addr_info = socket.getaddrinfo(host_clean, None, proto=socket.IPPROTO_TCP)
                for entry in addr_info:
                    entry_ip = ipaddress.ip_address(entry[4][0])
                    if entry_ip.is_loopback:
                        is_loopback = True
                    if entry_ip.is_private or (entry_ip.version == 4 and entry_ip in cgnat_net) or not entry_ip.is_global:
                        is_private = True
            except Exception:
                pass

        return {"is_loopback": is_loopback, "is_private": is_private}

    @classmethod
    def revalidate_destination_before_connection(
        cls,
        destination_host: str,
        allow_private: bool = False,
        allow_loopback: bool = False,
    ) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Pre-connection destination revalidation to prevent DNS rebinding, SSRF, and metadata access.
        Normalizes obfuscated IP representations, resolves host, unwraps IPv4-mapped IPv6,
        and verifies that the resolved destination IP is safe.
        Returns: (is_safe, error_message, resolved_ip)
        """
        if not destination_host or not destination_host.strip():
            return False, "Destination host cannot be empty.", None

        host_clean = destination_host.strip().lower()
        if "://" in host_clean:
            parsed = urlparse(host_clean)
            host_clean = (parsed.hostname or host_clean).strip("[]")
        else:
            host_clean = host_clean.split("/")[0].split(":")[0].strip("[]")

        # 1. Cloud metadata check
        if host_clean in DANGEROUS_METADATA_HOSTNAMES or host_clean in CLOUD_METADATA_IPS:
            return False, f"Prohibited cloud metadata destination '{host_clean}' blocked.", None

        # 2. Check if already an IP literal
        try:
            ip = ipaddress.ip_address(host_clean)
            if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
                ip = ip.ipv4_mapped

            ip_str = str(ip)
            if ip_str in CLOUD_METADATA_IPS or ip.is_link_local:
                return False, f"Prohibited metadata/link-local IP '{ip_str}' blocked.", None

            if ip.is_loopback:
                if allow_loopback:
                    return True, None, ip_str
                return False, f"Loopback address '{ip_str}' not authorized for assessment.", None

            cgnat_net = ipaddress.ip_network("100.64.0.0/10")
            if (ip.is_private or (ip.version == 4 and ip in cgnat_net) or not ip.is_global) and not allow_private:
                return False, f"Private/reserved address '{ip_str}' not authorized for external assessment.", None

            return True, None, ip_str
        except ValueError:
            pass

        # 3. Resolve destination hostname immediately before connection
        try:
            addr_info = socket.getaddrinfo(host_clean, None, proto=socket.IPPROTO_TCP)
            if not addr_info:
                return False, f"DNS resolution failed for destination '{host_clean}'.", None

            for entry in addr_info:
                res_ip_str = entry[4][0]
                res_ip = ipaddress.ip_address(res_ip_str)
                if isinstance(res_ip, ipaddress.IPv6Address) and res_ip.ipv4_mapped:
                    res_ip = res_ip.ipv4_mapped

                ip_str = str(res_ip)
                if ip_str in CLOUD_METADATA_IPS or res_ip.is_link_local:
                    return False, f"DNS resolved to prohibited metadata/link-local address '{ip_str}'.", None

                if res_ip.is_loopback:
                    if not allow_loopback:
                        return False, f"DNS resolved to loopback address '{ip_str}'.", None
                else:
                    cgnat_net = ipaddress.ip_network("100.64.0.0/10")
                    if (res_ip.is_private or (res_ip.version == 4 and res_ip in cgnat_net) or not res_ip.is_global) and not allow_private:
                        return False, f"DNS resolved to internal/private IP '{ip_str}' without authorization.", None

            return True, None, addr_info[0][4][0]
        except socket.gaierror as e:
            return False, f"DNS resolution error for '{host_clean}': {e}", None
        except Exception as e:
            return False, f"Destination revalidation error: {e}", None

    @classmethod
    def validate_target_in_scope(
        cls,
        db: Session,
        project_id: str,
        target: str,
        now: Optional[datetime] = None,
        allow_dns_resolution: bool = False,
    ) -> Dict[str, Any]:
        """
        Pure server-side scope authorization check.
        1. Checks for prohibited cloud metadata destinations (fails closed).
        2. Normalizes target.
        3. Enforces exclusions: if any match -> immediately REJECT.
        4. Scans authorized targets: must have AUTHORIZED status and non-expired time.
        5. Fails closed with descriptive reason code.
        """
        # Step 0: Check if prohibited cloud metadata destination
        if cls.is_cloud_metadata_destination(target):
            return {
                "is_authorized": False,
                "status": "PROHIBITED_METADATA",
                "reason": "Target matches prohibited cloud metadata endpoint. Assessment rejected by security policy.",
                "normalized_target": target,
                "matched_rule": None,
                "matched_exclusion": None,
            }

        if now is None:
            now = datetime.now(timezone.utc)
        elif now.tzinfo is None:
            now = now.replace(tzinfo=timezone.utc)

        # Step 1: Normalize candidate target
        try:
            cand_type, cand_val = cls.normalize_target(target)
        except ScopeTargetParseException as e:
            return {
                "is_authorized": False,
                "status": "INVALID_TARGET",
                "reason": str(e),
                "normalized_target": target,
                "matched_rule": None,
                "matched_exclusion": None,
            }

        # Step 2: Check Exclusions first (Exclusions strictly override inclusions)
        exclusions = db.query(ScopeExclusion).filter(ScopeExclusion.project_id == project_id).all()
        for excl in exclusions:
            if cls.target_matches_rule(cand_type, cand_val, excl.target_type, excl.target_value, allow_dns_resolution=allow_dns_resolution):
                return {
                    "is_authorized": False,
                    "status": "EXCLUDED",
                    "reason": f"Target is strictly excluded: {excl.reason} (Exclusion rule: {excl.target_value})",
                    "normalized_target": cand_val,
                    "matched_rule": None,
                    "matched_exclusion": {
                        "id": excl.id,
                        "target_type": excl.target_type.value,
                        "target_value": excl.target_value,
                        "reason": excl.reason,
                    },
                }

        # Step 3: Check Scope Targets (all statuses for comprehensive feedback)
        targets = db.query(ScopeTarget).filter(ScopeTarget.project_id == project_id).all()

        matched_authorized_rule = None
        matched_pending_rule = None
        matched_revoked_rule = None
        matched_expired_rule = None

        for st in targets:
            if cls.target_matches_rule(cand_type, cand_val, st.target_type, st.target_value, allow_dns_resolution=allow_dns_resolution):
                # Check expiration
                is_expired = False
                if st.expires_at:
                    st_exp = st.expires_at
                    if st_exp.tzinfo is None:
                        st_exp = st_exp.replace(tzinfo=timezone.utc)
                    if st_exp <= now:
                        is_expired = True

                if st.authorization_status == AuthorizationStatus.AUTHORIZED:
                    if is_expired:
                        matched_expired_rule = st
                    else:
                        matched_authorized_rule = st
                        break  # Found active authorized scope
                elif st.authorization_status == AuthorizationStatus.PENDING:
                    matched_pending_rule = st
                elif st.authorization_status == AuthorizationStatus.REVOKED:
                    matched_revoked_rule = st
                elif st.authorization_status == AuthorizationStatus.EXPIRED or is_expired:
                    matched_expired_rule = st

        # Step 4: Evaluate match hierarchy (Fail Closed)
        if matched_authorized_rule:
            cand_chars = cls.evaluate_target_ip_characteristics(cand_val)
            rule_chars = cls.evaluate_target_ip_characteristics(matched_authorized_rule.target_value)
            is_priv_auth = bool(cand_chars["is_private"] or rule_chars["is_private"])
            is_loop_auth = bool(cand_chars["is_loopback"] or rule_chars["is_loopback"])

            return {
                "is_authorized": True,
                "status": "AUTHORIZED",
                "reason": f"Target is authorized under scope rule: {matched_authorized_rule.target_value}",
                "normalized_target": cand_val,
                "target_type": cand_type.value,
                "is_private_authorized": is_priv_auth,
                "is_loopback_authorized": is_loop_auth,
                "matched_rule": {
                    "id": matched_authorized_rule.id,
                    "target_type": matched_authorized_rule.target_type.value,
                    "target_value": matched_authorized_rule.target_value,
                    "status": matched_authorized_rule.authorization_status.value,
                    "evidence": matched_authorized_rule.authorization_evidence,
                    "expires_at": matched_authorized_rule.expires_at.isoformat() if matched_authorized_rule.expires_at else None,
                },
                "matched_exclusion": None,
            }

        if matched_revoked_rule:
            return {
                "is_authorized": False,
                "status": "REVOKED",
                "reason": f"Scope authorization was revoked: {matched_revoked_rule.revocation_reason or 'No reason provided'}",
                "normalized_target": cand_val,
                "matched_rule": {
                    "id": matched_revoked_rule.id,
                    "target_value": matched_revoked_rule.target_value,
                    "status": matched_revoked_rule.authorization_status.value,
                },
                "matched_exclusion": None,
            }

        if matched_expired_rule:
            return {
                "is_authorized": False,
                "status": "EXPIRED",
                "reason": "Scope authorization has expired.",
                "normalized_target": cand_val,
                "matched_rule": {
                    "id": matched_expired_rule.id,
                    "target_value": matched_expired_rule.target_value,
                    "status": "EXPIRED",
                },
                "matched_exclusion": None,
            }

        if matched_pending_rule:
            return {
                "is_authorized": False,
                "status": "PENDING_APPROVAL",
                "reason": "Target is registered in scope but pending authorization approval and evidence registration.",
                "normalized_target": cand_val,
                "matched_rule": {
                    "id": matched_pending_rule.id,
                    "target_value": matched_pending_rule.target_value,
                    "status": matched_pending_rule.authorization_status.value,
                },
                "matched_exclusion": None,
            }

        # Absolute default: Fail closed
        return {
            "is_authorized": False,
            "status": "NOT_IN_SCOPE",
            "reason": "Target is not within any registered and authorized scope boundary for this project.",
            "normalized_target": cand_val,
            "matched_rule": None,
            "matched_exclusion": None,
        }
