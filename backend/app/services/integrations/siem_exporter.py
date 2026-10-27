"""
SIEM and Log Platform Export Adapter (Phase 31).
Formats and exports audit events and vulnerability findings into
Common Event Format (CEF v0.1), RFC 5424 Syslog, and Normalized JSON streams.
"""
import logging
from typing import Dict, Any, Optional, List, Tuple
from datetime import datetime, timezone

from app.services.integrations.base import (
    BaseIntegrationAdapter,
    IntegrationType,
    IntegrationStatus,
)

logger = logging.getLogger("vapt.integrations.siem")


class SiemExporterAdapter(BaseIntegrationAdapter):
    """
    Adapter for exporting structured security events to SIEM platforms
    (Splunk, Microsoft Sentinel, IBM QRadar, Elastic Security).
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(
            name="SIEM Audit Exporter Adapter",
            version="1.0.0",
            integration_type=IntegrationType.SIEM_EXPORTER,
            config=config,
        )
        self.device_vendor = self.config.get("device_vendor", "VAPT_Platform")
        self.device_product = self.config.get("device_product", "VAPT_System")
        self.device_version = self.config.get("device_version", "1.0.0")

    def validate_configuration(self) -> Tuple[bool, Optional[str]]:
        return True, None

    def health_check(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "status": self.status.value,
            "supported_formats": ["CEF", "SYSLOG_RFC5424", "JSON_STREAM"],
            "device_vendor": self.device_vendor,
            "device_product": self.device_product,
        }

    @classmethod
    def sanitize_event_data(cls, data: Dict[str, Any]) -> Dict[str, Any]:
        """Scans and scrubs secrets from export payloads."""
        import re
        scrubbed = {}
        for k, v in data.items():
            if isinstance(v, str):
                v_clean = re.sub(r'(?i)(password|passwd|token|bearer|key)\s*[:=]\s*\S+', r'\1=[REDACTED]', v)
                scrubbed[k] = v_clean
            elif isinstance(v, dict):
                scrubbed[k] = cls.sanitize_event_data(v)
            else:
                scrubbed[k] = v
        return scrubbed

    def format_event_cef(self, event: Dict[str, Any]) -> str:
        """
        Formats an audit or security event as a CEF (Common Event Format) string:
        CEF:Version|Device Vendor|Device Product|Device Version|Device Event Class ID|Name|Severity|[Extension]
        """
        action = event.get("action", "SECURITY_EVENT")
        name = event.get("description") or f"VAPT Event: {action}"
        severity_map = {
            "CRITICAL": "10",
            "HIGH": "8",
            "MEDIUM": "5",
            "LOW": "3",
            "INFO": "1",
        }
        raw_sev = str(event.get("severity", "INFO")).upper()
        sev_num = severity_map.get(raw_sev, "3")

        clean_details = self.sanitize_event_data(event.get("details", {}) or {})

        # Extensions
        extensions = [
            f"act={action}",
            f"cs1Label=Project cs1={event.get('project_id', 'GLOBAL')}",
            f"duser={event.get('actor_id', 'SYSTEM')}",
            f"src={event.get('client_ip', '127.0.0.1')}",
        ]

        if event.get("event_hash"):
            extensions.append(f"cs2Label=AuditHash cs2={event.get('event_hash')}")
        if event.get("target_resource"):
            extensions.append(f"cs3Label=Target cs3={event.get('target_resource')}")

        return (
            f"CEF:0|{self.device_vendor}|{self.device_product}|{self.device_version}|"
            f"{action}|{name}|{sev_num}|{' '.join(extensions)}"
        )

    def format_event_syslog(self, event: Dict[str, Any]) -> str:
        """
        Formats an event as RFC 5424 Syslog:
        <PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
        """
        # Facility 10 (security/auth), Severity 5 (notice) -> PRI = 10*8 + 5 = 85
        pri = 85
        now_ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        host = "vapt-host"
        app = self.device_product
        action = event.get("action", "SECURITY_EVENT")
        pid = "-"
        msgid = str(event.get("sequence_id", "-"))

        cef_msg = self.format_event_cef(event)
        return f"<{pri}>1 {now_ts} {host} {app} {pid} {msgid} - {cef_msg}"

    def export_audit_stream(
        self,
        audit_events: List[Dict[str, Any]],
        format_type: str = "CEF",
    ) -> List[str]:
        """Exports a batch of audit events into the designated format."""
        formatted: List[str] = []
        fmt = (format_type or "CEF").upper().strip()

        for ev in audit_events:
            if fmt == "CEF":
                formatted.append(self.format_event_cef(ev))
            elif fmt in ("SYSLOG", "RFC5424"):
                formatted.append(self.format_event_syslog(ev))
            else:
                # JSON Stream
                import json
                clean_ev = self.sanitize_event_data(ev)
                formatted.append(json.dumps(clean_ev, sort_keys=True))

        return formatted
