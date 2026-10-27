"""
Base Integration Adapter Contract (Phase 31 / Part XV, Section 31).
Enforces structured contracts, configuration validation, rate-limiting,
and error handling across all external and optional platform integrations.
"""
import abc
import enum
import logging
from typing import Dict, Any, Optional, Tuple

logger = logging.getLogger("vapt.integrations")


class IntegrationType(str, enum.Enum):
    VULNERABILITY_FEED = "VULNERABILITY_FEED"
    WEBHOOK_NOTIFIER = "WEBHOOK_NOTIFIER"
    SIEM_EXPORTER = "SIEM_EXPORTER"
    ASSET_SOURCE = "ASSET_SOURCE"


class IntegrationStatus(str, enum.Enum):
    CONFIGURED = "CONFIGURED"
    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    DISABLED = "DISABLED"


class IntegrationError(Exception):
    """Base exception for all integration errors."""
    pass


class IntegrationConfigError(IntegrationError):
    """Raised when integration configuration is invalid or missing required parameters."""
    pass


class IntegrationNetworkError(IntegrationError):
    """Raised when communication with an external integration service fails."""
    pass


class IntegrationRateLimitError(IntegrationError):
    """Raised when rate limits are exceeded for an integration."""
    pass


class BaseIntegrationAdapter(abc.ABC):
    """
    Abstract base class for all enterprise integration adapters.
    Ensures safe lifecycle management, credential handling, and auditability.
    """

    def __init__(self, name: str, version: str, integration_type: IntegrationType, config: Optional[Dict[str, Any]] = None):
        self.name = name
        self.version = version
        self.integration_type = integration_type
        self.config = config or {}
        self.is_enabled = bool(self.config.get("enabled", True))
        self._status = IntegrationStatus.CONFIGURED if self.is_enabled else IntegrationStatus.DISABLED

    @property
    def status(self) -> IntegrationStatus:
        return self._status

    @abc.abstractmethod
    def validate_configuration(self) -> Tuple[bool, Optional[str]]:
        """Validates configuration parameters, secret formats, and reachability prerequisites."""
        pass

    @abc.abstractmethod
    def health_check(self) -> Dict[str, Any]:
        """Performs a non-destructive health probe of the integration."""
        pass
