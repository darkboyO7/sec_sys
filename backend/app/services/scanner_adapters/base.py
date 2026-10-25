import math
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Callable, Set, Tuple
from pydantic import BaseModel, Field, field_validator
from app.models.assessment import FindingSeverity, FindingConfidence

PERMITTED_EVIDENCE_TYPES: Set[str] = {
    "HANDSHAKE_TRANSCRIPT",
    "HTTP_RESPONSE_HEADERS",
    "HTTP_REQUEST_RESPONSE",
    "FRAME_TEST",
    "HTTP_HEADER_ANALYSIS",
    "CONFIG_AUDIT",
    "PORT_STATE",
    "APPLICATION_LOG",
    "DNS_RECORD",
}


class RawAdapterEvidence(BaseModel):
    evidence_type: str = Field(min_length=2, max_length=100)
    payload: str = Field(min_length=1, max_length=65536)  # 64KB safety limit per evidence item
    sha256_hash: str = Field(default="")
    observed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @field_validator("payload", mode="before")
    @classmethod
    def sanitize_payload(cls, v: Any) -> str:
        s = str(v) if v is not None else ""
        if len(s) > 65536:
            suffix = "... [TRUNCATED_AT_64KB]"
            return s[: 65536 - len(suffix)] + suffix
        return s

    @field_validator("evidence_type")
    @classmethod
    def validate_type(cls, v: str) -> str:
        clean = v.strip().upper()
        if clean not in PERMITTED_EVIDENCE_TYPES:
            raise ValueError(f"Evidence type '{clean}' is not permitted. Must be one of: {sorted(PERMITTED_EVIDENCE_TYPES)}")
        return clean

    def model_post_init(self, __context: Any) -> None:
        if not self.sha256_hash and self.payload:
            import hashlib
            self.sha256_hash = hashlib.sha256(self.payload.encode("utf-8")).hexdigest()


class RawAdapterFinding(BaseModel):
    title: str = Field(min_length=3, max_length=255)
    description: str = Field(default="")
    severity: FindingSeverity
    confidence: FindingConfidence = FindingConfidence.FIRM
    vuln_id: Optional[str] = Field(default=None, max_length=100)
    cvss_score: Optional[float] = None
    reproduction_steps: str = Field(default="")
    evidence_items: List[RawAdapterEvidence] = Field(default_factory=list)

    @field_validator("cvss_score")
    @classmethod
    def validate_cvss(cls, v: Optional[float]) -> Optional[float]:
        if v is None:
            return None
        if math.isnan(v) or math.isinf(v) or v < 0.0 or v > 10.0:
            raise ValueError("CVSS score must be a finite float between 0.0 and 10.0")
        return round(v, 1)


class AdapterResult(BaseModel):
    adapter_name: str
    adapter_version: str
    target: str
    is_simulated: bool = True  # Strict transparency: always flags synthetic/fixture execution
    success: bool
    status_summary: str
    findings: List[RawAdapterFinding] = Field(default_factory=list)
    errors: List[str] = Field(default_factory=list)
    failure_category: Optional[str] = None
    execution_duration_ms: float = 0.0

    @field_validator("findings")
    @classmethod
    def check_findings_limit(cls, v: List[RawAdapterFinding]) -> List[RawAdapterFinding]:
        if len(v) > 50:
            raise ValueError("Adapter exceeded maximum allowed findings threshold per assessment (50).")
        return v


class BaseScannerAdapter(ABC):
    """
    Formal Typed Contract for Scanner Adapters.
    Every adapter must declare identity, version, capabilities, supported profiles,
    and supply configuration preflight and bounded execution without shell escapes.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Stable adapter identifier."""
        pass

    @property
    @abstractmethod
    def version(self) -> str:
        """SemVer adapter version."""
        pass

    @property
    @abstractmethod
    def declared_capabilities(self) -> List[str]:
        """List of security check capabilities provided by this adapter."""
        pass

    @property
    @abstractmethod
    def supported_profiles(self) -> List[str]:
        """List of supported assessment profile identifiers."""
        pass

    @property
    @abstractmethod
    def permitted_check_categories(self) -> List[str]:
        """List of permitted check categories for this adapter."""
        pass

    @abstractmethod
    def validate_config(self, config: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        """Validate adapter-specific execution configuration before preflight."""
        pass

    @abstractmethod
    def preflight_check(self, target: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """Verify target and configuration readiness without initiating network scans."""
        pass

    @abstractmethod
    def execute(
        self,
        target: str,
        config: Dict[str, Any],
        cancellation_check: Optional[Callable[[], bool]] = None,
    ) -> AdapterResult:
        """
        Execute bounded assessment against target.
        Must periodically invoke cancellation_check() if provided.
        """
        pass

    @abstractmethod
    def get_health(self) -> Dict[str, Any]:
        """Return readiness and operational health status."""
        pass


class AdapterRegistry:
    """
    Central Governance Registry for Approved Scanner Adapters.
    Enforces that only verified, permissioned adapters can be dispatched.
    """
    _registry: Dict[str, BaseScannerAdapter] = {}

    @classmethod
    def register(cls, adapter: BaseScannerAdapter) -> None:
        cls._registry[adapter.name] = adapter

    @classmethod
    def get(cls, name: str) -> Optional[BaseScannerAdapter]:
        return cls._registry.get(name)

    @classmethod
    def is_approved(cls, name: str) -> bool:
        return name in cls._registry

    @classmethod
    def list_capabilities(cls) -> List[Dict[str, Any]]:
        """List metadata and declared capabilities of all registered adapters."""
        return [
            {
                "name": a.name,
                "version": a.version,
                "declared_capabilities": a.declared_capabilities,
                "supported_profiles": a.supported_profiles,
                "permitted_check_categories": a.permitted_check_categories,
                "health": a.get_health(),
            }
            for a in cls._registry.values()
        ]
