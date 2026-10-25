import hashlib
import math
from abc import ABC, abstractmethod
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional, Callable, Set, Tuple
from pydantic import BaseModel, Field, field_validator, model_validator
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

MAX_EVIDENCE_PAYLOAD_BYTES = 65536  # 64KB per individual evidence item
MAX_JOB_EVIDENCE_TOTAL_BYTES = 1048576  # 1MB aggregate evidence payload per job
MAX_FINDINGS_PER_JOB = 50
MAX_EVIDENCE_PER_FINDING = 20


def truncate_utf8_to_bytes(text: str, max_bytes: int = MAX_EVIDENCE_PAYLOAD_BYTES) -> Tuple[str, bool]:
    """
    Safely truncates text so its UTF-8 byte length is <= max_bytes.
    Preserves valid multibyte code point boundaries without corrupting characters.
    Returns (safe_text, was_truncated).
    """
    raw_bytes = text.encode("utf-8", errors="replace")
    if len(raw_bytes) <= max_bytes:
        return text, False

    suffix = b"... [TRUNCATED_AT_64KB]"
    allowed_bytes = max_bytes - len(suffix)
    truncated_slice = raw_bytes[:allowed_bytes]

    # Decode ignoring trailing incomplete multibyte byte
    safe_str = truncated_slice.decode("utf-8", errors="ignore") + "... [TRUNCATED_AT_64KB]"
    return safe_str, True


class RawAdapterEvidence(BaseModel):
    evidence_type: str = Field(min_length=2, max_length=100)
    payload: str = Field(default="")
    sha256_hash: str = Field(default="")  # Hash of persisted/stored payload
    raw_sha256_hash: str = Field(default="")  # Hash of untruncated raw payload
    is_truncated: bool = Field(default=False)
    observed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @model_validator(mode="before")
    @classmethod
    def process_and_sanitize_payload(cls, data: Any) -> Any:
        if isinstance(data, dict):
            raw_val = data.get("payload", "")
            s = str(raw_val) if raw_val is not None else ""
            raw_bytes = s.encode("utf-8", errors="replace")
            raw_hash = hashlib.sha256(raw_bytes).hexdigest()

            safe_text, was_truncated = truncate_utf8_to_bytes(s, max_bytes=MAX_EVIDENCE_PAYLOAD_BYTES)
            persisted_hash = hashlib.sha256(safe_text.encode("utf-8")).hexdigest()

            data["payload"] = safe_text
            data["raw_sha256_hash"] = raw_hash
            data["sha256_hash"] = persisted_hash
            data["is_truncated"] = was_truncated

            # Validate and clamp observed_at timestamp
            obs = data.get("observed_at")
            if obs is not None:
                if isinstance(obs, str):
                    try:
                        obs = datetime.fromisoformat(obs)
                    except Exception:
                        obs = datetime.now(timezone.utc)
                if isinstance(obs, datetime):
                    if obs.tzinfo is None:
                        obs = obs.replace(tzinfo=timezone.utc)
                    now = datetime.now(timezone.utc)
                    if obs > now + timedelta(seconds=5):
                        obs = now
                    data["observed_at"] = obs
        return data

    @field_validator("evidence_type")
    @classmethod
    def validate_type(cls, v: str) -> str:
        clean = v.strip().upper()
        if clean not in PERMITTED_EVIDENCE_TYPES:
            raise ValueError(f"Evidence type '{clean}' is not permitted. Must be one of: {sorted(PERMITTED_EVIDENCE_TYPES)}")
        return clean


class RawAdapterFinding(BaseModel):
    title: str = Field(min_length=3, max_length=255)
    description: str = Field(default="")
    severity: FindingSeverity
    confidence: FindingConfidence = FindingConfidence.FIRM
    vuln_id: Optional[str] = Field(default=None, max_length=100)
    cvss_score: Optional[float] = None
    reproduction_steps: str = Field(default="")
    evidence_items: List[RawAdapterEvidence] = Field(default_factory=list)

    @field_validator("evidence_items")
    @classmethod
    def bound_evidence_items(cls, v: List[RawAdapterEvidence]) -> List[RawAdapterEvidence]:
        if len(v) > MAX_EVIDENCE_PER_FINDING:
            return v[:MAX_EVIDENCE_PER_FINDING]
        return v

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
        if len(v) > MAX_FINDINGS_PER_JOB:
            return v[:MAX_FINDINGS_PER_JOB]
        return v

    @model_validator(mode="after")
    def bound_total_evidence_size(self) -> "AdapterResult":
        total_bytes = 0
        for f in self.findings:
            for ev in f.evidence_items:
                total_bytes += len(ev.payload.encode("utf-8", errors="replace"))
        if total_bytes > MAX_JOB_EVIDENCE_TOTAL_BYTES:
            raise ValueError(f"Total evidence payload exceeds maximum job limit of 1MB (observed {total_bytes} bytes).")
        return self


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
