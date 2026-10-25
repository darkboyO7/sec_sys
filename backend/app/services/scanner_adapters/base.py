from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field, field_validator
from app.models.assessment import FindingSeverity, FindingConfidence


class RawAdapterEvidence(BaseModel):
    evidence_type: str = Field(min_length=2, max_length=100)
    payload: str = Field(min_length=1, max_length=65536)  # 64KB safety limit per evidence item
    observed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class RawAdapterFinding(BaseModel):
    title: str = Field(min_length=3, max_length=255)
    description: str = Field(default="")
    severity: FindingSeverity
    confidence: FindingConfidence = FindingConfidence.FIRM
    vuln_id: Optional[str] = Field(default=None, max_length=100)
    cvss_score: Optional[float] = Field(default=None, ge=0.0, le=10.0)
    reproduction_steps: str = Field(default="")
    evidence_items: List[RawAdapterEvidence] = Field(default_factory=list)


class AdapterResult(BaseModel):
    adapter_name: str
    adapter_version: str
    target: str
    is_simulated: bool = True  # Defaults to True for safe local fixtures
    success: bool
    status_summary: str
    findings: List[RawAdapterFinding] = Field(default_factory=list)
    errors: List[str] = Field(default_factory=list)
    execution_duration_ms: float = 0.0

    @field_validator("findings")
    @classmethod
    def check_findings_limit(cls, v: List[RawAdapterFinding]) -> List[RawAdapterFinding]:
        if len(v) > 50:
            raise ValueError("Adapter exceeded maximum allowed findings threshold per assessment (50).")
        return v


class BaseScannerAdapter(ABC):
    @property
    @abstractmethod
    def name(self) -> str:
        pass

    @property
    @abstractmethod
    def version(self) -> str:
        pass

    @abstractmethod
    def execute(self, target: str, config: Dict[str, Any]) -> AdapterResult:
        """
        Execute the adapter against the target.
        Must validate all schemas and return an AdapterResult.
        """
        pass
