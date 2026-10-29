"""
VAPT Platform — Security Control Verification & Mutation Testing Schemas (Prompt 27).
Typed models for security invariant mapping, mutation scenarios, kill ratio metrics,
and continuous regression test assurance.
"""
from typing import Optional, List, Dict, Any
from datetime import datetime, timezone
import enum
from pydantic import BaseModel, Field


class ControlCategory(str, enum.Enum):
    AUTHENTICATION = "AUTHENTICATION"
    AUTHORIZATION_RBAC = "AUTHORIZATION_RBAC"
    SCOPE_ENFORCEMENT = "SCOPE_ENFORCEMENT"
    EXCLUSIONS_PRECEDENCE = "EXCLUSIONS_PRECEDENCE"
    EVIDENCE_INTEGRITY = "EVIDENCE_INTEGRITY"
    AUDIT_CHAIN_CONSISTENCY = "AUDIT_CHAIN_CONSISTENCY"
    REMEDIATION_GOVERNANCE = "REMEDIATION_GOVERNANCE"
    INDEPENDENT_RETEST = "INDEPENDENT_RETEST"
    DISASTER_RECOVERY_POSTCONDITION = "DISASTER_RECOVERY_POSTCONDITION"
    SSRF_PROTECTION = "SSRF_PROTECTION"
    SUPPLY_CHAIN_PROVENANCE = "SUPPLY_CHAIN_PROVENANCE"
    CONCURRENCY_WORKLOAD = "CONCURRENCY_WORKLOAD"


class MutationStatus(str, enum.Enum):
    KILLED = "KILLED"
    SURVIVED = "SURVIVED"
    PENDING = "PENDING"
    BLOCKED = "BLOCKED"


class SecurityControlRecord(BaseModel):
    control_id: str
    category: ControlCategory
    name: str
    description: str
    enforcement_point: str
    positive_test: str
    negative_test: str
    failure_behavior: str
    is_verified: bool = True
    last_verified_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class MutationScenario(BaseModel):
    mutation_id: str
    control_id: str
    name: str
    description: str
    target_component: str
    mutation_type: str  # e.g., INVERT_BOOLEAN, REMOVE_VALIDATION, BYPASS_AUTH, ALWAYS_TRUE
    expected_killer_test: str
    observed_failure: Optional[str] = None
    status: MutationStatus = MutationStatus.KILLED
    execution_time_ms: float = 0.0


class MutationDrillResult(BaseModel):
    drill_id: str
    total_mutations: int
    killed_count: int
    survived_count: int
    blocked_count: int
    kill_ratio_pct: float
    scenarios: List[MutationScenario]
    verdict: str  # QUALIFIED or DEFECT_DETECTED
    executed_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    details: Dict[str, Any] = Field(default_factory=dict)


class SecurityControlsCatalogResponse(BaseModel):
    total_controls: int
    verified_controls: int
    verification_pct: float
    controls: List[SecurityControlRecord]
    catalog_updated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
