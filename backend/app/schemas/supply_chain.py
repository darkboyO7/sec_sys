"""
VAPT Platform — Supply-Chain Security & Release Provenance Schemas (Prompt 25).
Provides typed models for dependency inventory, vulnerability auditing, CycloneDX/SPDX SBOMs,
secret detection, and verifiable cryptographic release provenance.
"""
from typing import Optional, List, Dict, Any
from datetime import datetime, timezone
import enum
from pydantic import BaseModel, Field


class DependencyEcosystem(str, enum.Enum):
    PYPI = "pypi"
    NPM = "npm"


class DependencyScope(str, enum.Enum):
    REQUIRED = "required"
    OPTIONAL = "optional"
    DEV = "dev"


class VulnerabilitySeverity(str, enum.Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class DependencyItem(BaseModel):
    name: str = Field(..., description="Package identifier")
    version: str = Field(..., description="Resolved package version")
    ecosystem: str = Field(..., description="Ecosystem (pypi or npm)")
    purl: str = Field(..., description="Package URL (PURL specification)")
    is_direct: bool = Field(..., description="Whether explicitly listed in top-level manifest")
    scope: str = Field("required", description="Dependency scope: required, dev, optional")
    license: Optional[str] = Field(None, description="SPDX license ID or declared license")
    checksum: Optional[str] = Field(None, description="SHA256 or SHA512 hash if known")
    supplier: Optional[str] = Field(None, description="Package author or publisher")


class DependencyInventoryResponse(BaseModel):
    total_dependencies: int
    pypi_count: int
    npm_count: int
    direct_count: int
    transitive_count: int
    items: List[DependencyItem]
    generated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class VulnerabilityAdvisory(BaseModel):
    id: str = Field(..., description="Advisory identifier (CVE or GHSA)")
    package_name: str
    ecosystem: str
    affected_version: str
    severity: str
    title: str
    description: Optional[str] = None
    remediation_version: Optional[str] = None
    advisory_url: Optional[str] = None


class DependencyAuditResponse(BaseModel):
    status: str = Field(..., description="Audit status: CLEAN, VULNERABILITIES_FOUND, DEGRADED_SCAN, CRITICAL_BLOCKED")
    advisory_service_status: str = Field(..., description="Advisory connectivity status: ONLINE, OFFLINE_FALLBACK, UNAVAILABLE")
    total_vulnerabilities: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    release_gate_passed: bool = True
    advisories: List[VulnerabilityAdvisory] = Field(default_factory=list)
    scanned_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    details: Dict[str, Any] = Field(default_factory=dict)


class SecretFinding(BaseModel):
    file_path: str
    line_number: Optional[int] = None
    rule_name: str
    severity: str
    redacted_match: str


class SecretScanResponse(BaseModel):
    status: str = Field(..., description="CLEAN or SECRETS_DETECTED")
    total_scanned_files: int
    total_findings: int
    findings: List[SecretFinding] = Field(default_factory=list)
    scanned_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class ReleaseFileEntry(BaseModel):
    path: str
    size_bytes: int
    sha256: str


class ReleaseManifest(BaseModel):
    manifest_version: str = "1.0"
    release_id: str
    app_name: str = "vapt-platform"
    version: str = "1.0.0"
    build_timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    git_commit: Optional[str] = None
    environment: Dict[str, str] = Field(default_factory=dict)
    sbom_sha256: Optional[str] = None
    files: List[ReleaseFileEntry] = Field(default_factory=list)
    signature: Optional[str] = None
    signature_algorithm: str = "HMAC-SHA256"


class ReleaseVerificationRequest(BaseModel):
    archive_path: Optional[str] = Field(None, description="Path to .tar.gz release archive on disk")
    manifest_path: Optional[str] = Field(None, description="Path to release-manifest.json")


class ReleaseVerificationResult(BaseModel):
    valid: bool
    release_id: str
    version: str
    total_files_verified: int = 0
    mismatched_files: List[str] = Field(default_factory=list)
    missing_files: List[str] = Field(default_factory=list)
    unexpected_files: List[str] = Field(default_factory=list)
    forbidden_files_detected: List[str] = Field(default_factory=list)
    signature_valid: bool = False
    message: str = ""
    errors: List[str] = Field(default_factory=list)
