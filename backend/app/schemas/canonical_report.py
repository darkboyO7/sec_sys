"""
Canonical Assessment Report & Verifiable Export Schemas (Prompt 32).
Strict versioned contracts for evidence-backed reports, portable bundles, and validation results.
"""
from datetime import datetime
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, ConfigDict, Field


class CanonicalEvidenceRef(BaseModel):
    evidence_id: str
    finding_id: str
    evidence_type: str
    sha256_digest: str
    collected_at: Optional[str] = None
    source: str = "assessment_probe"
    redacted: bool = False


class CanonicalFindingRecord(BaseModel):
    id: str
    fingerprint: str
    title: str
    description: str
    severity: str
    confidence: str
    cvss_score: Optional[float] = None
    target: str
    status: str
    remediation_status: Optional[str] = None
    retest_outcome: Optional[str] = None
    is_simulated: bool = False
    evidence_refs: List[str] = Field(default_factory=list)
    has_missing_evidence: bool = False
    contradictory_evidence_noted: bool = False
    uncertainty_rationale: Optional[str] = None
    first_detected_at: Optional[str] = None
    last_observed_at: Optional[str] = None


class CanonicalAssetRecord(BaseModel):
    id: str
    name: str
    target_value: str
    asset_type: str
    criticality: str
    has_active_findings: bool = False
    assessment_covered: bool = True


class CanonicalRemediationRecord(BaseModel):
    id: str
    finding_id: str
    title: str
    action_type: str
    governance_stage: str
    status: str


class CanonicalRetestRecord(BaseModel):
    id: str
    finding_id: str
    outcome: str
    verification_method: str
    verified_at: Optional[str] = None


class ReportCoverageSummary(BaseModel):
    assessment_id: str
    target_input: str
    status: str
    total_targets_assessed: int = 1
    total_checks_attempted: int = 0
    total_checks_completed: int = 0
    checks_failed_count: int = 0
    skipped_checks: List[str] = Field(default_factory=list)
    missing_evidence_count: int = 0
    coverage_gap_identified: bool = False
    is_incomplete: bool = False
    disclaimer: str = (
        "Clean assessment results on an asset reflect absence of detected indicators "
        "during testing; unassessed components are not certified secure."
    )


class AssessmentReportManifest(BaseModel):
    schema_version: str = "1.0.0"
    report_id: str
    project_id: str
    assessment_id: str
    title: str
    assessment_status: str
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    generated_at: str
    methodology: Dict[str, Any] = Field(default_factory=dict)
    scope_summary: Dict[str, Any] = Field(default_factory=dict)
    coverage_summary: ReportCoverageSummary
    finding_counts_by_severity: Dict[str, int] = Field(default_factory=dict)
    findings: List[CanonicalFindingRecord] = Field(default_factory=list)
    assets: List[CanonicalAssetRecord] = Field(default_factory=list)
    remediation_summary: List[CanonicalRemediationRecord] = Field(default_factory=list)
    retest_verifications: List[CanonicalRetestRecord] = Field(default_factory=list)
    evidence_manifest: List[CanonicalEvidenceRef] = Field(default_factory=list)
    limitations: List[str] = Field(default_factory=list)
    provenance_digest: str


class AssessmentBundleManifest(BaseModel):
    manifest_version: str = "1.0.0"
    bundle_version: str = "1.0.0"
    report_id: str
    assessment_id: str
    project_id: str
    exported_at: str
    exporter_version: str = "vapt-bundle-exporter-3.2.0"
    files: Dict[str, str] = Field(default_factory=dict)  # relative_path -> sha256
    omitted_content: List[str] = Field(
        default_factory=lambda: [
            "unredacted_raw_credentials",
            "active_session_tokens",
            "private_cryptographic_keys",
            "out_of_scope_assets",
        ]
    )
    integrity_digest: str


class BundleVerificationResult(BaseModel):
    is_valid: bool
    manifest_version: Optional[str] = None
    bundle_version: Optional[str] = None
    assessment_id: Optional[str] = None
    project_id: Optional[str] = None
    file_count: int = 0
    total_decompressed_bytes: int = 0
    checked_files: List[str] = Field(default_factory=list)
    corrupted_files: List[str] = Field(default_factory=list)
    missing_files: List[str] = Field(default_factory=list)
    violations: List[str] = Field(default_factory=list)
    assessment_summary: Optional[Dict[str, Any]] = None
    inspection_mode: str = "validation_only"
