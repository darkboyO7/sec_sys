"""
VAPT Platform — Supply-Chain Security & Release Provenance API (Prompt 25).
Provides endpoints for dependency intelligence, automated vulnerability auditing,
CycloneDX/SPDX SBOM retrieval, secret scanning, and verifiable release provenance.
"""
from pathlib import Path
from typing import Optional
from fastapi import APIRouter, Depends, Query, HTTPException, status
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.api.deps import get_current_user, require_system_roles
from app.models.user import User, SystemRole
from app.services.supply_chain_security_service import supply_chain_security_service
from app.schemas.supply_chain import (
    DependencyInventoryResponse,
    DependencyAuditResponse,
    SecretScanResponse,
    ReleaseVerificationRequest,
    ReleaseVerificationResult,
)

router = APIRouter()


@router.get("/inventory", response_model=DependencyInventoryResponse)
def get_dependency_inventory(
    current_user: User = Depends(require_system_roles([SystemRole.ADMIN, SystemRole.SECURITY_LEAD, SystemRole.AUDITOR, SystemRole.SECURITY_TESTER])),
):
    """
    Returns full direct and transitive dependency inventory across Python and Node ecosystems.
    """
    return supply_chain_security_service.generate_dependency_inventory()


@router.post("/audit", response_model=DependencyAuditResponse)
def run_dependency_audit(
    allow_network: bool = Query(True, description="Whether to attempt remote advisory lookup"),
    current_user: User = Depends(require_system_roles([SystemRole.ADMIN, SystemRole.SECURITY_LEAD, SystemRole.AUDITOR])),
):
    """
    Executes an on-demand dependency security audit evaluating package advisories against release gates.
    """
    return supply_chain_security_service.audit_dependencies(allow_network=allow_network)


@router.get("/sbom")
def get_sbom(
    format: str = Query("cyclonedx", description="SBOM specification: 'cyclonedx' (1.5) or 'spdx' (2.3)"),
    current_user: User = Depends(require_system_roles([SystemRole.ADMIN, SystemRole.SECURITY_LEAD, SystemRole.AUDITOR, SystemRole.SECURITY_TESTER])),
):
    """
    Generates and returns machine-readable Software Bill of Materials (SBOM).
    """
    if format.lower() == "spdx":
        data = supply_chain_security_service.generate_spdx_sbom()
        filename = "vapt-sbom.spdx.json"
    else:
        data = supply_chain_security_service.generate_cyclonedx_sbom()
        filename = "vapt-sbom.cdx.json"

    return JSONResponse(
        content=data,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.post("/secrets/scan", response_model=SecretScanResponse)
def scan_secrets(
    current_user: User = Depends(require_system_roles([SystemRole.ADMIN, SystemRole.SECURITY_LEAD, SystemRole.AUDITOR])),
):
    """
    Scans repository and configuration for high-entropy tokens, leaked credentials, or forbidden files.
    """
    return supply_chain_security_service.scan_sensitive_artifacts()


@router.post("/release/verify", response_model=ReleaseVerificationResult)
def verify_release(
    req: ReleaseVerificationRequest,
    current_user: User = Depends(require_system_roles([SystemRole.ADMIN, SystemRole.SECURITY_LEAD, SystemRole.AUDITOR])),
):
    """
    Verifies cryptographic signature, file checksums, and exclusion rules for a packaged release candidate.
    """
    archive_p = Path(req.archive_path) if req.archive_path else (supply_chain_security_service.dist_dir / "vapt-platform-v1.0.0.tar.gz")
    manifest_p = Path(req.manifest_path) if req.manifest_path else (archive_p.parent / "release-manifest.json")
    return supply_chain_security_service.verify_release_package(archive_p, manifest_p)

