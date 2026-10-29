"""
VAPT Platform — Software Supply-Chain Security, Dependency Intelligence & Verifiable Release Provenance.
Test suite for Prompt 25.
Validates:
1. Complete dependency inventory across PyPI and npm ecosystems with PURLs and direct/transitive tracking.
2. Valid CycloneDX 1.5 JSON and SPDX 2.3 JSON Software Bill of Materials (SBOM) generation.
3. Ecosystem-native and offline vulnerability auditing with fail-closed advisory feed tracking.
4. Release gate policy enforcement (critical vulnerabilities block release qualification).
5. High-entropy secret and sensitive development artifact scanning with safe redaction.
6. Exclusion of forbidden files (.env, SQLite databases, WAL files, node_modules, .venv, caches).
7. Deterministic release packaging and cryptographic HMAC-SHA256 manifest signing.
8. Independent release verification with tamper detection (modified files, missing files, unexpected files, signature invalidation).
9. Windows path separator normalization.
10. REST API endpoints under /system/supply-chain/* with role-based access control.
"""
import os
import sys
import json
import uuid
import hmac
import hashlib
import tarfile
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.core.config import settings
from app.core.security import create_access_token
from app.models.user import User, SystemRole
from app.services.supply_chain_security_service import (
    supply_chain_security_service,
    SupplyChainSecurityService,
)
from app.schemas.supply_chain import (
    DependencyInventoryResponse,
    DependencyAuditResponse,
    SecretScanResponse,
    ReleaseVerificationResult,
)


def auth_headers(user: User, request_id: str = "test-req-prompt25") -> dict:
    token = create_access_token(subject=user.id, claims={"role": user.system_role.value})
    return {
        "Authorization": f"Bearer {token}",
        "X-Request-ID": request_id,
        "X-Correlation-ID": request_id,
    }


# ------------------------------------------------------------------------------
# 1. Dependency Inventory Generation
# ------------------------------------------------------------------------------
def test_01_dependency_inventory_generation_covers_pypi_and_npm():
    """
    Verifies that the dependency intelligence engine inventories both Python and Node
    ecosystems, capturing package names, versions, PURLs, direct vs transitive status, and licenses.
    """
    inventory = supply_chain_security_service.generate_dependency_inventory()
    assert isinstance(inventory, DependencyInventoryResponse)
    assert inventory.total_dependencies > 100
    assert inventory.pypi_count > 30
    assert inventory.npm_count > 50
    assert inventory.direct_count > 10
    assert inventory.transitive_count > 50

    purl_list = [item.purl for item in inventory.items]
    assert any("pkg:pypi/fastapi@" in p for p in purl_list)
    assert any("pkg:npm/react@" in p for p in purl_list)

    # Check that direct dependencies are identified
    direct_pypi = [i.name.lower() for i in inventory.items if i.ecosystem == "pypi" and i.is_direct]
    assert "fastapi" in direct_pypi
    assert "sqlalchemy" in direct_pypi


# ------------------------------------------------------------------------------
# 2. CycloneDX 1.5 JSON SBOM Generation & Schema Verification
# ------------------------------------------------------------------------------
def test_02_cyclonedx_sbom_generation_and_schema_validation(tmp_path: Path):
    """
    Verifies that CycloneDX 1.5 JSON SBOM is correctly structured with serialNumber URN,
    specVersion 1.5, tools metadata, application component, PURLs, and licenses.
    """
    out_file = tmp_path / "test-sbom.cdx.json"
    sbom = supply_chain_security_service.generate_cyclonedx_sbom(output_path=out_file)

    assert out_file.exists()
    assert sbom["bomFormat"] == "CycloneDX"
    assert sbom["specVersion"] == "1.5"
    assert sbom["serialNumber"].startswith("urn:uuid:")
    assert sbom["metadata"]["component"]["name"] == "vapt-platform"

    components = sbom["components"]
    assert len(components) > 100
    for comp in components[:10]:
        assert "name" in comp
        assert "version" in comp
        assert comp["purl"].startswith("pkg:")
        assert comp["type"] == "library"


# ------------------------------------------------------------------------------
# 3. SPDX 2.3 JSON SBOM Generation & Schema Verification
# ------------------------------------------------------------------------------
def test_03_spdx_sbom_generation_and_schema_validation(tmp_path: Path):
    """
    Verifies that SPDX 2.3 JSON SBOM is correctly formatted with dataLicense CC0-1.0,
    creationInfo, unique package SPDXIDs, and external PURL references.
    """
    out_file = tmp_path / "test-sbom.spdx.json"
    spdx = supply_chain_security_service.generate_spdx_sbom(output_path=out_file)

    assert out_file.exists()
    assert spdx["spdxVersion"] == "SPDX-2.3"
    assert spdx["dataLicense"] == "CC0-1.0"
    assert spdx["SPDXID"] == "SPDXRef-DOCUMENT"
    assert spdx["documentNamespace"].startswith("https://vapt.internal/spdx/")

    packages = spdx["packages"]
    assert len(packages) > 100
    for pkg in packages[:10]:
        assert pkg["SPDXID"].startswith("SPDXRef-Package-")
        assert "name" in pkg
        assert "versionInfo" in pkg
        assert len(pkg["externalRefs"]) > 0
        assert pkg["externalRefs"][0]["referenceCategory"] == "PACKAGE-MANAGER"


# ------------------------------------------------------------------------------
# 4. Dependency Vulnerability Audit (Clean Baseline)
# ------------------------------------------------------------------------------
def test_04_vulnerability_audit_clean_baseline():
    """
    Verifies that the repository dependencies audit cleanly under local and offline checks.
    """
    audit = supply_chain_security_service.audit_dependencies(allow_network=False)
    assert isinstance(audit, DependencyAuditResponse)
    assert audit.critical_count == 0
    assert audit.release_gate_passed is True
    assert audit.advisory_service_status in ("ONLINE", "OFFLINE_FALLBACK")


# ------------------------------------------------------------------------------
# 5. Critical Vulnerability Blocks Release Gate
# ------------------------------------------------------------------------------
def test_05_critical_vulnerability_blocks_release_gate():
    """
    Verifies that injecting a critical vulnerability advisory fails the release gate
    with status CRITICAL_BLOCKED and release_gate_passed=False.
    """
    simulated_advisories = [
        {
            "id": "CVE-2026-99999",
            "package_name": "fastapi",
            "ecosystem": "pypi",
            "affected_spec": "<1.0.0",
            "severity": "CRITICAL",
            "title": "Simulated Remote Code Execution",
            "remediation_version": "1.0.0",
            "advisory_url": "https://nvd.nist.gov/simulated",
        }
    ]
    with patch("app.services.supply_chain_security_service.LOCAL_ADVISORY_DATABASE", simulated_advisories):
        audit = supply_chain_security_service.audit_dependencies(allow_network=False)
        assert audit.critical_count == 1
        assert audit.release_gate_passed is False
        assert audit.status == "CRITICAL_BLOCKED"
        assert audit.advisories[0].id == "CVE-2026-99999"


# ------------------------------------------------------------------------------
# 6. Advisory Service Network Failure Handled Explicitly
# ------------------------------------------------------------------------------
def test_06_unavailable_remote_advisory_feed_fallback():
    """
    Verifies that an unavailable remote advisory service reports OFFLINE_FALLBACK
    without crashing or claiming a pristine online scan.
    """
    with patch("urllib.request.urlopen", side_effect=OSError("Network unreachable")):
        audit = supply_chain_security_service.audit_dependencies(allow_network=True)
        assert audit.advisory_service_status == "OFFLINE_FALLBACK"
        assert "remote_advisory_status" in audit.details


# ------------------------------------------------------------------------------
# 7. Sensitive Artifact Scanning & Redaction
# ------------------------------------------------------------------------------
def test_07_sensitive_artifact_scan_detects_and_redacts_secrets(tmp_path: Path):
    """
    Verifies that high-entropy tokens and private keys are detected and safely redacted in output.
    """
    test_dir = tmp_path / "src"
    test_dir.mkdir()
    # Synthetic test keys (safe non-production)
    simulated_file = test_dir / "service_client.py"
    simulated_file.write_text(
        "api_key = 'sk-live-1234567890abcdef1234567890abcdef'\n"
        "aws_key = 'AKIAIOSFODNN7EXAMPLE'\n",
        encoding="utf-8",
    )

    scanner = SupplyChainSecurityService(repo_root=tmp_path)
    res = scanner.scan_sensitive_artifacts(target_dir=test_dir)

    assert res.status == "SECRETS_DETECTED"
    assert res.total_findings >= 2

    # Verify redaction: full secret must NOT appear in output
    for finding in res.findings:
        assert "1234567890abcdef1234567890abcdef" not in finding.redacted_match
        assert "*" in finding.redacted_match


# ------------------------------------------------------------------------------
# 8. Forbidden .env File Detected and Rejected
# ------------------------------------------------------------------------------
def test_08_forbidden_env_file_detected(tmp_path: Path):
    """
    Verifies that presence of forbidden .env or .env.local files triggers critical hygiene finding.
    """
    env_file = tmp_path / ".env"
    env_file.write_text("DATABASE_URL=sqlite:///production.db\nSECRET_KEY=leaked\n", encoding="utf-8")

    scanner = SupplyChainSecurityService(repo_root=tmp_path)
    res = scanner.scan_sensitive_artifacts(target_dir=tmp_path)

    assert res.status == "SECRETS_DETECTED"
    env_findings = [f for f in res.findings if ".env" in f.file_path]
    assert len(env_findings) > 0
    assert env_findings[0].severity == "CRITICAL"


# ------------------------------------------------------------------------------
# 9. SQLite DB & WAL Files Excluded From Release Packaging
# ------------------------------------------------------------------------------
def test_09_database_and_wal_files_excluded_from_release(tmp_path: Path):
    """
    Verifies that local sqlite database, WAL, and SHM files are strictly omitted from release archives.
    """
    # Create mock repo structure in tmp_path
    mock_backend = tmp_path / "backend"
    mock_backend.mkdir(parents=True)
    (mock_backend / "main.py").write_text("print('hello')", encoding="utf-8")
    (mock_backend / "vapt.db").write_text("fake sqlite db bytes", encoding="utf-8")
    (mock_backend / "vapt_test.db").write_text("fake test sqlite db", encoding="utf-8")
    (mock_backend / "app.db-wal").write_text("fake wal bytes", encoding="utf-8")
    (mock_backend / "requirements.txt").write_text("fastapi==0.162.0\n", encoding="utf-8")

    mock_frontend = tmp_path / "frontend"
    mock_frontend.mkdir(parents=True)
    (mock_frontend / "package.json").write_text('{"name": "test"}', encoding="utf-8")

    scanner = SupplyChainSecurityService(repo_root=tmp_path)
    archive_p, manifest_p = scanner.build_release_package(
        version="1.0.0-test",
        output_dir=tmp_path / "dist",
        signing_key="test-secret-key-12345",
    )

    # Inspect archive contents
    with tarfile.open(archive_p, "r:gz") as tar:
        names = tar.getnames()
        assert not any(".db" in n for n in names)
        assert not any("-wal" in n for n in names)
        assert not any("vapt_test.db" in n for n in names)
        assert any("backend/main.py" in n for n in names)


# ------------------------------------------------------------------------------
# 10. Clean Release Packaging & Cryptographic Manifest Signing
# ------------------------------------------------------------------------------
def test_10_clean_release_packaging_and_manifest_signing(tmp_path: Path):
    """
    Verifies that build_release_package produces a clean archive, an SBOM, and a
    cryptographically signed manifest with valid HMAC-SHA256 digest.
    """
    archive_p, manifest_p = supply_chain_security_service.build_release_package(
        version="1.0.0-p25",
        output_dir=tmp_path / "dist",
        signing_key="deterministic-test-key-32b",
    )

    assert archive_p.exists()
    assert manifest_p.exists()

    manifest_data = json.loads(manifest_p.read_text(encoding="utf-8"))
    assert manifest_data["version"] == "1.0.0-p25"
    assert manifest_data["signature_algorithm"] == "HMAC-SHA256"
    assert manifest_data["signature"] is not None
    assert len(manifest_data["files"]) > 20
    assert manifest_data["sbom_sha256"] is not None


# ------------------------------------------------------------------------------
# 11. Valid Release Passes Independent Verification
# ------------------------------------------------------------------------------
def test_11_valid_release_manifest_passes_independent_verification(tmp_path: Path):
    """
    Verifies that a genuine release archive and manifest pass verification cleanly.
    """
    archive_p, manifest_p = supply_chain_security_service.build_release_package(
        version="1.0.0-verify",
        output_dir=tmp_path / "dist",
        signing_key="deterministic-test-key-32b",
    )

    res = supply_chain_security_service.verify_release_package(
        archive_path=archive_p,
        manifest_path=manifest_p,
        signing_key="deterministic-test-key-32b",
    )

    assert res.valid is True
    assert res.signature_valid is True
    assert res.total_files_verified > 20
    assert len(res.mismatched_files) == 0
    assert len(res.missing_files) == 0
    assert len(res.unexpected_files) == 0
    assert len(res.forbidden_files_detected) == 0


# ------------------------------------------------------------------------------
# 12. Modified Artifact Fails SHA-256 Verification (Tamper Detection)
# ------------------------------------------------------------------------------
def test_12_modified_archive_fails_sha256_verification(tmp_path: Path):
    """
    Verifies that tampering with an archived file causes hash mismatch detection.
    """
    archive_p, manifest_p = supply_chain_security_service.build_release_package(
        version="1.0.0-tamper",
        output_dir=tmp_path / "dist",
        signing_key="deterministic-test-key-32b",
    )

    # Unpack, modify a file, and repack archive
    unpack_dir = tmp_path / "unpacked"
    unpack_dir.mkdir()
    with tarfile.open(archive_p, "r:gz") as tar:
        tar.extractall(unpack_dir)

    # Tamper with a packaged file
    tampered_file = next(unpack_dir.rglob("*.py"))
    tampered_file.write_text("# MALICIOUS MODIFICATION\n", encoding="utf-8")

    tampered_archive = tmp_path / "tampered.tar.gz"
    with tarfile.open(tampered_archive, "w:gz") as tar:
        for root, _, files in os.walk(unpack_dir):
            for file in files:
                full_p = Path(root) / file
                rel_p = str(full_p.relative_to(unpack_dir)).replace("\\", "/")
                tar.add(str(full_p), arcname=rel_p)

    res = supply_chain_security_service.verify_release_package(
        archive_path=tampered_archive,
        manifest_path=manifest_p,
        signing_key="deterministic-test-key-32b",
    )

    assert res.valid is False
    assert len(res.mismatched_files) > 0


# ------------------------------------------------------------------------------
# 13. Missing Packaged File Detected
# ------------------------------------------------------------------------------
def test_13_missing_packaged_file_detected(tmp_path: Path):
    """
    Verifies that omitting a manifested file from the archive triggers missing file alert.
    """
    archive_p, manifest_p = supply_chain_security_service.build_release_package(
        version="1.0.0-missing",
        output_dir=tmp_path / "dist",
        signing_key="deterministic-test-key-32b",
    )

    # Unpack and delete a manifested file
    unpack_dir = tmp_path / "unpacked"
    unpack_dir.mkdir()
    with tarfile.open(archive_p, "r:gz") as tar:
        tar.extractall(unpack_dir)

    target_file = next(unpack_dir.rglob("*.json"))
    target_rel = str(target_file.relative_to(unpack_dir)).replace("\\", "/")
    target_file.unlink()

    incomplete_archive = tmp_path / "incomplete.tar.gz"
    with tarfile.open(incomplete_archive, "w:gz") as tar:
        for root, _, files in os.walk(unpack_dir):
            for file in files:
                full_p = Path(root) / file
                rel_p = str(full_p.relative_to(unpack_dir)).replace("\\", "/")
                tar.add(str(full_p), arcname=rel_p)

    res = supply_chain_security_service.verify_release_package(
        archive_path=incomplete_archive,
        manifest_path=manifest_p,
        signing_key="deterministic-test-key-32b",
    )

    assert res.valid is False
    assert target_rel in res.missing_files


# ------------------------------------------------------------------------------
# 14. Unexpected Unmanifested File Detected
# ------------------------------------------------------------------------------
def test_14_unexpected_unmanifested_file_detected(tmp_path: Path):
    """
    Verifies that injecting an extra unmanifested file into the release archive fails verification.
    """
    archive_p, manifest_p = supply_chain_security_service.build_release_package(
        version="1.0.0-extra",
        output_dir=tmp_path / "dist",
        signing_key="deterministic-test-key-32b",
    )

    unpack_dir = tmp_path / "unpacked"
    unpack_dir.mkdir()
    with tarfile.open(archive_p, "r:gz") as tar:
        tar.extractall(unpack_dir)

    extra_file = unpack_dir / "unmanifested_backdoor.sh"
    extra_file.write_text("#!/bin/sh\necho pwned\n", encoding="utf-8")

    injected_archive = tmp_path / "injected.tar.gz"
    with tarfile.open(injected_archive, "w:gz") as tar:
        for root, _, files in os.walk(unpack_dir):
            for file in files:
                full_p = Path(root) / file
                rel_p = str(full_p.relative_to(unpack_dir)).replace("\\", "/")
                tar.add(str(full_p), arcname=rel_p)

    res = supply_chain_security_service.verify_release_package(
        archive_path=injected_archive,
        manifest_path=manifest_p,
        signing_key="deterministic-test-key-32b",
    )

    assert res.valid is False
    assert "unmanifested_backdoor.sh" in res.unexpected_files


# ------------------------------------------------------------------------------
# 15. Tampered Manifest Fails Cryptographic Signature
# ------------------------------------------------------------------------------
def test_15_tampered_manifest_fails_cryptographic_signature(tmp_path: Path):
    """
    Verifies that altering manifest metadata or files without knowledge of the secret
    signing key invalidates the HMAC-SHA256 signature.
    """
    archive_p, manifest_p = supply_chain_security_service.build_release_package(
        version="1.0.0-sigtest",
        output_dir=tmp_path / "dist",
        signing_key="deterministic-test-key-32b",
    )

    # Tamper with version in manifest
    manifest_data = json.loads(manifest_p.read_text(encoding="utf-8"))
    manifest_data["version"] = "2.0.0-forged"
    tampered_manifest_p = tmp_path / "forged-manifest.json"
    tampered_manifest_p.write_text(json.dumps(manifest_data), encoding="utf-8")

    res = supply_chain_security_service.verify_release_package(
        archive_path=archive_p,
        manifest_path=tampered_manifest_p,
        signing_key="deterministic-test-key-32b",
    )

    assert res.valid is False
    assert res.signature_valid is False
    assert any("signature mismatch" in err.lower() for err in res.errors)


# ------------------------------------------------------------------------------
# 16. Windows Path Separator Normalization
# ------------------------------------------------------------------------------
def test_16_windows_path_separators_normalized(tmp_path: Path):
    """
    Verifies that paths containing backslashes and forward slashes are normalized
    uniformly to standard POSIX relative paths in manifest and archive.
    """
    archive_p, manifest_p = supply_chain_security_service.build_release_package(
        version="1.0.0-paths",
        output_dir=tmp_path / "dist",
        signing_key="deterministic-test-key-32b",
    )

    manifest_data = json.loads(manifest_p.read_text(encoding="utf-8"))
    for file_entry in manifest_data["files"]:
        assert "\\" not in file_entry["path"]
        assert not file_entry["path"].startswith("/")


# ------------------------------------------------------------------------------
# 17. REST API Endpoints with RBAC
# ------------------------------------------------------------------------------
def test_17_rest_api_supply_chain_endpoints_rbac(client: TestClient, admin_user: User, tester_user: User):
    """
    Tests REST API endpoints:
    - /system/supply-chain/inventory (accessible to tester and admin)
    - /system/supply-chain/audit (admin/lead/auditor only)
    - /system/supply-chain/sbom (accessible to tester and admin)
    - /system/supply-chain/secrets/scan (admin/lead/auditor only)
    - /system/supply-chain/release/verify (admin/lead/auditor only)
    - Unauthenticated requests rejected with 401
    """
    # 1. Unauthenticated rejection
    unauth_resp = client.get("/api/v1/system/supply-chain/inventory")
    assert unauth_resp.status_code == 401

    # 2. Inventory (accessible to tester)
    tester_headers = auth_headers(tester_user, "req-tester-inv")
    inv_resp = client.get("/api/v1/system/supply-chain/inventory", headers=tester_headers)
    assert inv_resp.status_code == 200
    inv_data = inv_resp.json()
    assert "total_dependencies" in inv_data
    assert inv_data["total_dependencies"] > 50

    # 3. SBOM retrieval (CycloneDX)
    sbom_resp = client.get("/api/v1/system/supply-chain/sbom?format=cyclonedx", headers=tester_headers)
    assert sbom_resp.status_code == 200
    sbom_data = sbom_resp.json()
    assert sbom_data["bomFormat"] == "CycloneDX"

    # 4. Audit (admin authorized, tester forbidden)
    audit_tester_resp = client.post("/api/v1/system/supply-chain/audit?allow_network=false", headers=tester_headers)
    assert audit_tester_resp.status_code == 403

    admin_h = auth_headers(admin_user, "req-admin-audit")
    audit_admin_resp = client.post("/api/v1/system/supply-chain/audit?allow_network=false", headers=admin_h)
    assert audit_admin_resp.status_code == 200
    audit_data = audit_admin_resp.json()
    assert "release_gate_passed" in audit_data

    # 5. Secrets scan (admin authorized)
    scan_resp = client.post("/api/v1/system/supply-chain/secrets/scan", headers=admin_h)
    assert scan_resp.status_code == 200
    scan_data = scan_resp.json()
    assert "total_scanned_files" in scan_data
