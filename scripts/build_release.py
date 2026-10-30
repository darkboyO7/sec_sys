"""
VAPT Platform — Verifiable Release Packaging Tool (Prompt 25 & Prompt 44).
Builds a clean, deterministic release archive and cryptographic release manifest with HMAC-SHA256 signature.
Supports safe candidate staging (dist/candidates/) and atomic promotion to prevent overwriting
last-known-good releases until full acceptance checks pass.

Usage:
    python scripts/build_release.py [--version VERSION] [--signing-key KEY] [--output-dir DIR] [--candidate] [--promote]
"""
import sys
import argparse
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "backend"))

from app.services.supply_chain_security_service import supply_chain_security_service


def main():
    parser = argparse.ArgumentParser(description="Build and sign verified VAPT Platform release candidate")
    parser.add_argument("--version", default="1.0.0", help="Release version tag")
    parser.add_argument("--signing-key", default=None, help="Cryptographic signing key (defaults to platform secret)")
    parser.add_argument("--output-dir", default=str(REPO_ROOT / "dist"), help="Output directory for release artifacts")
    parser.add_argument("--candidate", action="store_true", help="Build as release candidate in dist/candidates")
    parser.add_argument("--promote", action="store_true", help="Promote candidate to release destination after verification")
    args = parser.parse_args()

    out_dir = Path(args.output_dir)
    print("=" * 80)
    mode_label = "RELEASE CANDIDATE (STAGED)" if args.candidate else "PRODUCTION RELEASE"
    print(f"   BUILDING VERIFIED {mode_label} (v{args.version})")
    print("=" * 80)

    # 1. Secret & sensitive file pre-packaging check
    print("Step 1: Scanning for forbidden files, unmasked secrets, and dangerous frontend variables...")
    secret_res = supply_chain_security_service.scan_sensitive_artifacts()
    if secret_res.findings:
        crit_findings = [f for f in secret_res.findings if f.severity == "CRITICAL"]
        if crit_findings:
            print(f" [FAIL] Critical sensitive artifacts detected ({len(crit_findings)}). Aborting packaging.")
            for f in crit_findings[:5]:
                print(f"   ! {f.rule_name} in {f.file_path}: {f.redacted_match}")
            sys.exit(1)

    vite_violations = supply_chain_security_service.audit_frontend_build_variables()
    if vite_violations:
        print(f" [FAIL] Insecure frontend build variables detected ({len(vite_violations)}). Aborting packaging.")
        for v in vite_violations[:5]:
            print(f"   ! {v}")
        sys.exit(1)

    print(" [PASS] Sensitive artifact, secret, and frontend variable pre-check passed.")

    # 2. Package release and sign manifest
    print(f"Step 2: Bundling release archive and computing file digests (as_candidate={args.candidate})...")
    archive_path, manifest_path = supply_chain_security_service.build_release_package(
        version=args.version,
        signing_key=args.signing_key,
        output_dir=out_dir,
        as_candidate=args.candidate,
    )

    print(f" [PASS] Archive created:  {archive_path} ({archive_path.stat().st_size / 1024:.1f} KB)")
    print(f" [PASS] Manifest created: {manifest_path}")

    # 3. Independent self-verification check
    print("Step 3: Performing independent cryptographic self-verification...")
    ver_res = supply_chain_security_service.verify_release_package(
        archive_path=archive_path,
        manifest_path=manifest_path,
        signing_key=args.signing_key,
    )

    if not ver_res.valid:
        print(f" [FAIL] Release self-verification failed: {ver_res.message}")
        for err in ver_res.errors:
            print(f"   ! {err}")
        sys.exit(1)

    print(f" [PASS] Release provenance verified! {ver_res.total_files_verified} files verified authentic.")
    print(" [PASS] Manifest signature valid (HMAC-SHA256).")

    # 4. Optional promotion upon verified success
    if args.candidate and args.promote:
        print("Step 4: Acceptance checks satisfied. Promoting candidate to final release destination...")
        final_archive, final_manifest = supply_chain_security_service.promote_release_candidate(
            candidate_archive=archive_path,
            candidate_manifest=manifest_path,
            target_dir=out_dir,
            version=args.version,
        )
        print(f" [PASS] Promoted archive:  {final_archive} ({final_archive.stat().st_size / 1024:.1f} KB)")
        print(f" [PASS] Promoted manifest: {final_manifest}")
        archive_path = final_archive

    print("=" * 80)
    print(f"RELEASE READY: {archive_path}")
    print("=" * 80)
    sys.exit(0)


if __name__ == "__main__":
    main()
