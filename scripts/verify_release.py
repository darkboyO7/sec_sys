"""
VAPT Platform — Standalone Release Verification Tool (Prompt 25).
Self-contained cryptographic verification tool:
- Validates HMAC-SHA256 signature of release manifest.
- Validates SHA-256 integrity hashes for all packaged files.
- Detects missing, modified, unmanifested, or forbidden files (.env, databases, caches).
Usage:
    python scripts/verify_release.py [ARCHIVE_PATH] [--manifest MANIFEST_PATH] [--signing-key KEY]
"""
import sys
import os
import argparse
import json
import hmac
import hashlib
import tarfile
import re
from pathlib import Path

DEFAULT_KEY = "dev_insecure_secret_key_change_in_production_min_32_bytes_long"

FORBIDDEN_RELEASE_PATTERNS = [
    r"\.env$",
    r"\.env\.local$",
    r"\.git",
    r"node_modules",
    r"\.venv",
    r"__pycache__",
    r"\.pytest_cache",
    r"\.db(?:-[a-z]+)?$",
    r"\.sqlite(?:3)?(?:-[a-z]+)?$",
    r"-wal$",
    r"-shm$",
    r"-journal$",
    r"vapt_test\.db",
    r"vapt\.db",
]


def canonical_manifest_bytes(manifest: dict) -> bytes:
    data = {
        "release_id": manifest.get("release_id"),
        "version": manifest.get("version"),
        "build_timestamp": manifest.get("build_timestamp"),
        "git_commit": manifest.get("git_commit"),
        "sbom_sha256": manifest.get("sbom_sha256"),
        "files": [
            {"path": f["path"], "sha256": f["sha256"], "size_bytes": f["size_bytes"]}
            for f in sorted(manifest.get("files", []), key=lambda x: x["path"])
        ],
    }
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")


def main():
    parser = argparse.ArgumentParser(description="Independently verify VAPT Platform release candidate archive")
    parser.add_argument("archive", nargs="?", default="dist/vapt-platform-v1.0.0.tar.gz", help="Path to .tar.gz release archive")
    parser.add_argument("--manifest", default=None, help="Path to release-manifest.json (default: next to archive)")
    parser.add_argument("--signing-key", default=None, help="Cryptographic HMAC-SHA256 verification key")
    args = parser.parse_args()

    archive_path = Path(args.archive)
    if not archive_path.exists():
        print(f" [FAIL] Release archive not found at '{archive_path}'")
        sys.exit(1)

    manifest_path = Path(args.manifest) if args.manifest else (archive_path.parent / "release-manifest.json")
    if not manifest_path.exists():
        print(f" [FAIL] Release manifest not found at '{manifest_path}'")
        sys.exit(1)

    print("=" * 80)
    print(f"   VERIFYING RELEASE ARCHIVE: {archive_path.name}")
    print(f"   MANIFEST:                 {manifest_path.name}")
    print("=" * 80)

    try:
        manifest_data = json.loads(manifest_path.read_text(encoding="utf-8"))
    except Exception as e:
        print(f" [FAIL] Malformed manifest JSON: {str(e)}")
        sys.exit(1)

    # 1. Signature verification
    signing_key = (args.signing_key or os.environ.get("VAPT_RELEASE_SIGNING_KEY", DEFAULT_KEY)).encode("utf-8")
    expected_sig = hmac.new(signing_key, canonical_manifest_bytes(manifest_data), hashlib.sha256).hexdigest()
    actual_sig = manifest_data.get("signature", "")

    if not hmac.compare_digest(actual_sig, expected_sig):
        print(f" [FAIL] Cryptographic signature verification failed!")
        print(f"        Expected: {expected_sig[:16]}...")
        print(f"        Actual:   {actual_sig[:16] if actual_sig else 'NONE'}...")
        sys.exit(1)
    print(" [PASS] Cryptographic manifest signature verified (HMAC-SHA256).")

    # 2. Archive contents verification
    manifest_files = {f["path"]: f["sha256"] for f in manifest_data.get("files", [])}
    archive_files = {}
    forbidden_found = []

    try:
        with tarfile.open(archive_path, "r:gz") as tar:
            for member in tar.getmembers():
                if not member.isfile():
                    continue
                rel_p = member.name.replace("\\", "/")
                # Check forbidden patterns
                for pat in FORBIDDEN_RELEASE_PATTERNS:
                    if re.search(pat, rel_p, re.IGNORECASE):
                        forbidden_found.append(rel_p)
                f = tar.extractfile(member)
                if f:
                    file_bytes = f.read()
                    f_sha = hashlib.sha256(file_bytes).hexdigest()
                    archive_files[rel_p] = f_sha
    except Exception as e:
        print(f" [FAIL] Failed extracting archive: {str(e)}")
        sys.exit(1)

    if forbidden_found:
        print(f" [FAIL] Forbidden files detected in release archive:")
        for forbidden in forbidden_found[:10]:
            print(f"   ! {forbidden}")
        sys.exit(1)
    print(" [PASS] Exclusion verification passed: 0 forbidden artifacts detected.")

    missing = []
    mismatched = []
    for p, exp_sha in manifest_files.items():
        if p not in archive_files:
            missing.append(p)
        elif archive_files[p] != exp_sha:
            mismatched.append(p)

    unexpected = [p for p in archive_files if p not in manifest_files]

    if missing:
        print(f" [FAIL] {len(missing)} manifested file(s) are MISSING from archive.")
        for p in missing[:5]:
            print(f"   ! Missing: {p}")
    if mismatched:
        print(f" [FAIL] {len(mismatched)} file(s) failed SHA-256 hash integrity check.")
        for p in mismatched[:5]:
            print(f"   ! Mismatch: {p}")
    if unexpected:
        print(f" [FAIL] {len(unexpected)} unmanifested file(s) found in archive.")
        for p in unexpected[:5]:
            print(f"   ! Unexpected: {p}")

    if not missing and not mismatched and not unexpected:
        print(f" [PASS] All {len(archive_files)} archived files verified intact with matching SHA-256 hashes.")
        print("=" * 80)
        print("RESULT: RELEASE VERIFIED AUTHENTIC & UNTAMPERED")
        print("=" * 80)
        sys.exit(0)
    else:
        print("=" * 80)
        print("RESULT: RELEASE VERIFICATION FAILED")
        print("=" * 80)
        sys.exit(1)


if __name__ == "__main__":
    main()
