"""
VAPT Platform — Standalone SBOM Generator (Prompt 25).
Generates and validates CycloneDX 1.5 JSON and SPDX 2.3 JSON Software Bill of Materials.
Usage:
    python scripts/generate_sbom.py [--format {cyclonedx,spdx,all}] [--output-dir DIR]
"""
import sys
import argparse
import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "backend"))

from app.services.supply_chain_security_service import supply_chain_security_service


def main():
    parser = argparse.ArgumentParser(description="Generate and validate VAPT Platform SBOMs")
    parser.add_argument("--format", choices=["cyclonedx", "spdx", "all"], default="all", help="SBOM format to produce")
    parser.add_argument("--output-dir", default=str(REPO_ROOT / "reports" / "sbom"), help="Target directory for SBOM outputs")
    args = parser.parse_args()

    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"Generating Software Bill of Materials (SBOM) into {out_dir}...")

    if args.format in ("cyclonedx", "all"):
        cdx_file = out_dir / "vapt-sbom.cdx.json"
        data = supply_chain_security_service.generate_cyclonedx_sbom(cdx_file)
        comps = len(data.get("components", []))
        print(f" [PASS] CycloneDX 1.5 JSON generated: {cdx_file} ({comps} components)")

    if args.format in ("spdx", "all"):
        spdx_file = out_dir / "vapt-sbom.spdx.json"
        data = supply_chain_security_service.generate_spdx_sbom(spdx_file)
        pkgs = len(data.get("packages", []))
        print(f" [PASS] SPDX 2.3 JSON generated: {spdx_file} ({pkgs} packages)")

    print("SBOM generation complete.")


if __name__ == "__main__":
    main()
