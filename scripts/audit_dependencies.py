"""
VAPT Platform — Standalone Dependency Audit Tool (Prompt 25).
Audits Python and Node dependencies for known vulnerabilities and applies release gate policies.
Usage:
    python scripts/audit_dependencies.py [--offline] [--json]
"""
import sys
import argparse
import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "backend"))

from app.services.supply_chain_security_service import supply_chain_security_service


def main():
    parser = argparse.ArgumentParser(description="Audit VAPT Platform dependencies for known vulnerabilities")
    parser.add_argument("--offline", action="store_true", help="Force offline advisory catalog only")
    parser.add_argument("--json", action="store_true", help="Output machine-readable JSON")
    args = parser.parse_args()

    allow_network = not args.offline
    res = supply_chain_security_service.audit_dependencies(allow_network=allow_network)

    if args.json:
        print(res.model_dump_json(indent=2))
    else:
        print("=" * 80)
        print("   VAPT PLATFORM — DEPENDENCY INTELLIGENCE & VULNERABILITY AUDIT")
        print("=" * 80)
        print(f"Status:                 {res.status}")
        print(f"Advisory Service:       {res.advisory_service_status}")
        print(f"Total Advisories:       {res.total_vulnerabilities}")
        print(f"  Critical:             {res.critical_count}")
        print(f"  High:                 {res.high_count}")
        print(f"  Medium:               {res.medium_count}")
        print(f"  Low:                  {res.low_count}")
        print(f"Release Gate Decision:  {'PASSED' if res.release_gate_passed else 'BLOCKED'}")
        print("=" * 80)

        if res.advisories:
            print("Active Vulnerability Advisories:")
            for adv in res.advisories:
                print(f"  - [{adv.severity}] {adv.id} in {adv.package_name} ({adv.affected_version}): {adv.title}")
                if adv.remediation_version:
                    print(f"    Remediation: Upgrade to {adv.remediation_version}")

    sys.exit(0 if res.release_gate_passed else 1)


if __name__ == "__main__":
    main()
