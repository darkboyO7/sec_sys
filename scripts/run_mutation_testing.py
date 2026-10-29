"""
VAPT Platform — Automated Mutation Testing & Control Verification CLI (Prompt 27).
Tests whether tests fail when security controls are mutated.
Outputs: mutation_test_report.json
"""
import sys
import os
import json
import time
import argparse
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "backend"))

from app.services.security_control_verification_service import security_control_verification_service


def main():
    parser = argparse.ArgumentParser(description="VAPT Platform Mutation Testing Runner")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON output")
    parser.add_argument("--output", type=str, default="mutation_test_report.json", help="Report output file path")
    args = parser.parse_args()

    print("=" * 80)
    print("   VAPT PLATFORM -- MUTATION TESTING & SECURITY CONTROL VERIFICATION")
    print("=" * 80)

    start_time = time.perf_counter()
    drill_result = security_control_verification_service.run_mutation_drill()
    duration = time.perf_counter() - start_time

    print(f"Drill ID:         {drill_result.drill_id}")
    print(f"Total Scenarios:  {drill_result.total_mutations}")
    print(f"Mutations Killed: {drill_result.killed_count} ({drill_result.kill_ratio_pct:.1f}%)")
    print(f"Survived:         {drill_result.survived_count}")
    print("-" * 80)
    print(f"{'Mutation ID':<14} | {'Target Component':<30} | {'Type':<16} | Status")
    print("-" * 80)

    for s in drill_result.scenarios:
        status_str = f"KILLED ({s.execution_time_ms:.1f}ms)" if s.status.value == "KILLED" else s.status.value
        target_short = s.target_component.split("/")[-1] if "/" in s.target_component else s.target_component
        print(f"{s.mutation_id:<14} | {target_short:<30} | {s.mutation_type:<16} | {status_str}")
        print(f"   -> Killer Test: {s.expected_killer_test}")

    print("=" * 80)
    print(f"MUTATION DRILL VERDICT: {drill_result.verdict}")
    print(f"Elapsed Time:           {duration:.3f}s")
    print("=" * 80)

    output_path = REPO_ROOT / args.output
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(drill_result.model_dump(), f, indent=2)
    print(f"Report written to: {output_path}")

    sys.exit(0 if drill_result.survived_count == 0 else 1)


if __name__ == "__main__":
    main()
