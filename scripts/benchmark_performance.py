"""
VAPT Platform — Standalone Performance Benchmark Tool (Prompt 26).
Measures query latencies, index efficiency, throughput, and performance budget conformance.
Usage:
    python scripts/benchmark_performance.py [--dataset-size {SMALL,MEDIUM,LARGE}] [--json]
"""
import sys
import argparse
import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "backend"))

from app.core.database import SessionLocal
from app.services.workload_isolation_service import workload_isolation_service


def main():
    parser = argparse.ArgumentParser(description="Run VAPT Platform performance benchmarks")
    parser.add_argument("--dataset-size", choices=["SMALL", "MEDIUM", "LARGE"], default="SMALL", help="Dataset size tier")
    parser.add_argument("--json", action="store_true", help="Output machine-readable JSON")
    args = parser.parse_args()

    db = SessionLocal()
    try:
        res = workload_isolation_service.run_synthetic_benchmark(db, dataset_size=args.dataset_size)
        budgets_resp = workload_isolation_service.get_performance_budgets()

        if args.json:
            out = {
                "benchmark": res.model_dump(),
                "budgets": budgets_resp.model_dump(),
            }
            print(json.dumps(out, indent=2))
        else:
            print("=" * 80)
            print(f"   VAPT PLATFORM — PERFORMANCE BENCHMARK RESULTS ({args.dataset_size})")
            print("=" * 80)
            print(f"Environment:       Python {res.environment.get('python_version')} ({res.environment.get('os')})")
            print(f"Database Engine:   {res.environment.get('db_dialect')} (WAL mode active)")
            print(f"Total Duration:    {res.total_duration_ms:.2f} ms")
            print("-" * 80)
            print(f"{'Operation':<45} | {'Records':<8} | {'Latency (ms)':<12} | {'Throughput'}")
            print("-" * 80)
            for b in res.benchmarks:
                print(f"{b.operation:<45} | {b.record_count:<8} | {b.duration_ms:<12.2f} | {b.ops_per_second:.1f} ops/s")
            print("=" * 80)
            print(f"Summary: {res.summary}")
            print("=" * 80)
    finally:
        db.close()


if __name__ == "__main__":
    main()
