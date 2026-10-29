"""
VAPT Platform — Evidence Lifecycle & Retention CLI Tool (Prompt 29).
Executes automated or operator-driven retention scans, previews, and verifiable deletions.
Usage:
    python scripts/run_retention_lifecycle.py [--preview] [--execute] [--json]
"""
import os
import sys
import json
import argparse
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
BACKEND_DIR = REPO_ROOT / "backend"
sys.path.insert(0, str(BACKEND_DIR))

from app.core.database import SessionLocal
from app.services.evidence_lifecycle_service import evidence_lifecycle_service
from app.schemas.evidence_lifecycle import RetentionExecutionRequest


def main():
    parser = argparse.ArgumentParser(description="Evidence Lifecycle & Data Retention Governance CLI")
    parser.add_argument("--preview", action="store_true", help="Generate retention preview report without executing")
    parser.add_argument("--execute", action="store_true", help="Execute retention actions on eligible expired records")
    parser.add_argument("--json", action="store_true", help="Emit output in structured JSON format")
    args = parser.parse_args()

    db = SessionLocal()
    try:
        report = evidence_lifecycle_service.generate_retention_preview(db=db)

        if not args.execute or args.preview:
            if args.json:
                print(json.dumps(report.dict(), indent=2))
            else:
                print("=" * 80)
                print("   VAPT PLATFORM -- EVIDENCE RETENTION PREVIEW")
                print("=" * 80)
                print(f"Preview ID:                  {report.preview_id}")
                print(f"Total Scanned Evidence:      {report.total_scanned_records}")
                print(f"Eligible for Action:         {report.eligible_records_count}")
                print(f"Excluded by Legal Hold:      {report.excluded_by_hold_count}")
                print(f"Excluded by Dependencies:    {report.excluded_by_dependency_count}")
                print(f"Dry-Run State Hash:          {report.dry_run_hash[:16]}...")
                print("=" * 80)
            return 0

        # Execute
        req = RetentionExecutionRequest(
            preview_id=report.preview_id,
            dry_run_hash=report.dry_run_hash,
            confirmed_by_lead=True,
        )
        res = evidence_lifecycle_service.execute_retention(
            req=req,
            db=db,
            executed_by_id="CLI_SYSTEM_ADMIN",
        )

        out_file = REPO_ROOT / "retention_lifecycle_report.json"
        out_file.write_text(json.dumps(res.dict(), indent=2), encoding="utf-8")

        if args.json:
            print(json.dumps(res.dict(), indent=2))
        else:
            print("=" * 80)
            print("   VAPT PLATFORM -- EVIDENCE RETENTION EXECUTION COMPLETED")
            print("=" * 80)
            print(f"Execution ID:                {res.execution_id}")
            print(f"Deleted Records:             {res.deleted_count}")
            print(f"Redacted Records:            {res.redacted_count}")
            print(f"Archived Records:            {res.archived_count}")
            print(f"Tombstones Generated:        {res.tombstones_created_count}")
            print(f"Audit Event ID:              {res.audit_event_id}")
            print(f"Report written to:           {out_file}")
            print("=" * 80)
        return 0
    finally:
        db.close()


if __name__ == "__main__":
    sys.exit(main())
