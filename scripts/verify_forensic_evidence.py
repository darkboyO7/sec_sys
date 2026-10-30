#!/usr/bin/env python3
"""
VAPT Platform — Forensic Evidence Verification CLI (Prompt 48).
Inspects evidence records, cryptographic digests, digital origin signatures,
and custody chains in a strictly read-only manner without altering records.
"""
import sys
import json
import argparse
from pathlib import Path
from typing import List

# Setup python path to import backend app
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "backend"))

from app.core.database import SessionLocal, engine
from app.models.forensic_evidence import ForensicEvidenceRecord, VerificationOutcome
from app.services.forensic_evidence_service import forensic_evidence_service
import logging

engine.echo = False
logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)
logging.getLogger("sqlalchemy.pool").setLevel(logging.WARNING)


def main():
    parser = argparse.ArgumentParser(description="Forensic Evidence Read-Only Verification Tool")
    parser.add_argument("--evidence-id", type=str, help="Specific evidence record ID to inspect")
    parser.add_argument("--project-id", type=str, help="Filter inspection by project ID")
    parser.add_argument("--all", action="store_true", help="Inspect all forensic evidence records")
    parser.add_argument("--json", action="store_true", help="Output machine-readable JSON report")
    parser.add_argument("--quiet", action="store_true", help="Exit code only without table output")
    parser.add_argument("--strict", action="store_true", help="Exit with code 1 if any record fails verification")

    args = parser.parse_args()

    db = SessionLocal()
    try:
        query = db.query(ForensicEvidenceRecord).filter(ForensicEvidenceRecord.is_deleted == False)
        if args.evidence_id:
            query = query.filter(ForensicEvidenceRecord.id == args.evidence_id)
        elif args.project_id:
            query = query.filter(ForensicEvidenceRecord.project_id == args.project_id)
        elif not args.all:
            # Default to inspecting all if no filter given
            pass

        records = query.all()

        results = []
        all_verified = True

        for rec in records:
            # Inspection with persist=False guarantees purely read-only verification
            item = forensic_evidence_service.verify_evidence_record(
                db=db,
                evidence_id=rec.id,
                actor_id="forensic-cli-auditor",
                actor_role="ADMIN",
                persist=False,
            )
            results.append(item)
            if item.status != VerificationOutcome.VERIFIED:
                all_verified = False

        if args.json:
            report_dict = {
                "total_inspected": len(results),
                "all_verified": all_verified,
                "verified_count": sum(1 for r in results if r.status == VerificationOutcome.VERIFIED),
                "failed_count": sum(1 for r in results if r.status == VerificationOutcome.FAILED),
                "unavailable_count": sum(1 for r in results if r.status == VerificationOutcome.UNAVAILABLE),
                "items": [
                    {
                        "evidence_id": r.evidence_id,
                        "status": r.status.value,
                        "raw_digest_match": r.raw_digest_match,
                        "signature_valid": r.signature_valid,
                        "custody_chain_valid": r.custody_chain_valid,
                        "artifacts_present": r.artifacts_present,
                        "contradiction_status": r.contradiction_status.value if hasattr(r.contradiction_status, "value") else str(r.contradiction_status),
                        "discrepancies": r.discrepancies,
                    }
                    for r in results
                ],
            }
            print(json.dumps(report_dict, indent=2))
        elif not args.quiet:
            print("=" * 80)
            print("   VAPT PLATFORM -- READ-ONLY FORENSIC EVIDENCE VERIFICATION")
            print("=" * 80)
            print(f"Total Inspected: {len(results)}")
            print("-" * 80)
            print(f"{'Evidence ID':<38} | {'Status':<12} | {'Digest':<6} | {'Sig':<5} | {'Custody':<7}")
            print("-" * 80)
            for r in results:
                d_str = "OK" if r.raw_digest_match else "FAIL"
                s_str = "OK" if r.signature_valid else "FAIL"
                c_str = "OK" if r.custody_chain_valid else "FAIL"
                print(f"{r.evidence_id:<38} | {r.status.value:<12} | {d_str:<6} | {s_str:<5} | {c_str:<7}")
                if r.discrepancies:
                    for disc in r.discrepancies:
                        print(f"   ! {disc}")
            print("=" * 80)
            verdict = "VERIFIED" if all_verified and len(results) > 0 else ("NO_RECORDS" if len(results) == 0 else "FAILURES_DETECTED")
            print(f"OVERALL FORENSIC VERDICT: {verdict}")
            print("=" * 80)

        if args.strict:
            sys.exit(0 if (all_verified or len(results) == 0) else 1)
        sys.exit(0)
    finally:
        db.close()


if __name__ == "__main__":
    main()
