"""
Background Assessment Worker Daemon for VAPT System.
Polls the database for queued assessment jobs and executes them asynchronously.
"""
import os
import sys
import time
import signal
import logging
import argparse
from datetime import datetime, timezone

# Ensure backend root is on sys.path
backend_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if backend_root not in sys.path:
    sys.path.insert(0, backend_root)

from app.core.database import SessionLocal
from app.services.assessment_engine import AssessmentExecutionEngine
from app.models.assessment import AssessmentStatus

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [worker] %(message)s",
)
logger = logging.getLogger("assessment_worker")

running = True


def handle_signal(sig, frame):
    global running
    logger.info("Shutdown signal received (%s), finishing active jobs and stopping...", sig)
    running = False


def run_worker_loop(
    worker_id: str,
    poll_interval: float = 1.0,
    once: bool = False,
    session_factory=None,
    db_session=None,
) -> int:
    global running
    logger.info(
        "Starting VAPT Background Assessment Worker daemon (worker_id=%s, poll_interval=%.1fs, once=%s)...",
        worker_id,
        poll_interval,
        once,
    )

    last_stale_recovery = time.time()
    jobs_processed = 0

    while running:
        db = db_session if db_session is not None else (session_factory() if session_factory else SessionLocal())
        try:
            # Check for stale workers every 60s
            if time.time() - last_stale_recovery > 60:
                recovered = AssessmentExecutionEngine.recover_stale_workers(db=db)
                if recovered:
                    logger.warning("Recovered %d stale/abandoned assessment job(s).", len(recovered))
                last_stale_recovery = time.time()

            # Process due continuous monitoring recurring schedules
            from app.services.continuous_monitoring_service import ContinuousMonitoringService
            due_runs = ContinuousMonitoringService.process_due_schedules(db=db)
            if due_runs:
                logger.info("Executed %d continuous monitoring recurring run(s).", len(due_runs))

            # Claim next available QUEUED job
            job = AssessmentExecutionEngine.claim_next_available_job(db=db, worker_id=worker_id)
            if job:
                logger.info(
                    "Claimed job %s for target '%s' (adapter: %s)",
                    job.id,
                    job.target_input,
                    job.adapter_name,
                )
                executed_job = AssessmentExecutionEngine.execute_job(
                    db=db,
                    job_id=job.id,
                    worker_id=worker_id,
                    client_ip="127.0.0.1",
                )
                jobs_processed += 1
                status_val = (
                    executed_job.status.value
                    if hasattr(executed_job.status, "value")
                    else str(executed_job.status)
                )
                duration_s = (
                    (executed_job.completed_at - executed_job.started_at).total_seconds()
                    if executed_job.completed_at and executed_job.started_at
                    else 0.0
                )
                logger.info(
                    "Job %s completed: status=%s, findings=%d, duration=%.2fs",
                    executed_job.id,
                    status_val,
                    len(executed_job.findings),
                    duration_s,
                )
                if once:
                    break
                continue  # Immediately check for another queued job
        except Exception as e:
            logger.exception("Error processing assessment queue: %s", e)
        finally:
            if db_session is None:
                db.close()

        if once:
            break

        time.sleep(poll_interval)

    logger.info("VAPT Background Assessment Worker stopped cleanly. Processed %d job(s).", jobs_processed)
    return jobs_processed


def main():
    parser = argparse.ArgumentParser(description="VAPT System Background Assessment Worker")
    parser.add_argument(
        "--worker-id",
        type=str,
        default=f"worker-daemon-{os.getpid()}",
        help="Unique worker identifier",
    )
    parser.add_argument(
        "--poll-interval",
        type=float,
        default=1.0,
        help="Queue polling interval in seconds (default: 1.0)",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Process at most one job or claim cycle and exit",
    )

    args = parser.parse_args()

    # Register signals if in main thread
    try:
        signal.signal(signal.SIGINT, handle_signal)
        signal.signal(signal.SIGTERM, handle_signal)
    except (ValueError, AttributeError):
        pass

    run_worker_loop(
        worker_id=args.worker_id,
        poll_interval=args.poll_interval,
        once=args.once,
    )


if __name__ == "__main__":
    main()
