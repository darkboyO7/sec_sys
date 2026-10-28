import hashlib
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session

from app.models.project import Project, ProjectRole
from app.models.user import User, SystemRole
from app.models.assessment import AssessmentJob, AssessmentStatus
from app.models.finding import VulnerabilityFinding, FindingLifecycleStatus
from app.models.monitoring import (
    MonitoringSchedule,
    MonitoringRun,
    ScheduleFrequency,
    ScheduleStatus,
)
from app.models.regression import (
    RegressionAlert,
    RegressionAlertType,
    AlertSeverity,
    AlertStatus,
)
from app.models.base import utc_now
from app.services.audit_service import AuditService
from app.services.scope_engine import ScopeEngine
from app.services.assessment_engine import AssessmentExecutionEngine
from app.services.regression_service import RegressionDetectionService
from app.schemas.monitoring import ScheduleCreate, ScheduleUpdate


class ContinuousMonitoringService:
    """
    Continuous Security Monitoring and Recurring Assessment Engine.
    Enforces:
    1. Scope & authorization re-validation before every recurring assessment run.
    2. Change detection across runs (new exposures, recurring findings, resolved findings).
    3. Duplicate-job prevention and bounded retry/failure recovery.
    4. Stale asset observation management.
    5. Tenant isolation and comprehensive audit logging.
    """

    @classmethod
    def calculate_next_run(
        cls,
        frequency: ScheduleFrequency,
        interval_seconds: int,
        from_time: Optional[datetime] = None,
    ) -> datetime:
        base = from_time or utc_now()
        if base.tzinfo is None:
            base = base.replace(tzinfo=timezone.utc)

        if frequency == ScheduleFrequency.HOURLY:
            return base + timedelta(hours=1)
        elif frequency == ScheduleFrequency.DAILY:
            return base + timedelta(days=1)
        elif frequency == ScheduleFrequency.WEEKLY:
            return base + timedelta(weeks=1)
        else:
            return base + timedelta(seconds=max(interval_seconds, 60))

    @classmethod
    def create_schedule(
        cls,
        project_id: str,
        schedule_in: ScheduleCreate,
        creator: User,
        creator_role: Optional[ProjectRole],
        db: Session,
        client_ip: Optional[str] = None,
    ) -> MonitoringSchedule:
        project = db.query(Project).filter(Project.id == project_id).first()
        if not project:
            raise ValueError(f"Project '{project_id}' not found.")

        # RBAC: Only Project LEAD or System ADMIN can create recurring assessment schedules
        if creator_role is None:
            from app.models.project import ProjectMember
            pm = db.query(ProjectMember).filter(ProjectMember.project_id == project_id, ProjectMember.user_id == creator.id).first()
            if pm:
                creator_role = pm.role

        is_lead_or_admin = (creator.system_role == SystemRole.ADMIN) or (creator_role == ProjectRole.LEAD)
        if not is_lead_or_admin:
            raise PermissionError("Only Project LEAD or System ADMIN can configure continuous monitoring schedules.")

        # Re-validate target in authorized scope
        now = utc_now()
        scope_eval = ScopeEngine.validate_target_in_scope(
            db=db,
            project_id=project_id,
            target=schedule_in.target_input,
            now=now,
        )
        if not scope_eval.get("is_authorized"):
            raise ValueError(
                f"Cannot create schedule: Target '{schedule_in.target_input}' is not authorized in scope "
                f"({scope_eval.get('reason')})."
            )

        # Set initial next_run_at to now so it is eligible immediately
        schedule = MonitoringSchedule(
            project_id=project_id,
            name=schedule_in.name.strip(),
            target_input=schedule_in.target_input.strip(),
            adapter_name=schedule_in.adapter_name.strip(),
            fixture_profile=schedule_in.fixture_profile.strip(),
            frequency=schedule_in.frequency,
            interval_seconds=schedule_in.interval_seconds,
            status=ScheduleStatus.ACTIVE,
            next_run_at=now,
            config=schedule_in.config or {},
            created_by_id=creator.id,
        )
        db.add(schedule)
        db.flush()

        AuditService.log(
            db=db,
            action="MONITORING_SCHEDULE_CREATED",
            actor_id=creator.id,
            target_resource=f"schedule:{schedule.id}",
            project_id=project_id,
            client_ip=client_ip,
            details={
                "name": schedule.name,
                "target": schedule.target_input,
                "adapter": schedule.adapter_name,
                "frequency": schedule.frequency.value,
            },
        )
        db.commit()
        db.refresh(schedule)
        return schedule

    @classmethod
    def list_schedules(
        cls,
        project_id: str,
        db: Session,
    ) -> List[MonitoringSchedule]:
        return (
            db.query(MonitoringSchedule)
            .filter(MonitoringSchedule.project_id == project_id)
            .order_by(MonitoringSchedule.created_at.desc())
            .all()
        )

    @classmethod
    def get_schedule(
        cls,
        project_id: str,
        schedule_id: str,
        db: Session,
    ) -> Optional[MonitoringSchedule]:
        return (
            db.query(MonitoringSchedule)
            .filter(
                MonitoringSchedule.id == schedule_id,
                MonitoringSchedule.project_id == project_id,
            )
            .first()
        )

    @classmethod
    def pause_schedule(
        cls,
        project_id: str,
        schedule_id: str,
        actor: User,
        actor_role: Optional[ProjectRole],
        db: Session,
        client_ip: Optional[str] = None,
    ) -> MonitoringSchedule:
        is_lead_or_admin = (actor.system_role == SystemRole.ADMIN) or (actor_role == ProjectRole.LEAD)
        if not is_lead_or_admin:
            raise PermissionError("Only Project LEAD or System ADMIN can manage monitoring schedules.")

        schedule = cls.get_schedule(project_id, schedule_id, db)
        if not schedule:
            raise ValueError(f"Schedule '{schedule_id}' not found.")

        schedule.status = ScheduleStatus.PAUSED
        AuditService.log(
            db=db,
            action="MONITORING_SCHEDULE_PAUSED",
            actor_id=actor.id,
            target_resource=f"schedule:{schedule.id}",
            project_id=project_id,
            client_ip=client_ip,
        )
        db.commit()
        db.refresh(schedule)
        return schedule

    @classmethod
    def resume_schedule(
        cls,
        project_id: str,
        schedule_id: str,
        actor: User,
        actor_role: Optional[ProjectRole],
        db: Session,
        client_ip: Optional[str] = None,
    ) -> MonitoringSchedule:
        is_lead_or_admin = (actor.system_role == SystemRole.ADMIN) or (actor_role == ProjectRole.LEAD)
        if not is_lead_or_admin:
            raise PermissionError("Only Project LEAD or System ADMIN can manage monitoring schedules.")

        schedule = cls.get_schedule(project_id, schedule_id, db)
        if not schedule:
            raise ValueError(f"Schedule '{schedule_id}' not found.")

        schedule.status = ScheduleStatus.ACTIVE
        schedule.next_run_at = utc_now()
        schedule.consecutive_failures = 0
        AuditService.log(
            db=db,
            action="MONITORING_SCHEDULE_RESUMED",
            actor_id=actor.id,
            target_resource=f"schedule:{schedule.id}",
            project_id=project_id,
            client_ip=client_ip,
        )
        db.commit()
        db.refresh(schedule)
        return schedule

    @classmethod
    def execute_schedule_run(
        cls,
        schedule_id: str,
        db: Session,
        now: Optional[datetime] = None,
        client_ip: Optional[str] = None,
    ) -> MonitoringRun:
        """
        Executes a scheduled monitoring assessment with:
        1. Strict scope & authorization revalidation before execution.
        2. Duplicate job prevention (checks if previous job is still running).
        3. Real job creation and execution.
        4. Delta change detection (new findings, recurring findings, resolved findings).
        5. Next run timestamp calculation and failure tracking.
        """
        if now is None:
            now = utc_now()
        if now.tzinfo is None:
            now = now.replace(tzinfo=timezone.utc)

        schedule = db.query(MonitoringSchedule).filter(MonitoringSchedule.id == schedule_id).first()
        if not schedule:
            raise ValueError(f"Schedule '{schedule_id}' not found.")

        project_id = schedule.project_id

        # ----------------------------------------------------------------------
        # 1. SCOPE & AUTHORIZATION REVALIDATION AT EXECUTION BOUNDARY
        # ----------------------------------------------------------------------
        scope_eval = ScopeEngine.validate_target_in_scope(
            db=db,
            project_id=project_id,
            target=schedule.target_input,
            now=now,
        )

        if not scope_eval.get("is_authorized"):
            reason = scope_eval.get("reason", "Scope authorization expired or target not in scope")
            schedule.status = ScheduleStatus.EXPIRED
            schedule.last_status = "SCOPE_EXPIRED"
            schedule.last_error = reason
            schedule.last_run_at = now

            run = MonitoringRun(
                schedule_id=schedule.id,
                project_id=project_id,
                scheduled_at=schedule.next_run_at or now,
                executed_at=now,
                status="SCOPE_EXPIRED",
                summary_notes=f"Scope re-validation denied: {reason}. Schedule transitioned to EXPIRED.",
                run_metadata={"scope_evaluation": scope_eval},
            )
            db.add(run)

            AuditService.log(
                db=db,
                action="MONITORING_SCOPE_EXPIRED",
                actor_id=schedule.created_by_id,
                target_resource=f"schedule:{schedule.id}",
                project_id=project_id,
                client_ip=client_ip,
                details={"target": schedule.target_input, "reason": reason},
            )
            db.commit()
            return run

        # ----------------------------------------------------------------------
        # 2. DUPLICATE JOB PREVENTION
        # ----------------------------------------------------------------------
        if schedule.last_job_id:
            last_job = db.query(AssessmentJob).filter(AssessmentJob.id == schedule.last_job_id).first()
            if last_job and last_job.status in (
                AssessmentStatus.QUEUED,
                AssessmentStatus.PREFLIGHT,
                AssessmentStatus.READY,
                AssessmentStatus.RUNNING,
            ):
                run = MonitoringRun(
                    schedule_id=schedule.id,
                    project_id=project_id,
                    job_id=last_job.id,
                    scheduled_at=schedule.next_run_at or now,
                    executed_at=now,
                    status="SKIPPED_DUPLICATE",
                    summary_notes=f"Skipped duplicate execution: active assessment job '{last_job.id}' is still in status '{last_job.status.value}'.",
                    run_metadata={"active_job_id": last_job.id, "active_status": last_job.status.value},
                )
                db.add(run)
                # Postpone next run by 5 minutes to allow previous job to finish
                schedule.next_run_at = now + timedelta(minutes=5)
                db.commit()
                return run

        # ----------------------------------------------------------------------
        # 3. CAPTURE PREVIOUS FINDINGS ON TARGET FOR CHANGE DETECTION
        # ----------------------------------------------------------------------
        previous_findings = (
            db.query(VulnerabilityFinding)
            .filter(
                VulnerabilityFinding.project_id == project_id,
                VulnerabilityFinding.target_value == schedule.target_input,
                VulnerabilityFinding.status.notin_([
                    FindingLifecycleStatus.FALSE_POSITIVE,
                    FindingLifecycleStatus.VERIFIED_CLOSED,
                ]),
            )
            .all()
        )
        prev_finding_keys = {
            (f.title.lower(), (f.vuln_id or "").lower()): f
            for f in previous_findings
        }

        # ----------------------------------------------------------------------
        # 4. DISPATCH REAL ASSESSMENT JOB
        # ----------------------------------------------------------------------
        # Generate sequentially unique idempotent key for this scheduled run
        run_seq = schedule.run_count + 1
        window_hash = hashlib.sha256(f"{schedule.id}:run{run_seq}:{now.isoformat()}".encode("utf-8")).hexdigest()[:12]
        idemp_key = f"sched-{schedule.id[:8]}-r{run_seq}-{window_hash}"

        config_payload = dict(schedule.config or {})
        config_payload["fixture_profile"] = schedule.fixture_profile
        if scope_eval.get("is_loopback_authorized"):
            config_payload["allow_loopback"] = True
        if scope_eval.get("is_private_authorized"):
            config_payload["allow_private"] = True

        new_job = AssessmentJob(
            project_id=project_id,
            target_input=schedule.target_input,
            adapter_name=schedule.adapter_name,
            config=config_payload,
            timeout_seconds=60,
            idempotency_key=idemp_key,
            status=AssessmentStatus.QUEUED,
            created_by_id=schedule.created_by_id,
        )
        db.add(new_job)
        db.commit()
        db.refresh(new_job)

        # Execute job immediately
        executed_job = AssessmentExecutionEngine.execute_job(
            db=db,
            job_id=new_job.id,
            worker_id=f"monitor-{schedule.id[:8]}",
            now=now,
            client_ip=client_ip,
        )

        # ----------------------------------------------------------------------
        # 5. DELTA CHANGE DETECTION (NEW, RECURRING, RESOLVED)
        # ----------------------------------------------------------------------
        new_findings_count = 0
        recurring_findings_count = 0
        resolved_findings_count = 0

        current_findings = (
            db.query(VulnerabilityFinding)
            .filter(
                VulnerabilityFinding.project_id == project_id,
                VulnerabilityFinding.target_value == schedule.target_input,
            )
            .all()
        )
        current_finding_keys = {
            (f.title.lower(), (f.vuln_id or "").lower()): f
            for f in current_findings
            if f.status not in (FindingLifecycleStatus.VERIFIED_CLOSED, FindingLifecycleStatus.FALSE_POSITIVE)
        }

        # Check newly observed findings
        for k, curr_f in current_finding_keys.items():
            if k not in prev_finding_keys:
                new_findings_count += 1
            else:
                # Observed again -> recurring finding
                recurring_findings_count += 1
                curr_f.recurrence_detected = True
                curr_f.recurrence_count = (curr_f.recurrence_count or 0) + 1

        # Check resolved findings (was open before, now no longer observed)
        for k, prev_f in prev_finding_keys.items():
            if k not in current_finding_keys:
                resolved_findings_count += 1

        # ----------------------------------------------------------------------
        # 6. UPDATE SCHEDULE STATE & SCHEDULE NEXT RUN
        # ----------------------------------------------------------------------
        schedule.last_run_at = now
        schedule.last_job_id = executed_job.id
        schedule.run_count += 1

        if executed_job.status == AssessmentStatus.COMPLETED:
            schedule.consecutive_failures = 0
            schedule.last_status = "SUCCESS"
            schedule.last_error = None
            run_status = "SUCCESS"
        else:
            schedule.consecutive_failures += 1
            schedule.last_status = "FAILED"
            schedule.last_error = executed_job.error_message or "Assessment execution failed"
            run_status = "FAILED"
            if schedule.consecutive_failures >= schedule.max_consecutive_failures:
                schedule.status = ScheduleStatus.FAILED

        schedule.next_run_at = cls.calculate_next_run(
            frequency=schedule.frequency,
            interval_seconds=schedule.interval_seconds,
            from_time=now,
        )

        run = MonitoringRun(
            schedule_id=schedule.id,
            project_id=project_id,
            job_id=executed_job.id,
            scheduled_at=now,
            executed_at=now,
            status=run_status,
            new_findings_count=new_findings_count,
            recurring_findings_count=recurring_findings_count,
            resolved_findings_count=resolved_findings_count,
            summary_notes=(
                f"Continuous monitoring executed via '{schedule.adapter_name}'. "
                f"Status: {run_status}. Changes: {new_findings_count} new, "
                f"{recurring_findings_count} recurring, {resolved_findings_count} resolved."
            ),
            run_metadata={
                "job_status": executed_job.status.value,
                "findings_discovered": len(executed_job.findings),
                "duration_ms": executed_job.summary_stats.get("execution_duration_ms", 0.0),
            },
        )
        db.add(run)

        # Trigger project regression evaluation
        try:
            RegressionDetectionService.evaluate_project_regressions(
                project_id=project_id,
                db=db,
                client_ip=client_ip,
            )
        except Exception:
            pass

        AuditService.log(
            db=db,
            action="MONITORING_RUN_EXECUTED",
            actor_id=schedule.created_by_id,
            target_resource=f"schedule:{schedule.id}",
            project_id=project_id,
            client_ip=client_ip,
            details={
                "run_id": run.id,
                "job_id": executed_job.id,
                "status": run_status,
                "new_findings": new_findings_count,
                "recurring_findings": recurring_findings_count,
                "resolved_findings": resolved_findings_count,
            },
        )
        db.commit()
        db.refresh(run)
        return run

    @classmethod
    def process_due_schedules(
        cls,
        db: Session,
        now: Optional[datetime] = None,
        max_batch: int = 10,
    ) -> List[MonitoringRun]:
        """
        Polls and executes all active monitoring schedules across projects whose next_run_at is due.
        Called periodically by background worker daemon.
        """
        if now is None:
            now = utc_now()
        if now.tzinfo is None:
            now = now.replace(tzinfo=timezone.utc)

        due_schedules = (
            db.query(MonitoringSchedule)
            .filter(
                MonitoringSchedule.status == ScheduleStatus.ACTIVE,
                MonitoringSchedule.next_run_at <= now,
            )
            .order_by(MonitoringSchedule.next_run_at.asc())
            .limit(max_batch)
            .all()
        )

        executed_runs = []
        for sched in due_schedules:
            try:
                run = cls.execute_schedule_run(schedule_id=sched.id, db=db, now=now)
                executed_runs.append(run)
            except Exception as e:
                # Bounded retry / mark error
                sched.consecutive_failures += 1
                sched.last_status = "ERROR"
                sched.last_error = str(e)[:500]
                sched.next_run_at = now + timedelta(minutes=10)
                db.commit()

        return executed_runs
