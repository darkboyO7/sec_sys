"""prompt15_autonomous_security_orchestration

Revision ID: b9c0d1e2f3a4
Revises: a8b9c0d1e2f3
Create Date: 2026-10-28 19:30:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa


revision: str = 'b9c0d1e2f3a4'
down_revision: Union[str, None] = 'a8b9c0d1e2f3'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    orchestration_state_enum = sa.Enum(
        'IDLE',
        'EVENT_RECEIVED',
        'CONTEXT_GATHERED',
        'DECISION_PENDING',
        'AWAITING_APPROVAL',
        'ACTION_QUEUED',
        'ACTION_RUNNING',
        'VERIFYING_OUTCOME',
        'COMPLETED',
        'PARTIALLY_COMPLETED',
        'FAILED',
        'SUSPENDED',
        name='orchestrationstate',
    )
    orchestration_event_type_enum = sa.Enum(
        'ASSET_DISCOVERED',
        'CONFIG_CHANGED',
        'SCAN_COMPLETED',
        'FINDING_DETECTED',
        'REMEDIATION_APPLIED',
        'INTEGRITY_ALERT',
        'DIAGNOSTIC_FAILURE',
        'SCHEDULED_POLL',
        'MANUAL_TRIGGER',
        name='orchestrationeventtype',
    )
    orchestration_action_type_enum = sa.Enum(
        'REASSESS_CHANGED_ASSET',
        'REFRESH_STALE_EVIDENCE',
        'RETRY_FAILED_ASSESSMENT',
        'RECALCULATE_RISK_AND_PATHS',
        'RECOMMEND_REMEDIATION',
        'REQUEST_HUMAN_APPROVAL',
        'SCHEDULE_INDEPENDENT_RETEST',
        'RUN_DIAGNOSTICS',
        'SUSPEND_ACTIVITY',
        'NO_ACTION_REQUIRED',
        name='orchestrationactiontype',
    )
    outcome_measurement_status_enum = sa.Enum(
        'ACTION_EXECUTED_SUCCESSFULLY',
        'FINDING_VERIFIED_RESOLVED',
        'RISK_SCORE_DECREASED',
        'EVIDENCE_COVERAGE_IMPROVED',
        'NO_MEASURABLE_IMPROVEMENT',
        'OUTCOME_INCONCLUSIVE',
        'FAILED',
        name='outcomemeasurementstatus',
    )
    event_processing_status_enum = sa.Enum(
        'RECEIVED',
        'PROCESSED',
        'DEDUPLICATED',
        'DEFERRED',
        'REJECTED',
        'FAILED',
        name='eventprocessingstatus',
    )
    invalidation_status_enum = sa.Enum(
        'PENDING',
        'RECALCULATED',
        'SUPERSEDED',
        'FAILED',
        name='invalidationstatus',
    )

    # 1. orchestration_events
    op.create_table(
        'orchestration_events',
        sa.Column('id', sa.String(length=36), primary_key=True),
        sa.Column('project_id', sa.String(length=36), sa.ForeignKey('projects.id', ondelete='CASCADE'), nullable=False),
        sa.Column('event_type', orchestration_event_type_enum, nullable=False),
        sa.Column('event_source', sa.String(length=100), server_default='ORCHESTRATOR', nullable=False),
        sa.Column('dedup_key', sa.String(length=64), nullable=False),
        sa.Column('target_resource', sa.String(length=500), nullable=False),
        sa.Column('payload', sa.JSON(), nullable=False),
        sa.Column('status', event_processing_status_enum, server_default='RECEIVED', nullable=False),
        sa.Column('coalesced_count', sa.Integer(), server_default='1', nullable=False),
        sa.Column('received_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('processed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('rejection_reason', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index('ix_orchestration_events_project_id', 'orchestration_events', ['project_id'])
    op.create_index('ix_orchestration_events_event_type', 'orchestration_events', ['event_type'])
    op.create_index('ix_orchestration_events_dedup_key', 'orchestration_events', ['dedup_key'])
    op.create_index('ix_orchestration_events_target_resource', 'orchestration_events', ['target_resource'])
    op.create_index('ix_orchestration_events_status', 'orchestration_events', ['status'])
    op.create_index('ix_orchestration_events_project_dedup', 'orchestration_events', ['project_id', 'dedup_key'])
    op.create_index('ix_orchestration_events_status_received', 'orchestration_events', ['status', 'received_at'])

    # 2. orchestration_workflows
    op.create_table(
        'orchestration_workflows',
        sa.Column('id', sa.String(length=36), primary_key=True),
        sa.Column('project_id', sa.String(length=36), sa.ForeignKey('projects.id', ondelete='CASCADE'), nullable=False),
        sa.Column('state', orchestration_state_enum, server_default='IDLE', nullable=False),
        sa.Column('trigger_event_id', sa.String(length=36), sa.ForeignKey('orchestration_events.id', ondelete='SET NULL'), nullable=True),
        sa.Column('workflow_type', sa.String(length=100), server_default='ASSESSMENT_CYCLE', nullable=False),
        sa.Column('target_resource', sa.String(length=500), nullable=False),
        sa.Column('context_data', sa.JSON(), nullable=False),
        sa.Column('recommended_action', orchestration_action_type_enum, nullable=True),
        sa.Column('action_rationale', sa.Text(), nullable=True),
        sa.Column('confidence', sa.Float(), server_default='1.0', nullable=False),
        sa.Column('uncertainty', sa.Float(), server_default='0.0', nullable=False),
        sa.Column('decision_record_id', sa.String(length=36), sa.ForeignKey('security_decision_records.id', ondelete='SET NULL'), nullable=True),
        sa.Column('action_job_id', sa.String(length=36), sa.ForeignKey('assessment_jobs.id', ondelete='SET NULL'), nullable=True),
        sa.Column('remediation_id', sa.String(length=36), sa.ForeignKey('remediation_recommendations.id', ondelete='SET NULL'), nullable=True),
        sa.Column('verification_id', sa.String(length=36), sa.ForeignKey('remediation_verifications.id', ondelete='SET NULL'), nullable=True),
        sa.Column('required_approval_role', sa.String(length=50), nullable=True),
        sa.Column('approved_by_id', sa.String(length=36), sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True),
        sa.Column('approved_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('locked_by', sa.String(length=100), nullable=True),
        sa.Column('locked_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('lock_expires_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('attempt_count', sa.Integer(), server_default='0', nullable=False),
        sa.Column('max_retries', sa.Integer(), server_default='3', nullable=False),
        sa.Column('suspension_reason', sa.Text(), nullable=True),
        sa.Column('failure_reason', sa.Text(), nullable=True),
        sa.Column('partial_results', sa.JSON(), nullable=False),
        sa.Column('outcome_status', outcome_measurement_status_enum, nullable=True),
        sa.Column('outcome_measurement', sa.JSON(), nullable=False),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index('ix_orchestration_workflows_project_id', 'orchestration_workflows', ['project_id'])
    op.create_index('ix_orchestration_workflows_state', 'orchestration_workflows', ['state'])
    op.create_index('ix_orchestration_workflows_trigger_event_id', 'orchestration_workflows', ['trigger_event_id'])
    op.create_index('ix_orchestration_workflows_target_resource', 'orchestration_workflows', ['target_resource'])
    op.create_index('ix_orchestration_workflows_recommended_action', 'orchestration_workflows', ['recommended_action'])
    op.create_index('ix_orchestration_workflows_locked_by', 'orchestration_workflows', ['locked_by'])
    op.create_index('ix_orchestration_workflows_lock_expires_at', 'orchestration_workflows', ['lock_expires_at'])
    op.create_index('ix_orchestration_workflows_outcome_status', 'orchestration_workflows', ['outcome_status'])
    op.create_index('ix_orchestration_workflows_project_state', 'orchestration_workflows', ['project_id', 'state'])
    op.create_index('ix_orchestration_workflows_locked', 'orchestration_workflows', ['locked_by', 'lock_expires_at'])

    # 3. dependency_invalidation_records
    op.create_table(
        'dependency_invalidation_records',
        sa.Column('id', sa.String(length=36), primary_key=True),
        sa.Column('project_id', sa.String(length=36), sa.ForeignKey('projects.id', ondelete='CASCADE'), nullable=False),
        sa.Column('source_entity_type', sa.String(length=50), nullable=False),
        sa.Column('source_entity_id', sa.String(length=255), nullable=False),
        sa.Column('invalidation_type', sa.String(length=50), nullable=False),
        sa.Column('invalidated_targets', sa.JSON(), nullable=False),
        sa.Column('recalculation_status', invalidation_status_enum, server_default='PENDING', nullable=False),
        sa.Column('provenance', sa.JSON(), nullable=False),
        sa.Column('recalculated_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index('ix_dependency_invalidation_records_project_id', 'dependency_invalidation_records', ['project_id'])
    op.create_index('ix_dependency_invalidation_records_source_entity_type', 'dependency_invalidation_records', ['source_entity_type'])
    op.create_index('ix_dependency_invalidation_records_source_entity_id', 'dependency_invalidation_records', ['source_entity_id'])
    op.create_index('ix_dependency_invalidation_records_invalidation_type', 'dependency_invalidation_records', ['invalidation_type'])
    op.create_index('ix_dependency_invalidation_records_recalculation_status', 'dependency_invalidation_records', ['recalculation_status'])
    op.create_index('ix_dep_invalidations_project_status', 'dependency_invalidation_records', ['project_id', 'recalculation_status'])

    # 4. adaptive_optimization_records
    op.create_table(
        'adaptive_optimization_records',
        sa.Column('id', sa.String(length=36), primary_key=True),
        sa.Column('project_id', sa.String(length=36), sa.ForeignKey('projects.id', ondelete='CASCADE'), nullable=False),
        sa.Column('optimization_name', sa.String(length=100), nullable=False),
        sa.Column('objective', sa.Text(), nullable=False),
        sa.Column('evaluation_metric', sa.String(length=100), nullable=False),
        sa.Column('baseline_value', sa.Float(), nullable=False),
        sa.Column('evaluated_value', sa.Float(), nullable=False),
        sa.Column('threshold_value', sa.Float(), nullable=False),
        sa.Column('dataset_summary', sa.JSON(), nullable=False),
        sa.Column('is_accepted', sa.Boolean(), server_default='0', nullable=False),
        sa.Column('rejection_reason', sa.Text(), nullable=True),
        sa.Column('rollback_payload', sa.JSON(), nullable=False),
        sa.Column('evaluated_by_model', sa.String(length=100), server_default='governed_rule_engine_v1', nullable=False),
        sa.Column('evaluated_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index('ix_adaptive_optimization_records_project_id', 'adaptive_optimization_records', ['project_id'])
    op.create_index('ix_adaptive_optimization_records_optimization_name', 'adaptive_optimization_records', ['optimization_name'])
    op.create_index('ix_adaptive_optimization_records_is_accepted', 'adaptive_optimization_records', ['is_accepted'])
    op.create_index('ix_adaptive_optimizations_project_accepted', 'adaptive_optimization_records', ['project_id', 'is_accepted'])


def downgrade() -> None:
    op.drop_table('adaptive_optimization_records')
    op.drop_table('dependency_invalidation_records')
    op.drop_table('orchestration_workflows')
    op.drop_table('orchestration_events')
