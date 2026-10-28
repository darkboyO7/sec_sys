"""prompt12_self_diagnostics_and_recovery

Revision ID: a8b9c0d1e2f3
Revises: f7a8b9c0d1e2
Create Date: 2026-10-28 17:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa


revision: str = 'a8b9c0d1e2f3'
down_revision: Union[str, None] = 'f7a8b9c0d1e2'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    component_health_status_enum = sa.Enum(
        'HEALTHY',
        'DEGRADED',
        'UNHEALTHY',
        'UNKNOWN',
        'NOT_CONFIGURED',
        name='componenthealthstatus',
    )
    diagnostic_severity_enum = sa.Enum(
        'INFO',
        'LOW',
        'MEDIUM',
        'HIGH',
        'CRITICAL',
        name='diagnosticseverity',
    )
    diagnostic_confidence_enum = sa.Enum(
        'CONFIRMED',
        'SUSPECTED',
        'UNAVAILABLE',
        name='diagnosticconfidence',
    )
    diagnostic_category_enum = sa.Enum(
        'DATABASE',
        'JOBS',
        'ADAPTERS',
        'CONFIG',
        'EVIDENCE',
        'ASSETS',
        'FINDINGS',
        'NOTIFICATIONS',
        'BACKUP',
        'SECURITY',
        name='diagnosticcategory',
    )
    recovery_action_type_enum = sa.Enum(
        'RETRY_ASSESSMENT',
        'RECOVER_STUCK_JOB',
        'REQUEUE_NOTIFICATION',
        'RECALCULATE_RISK_SCORES',
        'REBUILD_KNOWLEDGE_GRAPH',
        'RESUME_MONITORING',
        'TRIGGER_BACKUP',
        'RETEST_REMEDIATION',
        name='recoveryactiontype',
    )
    recovery_outcome_enum = sa.Enum(
        'SUCCESS',
        'PARTIAL_SUCCESS',
        'FAILED',
        'INCONCLUSIVE',
        name='recoveryoutcome',
    )

    # 1. system_health_snapshots
    op.create_table(
        'system_health_snapshots',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('timestamp', sa.DateTime(timezone=True), nullable=False),
        sa.Column('overall_status', component_health_status_enum, nullable=False),
        sa.Column('healthy_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('degraded_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('unhealthy_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('components', sa.JSON(), nullable=False),
        sa.Column('environment', sa.String(length=50), nullable=False, server_default='development'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(
        op.f('ix_system_health_snapshots_timestamp'),
        'system_health_snapshots',
        ['timestamp'],
        unique=False,
    )

    # 2. diagnostic_runs
    op.create_table(
        'diagnostic_runs',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('project_id', sa.String(length=36), nullable=False),
        sa.Column('run_timestamp', sa.DateTime(timezone=True), nullable=False),
        sa.Column('executed_by_id', sa.String(length=36), nullable=True),
        sa.Column('trigger_type', sa.String(length=50), nullable=False, server_default='MANUAL'),
        sa.Column('total_checks', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('passed_checks', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('warning_checks', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('failed_checks', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('summary', sa.Text(), nullable=False, server_default=''),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['executed_by_id'], ['users.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['project_id'], ['projects.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(
        op.f('ix_diagnostic_runs_project_id'),
        'diagnostic_runs',
        ['project_id'],
        unique=False,
    )
    op.create_index(
        op.f('ix_diagnostic_runs_run_timestamp'),
        'diagnostic_runs',
        ['run_timestamp'],
        unique=False,
    )

    # 3. diagnostic_findings
    op.create_table(
        'diagnostic_findings',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('run_id', sa.String(length=36), nullable=False),
        sa.Column('project_id', sa.String(length=36), nullable=False),
        sa.Column('check_id', sa.String(length=100), nullable=False),
        sa.Column('category', diagnostic_category_enum, nullable=False),
        sa.Column('severity', diagnostic_severity_enum, nullable=False),
        sa.Column('confidence', diagnostic_confidence_enum, nullable=False),
        sa.Column('title', sa.String(length=255), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('observed_issue', sa.Text(), nullable=False),
        sa.Column('affected_entities', sa.JSON(), nullable=False),
        sa.Column('recommended_action', sa.Text(), nullable=False),
        sa.Column('recovery_action_available', sa.String(length=100), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['project_id'], ['projects.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['run_id'], ['diagnostic_runs.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(
        op.f('ix_diagnostic_findings_check_id'),
        'diagnostic_findings',
        ['check_id'],
        unique=False,
    )
    op.create_index(
        op.f('ix_diagnostic_findings_project_id'),
        'diagnostic_findings',
        ['project_id'],
        unique=False,
    )
    op.create_index(
        op.f('ix_diagnostic_findings_run_id'),
        'diagnostic_findings',
        ['run_id'],
        unique=False,
    )
    op.create_index(
        'ix_diagnostic_findings_category_severity',
        'diagnostic_findings',
        ['category', 'severity'],
        unique=False,
    )

    # 4. recovery_action_records
    op.create_table(
        'recovery_action_records',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('project_id', sa.String(length=36), nullable=False),
        sa.Column('action_type', recovery_action_type_enum, nullable=False),
        sa.Column('target_entity_type', sa.String(length=50), nullable=False),
        sa.Column('target_entity_id', sa.String(length=36), nullable=True),
        sa.Column('target_resource', sa.String(length=255), nullable=True),
        sa.Column('executed_by_id', sa.String(length=36), nullable=True),
        sa.Column('execution_timestamp', sa.DateTime(timezone=True), nullable=False),
        sa.Column('reason', sa.Text(), nullable=False),
        sa.Column('pre_condition', sa.JSON(), nullable=False),
        sa.Column('post_condition', sa.JSON(), nullable=False),
        sa.Column('outcome', recovery_outcome_enum, nullable=False),
        sa.Column('verification_notes', sa.Text(), nullable=False, server_default=''),
        sa.Column('verification_timestamp', sa.DateTime(timezone=True), nullable=False),
        sa.Column('ledger_record_id', sa.String(length=36), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['executed_by_id'], ['users.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['project_id'], ['projects.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(
        op.f('ix_recovery_action_records_action_type'),
        'recovery_action_records',
        ['action_type'],
        unique=False,
    )
    op.create_index(
        op.f('ix_recovery_action_records_project_id'),
        'recovery_action_records',
        ['project_id'],
        unique=False,
    )
    op.create_index(
        op.f('ix_recovery_action_records_outcome'),
        'recovery_action_records',
        ['outcome'],
        unique=False,
    )

    # 5. failure_pattern_records
    op.create_table(
        'failure_pattern_records',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('project_id', sa.String(length=36), nullable=False),
        sa.Column('pattern_key', sa.String(length=100), nullable=False),
        sa.Column('category', sa.String(length=50), nullable=False, server_default='GENERAL'),
        sa.Column('occurrence_count', sa.Integer(), nullable=False, server_default='1'),
        sa.Column('first_observed_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('last_observed_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('affected_targets', sa.JSON(), nullable=False),
        sa.Column('sample_error_message', sa.Text(), nullable=False, server_default=''),
        sa.Column('advisory_recommendation', sa.Text(), nullable=False, server_default=''),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['project_id'], ['projects.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(
        op.f('ix_failure_pattern_records_pattern_key'),
        'failure_pattern_records',
        ['pattern_key'],
        unique=False,
    )
    op.create_index(
        op.f('ix_failure_pattern_records_project_id'),
        'failure_pattern_records',
        ['project_id'],
        unique=False,
    )


def downgrade() -> None:
    op.drop_table('failure_pattern_records')
    op.drop_table('recovery_action_records')
    op.drop_table('diagnostic_findings')
    op.drop_table('diagnostic_runs')
    op.drop_table('system_health_snapshots')
