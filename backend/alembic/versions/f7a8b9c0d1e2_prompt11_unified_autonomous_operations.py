"""prompt11_unified_autonomous_operations

Revision ID: f7a8b9c0d1e2
Revises: e6f7a8b9c0d1
Create Date: 2026-10-28 16:00:00.000000

"""
from typing import Sequence, Union
from alembic import op, context
import sqlalchemy as sa


revision: str = 'f7a8b9c0d1e2'
down_revision: Union[str, None] = 'e6f7a8b9c0d1'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    autonomy_intensity_enum = sa.Enum(
        'LOW',
        'NORMAL',
        'AGGRESSIVE',
        name='autonomyintensity',
    )
    decision_ledger_type_enum = sa.Enum(
        'ASSESSMENT_SCHEDULED',
        'TARGET_ACCEPTED',
        'TARGET_REJECTED',
        'FINDING_PRIORITIZED',
        'REMEDIATION_RECOMMENDED',
        'REMEDIATION_EXECUTED',
        'FINDING_RESOLVED',
        'FINDING_REOPENED',
        'LEARNING_ACCEPTED',
        'LEARNING_REJECTED',
        'AUTONOMY_SUSPENDED',
        'AUTONOMY_RESUMED',
        'AUTONOMY_CANCELLED',
        'POLICY_EVALUATION',
        name='decisionledgertype',
    )
    notification_event_type_enum = sa.Enum(
        'CRITICAL_FINDING_DISCOVERED',
        'NEW_EXPOSURE_DETECTED',
        'ASSESSMENT_FAILED',
        'REPEATED_JOB_FAILURES',
        'REMEDIATION_DEADLINE_APPROACHING',
        'REMEDIATION_OVERDUE',
        'VERIFICATION_FAILED',
        'POLICY_VIOLATION',
        'AUTONOMY_SUSPENDED',
        'BACKUP_FAILED',
        'RESTORE_FAILED',
        name='notificationeventtype',
    )
    notification_severity_enum = sa.Enum(
        'CRITICAL',
        'HIGH',
        'MEDIUM',
        'LOW',
        'INFO',
        name='notificationseverity',
    )
    notification_status_enum = sa.Enum(
        'PENDING',
        'DELIVERED',
        'FAILED',
        'SUPPRESSED_DUPLICATE',
        'UNCONFIGURED',
        name='notificationstatus',
    )

    # 1. autonomous_policies
    op.create_table(
        'autonomous_policies',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('project_id', sa.String(length=36), nullable=False),
        sa.Column('policy_version', sa.String(length=50), nullable=False, server_default='v1.0.0'),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default='1'),
        sa.Column('is_suspended', sa.Boolean(), nullable=False, server_default='0'),
        sa.Column('suspension_reason', sa.String(length=500), nullable=True),
        sa.Column('suspended_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('suspended_by_id', sa.String(length=36), nullable=True),
        sa.Column('permitted_assessment_types', sa.JSON(), nullable=False),
        sa.Column('intensity', autonomy_intensity_enum, nullable=False, server_default='NORMAL'),
        sa.Column('max_concurrency', sa.Integer(), nullable=False, server_default='2'),
        sa.Column('rate_limit_rps', sa.Float(), nullable=False, server_default='10.0'),
        sa.Column('permitted_time_windows', sa.JSON(), nullable=False),
        sa.Column('max_daily_budget', sa.Integer(), nullable=False, server_default='20'),
        sa.Column('daily_budget_spent', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('last_budget_reset_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('permitted_remediation_actions', sa.JSON(), nullable=False),
        sa.Column('require_approval_for_disruptive', sa.Boolean(), nullable=False, server_default='1'),
        sa.Column('require_approval_for_remediation', sa.Boolean(), nullable=False, server_default='1'),
        sa.Column('max_retries', sa.Integer(), nullable=False, server_default='2'),
        sa.Column('failure_threshold', sa.Integer(), nullable=False, server_default='3'),
        sa.Column('consecutive_failures', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('created_by_id', sa.String(length=36), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['created_by_id'], ['users.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['suspended_by_id'], ['users.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['project_id'], ['projects.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('project_id', name='uq_autonomous_policies_project_id'),
    )
    op.create_index(
        op.f('ix_autonomous_policies_project_id'),
        'autonomous_policies',
        ['project_id'],
        unique=True,
    )

    # 2. security_decision_ledger
    op.create_table(
        'security_decision_ledger',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('project_id', sa.String(length=36), nullable=False),
        sa.Column('decision_type', decision_ledger_type_enum, nullable=False),
        sa.Column('decision_outcome', sa.String(length=50), nullable=False),
        sa.Column('initiating_event', sa.String(length=100), nullable=False),
        sa.Column('target_type', sa.String(length=50), nullable=False),
        sa.Column('target_id', sa.String(length=255), nullable=True),
        sa.Column('target_resource', sa.String(length=255), nullable=True),
        sa.Column('policy_version', sa.String(length=50), nullable=False, server_default='v1.0.0'),
        sa.Column('reason', sa.Text(), nullable=False),
        sa.Column('evidence_references', sa.JSON(), nullable=False),
        sa.Column('details', sa.JSON(), nullable=False),
        sa.Column('actor_id', sa.String(length=36), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['actor_id'], ['users.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['project_id'], ['projects.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(
        'ix_decision_ledger_project_type',
        'security_decision_ledger',
        ['project_id', 'decision_type'],
        unique=False,
    )
    op.create_index(
        'ix_decision_ledger_project_created',
        'security_decision_ledger',
        ['project_id', 'created_at'],
        unique=False,
    )
    op.create_index(
        op.f('ix_security_decision_ledger_project_id'),
        'security_decision_ledger',
        ['project_id'],
        unique=False,
    )

    # 3. notification_records
    op.create_table(
        'notification_records',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('project_id', sa.String(length=36), nullable=False),
        sa.Column('event_type', notification_event_type_enum, nullable=False),
        sa.Column('severity', notification_severity_enum, nullable=False, server_default='INFO'),
        sa.Column('title', sa.String(length=255), nullable=False),
        sa.Column('summary', sa.Text(), nullable=False),
        sa.Column('deduplication_key', sa.String(length=255), nullable=False),
        sa.Column('status', notification_status_enum, nullable=False, server_default='PENDING'),
        sa.Column('retry_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('max_retries', sa.Integer(), nullable=False, server_default='3'),
        sa.Column('last_attempt_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('delivery_metadata', sa.JSON(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['project_id'], ['projects.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(
        'ix_notifications_project_status',
        'notification_records',
        ['project_id', 'status'],
        unique=False,
    )
    op.create_index(
        'ix_notifications_dedup',
        'notification_records',
        ['project_id', 'deduplication_key', 'created_at'],
        unique=False,
    )
    op.create_index(
        op.f('ix_notification_records_project_id'),
        'notification_records',
        ['project_id'],
        unique=False,
    )

    # 4. notification_delivery_records
    op.create_table(
        'notification_delivery_records',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('notification_id', sa.String(length=36), nullable=False),
        sa.Column('channel', sa.String(length=50), nullable=False, server_default='WEBHOOK'),
        sa.Column('attempt_number', sa.Integer(), nullable=False),
        sa.Column('status', sa.String(length=50), nullable=False),
        sa.Column('response_code', sa.Integer(), nullable=True),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('attempted_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['notification_id'], ['notification_records.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(
        op.f('ix_notification_delivery_records_notification_id'),
        'notification_delivery_records',
        ['notification_id'],
        unique=False,
    )

    # 5. operational_slo_configs
    op.create_table(
        'operational_slo_configs',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('project_id', sa.String(length=36), nullable=False),
        sa.Column('min_assessment_completion_rate', sa.Float(), nullable=False, server_default='95.0'),
        sa.Column('max_queue_delay_seconds', sa.Float(), nullable=False, server_default='300.0'),
        sa.Column('min_evidence_completeness_rate', sa.Float(), nullable=False, server_default='90.0'),
        sa.Column('max_inconclusive_rate', sa.Float(), nullable=False, server_default='10.0'),
        sa.Column('min_remediation_completion_rate', sa.Float(), nullable=False, server_default='80.0'),
        sa.Column('min_verification_pass_rate', sa.Float(), nullable=False, server_default='85.0'),
        sa.Column('min_asset_coverage_rate', sa.Float(), nullable=False, server_default='90.0'),
        sa.Column('coverage_stale_days', sa.Integer(), nullable=False, server_default='14'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['project_id'], ['projects.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('project_id', name='uq_operational_slo_configs_project_id'),
    )
    op.create_index(
        op.f('ix_operational_slo_configs_project_id'),
        'operational_slo_configs',
        ['project_id'],
        unique=True,
    )


def downgrade() -> None:
    op.drop_table('operational_slo_configs')
    op.drop_table('notification_delivery_records')
    op.drop_table('notification_records')
    op.drop_table('security_decision_ledger')
    op.drop_table('autonomous_policies')
