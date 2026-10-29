"""prompt34 intelligent scheduling and orchestration

Revision ID: d1e2f3a4b5c6
Revises: c1d2e3f4a5b6
Create Date: 2026-10-29 19:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'd1e2f3a4b5c6'
down_revision = 'c1d2e3f4a5b6'
branch_labels = None
depends_on = None


def upgrade():
    # 1. Assessment Queue Items
    op.create_table(
        'assessment_queue_items',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('project_id', sa.String(length=36), nullable=False),
        sa.Column('target_id', sa.String(length=36), nullable=True),
        sa.Column('schedule_name', sa.String(length=100), nullable=False, server_default='Ad-Hoc Assessment'),
        sa.Column('target_input', sa.String(length=500), nullable=False),
        sa.Column('adapter_name', sa.String(length=100), nullable=False, server_default='local_fixture_adapter'),
        sa.Column('adapter_version', sa.String(length=50), nullable=False, server_default='1.0.0'),
        sa.Column('status', sa.String(length=50), nullable=False, server_default='SCHEDULED'),
        sa.Column('priority_score', sa.Float(), nullable=False, server_default='50.0'),
        sa.Column('priority_band', sa.String(length=20), nullable=False, server_default='MEDIUM'),
        sa.Column('priority_explanation', sa.Text(), nullable=False),
        sa.Column('priority_factors', sa.JSON(), nullable=False),
        sa.Column('policy_version', sa.String(length=50), nullable=False, server_default='scheduling_v1.0'),
        sa.Column('eligibility_status', sa.String(length=50), nullable=False, server_default='ELIGIBLE'),
        sa.Column('eligibility_reasons', sa.JSON(), nullable=False),
        sa.Column('idempotency_key', sa.String(length=100), nullable=True),
        sa.Column('concurrency_key', sa.String(length=100), nullable=False),
        sa.Column('worker_claim_id', sa.String(length=100), nullable=True),
        sa.Column('claimed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('lease_expires_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('attempt_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('retry_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('max_retries', sa.Integer(), nullable=False, server_default='3'),
        sa.Column('backoff_seconds', sa.Integer(), nullable=False, server_default='30'),
        sa.Column('next_eligible_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('deadline_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('execution_budget_seconds', sa.Integer(), nullable=False, server_default='600'),
        sa.Column('cancellation_requested_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('cancellation_reason', sa.Text(), nullable=True),
        sa.Column('cancelled_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_error_category', sa.String(length=100), nullable=True),
        sa.Column('last_error_message', sa.Text(), nullable=True),
        sa.Column('job_id', sa.String(length=36), nullable=True),
        sa.Column('created_by_id', sa.String(length=36), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['created_by_id'], ['users.id'], ondelete='RESTRICT'),
        sa.ForeignKeyConstraint(['job_id'], ['assessment_jobs.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['project_id'], ['projects.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['target_id'], ['scope_targets.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_queue_items_project_id', 'assessment_queue_items', ['project_id'])
    op.create_index('ix_queue_items_target_id', 'assessment_queue_items', ['target_id'])
    op.create_index('ix_queue_items_target_input', 'assessment_queue_items', ['target_input'])
    op.create_index('ix_queue_items_status', 'assessment_queue_items', ['status'])
    op.create_index('ix_queue_items_priority_score', 'assessment_queue_items', ['priority_score'])
    op.create_index('ix_queue_items_priority_band', 'assessment_queue_items', ['priority_band'])
    op.create_index('ix_queue_items_eligibility', 'assessment_queue_items', ['eligibility_status'])
    op.create_index('ix_queue_items_worker_claim', 'assessment_queue_items', ['worker_claim_id'])
    op.create_index('ix_queue_items_lease_expires', 'assessment_queue_items', ['lease_expires_at'])
    op.create_index('ix_queue_items_next_eligible', 'assessment_queue_items', ['next_eligible_at'])
    op.create_index('ix_queue_items_proj_status_prio', 'assessment_queue_items', ['project_id', 'status', 'priority_score'])
    op.create_index('ix_queue_items_claim_lease', 'assessment_queue_items', ['status', 'lease_expires_at'])
    op.create_index('ix_queue_items_concurrency', 'assessment_queue_items', ['project_id', 'concurrency_key', 'status'])
    op.create_index('ix_queue_items_idempotency', 'assessment_queue_items', ['project_id', 'idempotency_key'])

    # 2. Scheduler Decision Records
    op.create_table(
        'scheduler_decision_records',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('project_id', sa.String(length=36), nullable=False),
        sa.Column('queue_item_id', sa.String(length=36), nullable=True),
        sa.Column('trigger_source', sa.String(length=100), nullable=False, server_default='MANUAL_DISPATCH'),
        sa.Column('target_input', sa.String(length=500), nullable=False),
        sa.Column('decision_type', sa.String(length=50), nullable=False),
        sa.Column('priority_score', sa.Float(), nullable=False, server_default='0.0'),
        sa.Column('decision_rationale', sa.Text(), nullable=False),
        sa.Column('capacity_snapshot', sa.JSON(), nullable=False),
        sa.Column('metadata_payload', sa.JSON(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['project_id'], ['projects.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['queue_item_id'], ['assessment_queue_items.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_sched_decisions_project_id', 'scheduler_decision_records', ['project_id'])
    op.create_index('ix_sched_decisions_type', 'scheduler_decision_records', ['decision_type'])
    op.create_index('ix_sched_decisions_trigger', 'scheduler_decision_records', ['trigger_source'])
    op.create_index('ix_sched_decisions_target', 'scheduler_decision_records', ['target_input'])
    op.create_index('ix_sched_decisions_proj_type_created', 'scheduler_decision_records', ['project_id', 'decision_type', 'created_at'])

    # 3. Scheduler Policies
    op.create_table(
        'scheduler_policies',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('project_id', sa.String(length=36), nullable=False),
        sa.Column('policy_version', sa.String(length=50), nullable=False, server_default='scheduling_v1.0'),
        sa.Column('max_concurrent_assessments', sa.Integer(), nullable=False, server_default='5'),
        sa.Column('max_per_target_concurrency', sa.Integer(), nullable=False, server_default='1'),
        sa.Column('max_per_adapter_concurrency', sa.Integer(), nullable=False, server_default='2'),
        sa.Column('max_queued_jobs', sa.Integer(), nullable=False, server_default='100'),
        sa.Column('max_execution_duration_sec', sa.Integer(), nullable=False, server_default='600'),
        sa.Column('max_retries', sa.Integer(), nullable=False, server_default='3'),
        sa.Column('aging_factor_per_hour', sa.Float(), nullable=False, server_default='2.0'),
        sa.Column('stale_lease_timeout_sec', sa.Integer(), nullable=False, server_default='120'),
        sa.Column('cooldown_period_sec', sa.Integer(), nullable=False, server_default='3600'),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default=sa.text('1')),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['project_id'], ['projects.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('project_id', name='uq_scheduler_policies_project_id')
    )
    op.create_index('ix_scheduler_policies_project_id', 'scheduler_policies', ['project_id'])


def downgrade():
    op.drop_table('scheduler_policies')
    op.drop_table('scheduler_decision_records')
    op.drop_table('assessment_queue_items')
