"""phase17_regression_detection_and_change_intelligence

Revision ID: d0e1f2a3b4c5
Revises: c9d0e1f2a3b4
Create Date: 2026-10-26 22:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa


revision: str = 'd0e1f2a3b4c5'
down_revision: Union[str, None] = 'c9d0e1f2a3b4'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'regression_baselines',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('project_id', sa.String(length=36), nullable=False),
        sa.Column('snapshot_id', sa.String(length=36), nullable=True),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default=sa.text('1')),
        sa.Column('risk_score_threshold_delta', sa.Float(), nullable=False, server_default='5.0'),
        sa.Column('evidence_stale_days', sa.Integer(), nullable=False, server_default='30'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['project_id'], ['projects.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['snapshot_id'], ['security_snapshots.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_regression_baselines_project_id', 'regression_baselines', ['project_id'], unique=False)
    op.create_index('ix_regression_baselines_snapshot_id', 'regression_baselines', ['snapshot_id'], unique=False)
    op.create_index('ix_regression_baselines_is_active', 'regression_baselines', ['is_active'], unique=False)

    op.create_table(
        'regression_alerts',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('project_id', sa.String(length=36), nullable=False),
        sa.Column('alert_type', sa.String(length=50), nullable=False),
        sa.Column('severity', sa.String(length=50), nullable=False),
        sa.Column('status', sa.String(length=50), nullable=False, server_default='ACTIVE'),
        sa.Column('title', sa.String(length=255), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('evidence_rationale', sa.Text(), nullable=False),
        sa.Column('baseline_reference', sa.String(length=255), nullable=True),
        sa.Column('current_reference', sa.String(length=255), nullable=True),
        sa.Column('target_resource', sa.String(length=255), nullable=False),
        sa.Column('fingerprint', sa.String(length=64), nullable=False),
        sa.Column('acknowledged_by_id', sa.String(length=36), nullable=True),
        sa.Column('acknowledged_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('resolution_notes', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['project_id'], ['projects.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['acknowledged_by_id'], ['users.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_regression_alerts_project_id', 'regression_alerts', ['project_id'], unique=False)
    op.create_index('ix_regression_alerts_alert_type', 'regression_alerts', ['alert_type'], unique=False)
    op.create_index('ix_regression_alerts_severity', 'regression_alerts', ['severity'], unique=False)
    op.create_index('ix_regression_alerts_status', 'regression_alerts', ['status'], unique=False)
    op.create_index('ix_regression_alerts_target_resource', 'regression_alerts', ['target_resource'], unique=False)
    op.create_index('ix_regression_alerts_fingerprint', 'regression_alerts', ['fingerprint'], unique=False)


def downgrade() -> None:
    op.drop_index('ix_regression_alerts_fingerprint', table_name='regression_alerts')
    op.drop_index('ix_regression_alerts_target_resource', table_name='regression_alerts')
    op.drop_index('ix_regression_alerts_status', table_name='regression_alerts')
    op.drop_index('ix_regression_alerts_severity', table_name='regression_alerts')
    op.drop_index('ix_regression_alerts_alert_type', table_name='regression_alerts')
    op.drop_index('ix_regression_alerts_project_id', table_name='regression_alerts')
    op.drop_table('regression_alerts')

    op.drop_index('ix_regression_baselines_is_active', table_name='regression_baselines')
    op.drop_index('ix_regression_baselines_snapshot_id', table_name='regression_baselines')
    op.drop_index('ix_regression_baselines_project_id', table_name='regression_baselines')
    op.drop_table('regression_baselines')
