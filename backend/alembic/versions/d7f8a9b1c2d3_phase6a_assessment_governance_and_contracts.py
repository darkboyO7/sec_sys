"""phase6a_assessment_governance_and_contracts

Revision ID: d7f8a9b1c2d3
Revises: c7b91d4e28a1
Create Date: 2026-10-25 12:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa


revision: str = 'd7f8a9b1c2d3'
down_revision: Union[str, None] = 'c7b91d4e28a1'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table('assessment_jobs', schema=None) as batch_op:
        batch_op.add_column(sa.Column('policy_version', sa.String(length=50), nullable=False, server_default='2026.1'))
        batch_op.add_column(sa.Column('authorization_reference', sa.String(length=255), nullable=True))
        batch_op.add_column(sa.Column('authorization_status', sa.String(length=50), nullable=False, server_default='AUTHORIZED'))
        batch_op.add_column(sa.Column('scope_snapshot', sa.JSON(), nullable=False, server_default='{}'))
        batch_op.add_column(sa.Column('scope_snapshot_digest', sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column('preflight_at', sa.DateTime(timezone=True), nullable=True))
        batch_op.add_column(sa.Column('heartbeat_at', sa.DateTime(timezone=True), nullable=True))
        batch_op.add_column(sa.Column('cancellation_requested_at', sa.DateTime(timezone=True), nullable=True))
        batch_op.add_column(sa.Column('failure_category', sa.String(length=100), nullable=True))
        batch_op.add_column(sa.Column('attempt_count', sa.Integer(), nullable=False, server_default='1'))
        batch_op.create_index(batch_op.f('ix_assessment_jobs_scope_snapshot_digest'), ['scope_snapshot_digest'], unique=False)
        batch_op.create_index(batch_op.f('ix_assessment_jobs_failure_category'), ['failure_category'], unique=False)


def downgrade() -> None:
    with op.batch_alter_table('assessment_jobs', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_assessment_jobs_failure_category'))
        batch_op.drop_index(batch_op.f('ix_assessment_jobs_scope_snapshot_digest'))
        batch_op.drop_column('attempt_count')
        batch_op.drop_column('failure_category')
        batch_op.drop_column('cancellation_requested_at')
        batch_op.drop_column('heartbeat_at')
        batch_op.drop_column('preflight_at')
        batch_op.drop_column('scope_snapshot_digest')
        batch_op.drop_column('scope_snapshot')
        batch_op.drop_column('authorization_status')
        batch_op.drop_column('authorization_reference')
        batch_op.drop_column('policy_version')
