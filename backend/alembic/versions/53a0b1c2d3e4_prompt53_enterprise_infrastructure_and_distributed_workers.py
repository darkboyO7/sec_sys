"""prompt53_enterprise_infrastructure_and_distributed_workers

Revision ID: 53a0b1c2d3e4
Revises: 51a0b1c2d3e4
Create Date: 2026-10-31 06:30:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '53a0b1c2d3e4'
down_revision: Union[str, None] = '51a0b1c2d3e4'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Alter assessment_jobs table for dead-letter queuing
    with op.batch_alter_table('assessment_jobs', schema=None) as batch_op:
        batch_op.add_column(sa.Column('dead_letter_reason', sa.Text(), nullable=True))
        batch_op.add_column(sa.Column('dead_letter_at', sa.DateTime(timezone=True), nullable=True))

    # 2. Create worker_nodes table
    op.create_table(
        'worker_nodes',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('worker_id', sa.String(length=100), nullable=False),
        sa.Column('worker_type', sa.String(length=50), nullable=False, server_default='LOCAL_SUBPROCESS'),
        sa.Column('hostname', sa.String(length=255), nullable=False),
        sa.Column('pid', sa.Integer(), nullable=True),
        sa.Column('status', sa.String(length=50), nullable=False, server_default='ONLINE'),
        sa.Column('concurrency_slots', sa.Integer(), nullable=False, server_default='4'),
        sa.Column('active_jobs_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('capabilities', sa.JSON(), nullable=False, server_default='[]'),
        sa.Column('registered_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('last_heartbeat_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('auth_token_hash', sa.String(length=128), nullable=False),
        sa.Column('metadata_json', sa.JSON(), nullable=False, server_default='{}'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_worker_nodes_worker_id', 'worker_nodes', ['worker_id'], unique=True)
    op.create_index('ix_worker_nodes_status', 'worker_nodes', ['status'], unique=False)
    op.create_index('ix_worker_nodes_last_heartbeat_at', 'worker_nodes', ['last_heartbeat_at'], unique=False)


def downgrade() -> None:
    op.drop_index('ix_worker_nodes_last_heartbeat_at', table_name='worker_nodes')
    op.drop_index('ix_worker_nodes_status', table_name='worker_nodes')
    op.drop_index('ix_worker_nodes_worker_id', table_name='worker_nodes')
    op.drop_table('worker_nodes')

    with op.batch_alter_table('assessment_jobs', schema=None) as batch_op:
        batch_op.drop_column('dead_letter_at')
        batch_op.drop_column('dead_letter_reason')
