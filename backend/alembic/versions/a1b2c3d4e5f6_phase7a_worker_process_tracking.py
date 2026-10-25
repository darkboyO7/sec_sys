"""phase7a_worker_process_tracking

Revision ID: a1b2c3d4e5f6
Revises: f9a0b1c2d3e4
Create Date: 2026-10-25 15:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa


revision: str = 'a1b2c3d4e5f6'
down_revision: Union[str, None] = 'f9a0b1c2d3e4'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table('assessment_jobs', schema=None) as batch_op:
        batch_op.add_column(sa.Column('worker_pid', sa.Integer(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table('assessment_jobs', schema=None) as batch_op:
        batch_op.drop_column('worker_pid')
