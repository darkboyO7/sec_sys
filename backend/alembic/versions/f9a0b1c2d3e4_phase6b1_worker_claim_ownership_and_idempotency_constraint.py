"""phase6b1_worker_claim_ownership_and_idempotency_constraint

Revision ID: f9a0b1c2d3e4
Revises: e8a9b0c1d2e3
Create Date: 2026-10-25 12:45:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa


revision: str = 'f9a0b1c2d3e4'
down_revision: Union[str, None] = 'e8a9b0c1d2e3'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table('assessment_jobs', schema=None) as batch_op:
        batch_op.add_column(sa.Column('claimed_by', sa.String(length=100), nullable=True))
        batch_op.create_index('ix_assessment_jobs_claimed_by', ['claimed_by'], unique=False)
        batch_op.create_index('uq_assessment_jobs_project_idempotency_key', ['project_id', 'idempotency_key'], unique=True)


def downgrade() -> None:
    with op.batch_alter_table('assessment_jobs', schema=None) as batch_op:
        batch_op.drop_index('uq_assessment_jobs_project_idempotency_key')
        batch_op.drop_index('ix_assessment_jobs_claimed_by')
        batch_op.drop_column('claimed_by')
