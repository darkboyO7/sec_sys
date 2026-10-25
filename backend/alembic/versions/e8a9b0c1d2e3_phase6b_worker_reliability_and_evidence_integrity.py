"""phase6b_worker_reliability_and_evidence_integrity

Revision ID: e8a9b0c1d2e3
Revises: d7f8a9b1c2d3
Create Date: 2026-10-25 12:20:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa


revision: str = 'e8a9b0c1d2e3'
down_revision: Union[str, None] = 'd7f8a9b1c2d3'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table('assessment_jobs', schema=None) as batch_op:
        batch_op.add_column(sa.Column('idempotency_digest', sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column('lock_version', sa.Integer(), nullable=False, server_default='1'))
        batch_op.create_index(batch_op.f('ix_assessment_jobs_idempotency_digest'), ['idempotency_digest'], unique=False)

    with op.batch_alter_table('finding_evidence', schema=None) as batch_op:
        batch_op.add_column(sa.Column('raw_sha256_hash', sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column('is_truncated', sa.Boolean(), nullable=False, server_default='0'))


def downgrade() -> None:
    with op.batch_alter_table('finding_evidence', schema=None) as batch_op:
        batch_op.drop_column('is_truncated')
        batch_op.drop_column('raw_sha256_hash')

    with op.batch_alter_table('assessment_jobs', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_assessment_jobs_idempotency_digest'))
        batch_op.drop_column('lock_version')
        batch_op.drop_column('idempotency_digest')
