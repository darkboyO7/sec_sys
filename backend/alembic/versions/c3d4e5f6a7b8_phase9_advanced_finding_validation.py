"""phase9_advanced_finding_validation

Revision ID: c3d4e5f6a7b8
Revises: b2c3d4e5f6a7
Create Date: 2026-10-26 16:30:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa


revision: str = 'c3d4e5f6a7b8'
down_revision: Union[str, None] = 'b2c3d4e5f6a7'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table('vulnerability_findings', schema=None) as batch_op:
        batch_op.add_column(sa.Column('validation_outcome', sa.String(length=50), nullable=True))
        batch_op.add_column(sa.Column('evidence_quality_score', sa.Float(), nullable=True, server_default='1.0'))
        batch_op.add_column(sa.Column('analyst_review_notes', sa.Text(), nullable=True))
        batch_op.add_column(sa.Column('reviewed_by_id', sa.String(length=36), nullable=True))
        batch_op.add_column(sa.Column('reviewed_at', sa.DateTime(timezone=True), nullable=True))
        batch_op.add_column(sa.Column('recurrence_detected', sa.Boolean(), nullable=False, server_default=sa.false()))
        batch_op.add_column(sa.Column('recurrence_count', sa.Integer(), nullable=False, server_default='0'))


def downgrade() -> None:
    with op.batch_alter_table('vulnerability_findings', schema=None) as batch_op:
        batch_op.drop_column('recurrence_count')
        batch_op.drop_column('recurrence_detected')
        batch_op.drop_column('reviewed_at')
        batch_op.drop_column('reviewed_by_id')
        batch_op.drop_column('analyst_review_notes')
        batch_op.drop_column('evidence_quality_score')
        batch_op.drop_column('validation_outcome')
