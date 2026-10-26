"""phase11_contextual_risk_intelligence

Revision ID: e5f6a7b8c9d0
Revises: d4e5f6a7b8c9
Create Date: 2026-10-26 17:30:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa


revision: str = 'e5f6a7b8c9d0'
down_revision: Union[str, None] = 'd4e5f6a7b8c9'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table('risk_assessments', schema=None) as batch_op:
        batch_op.add_column(sa.Column('inherent_score', sa.Float(), nullable=True))
        batch_op.add_column(sa.Column('residual_score', sa.Float(), nullable=True))
        batch_op.add_column(sa.Column('uncertainty_range', sa.JSON(), nullable=False, server_default='{}'))


def downgrade() -> None:
    with op.batch_alter_table('risk_assessments', schema=None) as batch_op:
        batch_op.drop_column('uncertainty_range')
        batch_op.drop_column('residual_score')
        batch_op.drop_column('inherent_score')
