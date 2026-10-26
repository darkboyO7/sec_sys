"""phase13_remediation_planning_and_governance

Revision ID: f6a7b8c9d0e1
Revises: e5f6a7b8c9d0
Create Date: 2026-10-26 18:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa


revision: str = 'f6a7b8c9d0e1'
down_revision: Union[str, None] = 'e5f6a7b8c9d0'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table('remediation_recommendations', schema=None) as batch_op:
        batch_op.add_column(sa.Column('root_cause', sa.Text(), nullable=True))
        batch_op.add_column(sa.Column('recommended_change', sa.Text(), nullable=True))
        batch_op.add_column(sa.Column('estimated_effort', sa.String(length=50), nullable=True))
        batch_op.add_column(sa.Column('related_controls', sa.JSON(), nullable=False, server_default='[]'))
        batch_op.add_column(sa.Column('execution_governance_stage', sa.String(length=50), nullable=False, server_default='GENERATED'))


def downgrade() -> None:
    with op.batch_alter_table('remediation_recommendations', schema=None) as batch_op:
        batch_op.drop_column('execution_governance_stage')
        batch_op.drop_column('related_controls')
        batch_op.drop_column('estimated_effort')
        batch_op.drop_column('recommended_change')
        batch_op.drop_column('root_cause')
