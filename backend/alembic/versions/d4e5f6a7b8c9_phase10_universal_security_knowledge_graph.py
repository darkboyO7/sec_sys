"""phase10_universal_security_knowledge_graph

Revision ID: d4e5f6a7b8c9
Revises: c3d4e5f6a7b8
Create Date: 2026-10-26 17:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa


revision: str = 'd4e5f6a7b8c9'
down_revision: Union[str, None] = 'c3d4e5f6a7b8'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table('graph_nodes', schema=None) as batch_op:
        batch_op.alter_column('category', existing_type=sa.String(length=16), type_=sa.String(length=50), nullable=False)
        batch_op.add_column(sa.Column('epistemic_status', sa.String(length=20), nullable=False, server_default='VERIFIED'))

    with op.batch_alter_table('graph_relationships', schema=None) as batch_op:
        batch_op.alter_column('relationship_type', existing_type=sa.String(length=16), type_=sa.String(length=50), nullable=False)
        batch_op.add_column(sa.Column('verification_history', sa.JSON(), nullable=False, server_default='[]'))


def downgrade() -> None:
    with op.batch_alter_table('graph_relationships', schema=None) as batch_op:
        batch_op.drop_column('verification_history')
        batch_op.alter_column('relationship_type', existing_type=sa.String(length=50), type_=sa.String(length=16), nullable=False)

    with op.batch_alter_table('graph_nodes', schema=None) as batch_op:
        batch_op.drop_column('epistemic_status')
        batch_op.alter_column('category', existing_type=sa.String(length=50), type_=sa.String(length=16), nullable=False)
