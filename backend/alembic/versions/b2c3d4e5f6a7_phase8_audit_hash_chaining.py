"""phase8_audit_hash_chaining

Revision ID: b2c3d4e5f6a7
Revises: a1b2c3d4e5f6
Create Date: 2026-10-26 16:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa


revision: str = 'b2c3d4e5f6a7'
down_revision: Union[str, None] = 'a1b2c3d4e5f6'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table('audit_events', schema=None) as batch_op:
        batch_op.add_column(sa.Column('prev_event_hash', sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column('event_hash', sa.String(length=64), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table('audit_events', schema=None) as batch_op:
        batch_op.drop_column('event_hash')
        batch_op.drop_column('prev_event_hash')
