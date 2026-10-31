"""prompt63_security_audit_remediation_and_hardening

Revision ID: 63a0b1c2d3e4
Revises: 58a0b1c2d3e4
Create Date: 2026-10-31 13:40:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '63a0b1c2d3e4'
down_revision: Union[str, None] = '58a0b1c2d3e4'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Add session_token_hash and session_expires_at to worker_nodes table
    with op.batch_alter_table('worker_nodes', schema=None) as batch_op:
        batch_op.add_column(sa.Column('session_token_hash', sa.String(length=128), nullable=True))
        batch_op.add_column(sa.Column('session_expires_at', sa.DateTime(timezone=True), nullable=True))
        batch_op.create_index(batch_op.f('ix_worker_nodes_session_token_hash'), ['session_token_hash'], unique=False)

    # 2. Add sequence_number to audit_events table
    with op.batch_alter_table('audit_events', schema=None) as batch_op:
        batch_op.add_column(sa.Column('sequence_number', sa.Integer(), nullable=True))
        batch_op.create_index(batch_op.f('ix_audit_events_sequence_number'), ['sequence_number'], unique=False)
        batch_op.create_index('ix_audit_events_project_sequence', ['project_id', 'sequence_number'], unique=False)


def downgrade() -> None:
    with op.batch_alter_table('audit_events', schema=None) as batch_op:
        batch_op.drop_index('ix_audit_events_project_sequence')
        batch_op.drop_index(batch_op.f('ix_audit_events_sequence_number'))
        batch_op.drop_column('sequence_number')

    with op.batch_alter_table('worker_nodes', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_worker_nodes_session_token_hash'))
        batch_op.drop_column('session_expires_at')
        batch_op.drop_column('session_token_hash')
