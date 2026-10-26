"""phase16_historical_security_digital_twin

Revision ID: c9d0e1f2a3b4
Revises: b8c9d0e1f2a3
Create Date: 2026-10-26 21:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa


revision: str = 'c9d0e1f2a3b4'
down_revision: Union[str, None] = 'b8c9d0e1f2a3'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'security_snapshots',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('project_id', sa.String(length=36), nullable=False),
        sa.Column('snapshot_label', sa.String(length=255), nullable=False),
        sa.Column('snapshot_timestamp', sa.DateTime(timezone=True), nullable=False),
        sa.Column('captured_by_id', sa.String(length=36), nullable=True),
        sa.Column('assets_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('findings_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('risk_summary', sa.JSON(), nullable=False, server_default='{}'),
        sa.Column('state_manifest', sa.JSON(), nullable=False, server_default='{}'),
        sa.Column('manifest_sha256', sa.String(length=64), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['project_id'], ['projects.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['captured_by_id'], ['users.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_security_snapshots_project_id', 'security_snapshots', ['project_id'], unique=False)
    op.create_index('ix_security_snapshots_snapshot_timestamp', 'security_snapshots', ['snapshot_timestamp'], unique=False)
    op.create_index('ix_security_snapshots_captured_by_id', 'security_snapshots', ['captured_by_id'], unique=False)
    op.create_index('ix_security_snapshots_manifest_sha256', 'security_snapshots', ['manifest_sha256'], unique=False)


def downgrade() -> None:
    op.drop_index('ix_security_snapshots_manifest_sha256', table_name='security_snapshots')
    op.drop_index('ix_security_snapshots_captured_by_id', table_name='security_snapshots')
    op.drop_index('ix_security_snapshots_snapshot_timestamp', table_name='security_snapshots')
    op.drop_index('ix_security_snapshots_project_id', table_name='security_snapshots')
    op.drop_table('security_snapshots')
