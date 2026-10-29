"""prompt23_disaster_recovery

Revision ID: d3e4f5a6b7c8
Revises: c2d3e4f5a6b7
Create Date: 2026-10-29 06:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import sqlite

# revision identifiers, used by Alembic.
revision = 'd3e4f5a6b7c8'
down_revision = 'c2d3e4f5a6b7'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'disaster_recovery_bundles',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('bundle_id', sa.String(length=128), nullable=False),
        sa.Column('bundle_path', sa.String(length=512), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('created_by_id', sa.String(length=36), nullable=True),
        sa.Column('manifest_sha256', sa.String(length=64), nullable=False),
        sa.Column('database_sha256', sa.String(length=64), nullable=False),
        sa.Column('size_bytes', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('status', sa.String(length=50), nullable=False, server_default='UNVERIFIED'),
        sa.Column('last_verified_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('verification_report', sa.JSON(), nullable=True),
        sa.Column('last_restore_drill_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('restore_drill_report', sa.JSON(), nullable=True),
        sa.Column('is_last_known_good', sa.Boolean(), nullable=False, server_default='0'),
        sa.Column('table_counts', sa.JSON(), nullable=True),
        sa.Column('schema_revision', sa.String(length=64), nullable=True),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['created_by_id'], ['users.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_disaster_recovery_bundles_bundle_id', 'disaster_recovery_bundles', ['bundle_id'], unique=True)
    op.create_index('ix_disaster_recovery_bundles_created_at', 'disaster_recovery_bundles', ['created_at'], unique=False)
    op.create_index('ix_disaster_recovery_bundles_status', 'disaster_recovery_bundles', ['status'], unique=False)
    op.create_index('ix_disaster_recovery_bundles_is_last_known_good', 'disaster_recovery_bundles', ['is_last_known_good'], unique=False)


def downgrade() -> None:
    op.drop_index('ix_disaster_recovery_bundles_is_last_known_good', table_name='disaster_recovery_bundles')
    op.drop_index('ix_disaster_recovery_bundles_status', table_name='disaster_recovery_bundles')
    op.drop_index('ix_disaster_recovery_bundles_created_at', table_name='disaster_recovery_bundles')
    op.drop_index('ix_disaster_recovery_bundles_bundle_id', table_name='disaster_recovery_bundles')
    op.drop_table('disaster_recovery_bundles')
