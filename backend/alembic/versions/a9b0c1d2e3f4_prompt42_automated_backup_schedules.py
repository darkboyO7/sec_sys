"""prompt42 automated backup schedules

Revision ID: a9b0c1d2e3f4
Revises: f8a9b0c1d2e3
Create Date: 2026-10-29 22:50:00.000000

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'a9b0c1d2e3f4'
down_revision = 'f8a9b0c1d2e3'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'backup_schedules',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('name', sa.String(length=128), nullable=False),
        sa.Column('interval_hours', sa.Integer(), nullable=False, server_default='24'),
        sa.Column('retention_days', sa.Integer(), nullable=False, server_default='30'),
        sa.Column('max_bundles_to_keep', sa.Integer(), nullable=False, server_default='10'),
        sa.Column('storage_location', sa.String(length=512), nullable=False, server_default='./data/backups'),
        sa.Column('include_evidence', sa.Boolean(), nullable=False, server_default=sa.text('1')),
        sa.Column('auto_verify_after_backup', sa.Boolean(), nullable=False, server_default=sa.text('1')),
        sa.Column('auto_drill_after_backup', sa.Boolean(), nullable=False, server_default=sa.text('0')),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default=sa.text('1')),
        sa.Column('last_run_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_run_status', sa.String(length=32), nullable=True),
        sa.Column('last_run_error', sa.Text(), nullable=True),
        sa.Column('last_bundle_id', sa.String(length=128), nullable=True),
        sa.Column('consecutive_failures', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('next_run_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_by_id', sa.String(length=36), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(['created_by_id'], ['users.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_backup_schedules_is_active'), 'backup_schedules', ['is_active'], unique=False)
    op.create_index(op.f('ix_backup_schedules_next_run_at'), 'backup_schedules', ['next_run_at'], unique=False)


def downgrade():
    op.drop_index(op.f('ix_backup_schedules_next_run_at'), table_name='backup_schedules')
    op.drop_index(op.f('ix_backup_schedules_is_active'), table_name='backup_schedules')
    op.drop_table('backup_schedules')
