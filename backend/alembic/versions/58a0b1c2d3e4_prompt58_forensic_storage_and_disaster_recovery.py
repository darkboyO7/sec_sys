"""prompt58_forensic_storage_and_disaster_recovery

Revision ID: 58a0b1c2d3e4
Revises: 53a0b1c2d3e4
Create Date: 2026-10-31 08:50:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '58a0b1c2d3e4'
down_revision: Union[str, None] = '53a0b1c2d3e4'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Alter disaster_recovery_bundles table
    with op.batch_alter_table('disaster_recovery_bundles', schema=None) as batch_op:
        batch_op.add_column(sa.Column('manifest_signature', sa.String(length=512), nullable=True))
        batch_op.add_column(sa.Column('evidence_count', sa.Integer(), nullable=False, server_default='0'))
        batch_op.add_column(sa.Column('evidence_sha256', sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column('backup_type', sa.String(length=50), nullable=False, server_default='OPERATOR_TRIGGERED'))
        batch_op.add_column(sa.Column('configuration_metadata', sa.JSON(), nullable=False, server_default='{}'))

    # 2. Create legal_holds table
    op.create_table(
        'legal_holds',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('hold_id', sa.String(length=100), nullable=False),
        sa.Column('hold_type', sa.String(length=50), nullable=False, server_default='INVESTIGATION_HOLD'),
        sa.Column('target_scope', sa.String(length=50), nullable=False),
        sa.Column('target_id', sa.String(length=100), nullable=False),
        sa.Column('reason', sa.Text(), nullable=False),
        sa.Column('status', sa.String(length=50), nullable=False, server_default='ACTIVE'),
        sa.Column('placed_by_id', sa.String(length=36), nullable=True),
        sa.Column('placed_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('released_by_id', sa.String(length=36), nullable=True),
        sa.Column('released_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('metadata_json', sa.JSON(), nullable=False, server_default='{}'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['placed_by_id'], ['users.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['released_by_id'], ['users.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_legal_holds_hold_id', 'legal_holds', ['hold_id'], unique=True)
    op.create_index('ix_legal_holds_target_id', 'legal_holds', ['target_id'], unique=False)
    op.create_index('ix_legal_holds_status', 'legal_holds', ['status'], unique=False)

    # 3. Create evidence_tombstones table
    op.create_table(
        'evidence_tombstones',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('tombstone_id', sa.String(length=100), nullable=False),
        sa.Column('evidence_id', sa.String(length=36), nullable=False),
        sa.Column('original_sha256_hash', sa.String(length=64), nullable=False),
        sa.Column('classification', sa.String(length=50), nullable=False, server_default='RAW_EVIDENCE'),
        sa.Column('policy_id', sa.String(length=100), nullable=False, server_default='DEFAULT_RETENTION'),
        sa.Column('deleted_by_id', sa.String(length=36), nullable=True),
        sa.Column('deleted_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('tombstone_digest', sa.String(length=128), nullable=False),
        sa.Column('reason', sa.Text(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['deleted_by_id'], ['users.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_evidence_tombstones_tombstone_id', 'evidence_tombstones', ['tombstone_id'], unique=True)
    op.create_index('ix_evidence_tombstones_evidence_id', 'evidence_tombstones', ['evidence_id'], unique=False)
    op.create_index('ix_evidence_tombstones_original_sha256_hash', 'evidence_tombstones', ['original_sha256_hash'], unique=False)


def downgrade() -> None:
    op.drop_index('ix_evidence_tombstones_original_sha256_hash', table_name='evidence_tombstones')
    op.drop_index('ix_evidence_tombstones_evidence_id', table_name='evidence_tombstones')
    op.drop_index('ix_evidence_tombstones_tombstone_id', table_name='evidence_tombstones')
    op.drop_table('evidence_tombstones')

    op.drop_index('ix_legal_holds_status', table_name='legal_holds')
    op.drop_index('ix_legal_holds_target_id', table_name='legal_holds')
    op.drop_index('ix_legal_holds_hold_id', table_name='legal_holds')
    op.drop_table('legal_holds')

    with op.batch_alter_table('disaster_recovery_bundles', schema=None) as batch_op:
        batch_op.drop_column('configuration_metadata')
        batch_op.drop_column('backup_type')
        batch_op.drop_column('evidence_sha256')
        batch_op.drop_column('evidence_count')
        batch_op.drop_column('manifest_signature')
