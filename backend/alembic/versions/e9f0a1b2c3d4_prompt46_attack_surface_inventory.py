"""prompt46 attack surface inventory and inclusion proposals

Revision ID: e9f0a1b2c3d4
Revises: a9b0c1d2e3f4
Create Date: 2026-10-30 06:30:00.000000

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'e9f0a1b2c3d4'
down_revision = 'a9b0c1d2e3f4'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'attack_surface_exposures',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('project_id', sa.String(length=36), nullable=False),
        sa.Column('asset_id', sa.String(length=36), nullable=False),
        sa.Column('canonical_identifier', sa.String(length=500), nullable=False),
        sa.Column('service_name', sa.String(length=100), nullable=False, server_default='unknown'),
        sa.Column('port', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('protocol', sa.String(length=20), nullable=False, server_default='tcp'),
        sa.Column('transport_security', sa.String(length=50), nullable=False, server_default='PLAINTEXT'),
        sa.Column('certificate_details', sa.JSON(), nullable=False),
        sa.Column('relevant_hostnames', sa.JSON(), nullable=False),
        sa.Column('exposure_classification', sa.String(length=50), nullable=False, server_default='INTERNET_FACING'),
        sa.Column('provenance_type', sa.String(length=50), nullable=False, server_default='VERIFIED_OBSERVATION'),
        sa.Column('freshness', sa.String(length=50), nullable=False, server_default='FRESH'),
        sa.Column('is_authorized', sa.Boolean(), nullable=False, server_default=sa.text('1')),
        sa.Column('first_observed_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('last_observed_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('consecutive_absences', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('observation_count', sa.Integer(), nullable=False, server_default='1'),
        sa.Column('evidence_hashes', sa.JSON(), nullable=False),
        sa.Column('latest_observation_id', sa.String(length=36), nullable=True),
        sa.Column('dedup_hash', sa.String(length=64), nullable=False),
        sa.Column('attributes', sa.JSON(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(['asset_id'], ['assets.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['latest_observation_id'], ['asset_observations.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['project_id'], ['projects.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_attack_surface_exposures_project_id'), 'attack_surface_exposures', ['project_id'], unique=False)
    op.create_index(op.f('ix_attack_surface_exposures_asset_id'), 'attack_surface_exposures', ['asset_id'], unique=False)
    op.create_index(op.f('ix_attack_surface_exposures_canonical_identifier'), 'attack_surface_exposures', ['canonical_identifier'], unique=False)
    op.create_index('ix_exposure_proj_asset', 'attack_surface_exposures', ['project_id', 'asset_id'], unique=False)
    op.create_index('ix_exposure_dedup', 'attack_surface_exposures', ['dedup_hash'], unique=True)
    op.create_index('ix_exposure_class_freshness', 'attack_surface_exposures', ['project_id', 'exposure_classification', 'freshness'], unique=False)

    op.create_table(
        'asset_inclusion_proposals',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('project_id', sa.String(length=36), nullable=False),
        sa.Column('target_type', sa.String(length=50), nullable=False),
        sa.Column('target_value', sa.String(length=500), nullable=False),
        sa.Column('discovery_source', sa.String(length=100), nullable=False),
        sa.Column('provenance_type', sa.String(length=50), nullable=False, server_default='INFERRED_RELATIONSHIP'),
        sa.Column('status', sa.String(length=50), nullable=False, server_default='PENDING'),
        sa.Column('rationale', sa.Text(), nullable=True),
        sa.Column('discovered_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('evidence_hash', sa.String(length=64), nullable=True),
        sa.Column('is_simulated', sa.Boolean(), nullable=False, server_default=sa.text('0')),
        sa.Column('reviewed_by_id', sa.String(length=36), nullable=True),
        sa.Column('reviewed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('approval_notes', sa.Text(), nullable=True),
        sa.Column('resulting_scope_target_id', sa.String(length=36), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(['project_id'], ['projects.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['resulting_scope_target_id'], ['scope_targets.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['reviewed_by_id'], ['users.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('project_id', 'target_value', name='uq_project_proposed_target'),
    )
    op.create_index(op.f('ix_asset_inclusion_proposals_project_id'), 'asset_inclusion_proposals', ['project_id'], unique=False)
    op.create_index(op.f('ix_asset_inclusion_proposals_target_value'), 'asset_inclusion_proposals', ['target_value'], unique=False)
    op.create_index(op.f('ix_asset_inclusion_proposals_status'), 'asset_inclusion_proposals', ['status'], unique=False)
    op.create_index('ix_proposals_proj_status', 'asset_inclusion_proposals', ['project_id', 'status'], unique=False)


def downgrade():
    op.drop_index('ix_proposals_proj_status', table_name='asset_inclusion_proposals')
    op.drop_index(op.f('ix_asset_inclusion_proposals_status'), table_name='asset_inclusion_proposals')
    op.drop_index(op.f('ix_asset_inclusion_proposals_target_value'), table_name='asset_inclusion_proposals')
    op.drop_index(op.f('ix_asset_inclusion_proposals_project_id'), table_name='asset_inclusion_proposals')
    op.drop_table('asset_inclusion_proposals')

    op.drop_index('ix_exposure_class_freshness', table_name='attack_surface_exposures')
    op.drop_index('ix_exposure_dedup', table_name='attack_surface_exposures')
    op.drop_index('ix_exposure_proj_asset', table_name='attack_surface_exposures')
    op.drop_index(op.f('ix_attack_surface_exposures_canonical_identifier'), table_name='attack_surface_exposures')
    op.drop_index(op.f('ix_attack_surface_exposures_asset_id'), table_name='attack_surface_exposures')
    op.drop_index(op.f('ix_attack_surface_exposures_project_id'), table_name='attack_surface_exposures')
    op.drop_table('attack_surface_exposures')
