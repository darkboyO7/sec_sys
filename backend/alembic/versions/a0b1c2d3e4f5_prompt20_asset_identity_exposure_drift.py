"""prompt20_asset_identity_exposure_drift

Revision ID: a0b1c2d3e4f5
Revises: f9c0d1e2f3a5
Create Date: 2026-10-28 22:30:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa


revision: str = 'a0b1c2d3e4f5'
down_revision: Union[str, None] = 'f9c0d1e2f3a5'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    conn = op.get_bind()
    insp = sa.inspect(conn)
    existing_tables = insp.get_table_names()

    # 1. Add columns to assets
    if 'assets' in existing_tables:
        asset_cols = [c["name"] for c in insp.get_columns("assets")]
        with op.batch_alter_table('assets', schema=None) as batch_op:
            if 'last_successful_observation_at' not in asset_cols:
                batch_op.add_column(sa.Column('last_successful_observation_at', sa.DateTime(timezone=True), nullable=True))
            if 'completeness_score' not in asset_cols:
                batch_op.add_column(sa.Column('completeness_score', sa.Float(), nullable=False, server_default='1.0'))
            if 'freshness_status' not in asset_cols:
                batch_op.add_column(sa.Column('freshness_status', sa.String(length=50), nullable=False, server_default='FRESH'))
            if 'consecutive_absences' not in asset_cols:
                batch_op.add_column(sa.Column('consecutive_absences', sa.Integer(), nullable=False, server_default='0'))
            if 'confirmed_absent' not in asset_cols:
                batch_op.add_column(sa.Column('confirmed_absent', sa.Boolean(), nullable=False, server_default='0'))

    # 2. Add columns to asset_observations
    if 'asset_observations' in existing_tables:
        obs_cols = [c["name"] for c in insp.get_columns("asset_observations")]
        with op.batch_alter_table('asset_observations', schema=None) as batch_op:
            if 'monitoring_run_id' not in obs_cols:
                batch_op.add_column(sa.Column('monitoring_run_id', sa.String(length=36), nullable=True))
            if 'authorization_context' not in obs_cols:
                batch_op.add_column(sa.Column('authorization_context', sa.JSON(), nullable=False, server_default='{}'))
            if 'is_simulated' not in obs_cols:
                batch_op.add_column(sa.Column('is_simulated', sa.Boolean(), nullable=False, server_default='0'))
            if 'completeness' not in obs_cols:
                batch_op.add_column(sa.Column('completeness', sa.Float(), nullable=False, server_default='1.0'))
            if 'collection_errors' not in obs_cols:
                batch_op.add_column(sa.Column('collection_errors', sa.JSON(), nullable=False, server_default='[]'))
            if 'observation_schema_version' not in obs_cols:
                batch_op.add_column(sa.Column('observation_schema_version', sa.String(length=20), nullable=False, server_default='1.0'))
            if 'is_successful_absence' not in obs_cols:
                batch_op.add_column(sa.Column('is_successful_absence', sa.Boolean(), nullable=False, server_default='0'))
            if 'dedup_hash' not in obs_cols:
                batch_op.add_column(sa.Column('dedup_hash', sa.String(length=64), nullable=True))

    # 3. Create asset_identifier_aliases
    if 'asset_identifier_aliases' not in existing_tables:
        op.create_table(
            'asset_identifier_aliases',
            sa.Column('id', sa.String(length=36), primary_key=True),
            sa.Column('asset_id', sa.String(length=36), sa.ForeignKey('assets.id', ondelete='CASCADE'), nullable=False),
            sa.Column('project_id', sa.String(length=36), sa.ForeignKey('projects.id', ondelete='CASCADE'), nullable=False),
            sa.Column('identifier_type', sa.String(length=50), nullable=False),
            sa.Column('identifier_value', sa.String(length=500), nullable=False),
            sa.Column('is_primary', sa.Boolean(), nullable=False, server_default='0'),
            sa.Column('confidence', sa.Float(), nullable=False, server_default='1.0'),
            sa.Column('evidence_ref', sa.String(length=64), nullable=True),
            sa.Column('first_observed_at', sa.DateTime(timezone=True), nullable=False),
            sa.Column('last_observed_at', sa.DateTime(timezone=True), nullable=False),
            sa.Column('is_active', sa.Boolean(), nullable=False, server_default='1'),
            sa.Column('disassociation_reason', sa.Text(), nullable=True),
            sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
            sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
            sa.UniqueConstraint('project_id', 'asset_id', 'identifier_type', 'identifier_value', name='uq_project_asset_alias'),
        )
        op.create_index('ix_asset_aliases_lookup', 'asset_identifier_aliases', ['project_id', 'identifier_type', 'identifier_value'])

    # 4. Create asset_identity_merges
    if 'asset_identity_merges' not in existing_tables:
        op.create_table(
            'asset_identity_merges',
            sa.Column('id', sa.String(length=36), primary_key=True),
            sa.Column('project_id', sa.String(length=36), sa.ForeignKey('projects.id', ondelete='CASCADE'), nullable=False),
            sa.Column('target_asset_id', sa.String(length=36), sa.ForeignKey('assets.id', ondelete='CASCADE'), nullable=False),
            sa.Column('merged_asset_id', sa.String(length=36), nullable=False),
            sa.Column('merged_canonical_identifier', sa.String(length=500), nullable=False),
            sa.Column('merged_asset_type', sa.String(length=50), nullable=False),
            sa.Column('merged_attributes_snapshot', sa.JSON(), nullable=False, server_default='{}'),
            sa.Column('merge_rationale', sa.Text(), nullable=False),
            sa.Column('confidence', sa.Float(), nullable=False, server_default='1.0'),
            sa.Column('actor_id', sa.String(length=36), sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True),
            sa.Column('is_reversed', sa.Boolean(), nullable=False, server_default='0'),
            sa.Column('reversed_at', sa.DateTime(timezone=True), nullable=True),
            sa.Column('reversed_by_id', sa.String(length=36), sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True),
            sa.Column('reversal_notes', sa.Text(), nullable=True),
            sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
            sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        )

    # 5. Create exposure_drift_records
    if 'exposure_drift_records' not in existing_tables:
        op.create_table(
            'exposure_drift_records',
            sa.Column('id', sa.String(length=36), primary_key=True),
            sa.Column('project_id', sa.String(length=36), sa.ForeignKey('projects.id', ondelete='CASCADE'), nullable=False),
            sa.Column('asset_id', sa.String(length=36), sa.ForeignKey('assets.id', ondelete='CASCADE'), nullable=True),
            sa.Column('drift_type', sa.String(length=50), nullable=False),
            sa.Column('materiality', sa.String(length=50), nullable=False, server_default='MATERIAL'),
            sa.Column('materiality_reason', sa.Text(), nullable=False),
            sa.Column('target_resource', sa.String(length=500), nullable=False),
            sa.Column('title', sa.String(length=255), nullable=False),
            sa.Column('previous_observation_id', sa.String(length=36), sa.ForeignKey('asset_observations.id', ondelete='SET NULL'), nullable=True),
            sa.Column('current_observation_id', sa.String(length=36), sa.ForeignKey('asset_observations.id', ondelete='SET NULL'), nullable=True),
            sa.Column('previous_state', sa.JSON(), nullable=False, server_default='{}'),
            sa.Column('new_state', sa.JSON(), nullable=False, server_default='{}'),
            sa.Column('evidence_references', sa.JSON(), nullable=False, server_default='[]'),
            sa.Column('confidence', sa.Float(), nullable=False, server_default='1.0'),
            sa.Column('is_resolved', sa.Boolean(), nullable=False, server_default='0'),
            sa.Column('security_impact_summary', sa.Text(), nullable=True),
            sa.Column('reassessment_recommended', sa.Boolean(), nullable=False, server_default='0'),
            sa.Column('dedup_key', sa.String(length=64), nullable=True),
            sa.Column('detected_at', sa.DateTime(timezone=True), nullable=False),
            sa.Column('evaluated_at', sa.DateTime(timezone=True), nullable=False),
            sa.Column('acted_upon_at', sa.DateTime(timezone=True), nullable=True),
            sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
            sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        )
        op.create_index('ix_exposure_drift_project_detected', 'exposure_drift_records', ['project_id', 'detected_at'])
        op.create_index('ix_exposure_drift_project_materiality', 'exposure_drift_records', ['project_id', 'materiality'])

    # 6. Create reassessment_proposals
    if 'reassessment_proposals' not in existing_tables:
        op.create_table(
            'reassessment_proposals',
            sa.Column('id', sa.String(length=36), primary_key=True),
            sa.Column('project_id', sa.String(length=36), sa.ForeignKey('projects.id', ondelete='CASCADE'), nullable=False),
            sa.Column('asset_id', sa.String(length=36), sa.ForeignKey('assets.id', ondelete='CASCADE'), nullable=True),
            sa.Column('drift_record_id', sa.String(length=36), sa.ForeignKey('exposure_drift_records.id', ondelete='CASCADE'), nullable=True),
            sa.Column('target_input', sa.String(length=500), nullable=False),
            sa.Column('adapter_name', sa.String(length=100), nullable=False, server_default='live_network_auditor_adapter'),
            sa.Column('fixture_profile', sa.String(length=100), nullable=False, server_default='LIVE_WEB_SECURITY_AUDIT'),
            sa.Column('priority', sa.String(length=50), nullable=False, server_default='MEDIUM'),
            sa.Column('status', sa.String(length=50), nullable=False, server_default='PROPOSED'),
            sa.Column('rationale', sa.Text(), nullable=False),
            sa.Column('scope_authorized', sa.Boolean(), nullable=False, server_default='1'),
            sa.Column('scope_validation_details', sa.JSON(), nullable=False, server_default='{}'),
            sa.Column('requires_human_approval', sa.Boolean(), nullable=False, server_default='0'),
            sa.Column('approved_by_id', sa.String(length=36), sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True),
            sa.Column('approved_at', sa.DateTime(timezone=True), nullable=True),
            sa.Column('rejection_reason', sa.Text(), nullable=True),
            sa.Column('scheduled_job_id', sa.String(length=36), sa.ForeignKey('assessment_jobs.id', ondelete='SET NULL'), nullable=True),
            sa.Column('dedup_key', sa.String(length=64), nullable=False),
            sa.Column('attempt_count', sa.Integer(), nullable=False, server_default='0'),
            sa.Column('max_attempts', sa.Integer(), nullable=False, server_default='3'),
            sa.Column('last_error', sa.Text(), nullable=True),
            sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
            sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        )
        op.create_index('ix_reassessment_proposals_project_status', 'reassessment_proposals', ['project_id', 'status'])
        op.create_index('ix_reassessment_proposals_dedup', 'reassessment_proposals', ['project_id', 'dedup_key'])


def downgrade() -> None:
    pass
