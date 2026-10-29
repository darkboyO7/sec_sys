"""prompt37 asset identity resolution data quality and canonical security records

Revision ID: b4c5d6e7f8a9
Revises: a3b4c5d6e7f8
Create Date: 2026-10-29 20:38:00.000000

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'b4c5d6e7f8a9'
down_revision = 'a3b4c5d6e7f8'
branch_labels = None
depends_on = None


def upgrade():
    # 1. Asset Deduplication Proposals table
    op.create_table(
        'asset_deduplication_proposals',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('project_id', sa.String(length=36), nullable=False),
        sa.Column('source_asset_id', sa.String(length=36), nullable=False),
        sa.Column('target_asset_id', sa.String(length=36), nullable=False),
        sa.Column('status', sa.Enum('PROPOSED', 'APPROVED', 'REJECTED', 'REVERTED', name='deduplicationproposalstatus'), nullable=False),
        sa.Column('confidence_score', sa.Float(), nullable=False),
        sa.Column('match_reasons', sa.JSON(), nullable=False),
        sa.Column('conflicts_detected', sa.JSON(), nullable=False),
        sa.Column('dry_run_impact', sa.JSON(), nullable=False),
        sa.Column('proposed_by_id', sa.String(length=36), nullable=True),
        sa.Column('reviewed_by_id', sa.String(length=36), nullable=True),
        sa.Column('review_comments', sa.Text(), nullable=True),
        sa.Column('reviewed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('reverted_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('reverted_by_id', sa.String(length=36), nullable=True),
        sa.Column('merge_record_id', sa.String(length=36), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['project_id'], ['projects.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['source_asset_id'], ['assets.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['target_asset_id'], ['assets.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['proposed_by_id'], ['users.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['reviewed_by_id'], ['users.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['reverted_by_id'], ['users.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['merge_record_id'], ['asset_identity_merges.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_asset_dedup_proj_status', 'asset_deduplication_proposals', ['project_id', 'status'])
    op.create_index('ix_asset_dedup_source', 'asset_deduplication_proposals', ['source_asset_id'])
    op.create_index('ix_asset_dedup_target', 'asset_deduplication_proposals', ['target_asset_id'])

    # 2. Asset Data Quality Issues table
    op.create_table(
        'asset_data_quality_issues',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('project_id', sa.String(length=36), nullable=False),
        sa.Column('issue_type', sa.Enum('ORPHANED_FINDING', 'MISSING_ASSET_REFERENCE', 'DUPLICATE_IDENTIFIER', 'INCONSISTENT_TIMESTAMPS', 'INVALID_RELATIONSHIP', 'STALE_OBSERVATION', name='dataqualityissuetype'), nullable=False),
        sa.Column('severity', sa.String(length=50), nullable=False),
        sa.Column('affected_resource_type', sa.String(length=50), nullable=False),
        sa.Column('affected_resource_id', sa.String(length=36), nullable=False),
        sa.Column('details', sa.JSON(), nullable=False),
        sa.Column('status', sa.Enum('OPEN', 'RESOLVED', 'IGNORED', name='dataqualityissuestatus'), nullable=False),
        sa.Column('detected_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('resolved_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['project_id'], ['projects.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_asset_dq_proj_type_status', 'asset_data_quality_issues', ['project_id', 'issue_type', 'status'])
    op.create_index('ix_asset_dq_affected', 'asset_data_quality_issues', ['affected_resource_id'])


def downgrade():
    op.drop_table('asset_data_quality_issues')
    op.drop_table('asset_deduplication_proposals')
