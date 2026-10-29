"""prompt35 evidence grounded threat intelligence and vulnerability correlation

Revision ID: f2a3b4c5d6e7
Revises: d1e2f3a4b5c6
Create Date: 2026-10-29 19:40:00.000000

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'f2a3b4c5d6e7'
down_revision = 'd1e2f3a4b5c6'
branch_labels = None
depends_on = None


def upgrade():
    # 1. Threat Intel Feeds
    op.create_table(
        'threat_intel_feeds',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('feed_name', sa.String(length=50), nullable=False),
        sa.Column('feed_url', sa.String(length=500), nullable=False),
        sa.Column('is_authoritative', sa.Boolean(), nullable=False, server_default='1'),
        sa.Column('sync_status', sa.String(length=50), nullable=False, server_default='STALE'),
        sa.Column('record_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('last_sync_started_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_synced_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_sync_error', sa.Text(), nullable=True),
        sa.Column('stale_after_days', sa.Integer(), nullable=False, server_default='7'),
        sa.Column('feed_checksum', sa.String(length=64), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('feed_name', name='uq_threat_intel_feeds_name')
    )
    op.create_index('ix_threat_intel_feeds_name', 'threat_intel_feeds', ['feed_name'])
    op.create_index('ix_threat_intel_feeds_sync_status', 'threat_intel_feeds', ['sync_status'])

    # 2. Threat Intelligence Records
    op.create_table(
        'threat_intelligence_records',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('cve_id', sa.String(length=50), nullable=False),
        sa.Column('source', sa.String(length=50), nullable=False),
        sa.Column('title', sa.String(length=255), nullable=True),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('vendor', sa.String(length=100), nullable=True),
        sa.Column('product', sa.String(length=100), nullable=True),
        sa.Column('cpe', sa.String(length=255), nullable=True),
        sa.Column('version_start_including', sa.String(length=50), nullable=True),
        sa.Column('version_end_excluding', sa.String(length=50), nullable=True),
        sa.Column('version_end_including', sa.String(length=50), nullable=True),
        sa.Column('affected_versions_list', sa.JSON(), nullable=False),
        sa.Column('cvss_score', sa.Float(), nullable=True),
        sa.Column('cvss_vector', sa.String(length=100), nullable=True),
        sa.Column('epss_score', sa.Float(), nullable=True),
        sa.Column('epss_percentile', sa.Float(), nullable=True),
        sa.Column('is_known_exploited', sa.Boolean(), nullable=False, server_default='0'),
        sa.Column('cisa_kev_due_date', sa.DateTime(timezone=True), nullable=True),
        sa.Column('cisa_kev_action', sa.Text(), nullable=True),
        sa.Column('published_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('modified_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('retrieved_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('confidence', sa.Float(), nullable=False, server_default='1.0'),
        sa.Column('provenance_url', sa.String(length=500), nullable=True),
        sa.Column('raw_payload_checksum', sa.String(length=64), nullable=True),
        sa.Column('raw_payload', sa.JSON(), nullable=False),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default='1'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('cve_id', 'source', name='uq_threat_intel_cve_source')
    )
    op.create_index('ix_threat_intel_cve_id', 'threat_intelligence_records', ['cve_id'])
    op.create_index('ix_threat_intel_source', 'threat_intelligence_records', ['source'])
    op.create_index('ix_threat_intel_product_vendor', 'threat_intelligence_records', ['vendor', 'product'])
    op.create_index('ix_threat_intel_cve_exploited', 'threat_intelligence_records', ['cve_id', 'is_known_exploited'])

    # 3. Threat Correlations
    op.create_table(
        'threat_correlations',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('project_id', sa.String(length=36), nullable=False),
        sa.Column('finding_id', sa.String(length=36), nullable=False),
        sa.Column('threat_intel_id', sa.String(length=36), nullable=False),
        sa.Column('match_classification', sa.String(length=50), nullable=False),
        sa.Column('confidence_score', sa.Float(), nullable=False, server_default='1.0'),
        sa.Column('evidence_grounding', sa.JSON(), nullable=False),
        sa.Column('enriched_risk_score', sa.Float(), nullable=False),
        sa.Column('risk_enrichment_factors', sa.JSON(), nullable=False),
        sa.Column('correlated_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default='1'),
        sa.Column('superseded_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['project_id'], ['projects.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['finding_id'], ['vulnerability_findings.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['threat_intel_id'], ['threat_intelligence_records.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('finding_id', 'threat_intel_id', name='uq_finding_threat_intel')
    )
    op.create_index('ix_threat_correlations_project_id', 'threat_correlations', ['project_id'])
    op.create_index('ix_threat_correlations_finding_id', 'threat_correlations', ['finding_id'])
    op.create_index('ix_threat_correlations_threat_intel_id', 'threat_correlations', ['threat_intel_id'])
    op.create_index('ix_threat_correlations_proj_class', 'threat_correlations', ['project_id', 'match_classification'])


def downgrade():
    op.drop_table('threat_correlations')
    op.drop_table('threat_intelligence_records')
    op.drop_table('threat_intel_feeds')
