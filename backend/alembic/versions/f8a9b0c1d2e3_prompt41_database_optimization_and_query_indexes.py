"""prompt41 database optimization and query indexes

Revision ID: f8a9b0c1d2e3
Revises: e7f8a9b0c1d2
Create Date: 2026-10-29 22:15:00.000000

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'f8a9b0c1d2e3'
down_revision = 'e7f8a9b0c1d2'
branch_labels = None
depends_on = None


def upgrade():
    # Composite index for finding listing, sorting, and lifecycle filtering
    op.create_index(
        'ix_vf_proj_status_sev_lastobs',
        'vulnerability_findings',
        ['project_id', 'status', 'severity', 'last_observed_at'],
        unique=False,
    )

    # Composite index for asset inventory filtering and freshness status checks
    op.create_index(
        'ix_assets_proj_status_freshness',
        'assets',
        ['project_id', 'status', 'freshness_status'],
        unique=False,
    )

    # Composite index for finding evidence metadata projections without loading payloads
    op.create_index(
        'ix_finding_evidence_finding_type_obs',
        'finding_evidence',
        ['finding_id', 'evidence_type', 'observed_at'],
        unique=False,
    )

    # Composite index for connector health checks and scheduling lookups
    op.create_index(
        'ix_connector_configs_proj_health',
        'connector_configurations',
        ['project_id', 'last_health_status'],
        unique=False,
    )

    # Composite index for connector sync event chronological history
    op.create_index(
        'ix_connector_sync_events_conn_started',
        'connector_sync_events',
        ['connector_id', 'started_at'],
        unique=False,
    )


def downgrade():
    op.drop_index('ix_connector_sync_events_conn_started', table_name='connector_sync_events')
    op.drop_index('ix_connector_configs_proj_health', table_name='connector_configurations')
    op.drop_index('ix_finding_evidence_finding_type_obs', table_name='finding_evidence')
    op.drop_index('ix_assets_proj_status_freshness', table_name='assets')
    op.drop_index('ix_vf_proj_status_sev_lastobs', table_name='vulnerability_findings')
