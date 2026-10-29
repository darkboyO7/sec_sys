"""prompt40 secure integration framework and connector contracts

Revision ID: e7f8a9b0c1d2
Revises: d6e7f8a9b0c1
Create Date: 2026-10-29 21:50:00.000000

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'e7f8a9b0c1d2'
down_revision = 'd6e7f8a9b0c1'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'connector_configurations',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('project_id', sa.String(length=36), nullable=False),
        sa.Column('name', sa.String(length=100), nullable=False),
        sa.Column('provider_type', sa.String(length=50), nullable=False),
        sa.Column('version', sa.String(length=20), nullable=False),
        sa.Column('enabled', sa.Boolean(), nullable=False),
        sa.Column('capabilities', sa.JSON(), nullable=False),
        sa.Column('config_schema_version', sa.String(length=20), nullable=False),
        sa.Column('settings_masked', sa.JSON(), nullable=False),
        sa.Column('settings_encrypted', sa.Text(), nullable=True),
        sa.Column('rate_limit_per_minute', sa.Integer(), nullable=False),
        sa.Column('timeout_seconds', sa.Float(), nullable=False),
        sa.Column('max_retries', sa.Integer(), nullable=False),
        sa.Column('max_response_size_kb', sa.Integer(), nullable=False),
        sa.Column('last_sync_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_sync_watermark', sa.String(length=100), nullable=True),
        sa.Column('last_health_status', sa.String(length=30), nullable=False),
        sa.Column('last_health_message', sa.String(length=255), nullable=True),
        sa.Column('consecutive_failures', sa.Integer(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['project_id'], ['projects.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_connector_configs_project_id', 'connector_configurations', ['project_id'])
    op.create_index('ix_connector_configs_provider_type', 'connector_configurations', ['provider_type'])

    op.create_table(
        'connector_sync_events',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('connector_id', sa.String(length=36), nullable=False),
        sa.Column('project_id', sa.String(length=36), nullable=False),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('finished_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('status', sa.String(length=30), nullable=False),
        sa.Column('records_pulled', sa.Integer(), nullable=False),
        sa.Column('records_normalized', sa.Integer(), nullable=False),
        sa.Column('records_ingested', sa.Integer(), nullable=False),
        sa.Column('records_tombstoned', sa.Integer(), nullable=False),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('error_type', sa.String(length=50), nullable=True),
        sa.Column('raw_payload_digest', sa.String(length=64), nullable=True),
        sa.Column('sync_watermark', sa.String(length=100), nullable=True),
        sa.Column('execution_metadata', sa.JSON(), nullable=True),
        sa.ForeignKeyConstraint(['connector_id'], ['connector_configurations.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['project_id'], ['projects.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_connector_sync_events_connector_id', 'connector_sync_events', ['connector_id'])
    op.create_index('ix_connector_sync_events_project_id', 'connector_sync_events', ['project_id'])


def downgrade():
    op.drop_table('connector_sync_events')
    op.drop_table('connector_configurations')
