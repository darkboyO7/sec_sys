"""phase23_performance_indexes_and_resource_governance

Revision ID: b3c4d5e6f7a8
Revises: a2b3c4d5e6f7
Create Date: 2026-10-27 02:00:00.000000

"""
from typing import Sequence, Union
from alembic import op, context
import sqlalchemy as sa


revision: str = 'b3c4d5e6f7a8'
down_revision: Union[str, None] = 'a2b3c4d5e6f7'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    if context.is_offline_mode():
        op.create_index('ix_assessment_jobs_project_status_created', 'assessment_jobs', ['project_id', 'status', 'created_at'], unique=False)
        op.create_index('ix_assessment_findings_project_severity', 'assessment_findings', ['project_id', 'severity'], unique=False)
        op.create_index('ix_audit_events_project_timestamp', 'audit_events', ['project_id', 'timestamp'], unique=False)
        op.create_index('ix_regression_alerts_project_status_severity', 'regression_alerts', ['project_id', 'status', 'severity'], unique=False)
        return

    conn = op.get_bind()
    inspector = sa.inspect(conn)

    def safe_create_index(name: str, table: str, columns: list):
        existing = [idx['name'] for idx in inspector.get_indexes(table)]
        if name not in existing:
            op.create_index(name, table, columns, unique=False)

    # 1. Hot query index for assessment job queue monitoring and history
    safe_create_index(
        'ix_assessment_jobs_project_status_created',
        'assessment_jobs',
        ['project_id', 'status', 'created_at'],
    )

    # 2. Hot query index for finding triage by project and severity
    safe_create_index(
        'ix_assessment_findings_project_severity',
        'assessment_findings',
        ['project_id', 'severity'],
    )

    # 3. Hot query index for chronological audit timeline queries
    safe_create_index(
        'ix_audit_events_project_timestamp',
        'audit_events',
        ['project_id', 'timestamp'],
    )

    # 4. Hot query index for active regression alerts by severity
    safe_create_index(
        'ix_regression_alerts_project_status_severity',
        'regression_alerts',
        ['project_id', 'status', 'severity'],
    )


def downgrade() -> None:
    if context.is_offline_mode():
        op.drop_index('ix_regression_alerts_project_status_severity', table_name='regression_alerts')
        op.drop_index('ix_audit_events_project_timestamp', table_name='audit_events')
        op.drop_index('ix_assessment_findings_project_severity', table_name='assessment_findings')
        op.drop_index('ix_assessment_jobs_project_status_created', table_name='assessment_jobs')
        return

    conn = op.get_bind()
    inspector = sa.inspect(conn)

    def safe_drop_index(name: str, table: str):
        existing = [idx['name'] for idx in inspector.get_indexes(table)]
        if name in existing:
            op.drop_index(name, table_name=table)

    safe_drop_index('ix_regression_alerts_project_status_severity', table='regression_alerts')
    safe_drop_index('ix_audit_events_project_timestamp', table='audit_events')
    safe_drop_index('ix_assessment_findings_project_severity', table='assessment_findings')
    safe_drop_index('ix_assessment_jobs_project_status_created', table='assessment_jobs')
