"""prompt26_performance_indexes

Revision ID: e4f5a6b7c8d9
Revises: d3e4f5a6b7c8
Create Date: 2026-10-29 10:40:00.000000
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = 'e4f5a6b7c8d9'
down_revision: Union[str, None] = 'd3e4f5a6b7c8'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Composite indexes for high-throughput finding filters & timeline ordering
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_vulnerability_findings_proj_sev_status "
        "ON vulnerability_findings (project_id, severity, status)"
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_vulnerability_findings_proj_created "
        "ON vulnerability_findings (project_id, created_at)"
    )

    # 2. Composite indexes for asset inventory queries
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_assets_proj_criticality_status "
        "ON assets (project_id, criticality, status)"
    )

    # 3. Composite index for dead-worker lease scavenging & scheduler polling
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_assessment_jobs_status_heartbeat "
        "ON assessment_jobs (status, heartbeat_at)"
    )

    # 4. Composite index for graph edge traversal & multi-hop attack path search
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_graph_relationships_proj_src_tgt "
        "ON graph_relationships (project_id, source_node_id, target_node_id)"
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_graph_relationships_proj_src_tgt")
    op.execute("DROP INDEX IF EXISTS ix_assessment_jobs_status_heartbeat")
    op.execute("DROP INDEX IF EXISTS ix_assets_proj_criticality_status")
    op.execute("DROP INDEX IF EXISTS ix_vulnerability_findings_proj_created")
    op.execute("DROP INDEX IF EXISTS ix_vulnerability_findings_proj_sev_status")
