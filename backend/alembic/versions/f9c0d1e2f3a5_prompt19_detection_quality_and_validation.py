"""prompt19_detection_quality_and_validation

Revision ID: f9c0d1e2f3a5
Revises: b9c0d1e2f3a4
Create Date: 2026-10-28 22:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa


revision: str = 'f9c0d1e2f3a5'
down_revision: Union[str, None] = 'b9c0d1e2f3a4'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    conn = op.get_bind()
    insp = sa.inspect(conn)
    existing_tables = insp.get_table_names()

    # 1. Add validation status and provenance columns to vulnerability_findings
    vf_cols = [c["name"] for c in insp.get_columns("vulnerability_findings")] if "vulnerability_findings" in existing_tables else []

    with op.batch_alter_table('vulnerability_findings', schema=None) as batch_op:
        if 'validation_status' not in vf_cols:
            batch_op.add_column(
                sa.Column(
                    'validation_status',
                    sa.String(length=50),
                    nullable=False,
                    server_default='DETECTED',
                )
            )
        if 'validation_method' not in vf_cols:
            batch_op.add_column(sa.Column('validation_method', sa.String(length=50), nullable=True))
        if 'validation_evidence_ref' not in vf_cols:
            batch_op.add_column(sa.Column('validation_evidence_ref', sa.String(length=64), nullable=True))
        if 'validation_notes' not in vf_cols:
            batch_op.add_column(sa.Column('validation_notes', sa.Text(), nullable=True))
        if 'validation_updated_at' not in vf_cols:
            batch_op.add_column(
                sa.Column(
                    'validation_updated_at',
                    sa.DateTime(timezone=True),
                    nullable=True,
                )
            )

    # 2. Create finding_validation_transitions table if not exists
    if 'finding_validation_transitions' not in existing_tables:
        op.create_table(
            'finding_validation_transitions',
            sa.Column('id', sa.String(length=36), primary_key=True),
            sa.Column('finding_id', sa.String(length=36), sa.ForeignKey('vulnerability_findings.id', ondelete='CASCADE'), nullable=False),
            sa.Column('from_status', sa.String(length=50), nullable=False),
            sa.Column('to_status', sa.String(length=50), nullable=False),
            sa.Column('validation_method', sa.String(length=50), nullable=False),
            sa.Column('actor_id', sa.String(length=36), sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True),
            sa.Column('reason', sa.Text(), nullable=False),
            sa.Column('evidence_ref', sa.String(length=64), nullable=True),
            sa.Column('metadata_snapshot', sa.JSON(), nullable=False, server_default='{}'),
            sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        )
        op.create_index('ix_validation_transitions_finding_id', 'finding_validation_transitions', ['finding_id'])


def downgrade() -> None:
    op.drop_index('ix_validation_transitions_finding_id', table_name='finding_validation_transitions')
    op.drop_table('finding_validation_transitions')

    with op.batch_alter_table('vulnerability_findings', schema=None) as batch_op:
        batch_op.drop_index('ix_vulnerability_findings_validation_status')
        batch_op.drop_column('validation_updated_at')
        batch_op.drop_column('validation_notes')
        batch_op.drop_column('validation_evidence_ref')
        batch_op.drop_column('validation_method')
        batch_op.drop_column('validation_status')
