"""phase15_reporting_and_export

Revision ID: b8c9d0e1f2a3
Revises: a7b8c9d0e1f2
Create Date: 2026-10-26 20:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa


revision: str = 'b8c9d0e1f2a3'
down_revision: Union[str, None] = 'a7b8c9d0e1f2'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'report_records',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('project_id', sa.String(length=36), nullable=False),
        sa.Column('report_type', sa.String(length=50), nullable=False),
        sa.Column('report_format', sa.String(length=50), nullable=False),
        sa.Column('title', sa.String(length=255), nullable=False),
        sa.Column('generated_by_id', sa.String(length=36), nullable=True),
        sa.Column('report_sha256', sa.String(length=64), nullable=False),
        sa.Column('item_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('content_bytes', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('generated_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['project_id'], ['projects.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['generated_by_id'], ['users.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_report_records_project_id', 'report_records', ['project_id'], unique=False)
    op.create_index('ix_report_records_report_type', 'report_records', ['report_type'], unique=False)
    op.create_index('ix_report_records_report_format', 'report_records', ['report_format'], unique=False)
    op.create_index('ix_report_records_generated_by_id', 'report_records', ['generated_by_id'], unique=False)
    op.create_index('ix_report_records_report_sha256', 'report_records', ['report_sha256'], unique=False)


def downgrade() -> None:
    op.drop_index('ix_report_records_report_sha256', table_name='report_records')
    op.drop_index('ix_report_records_generated_by_id', table_name='report_records')
    op.drop_index('ix_report_records_report_format', table_name='report_records')
    op.drop_index('ix_report_records_report_type', table_name='report_records')
    op.drop_index('ix_report_records_project_id', table_name='report_records')
    op.drop_table('report_records')
