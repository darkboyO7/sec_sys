"""prompt10_adaptive_assessment_plans

Revision ID: e6f7a8b9c0d1
Revises: c4d5e6f7a8b9
Create Date: 2026-10-28 14:00:00.000000

"""
from typing import Sequence, Union
from alembic import op, context
import sqlalchemy as sa


revision: str = 'e6f7a8b9c0d1'
down_revision: Union[str, None] = 'c4d5e6f7a8b9'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    plan_status_enum = sa.Enum(
        'GENERATED',
        'PARTIALLY_EXECUTED',
        'COMPLETED',
        'SUPERSEDED',
        'CANCELLED',
        name='planstatus',
    )

    op.create_table(
        'adaptive_assessment_plans',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('project_id', sa.String(length=36), nullable=False),
        sa.Column('plan_name', sa.String(length=255), nullable=False),
        sa.Column('status', plan_status_enum, nullable=False),
        sa.Column('scan_budget', sa.Integer(), nullable=False, server_default='10'),
        sa.Column('total_recommended', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('total_skipped', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('recommended_checks', sa.JSON(), nullable=False),
        sa.Column('skipped_checks', sa.JSON(), nullable=False),
        sa.Column('execution_summary', sa.JSON(), nullable=False),
        sa.Column('created_by_id', sa.String(length=36), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['created_by_id'], ['users.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['project_id'], ['projects.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )

    op.create_index(
        'ix_adaptive_plans_project_status',
        'adaptive_assessment_plans',
        ['project_id', 'status'],
        unique=False,
    )
    op.create_index(
        op.f('ix_adaptive_assessment_plans_project_id'),
        'adaptive_assessment_plans',
        ['project_id'],
        unique=False,
    )
    op.create_index(
        op.f('ix_adaptive_assessment_plans_status'),
        'adaptive_assessment_plans',
        ['status'],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(op.f('ix_adaptive_assessment_plans_status'), table_name='adaptive_assessment_plans')
    op.drop_index(op.f('ix_adaptive_assessment_plans_project_id'), table_name='adaptive_assessment_plans')
    op.drop_index('ix_adaptive_plans_project_status', table_name='adaptive_assessment_plans')
    op.drop_table('adaptive_assessment_plans')
