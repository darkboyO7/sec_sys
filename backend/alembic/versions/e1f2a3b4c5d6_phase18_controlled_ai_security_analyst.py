"""phase18_controlled_ai_security_analyst

Revision ID: e1f2a3b4c5d6
Revises: d0e1f2a3b4c5
Create Date: 2026-10-26 23:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa


revision: str = 'e1f2a3b4c5d6'
down_revision: Union[str, None] = 'd0e1f2a3b4c5'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'ai_analyst_drafts',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('project_id', sa.String(length=36), nullable=False),
        sa.Column('draft_type', sa.String(length=50), nullable=False),
        sa.Column('status', sa.String(length=50), nullable=False, server_default='DRAFT'),
        sa.Column('prompt_version', sa.String(length=32), nullable=False, server_default='v1.0.0'),
        sa.Column('model_identifier', sa.String(length=64), nullable=False),
        sa.Column('target_resource', sa.String(length=255), nullable=False),
        sa.Column('title', sa.String(length=255), nullable=False),
        sa.Column('summary', sa.Text(), nullable=False),
        sa.Column('content', sa.JSON(), nullable=False),
        sa.Column('citations', sa.JSON(), nullable=False),
        sa.Column('uncertainty_notes', sa.Text(), nullable=True),
        sa.Column('prompt_injection_flags', sa.JSON(), nullable=True),
        sa.Column('is_reviewed', sa.Boolean(), nullable=False, server_default=sa.text('0')),
        sa.Column('reviewed_by_id', sa.String(length=36), nullable=True),
        sa.Column('reviewed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('review_notes', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['project_id'], ['projects.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['reviewed_by_id'], ['users.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_ai_analyst_drafts_project_id', 'ai_analyst_drafts', ['project_id'], unique=False)
    op.create_index('ix_ai_analyst_drafts_draft_type', 'ai_analyst_drafts', ['draft_type'], unique=False)
    op.create_index('ix_ai_analyst_drafts_status', 'ai_analyst_drafts', ['status'], unique=False)
    op.create_index('ix_ai_analyst_drafts_target_resource', 'ai_analyst_drafts', ['target_resource'], unique=False)
    op.create_index('ix_ai_analyst_drafts_created_at', 'ai_analyst_drafts', ['created_at'], unique=False)


def downgrade() -> None:
    op.drop_index('ix_ai_analyst_drafts_created_at', table_name='ai_analyst_drafts')
    op.drop_index('ix_ai_analyst_drafts_target_resource', table_name='ai_analyst_drafts')
    op.drop_index('ix_ai_analyst_drafts_status', table_name='ai_analyst_drafts')
    op.drop_index('ix_ai_analyst_drafts_draft_type', table_name='ai_analyst_drafts')
    op.drop_index('ix_ai_analyst_drafts_project_id', table_name='ai_analyst_drafts')
    op.drop_table('ai_analyst_drafts')
