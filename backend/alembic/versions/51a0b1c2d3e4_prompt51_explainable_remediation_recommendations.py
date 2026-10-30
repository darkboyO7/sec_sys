"""prompt51_explainable_remediation_recommendations

Revision ID: 51a0b1c2d3e4
Revises: f0a1b2c3d4e5
Create Date: 2026-10-30 18:30:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '51a0b1c2d3e4'
down_revision: Union[str, None] = 'f0a1b2c3d4e5'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Alter remediation_recommendations table
    with op.batch_alter_table('remediation_recommendations', schema=None) as batch_op:
        batch_op.add_column(sa.Column('guidance_type', sa.String(length=50), nullable=False, server_default='VERIFIED_INSTRUCTION'))
        batch_op.add_column(sa.Column('technical_severity', sa.String(length=50), nullable=False, server_default='MEDIUM'))
        batch_op.add_column(sa.Column('business_priority', sa.String(length=50), nullable=False, server_default='P3_MEDIUM'))
        batch_op.add_column(sa.Column('confidence', sa.Float(), nullable=False, server_default='1.0'))
        batch_op.add_column(sa.Column('remediation_urgency', sa.String(length=50), nullable=False, server_default='SCHEDULED_SPRINT'))
        batch_op.add_column(sa.Column('source_evidence_ids', sa.JSON(), nullable=False, server_default='[]'))
        batch_op.add_column(sa.Column('ranking_factors', sa.JSON(), nullable=False, server_default='{}'))
        batch_op.add_column(sa.Column('advisory_disclaimer', sa.Text(), nullable=False, server_default=''))
        batch_op.add_column(sa.Column('missing_prerequisites', sa.JSON(), nullable=False, server_default='[]'))
        batch_op.add_column(sa.Column('compatibility_concerns', sa.JSON(), nullable=False, server_default='[]'))
        batch_op.add_column(sa.Column('dependencies', sa.JSON(), nullable=False, server_default='[]'))
        batch_op.add_column(sa.Column('version', sa.Integer(), nullable=False, server_default='1'))
        batch_op.add_column(sa.Column('prior_version_id', sa.String(length=36), nullable=True))
        batch_op.add_column(sa.Column('is_latest', sa.Boolean(), nullable=False, server_default=sa.true()))
        batch_op.add_column(sa.Column('superseded_at', sa.DateTime(timezone=True), nullable=True))
        batch_op.add_column(sa.Column('verification_id', sa.String(length=36), nullable=True))
        batch_op.add_column(sa.Column('verified_outcome', sa.String(length=50), nullable=True))
        batch_op.create_foreign_key('fk_remediation_rec_prior_version', 'remediation_recommendations', ['prior_version_id'], ['id'], ondelete='SET NULL')
        batch_op.create_foreign_key('fk_remediation_rec_verification', 'remediation_verifications', ['verification_id'], ['id'], ondelete='SET NULL')
        batch_op.create_index('ix_remediation_rec_latest', ['project_id', 'is_latest'])
        batch_op.create_index('ix_remediation_rec_guidance_type', ['guidance_type'])
        batch_op.create_index('ix_remediation_rec_business_priority', ['business_priority'])

    # 2. Create recommendation_feedback table
    op.create_table(
        'recommendation_feedback',
        sa.Column('id', sa.String(length=36), primary_key=True, nullable=False),
        sa.Column('project_id', sa.String(length=36), sa.ForeignKey('projects.id', ondelete='CASCADE'), nullable=False),
        sa.Column('recommendation_id', sa.String(length=36), sa.ForeignKey('remediation_recommendations.id', ondelete='CASCADE'), nullable=False),
        sa.Column('user_id', sa.String(length=36), sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True),
        sa.Column('feedback_type', sa.String(length=50), nullable=False),
        sa.Column('rating', sa.Integer(), nullable=True),
        sa.Column('comment', sa.Text(), nullable=True),
        sa.Column('was_actionable', sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column('applied_as_instructed', sa.Boolean(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index('ix_rec_feedback_project_id', 'recommendation_feedback', ['project_id'])
    op.create_index('ix_rec_feedback_recommendation_id', 'recommendation_feedback', ['recommendation_id'])
    op.create_index('ix_rec_feedback_user_id', 'recommendation_feedback', ['user_id'])
    op.create_index('ix_rec_feedback_feedback_type', 'recommendation_feedback', ['feedback_type'])


def downgrade() -> None:
    op.drop_table('recommendation_feedback')
    with op.batch_alter_table('remediation_recommendations', schema=None) as batch_op:
        batch_op.drop_index('ix_remediation_rec_business_priority')
        batch_op.drop_index('ix_remediation_rec_guidance_type')
        batch_op.drop_index('ix_remediation_rec_latest')
        batch_op.drop_constraint('fk_remediation_rec_verification', type_='foreignkey')
        batch_op.drop_constraint('fk_remediation_rec_prior_version', type_='foreignkey')
        batch_op.drop_column('verified_outcome')
        batch_op.drop_column('verification_id')
        batch_op.drop_column('superseded_at')
        batch_op.drop_column('is_latest')
        batch_op.drop_column('prior_version_id')
        batch_op.drop_column('version')
        batch_op.drop_column('dependencies')
        batch_op.drop_column('compatibility_concerns')
        batch_op.drop_column('missing_prerequisites')
        batch_op.drop_column('advisory_disclaimer')
        batch_op.drop_column('ranking_factors')
        batch_op.drop_column('source_evidence_ids')
        batch_op.drop_column('remediation_urgency')
        batch_op.drop_column('confidence')
        batch_op.drop_column('business_priority')
        batch_op.drop_column('technical_severity')
        batch_op.drop_column('guidance_type')
