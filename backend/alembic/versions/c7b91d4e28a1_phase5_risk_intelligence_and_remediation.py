"""phase5_risk_intelligence_and_remediation

Revision ID: c7b91d4e28a1
Revises: 5cd23633bcb8
Create Date: 2026-10-25 11:15:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa


revision: str = 'c7b91d4e28a1'
down_revision: Union[str, None] = '5cd23633bcb8'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Create risk_assessments table
    op.create_table(
        'risk_assessments',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('project_id', sa.String(length=36), nullable=False),
        sa.Column('finding_id', sa.String(length=36), nullable=False),
        sa.Column('asset_id', sa.String(length=36), nullable=True),
        sa.Column('score', sa.Float(), nullable=False),
        sa.Column('priority', sa.Enum('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL', name='riskpriority'), nullable=False),
        sa.Column('scoring_version', sa.String(length=50), nullable=False),
        sa.Column('factor_breakdown', sa.JSON(), nullable=False),
        sa.Column('contributing_factors', sa.JSON(), nullable=False),
        sa.Column('missing_factors', sa.JSON(), nullable=False),
        sa.Column('evidence_references', sa.JSON(), nullable=False),
        sa.Column('input_snapshot', sa.JSON(), nullable=False),
        sa.Column('calculated_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('is_superseded', sa.Boolean(), nullable=False, default=False),
        sa.Column('superseded_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['project_id'], ['projects.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['finding_id'], ['vulnerability_findings.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['asset_id'], ['assets.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('risk_assessments', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_risk_assessments_project_id'), ['project_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_risk_assessments_finding_id'), ['finding_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_risk_assessments_asset_id'), ['asset_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_risk_assessments_score'), ['score'], unique=False)
        batch_op.create_index(batch_op.f('ix_risk_assessments_priority'), ['priority'], unique=False)
        batch_op.create_index(batch_op.f('ix_risk_assessments_is_superseded'), ['is_superseded'], unique=False)

    # 2. Create remediation_recommendations table
    op.create_table(
        'remediation_recommendations',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('project_id', sa.String(length=36), nullable=False),
        sa.Column('finding_id', sa.String(length=36), nullable=False),
        sa.Column('asset_id', sa.String(length=36), nullable=True),
        sa.Column('title', sa.String(length=255), nullable=False),
        sa.Column('action_type', sa.String(length=100), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('rationale', sa.Text(), nullable=False),
        sa.Column('qualitative_benefit', sa.Text(), nullable=False),
        sa.Column('estimated_risk_reduction', sa.Float(), nullable=True),
        sa.Column('prerequisites', sa.JSON(), nullable=False),
        sa.Column('operational_impact', sa.Text(), nullable=False),
        sa.Column('rollback_procedure', sa.Text(), nullable=False),
        sa.Column('verification_criteria', sa.Text(), nullable=False),
        sa.Column('verification_test_profile', sa.String(length=100), nullable=True),
        sa.Column('requires_approval', sa.Boolean(), nullable=False, default=True),
        sa.Column('approval_role', sa.String(length=50), nullable=False, default='LEAD'),
        sa.Column('status', sa.Enum('PENDING_REVIEW', 'APPROVED', 'DEFERRED', 'REJECTED', name='recommendationstatus'), nullable=False),
        sa.Column('reviewed_by_id', sa.String(length=36), nullable=True),
        sa.Column('reviewed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('review_notes', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['project_id'], ['projects.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['finding_id'], ['vulnerability_findings.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['asset_id'], ['assets.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['reviewed_by_id'], ['users.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('remediation_recommendations', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_remediation_recommendations_project_id'), ['project_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_remediation_recommendations_finding_id'), ['finding_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_remediation_recommendations_asset_id'), ['asset_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_remediation_recommendations_action_type'), ['action_type'], unique=False)
        batch_op.create_index(batch_op.f('ix_remediation_recommendations_status'), ['status'], unique=False)


def downgrade() -> None:
    with op.batch_alter_table('remediation_recommendations', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_remediation_recommendations_status'))
        batch_op.drop_index(batch_op.f('ix_remediation_recommendations_action_type'))
        batch_op.drop_index(batch_op.f('ix_remediation_recommendations_asset_id'))
        batch_op.drop_index(batch_op.f('ix_remediation_recommendations_finding_id'))
        batch_op.drop_index(batch_op.f('ix_remediation_recommendations_project_id'))
    op.drop_table('remediation_recommendations')

    with op.batch_alter_table('risk_assessments', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_risk_assessments_is_superseded'))
        batch_op.drop_index(batch_op.f('ix_risk_assessments_priority'))
        batch_op.drop_index(batch_op.f('ix_risk_assessments_score'))
        batch_op.drop_index(batch_op.f('ix_risk_assessments_asset_id'))
        batch_op.drop_index(batch_op.f('ix_risk_assessments_finding_id'))
        batch_op.drop_index(batch_op.f('ix_risk_assessments_project_id'))
    op.drop_table('risk_assessments')
