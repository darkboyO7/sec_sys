"""phase14_independent_remediation_verification

Revision ID: a7b8c9d0e1f2
Revises: f6a7b8c9d0e1
Create Date: 2026-10-26 19:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa


revision: str = 'a7b8c9d0e1f2'
down_revision: Union[str, None] = 'f6a7b8c9d0e1'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'remediation_verifications',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('project_id', sa.String(length=36), nullable=False),
        sa.Column('finding_id', sa.String(length=36), nullable=False),
        sa.Column('recommendation_id', sa.String(length=36), nullable=True),
        sa.Column('verifier_id', sa.String(length=36), nullable=True),
        sa.Column('verification_method', sa.String(length=50), nullable=False, server_default='PASSIVE_SCAN'),
        sa.Column('outcome', sa.String(length=50), nullable=False),
        sa.Column('verification_criteria', sa.Text(), nullable=False),
        sa.Column('baseline_evidence_hash', sa.String(length=64), nullable=True),
        sa.Column('verification_evidence_summary', sa.Text(), nullable=False),
        sa.Column('verification_evidence_data', sa.JSON(), nullable=False, server_default='{}'),
        sa.Column('notes', sa.Text(), nullable=False),
        sa.Column('verified_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['project_id'], ['projects.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['finding_id'], ['vulnerability_findings.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['recommendation_id'], ['remediation_recommendations.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['verifier_id'], ['users.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_remediation_verifications_project_id', 'remediation_verifications', ['project_id'], unique=False)
    op.create_index('ix_remediation_verifications_finding_id', 'remediation_verifications', ['finding_id'], unique=False)
    op.create_index('ix_remediation_verifications_recommendation_id', 'remediation_verifications', ['recommendation_id'], unique=False)
    op.create_index('ix_remediation_verifications_verifier_id', 'remediation_verifications', ['verifier_id'], unique=False)
    op.create_index('ix_remediation_verifications_outcome', 'remediation_verifications', ['outcome'], unique=False)


def downgrade() -> None:
    op.drop_index('ix_remediation_verifications_outcome', table_name='remediation_verifications')
    op.drop_index('ix_remediation_verifications_verifier_id', table_name='remediation_verifications')
    op.drop_index('ix_remediation_verifications_recommendation_id', table_name='remediation_verifications')
    op.drop_index('ix_remediation_verifications_finding_id', table_name='remediation_verifications')
    op.drop_index('ix_remediation_verifications_project_id', table_name='remediation_verifications')
    op.drop_table('remediation_verifications')
