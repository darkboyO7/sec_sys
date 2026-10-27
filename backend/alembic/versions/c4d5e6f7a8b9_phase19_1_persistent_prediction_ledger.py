"""phase19_1_persistent_prediction_ledger

Revision ID: c4d5e6f7a8b9
Revises: b3c4d5e6f7a8
Create Date: 2026-10-27 17:40:00.000000

"""
from typing import Sequence, Union
from alembic import op, context
import sqlalchemy as sa


revision: str = 'c4d5e6f7a8b9'
down_revision: Union[str, None] = 'b3c4d5e6f7a8'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    prediction_type_enum = sa.Enum(
        'FALSE_POSITIVE_LIKELIHOOD',
        'EXPLOITATION_PROBABILITY',
        'REMEDIATION_EFFORT_HOURS',
        'RISK_SCORE_FORECAST',
        'ATTACK_PATH_REACHABILITY',
        name='predictiontype',
    )
    eval_status_enum = sa.Enum(
        'PENDING',
        'VERIFIED_ACCURATE',
        'VERIFIED_INACCURATE',
        'INCONCLUSIVE',
        'EXPIRED',
        'INVALIDATED',
        name='predictionevaluationstatus',
    )

    op.create_table(
        'prediction_ledger',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('project_id', sa.String(length=36), nullable=False),
        sa.Column('model_id', sa.String(length=36), nullable=True),
        sa.Column('model_version', sa.String(length=32), nullable=False),
        sa.Column('rule_version', sa.String(length=32), nullable=True),
        sa.Column('target_entity_type', sa.String(length=50), nullable=False),
        sa.Column('target_entity_id', sa.String(length=36), nullable=False),
        sa.Column('prediction_type', prediction_type_enum, nullable=False),
        sa.Column('feature_snapshot', sa.JSON(), nullable=False),
        sa.Column('predicted_outcome', sa.String(length=255), nullable=False),
        sa.Column('confidence_score', sa.Float(), nullable=False),
        sa.Column('limitations', sa.Text(), nullable=True),
        sa.Column('decision_action_taken', sa.String(length=255), nullable=True),
        sa.Column('expected_evaluation_horizon', sa.DateTime(timezone=True), nullable=True),
        sa.Column('actual_outcome', sa.String(length=255), nullable=True),
        sa.Column('outcome_evidence', sa.JSON(), nullable=True),
        sa.Column('evaluation_status', eval_status_enum, nullable=False),
        sa.Column('invalidation_reason', sa.Text(), nullable=True),
        sa.Column('evaluated_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('evaluated_by_id', sa.String(length=36), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['project_id'], ['projects.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['model_id'], ['governed_models.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['evaluated_by_id'], ['users.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
    )

    op.create_index('ix_prediction_ledger_project_id', 'prediction_ledger', ['project_id'], unique=False)
    op.create_index('ix_prediction_ledger_model_id', 'prediction_ledger', ['model_id'], unique=False)
    op.create_index('ix_prediction_ledger_target', 'prediction_ledger', ['target_entity_type', 'target_entity_id'], unique=False)
    op.create_index('ix_prediction_ledger_evaluation_status', 'prediction_ledger', ['evaluation_status'], unique=False)
    op.create_index('ix_prediction_ledger_created_at', 'prediction_ledger', ['created_at'], unique=False)


def downgrade() -> None:
    op.drop_index('ix_prediction_ledger_created_at', table_name='prediction_ledger')
    op.drop_index('ix_prediction_ledger_evaluation_status', table_name='prediction_ledger')
    op.drop_index('ix_prediction_ledger_target', table_name='prediction_ledger')
    op.drop_index('ix_prediction_ledger_model_id', table_name='prediction_ledger')
    op.drop_index('ix_prediction_ledger_project_id', table_name='prediction_ledger')
    op.drop_table('prediction_ledger')
