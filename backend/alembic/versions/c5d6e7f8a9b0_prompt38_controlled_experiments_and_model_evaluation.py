"""prompt38 controlled experiments model evaluation and defensible adaptive learning

Revision ID: c5d6e7f8a9b0
Revises: b4c5d6e7f8a9
Create Date: 2026-10-29 21:02:00.000000

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'c5d6e7f8a9b0'
down_revision = 'b4c5d6e7f8a9'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'model_controlled_experiments',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('project_id', sa.String(length=36), nullable=False),
        sa.Column('model_id', sa.String(length=36), nullable=False),
        sa.Column('dataset_id', sa.String(length=36), nullable=False),
        sa.Column('experiment_name', sa.String(length=255), nullable=False),
        sa.Column('split_strategy', sa.Enum('TEMPORAL_AWARE', 'STRATIFIED_HASH', 'CHRONOLOGICAL_WINDOW', name='splitstrategy'), nullable=False),
        sa.Column('training_sample_size', sa.Integer(), nullable=False),
        sa.Column('test_sample_size', sa.Integer(), nullable=False),
        sa.Column('class_imbalance_ratio', sa.Float(), nullable=False),
        sa.Column('temporal_range_start', sa.DateTime(timezone=True), nullable=True),
        sa.Column('temporal_range_end', sa.DateTime(timezone=True), nullable=True),
        sa.Column('data_leakage_detected', sa.Boolean(), nullable=False),
        sa.Column('leakage_details', sa.JSON(), nullable=False),
        sa.Column('insufficient_data_flag', sa.Boolean(), nullable=False),
        sa.Column('baseline_model_id', sa.String(length=36), nullable=True),
        sa.Column('metrics', sa.JSON(), nullable=False),
        sa.Column('distribution_shift_detected', sa.Boolean(), nullable=False),
        sa.Column('decision_outcome', sa.Enum('ACCEPTED', 'REJECTED_INFERIOR_METRICS', 'REJECTED_LEAKAGE', 'REJECTED_INSUFFICIENT_DATA', 'PENDING_REVIEW', name='experimentdecision'), nullable=False),
        sa.Column('decision_rationale', sa.Text(), nullable=True),
        sa.Column('evaluated_by_id', sa.String(length=36), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['project_id'], ['projects.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['model_id'], ['governed_models.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['dataset_id'], ['learning_datasets.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['baseline_model_id'], ['governed_models.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['evaluated_by_id'], ['users.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_model_exp_proj_decision', 'model_controlled_experiments', ['project_id', 'decision_outcome'])
    op.create_index('ix_model_exp_model_id', 'model_controlled_experiments', ['model_id'])
    op.create_index('ix_model_exp_dataset_id', 'model_controlled_experiments', ['dataset_id'])


def downgrade():
    op.drop_table('model_controlled_experiments')
