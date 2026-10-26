"""phase19_controlled_learning_and_model_governance

Revision ID: f1a2b3c4d5e6
Revises: e1f2a3b4c5d6
Create Date: 2026-10-27 00:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa


revision: str = 'f1a2b3c4d5e6'
down_revision: Union[str, None] = 'e1f2a3b4c5d6'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'learning_datasets',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('project_id', sa.String(length=36), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('version', sa.String(length=32), nullable=False),
        sa.Column('dataset_hash', sa.String(length=64), nullable=False),
        sa.Column('total_records', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('train_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('val_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('test_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('created_by_id', sa.String(length=36), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['project_id'], ['projects.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['created_by_id'], ['users.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_learning_datasets_project_id', 'learning_datasets', ['project_id'], unique=False)
    op.create_index('ix_learning_datasets_dataset_hash', 'learning_datasets', ['dataset_hash'], unique=False)
    op.create_index('ix_learning_datasets_created_at', 'learning_datasets', ['created_at'], unique=False)

    op.create_table(
        'dataset_records',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('dataset_id', sa.String(length=36), nullable=False),
        sa.Column('split', sa.String(length=20), nullable=False),
        sa.Column('source_entity_type', sa.String(length=50), nullable=False),
        sa.Column('source_entity_id', sa.String(length=36), nullable=False),
        sa.Column('features', sa.JSON(), nullable=False),
        sa.Column('label', sa.String(length=50), nullable=False),
        sa.Column('provenance_digest', sa.String(length=64), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['dataset_id'], ['learning_datasets.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_dataset_records_dataset_id', 'dataset_records', ['dataset_id'], unique=False)
    op.create_index('ix_dataset_records_split', 'dataset_records', ['split'], unique=False)
    op.create_index('ix_dataset_records_source_entity_id', 'dataset_records', ['source_entity_id'], unique=False)
    op.create_index('ix_dataset_records_label', 'dataset_records', ['label'], unique=False)

    op.create_table(
        'governed_models',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('project_id', sa.String(length=36), nullable=False),
        sa.Column('model_name', sa.String(length=100), nullable=False),
        sa.Column('version', sa.String(length=32), nullable=False),
        sa.Column('model_type', sa.String(length=50), nullable=False),
        sa.Column('status', sa.String(length=30), nullable=False, server_default='CANDIDATE'),
        sa.Column('dataset_id', sa.String(length=36), nullable=False),
        sa.Column('metrics', sa.JSON(), nullable=False),
        sa.Column('hyperparameters', sa.JSON(), nullable=False),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default=sa.text('0')),
        sa.Column('activated_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('approved_by_id', sa.String(length=36), nullable=True),
        sa.Column('approved_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('approval_notes', sa.Text(), nullable=True),
        sa.Column('rollback_target_id', sa.String(length=36), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['project_id'], ['projects.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['dataset_id'], ['learning_datasets.id'], ondelete='RESTRICT'),
        sa.ForeignKeyConstraint(['approved_by_id'], ['users.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['rollback_target_id'], ['governed_models.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_governed_models_project_id', 'governed_models', ['project_id'], unique=False)
    op.create_index('ix_governed_models_model_name', 'governed_models', ['model_name'], unique=False)
    op.create_index('ix_governed_models_status', 'governed_models', ['status'], unique=False)
    op.create_index('ix_governed_models_dataset_id', 'governed_models', ['dataset_id'], unique=False)
    op.create_index('ix_governed_models_is_active', 'governed_models', ['is_active'], unique=False)
    op.create_index('ix_governed_models_created_at', 'governed_models', ['created_at'], unique=False)


def downgrade() -> None:
    op.drop_index('ix_governed_models_created_at', table_name='governed_models')
    op.drop_index('ix_governed_models_is_active', table_name='governed_models')
    op.drop_index('ix_governed_models_dataset_id', table_name='governed_models')
    op.drop_index('ix_governed_models_status', table_name='governed_models')
    op.drop_index('ix_governed_models_model_name', table_name='governed_models')
    op.drop_index('ix_governed_models_project_id', table_name='governed_models')
    op.drop_table('governed_models')

    op.drop_index('ix_dataset_records_label', table_name='dataset_records')
    op.drop_index('ix_dataset_records_source_entity_id', table_name='dataset_records')
    op.drop_index('ix_dataset_records_split', table_name='dataset_records')
    op.drop_index('ix_dataset_records_dataset_id', table_name='dataset_records')
    op.drop_table('dataset_records')

    op.drop_index('ix_learning_datasets_created_at', table_name='learning_datasets')
    op.drop_index('ix_learning_datasets_dataset_hash', table_name='learning_datasets')
    op.drop_index('ix_learning_datasets_project_id', table_name='learning_datasets')
    op.drop_table('learning_datasets')
