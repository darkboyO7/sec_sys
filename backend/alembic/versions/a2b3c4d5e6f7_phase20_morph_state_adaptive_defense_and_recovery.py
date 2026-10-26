"""phase20_morph_state_adaptive_defense_and_recovery

Revision ID: a2b3c4d5e6f7
Revises: f1a2b3c4d5e6
Create Date: 2026-10-27 01:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa


revision: str = 'a2b3c4d5e6f7'
down_revision: Union[str, None] = 'f1a2b3c4d5e6'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'morph_state_postures',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('project_id', sa.String(length=36), nullable=False),
        sa.Column('current_state', sa.String(length=50), nullable=False, server_default='NORMAL'),
        sa.Column('previous_state', sa.String(length=50), nullable=True),
        sa.Column('state_version', sa.Integer(), nullable=False, server_default='1'),
        sa.Column('kill_switch_active', sa.Boolean(), nullable=False, server_default=sa.text('0')),
        sa.Column('kill_switch_engaged_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('kill_switch_engaged_by_id', sa.String(length=36), nullable=True),
        sa.Column('kill_switch_reason', sa.Text(), nullable=True),
        sa.Column('monitoring_cadence_multiplier', sa.Float(), nullable=False, server_default='1.0'),
        sa.Column('active_recommendations', sa.JSON(), nullable=False),
        sa.Column('recovery_prerequisites', sa.JSON(), nullable=False),
        sa.Column('last_transition_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('last_evaluated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['project_id'], ['projects.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['kill_switch_engaged_by_id'], ['users.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_morph_state_postures_project_id', 'morph_state_postures', ['project_id'], unique=True)
    op.create_index('ix_morph_state_postures_current_state', 'morph_state_postures', ['current_state'], unique=False)
    op.create_index('ix_morph_state_postures_kill_switch_active', 'morph_state_postures', ['kill_switch_active'], unique=False)

    op.create_table(
        'morph_state_histories',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('posture_id', sa.String(length=36), nullable=False),
        sa.Column('from_state', sa.String(length=50), nullable=False),
        sa.Column('to_state', sa.String(length=50), nullable=False),
        sa.Column('trigger', sa.String(length=50), nullable=False),
        sa.Column('evidence_rationale', sa.Text(), nullable=False),
        sa.Column('triggered_by_id', sa.String(length=36), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['posture_id'], ['morph_state_postures.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['triggered_by_id'], ['users.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_morph_state_histories_posture_id', 'morph_state_histories', ['posture_id'], unique=False)
    op.create_index('ix_morph_state_histories_created_at', 'morph_state_histories', ['created_at'], unique=False)


def downgrade() -> None:
    op.drop_index('ix_morph_state_histories_created_at', table_name='morph_state_histories')
    op.drop_index('ix_morph_state_histories_posture_id', table_name='morph_state_histories')
    op.drop_table('morph_state_histories')

    op.drop_index('ix_morph_state_postures_kill_switch_active', table_name='morph_state_postures')
    op.drop_index('ix_morph_state_postures_current_state', table_name='morph_state_postures')
    op.drop_index('ix_morph_state_postures_project_id', table_name='morph_state_postures')
    op.drop_table('morph_state_postures')
