"""prompt22_governance_and_isolation

Revision ID: c2d3e4f5a6b7
Revises: b1c2d3e4f5a6
Create Date: 2026-10-28 23:45:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa


revision: str = 'c2d3e4f5a6b7'
down_revision: Union[str, None] = 'b1c2d3e4f5a6'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    conn = op.get_bind()
    insp = sa.inspect(conn)
    existing_tables = insp.get_table_names()

    # 1. Create table project_governance_policies
    if 'project_governance_policies' not in existing_tables:
        op.create_table(
            'project_governance_policies',
            sa.Column('id', sa.String(length=36), primary_key=True),
            sa.Column('project_id', sa.String(length=36), sa.ForeignKey('projects.id', ondelete='CASCADE'), nullable=False),
            sa.Column('enforce_separation_of_duties', sa.Boolean(), nullable=False, server_default='1'),
            sa.Column('allow_self_approval_override', sa.Boolean(), nullable=False, server_default='0'),
            sa.Column('require_two_person_rule_for_purge', sa.Boolean(), nullable=False, server_default='1'),
            sa.Column('require_lead_for_scope_authorization', sa.Boolean(), nullable=False, server_default='1'),
            sa.Column('require_lead_for_risk_acceptance', sa.Boolean(), nullable=False, server_default='1'),
            sa.Column('require_lead_for_remediation_approval', sa.Boolean(), nullable=False, server_default='1'),
            sa.Column('require_lead_for_model_promotion', sa.Boolean(), nullable=False, server_default='1'),
            sa.Column('policy_version', sa.String(length=50), nullable=False, server_default='v2026.2.0'),
            sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
            sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        )
        op.create_index('ix_project_gov_policies_project_id', 'project_governance_policies', ['project_id'], unique=True)

    # 2. Create table approval_request_records
    if 'approval_request_records' not in existing_tables:
        op.create_table(
            'approval_request_records',
            sa.Column('id', sa.String(length=36), primary_key=True),
            sa.Column('project_id', sa.String(length=36), sa.ForeignKey('projects.id', ondelete='CASCADE'), nullable=False),
            sa.Column('workflow_type', sa.String(length=50), nullable=False),
            sa.Column('resource_type', sa.String(length=100), nullable=False),
            sa.Column('resource_id', sa.String(length=255), nullable=False),
            sa.Column('status', sa.String(length=50), nullable=False, server_default='PENDING'),
            sa.Column('title', sa.String(length=255), nullable=False),
            sa.Column('description', sa.Text(), nullable=True),
            sa.Column('parameter_hash', sa.String(length=64), nullable=False),
            sa.Column('parameters_snapshot', sa.JSON(), nullable=False),
            sa.Column('requester_id', sa.String(length=36), sa.ForeignKey('users.id', ondelete='RESTRICT'), nullable=False),
            sa.Column('approver_id', sa.String(length=36), sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True),
            sa.Column('executed_by_id', sa.String(length=36), sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True),
            sa.Column('requested_at', sa.DateTime(timezone=True), nullable=False),
            sa.Column('decided_at', sa.DateTime(timezone=True), nullable=True),
            sa.Column('executed_at', sa.DateTime(timezone=True), nullable=True),
            sa.Column('invalidated_at', sa.DateTime(timezone=True), nullable=True),
            sa.Column('decision_reason', sa.Text(), nullable=True),
            sa.Column('invalidation_reason', sa.Text(), nullable=True),
            sa.Column('policy_version', sa.String(length=50), nullable=False, server_default='v2026.2.0'),
            sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
            sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        )
        op.create_index('ix_approval_project_workflow_status', 'approval_request_records', ['project_id', 'workflow_type', 'status'])
        op.create_index('ix_approval_resource_lookup', 'approval_request_records', ['project_id', 'resource_type', 'resource_id'])
        op.create_index('ix_approval_param_hash', 'approval_request_records', ['parameter_hash'])


def downgrade() -> None:
    conn = op.get_bind()
    insp = sa.inspect(conn)
    existing_tables = insp.get_table_names()

    if 'approval_request_records' in existing_tables:
        op.drop_table('approval_request_records')

    if 'project_governance_policies' in existing_tables:
        op.drop_table('project_governance_policies')
