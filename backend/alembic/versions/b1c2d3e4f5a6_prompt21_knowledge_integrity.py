"""prompt21_knowledge_integrity

Revision ID: b1c2d3e4f5a6
Revises: a0b1c2d3e4f5
Create Date: 2026-10-28 23:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa


revision: str = 'b1c2d3e4f5a6'
down_revision: Union[str, None] = 'a0b1c2d3e4f5'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    conn = op.get_bind()
    insp = sa.inspect(conn)
    existing_tables = insp.get_table_names()

    # 1. Add columns to graph_nodes
    if 'graph_nodes' in existing_tables:
        node_cols = [c["name"] for c in insp.get_columns("graph_nodes")]
        with op.batch_alter_table('graph_nodes', schema=None) as batch_op:
            if 'is_authoritative' not in node_cols:
                batch_op.add_column(sa.Column('is_authoritative', sa.Boolean(), nullable=False, server_default='1'))
            if 'is_simulated' not in node_cols:
                batch_op.add_column(sa.Column('is_simulated', sa.Boolean(), nullable=False, server_default='0'))
            if 'provenance' not in node_cols:
                batch_op.add_column(sa.Column('provenance', sa.String(length=255), nullable=False, server_default='AUTOMATED_INGESTION'))
            if 'evidence_reference' not in node_cols:
                batch_op.add_column(sa.Column('evidence_reference', sa.String(length=255), nullable=True))
            if 'derivation_rule' not in node_cols:
                batch_op.add_column(sa.Column('derivation_rule', sa.String(length=100), nullable=True))
            if 'input_sources' not in node_cols:
                batch_op.add_column(sa.Column('input_sources', sa.JSON(), nullable=False, server_default='[]'))
            if 'invalidated_at' not in node_cols:
                batch_op.add_column(sa.Column('invalidated_at', sa.DateTime(timezone=True), nullable=True))
            if 'invalidation_reason' not in node_cols:
                batch_op.add_column(sa.Column('invalidation_reason', sa.Text(), nullable=True))
            if 'contradiction_notes' not in node_cols:
                batch_op.add_column(sa.Column('contradiction_notes', sa.Text(), nullable=True))

    # 2. Add columns to graph_relationships
    if 'graph_relationships' in existing_tables:
        rel_cols = [c["name"] for c in insp.get_columns("graph_relationships")]
        with op.batch_alter_table('graph_relationships', schema=None) as batch_op:
            if 'epistemic_status' not in rel_cols:
                batch_op.add_column(sa.Column('epistemic_status', sa.String(length=30), nullable=False, server_default='OBSERVED_FACT'))
            if 'is_authoritative' not in rel_cols:
                batch_op.add_column(sa.Column('is_authoritative', sa.Boolean(), nullable=False, server_default='1'))
            if 'is_simulated' not in rel_cols:
                batch_op.add_column(sa.Column('is_simulated', sa.Boolean(), nullable=False, server_default='0'))
            if 'derivation_rule' not in rel_cols:
                batch_op.add_column(sa.Column('derivation_rule', sa.String(length=100), nullable=True))
            if 'input_sources' not in rel_cols:
                batch_op.add_column(sa.Column('input_sources', sa.JSON(), nullable=False, server_default='[]'))
            if 'invalidated_at' not in rel_cols:
                batch_op.add_column(sa.Column('invalidated_at', sa.DateTime(timezone=True), nullable=True))
            if 'invalidation_reason' not in rel_cols:
                batch_op.add_column(sa.Column('invalidation_reason', sa.Text(), nullable=True))
            if 'contradiction_notes' not in rel_cols:
                batch_op.add_column(sa.Column('contradiction_notes', sa.Text(), nullable=True))
            if 'freshness_expires_at' not in rel_cols:
                batch_op.add_column(sa.Column('freshness_expires_at', sa.DateTime(timezone=True), nullable=True))

    # 3. Add columns to risk_assessments
    if 'risk_assessments' in existing_tables:
        risk_cols = [c["name"] for c in insp.get_columns("risk_assessments")]
        with op.batch_alter_table('risk_assessments', schema=None) as batch_op:
            if 'prior_score' not in risk_cols:
                batch_op.add_column(sa.Column('prior_score', sa.Float(), nullable=True))
            if 'score_delta' not in risk_cols:
                batch_op.add_column(sa.Column('score_delta', sa.Float(), nullable=True))
            if 'delta_reasons' not in risk_cols:
                batch_op.add_column(sa.Column('delta_reasons', sa.JSON(), nullable=False, server_default='[]'))
            if 'is_invalidated' not in risk_cols:
                batch_op.add_column(sa.Column('is_invalidated', sa.Boolean(), nullable=False, server_default='0'))
            if 'invalidation_reason' not in risk_cols:
                batch_op.add_column(sa.Column('invalidation_reason', sa.Text(), nullable=True))
            if 'qualitative_label' not in risk_cols:
                batch_op.add_column(sa.Column('qualitative_label', sa.String(length=50), nullable=False, server_default='CALCULATED'))
            if 'unverified_penalty' not in risk_cols:
                batch_op.add_column(sa.Column('unverified_penalty', sa.Float(), nullable=False, server_default='0.0'))

    # 4. Create knowledge_dependency_records
    if 'knowledge_dependency_records' not in existing_tables:
        op.create_table(
            'knowledge_dependency_records',
            sa.Column('id', sa.String(length=36), primary_key=True),
            sa.Column('project_id', sa.String(length=36), sa.ForeignKey('projects.id', ondelete='CASCADE'), nullable=False),
            sa.Column('source_entity_type', sa.String(length=50), nullable=False),
            sa.Column('source_entity_id', sa.String(length=255), nullable=False),
            sa.Column('source_version', sa.String(length=64), nullable=True),
            sa.Column('dependent_entity_type', sa.String(length=50), nullable=False),
            sa.Column('dependent_entity_id', sa.String(length=255), nullable=False),
            sa.Column('dependency_type', sa.String(length=50), nullable=False, server_default='TOPOLOGY_LINK'),
            sa.Column('is_valid', sa.Boolean(), nullable=False, server_default='1'),
            sa.Column('invalidated_at', sa.DateTime(timezone=True), nullable=True),
            sa.Column('invalidation_reason', sa.Text(), nullable=True),
            sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
            sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
            sa.UniqueConstraint('project_id', 'source_entity_type', 'source_entity_id', 'dependent_entity_type', 'dependent_entity_id', name='uq_knowledge_dep_endpoints'),
        )
        op.create_index('ix_knowledge_dep_proj_source', 'knowledge_dependency_records', ['project_id', 'source_entity_type', 'source_entity_id'])
        op.create_index('ix_knowledge_dep_proj_dependent', 'knowledge_dependency_records', ['project_id', 'dependent_entity_type', 'dependent_entity_id'])

    # 5. Create explainable_attack_paths
    if 'explainable_attack_paths' not in existing_tables:
        op.create_table(
            'explainable_attack_paths',
            sa.Column('id', sa.String(length=64), primary_key=True),
            sa.Column('project_id', sa.String(length=36), sa.ForeignKey('projects.id', ondelete='CASCADE'), nullable=False),
            sa.Column('name', sa.String(length=255), nullable=False),
            sa.Column('start_node_id', sa.String(length=36), sa.ForeignKey('graph_nodes.id', ondelete='CASCADE'), nullable=False),
            sa.Column('target_node_id', sa.String(length=36), sa.ForeignKey('graph_nodes.id', ondelete='CASCADE'), nullable=False),
            sa.Column('path_status', sa.String(length=30), nullable=False, server_default='PLAUSIBLE'),
            sa.Column('cumulative_confidence', sa.Float(), nullable=False, server_default='1.0'),
            sa.Column('risk_impact_score', sa.Float(), nullable=False, server_default='50.0'),
            sa.Column('step_count', sa.Integer(), nullable=False, server_default='1'),
            sa.Column('is_scope_compliant', sa.Boolean(), nullable=False, server_default='1'),
            sa.Column('scope_violations', sa.JSON(), nullable=False, server_default='[]'),
            sa.Column('steps_explanation', sa.JSON(), nullable=False, server_default='[]'),
            sa.Column('chokepoints', sa.JSON(), nullable=False, server_default='[]'),
            sa.Column('calculation_version', sa.String(length=50), nullable=False, server_default='v2.1.0'),
            sa.Column('input_hashes', sa.JSON(), nullable=False, server_default='{}'),
            sa.Column('is_stale', sa.Boolean(), nullable=False, server_default='0'),
            sa.Column('is_invalidated', sa.Boolean(), nullable=False, server_default='0'),
            sa.Column('invalidation_reason', sa.Text(), nullable=True),
            sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
            sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        )
        op.create_index('ix_explainable_paths_project', 'explainable_attack_paths', ['project_id', 'path_status'])

    # 6. Create knowledge_reconciliation_audits
    if 'knowledge_reconciliation_audits' not in existing_tables:
        op.create_table(
            'knowledge_reconciliation_audits',
            sa.Column('id', sa.String(length=36), primary_key=True),
            sa.Column('project_id', sa.String(length=36), sa.ForeignKey('projects.id', ondelete='CASCADE'), nullable=False),
            sa.Column('run_by_user_id', sa.String(length=36), sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True),
            sa.Column('status', sa.String(length=30), nullable=False, server_default='COMPLETED'),
            sa.Column('total_nodes_audited', sa.Integer(), nullable=False, server_default='0'),
            sa.Column('total_relationships_audited', sa.Integer(), nullable=False, server_default='0'),
            sa.Column('dangling_references_detected', sa.Integer(), nullable=False, server_default='0'),
            sa.Column('duplicate_relationships_detected', sa.Integer(), nullable=False, server_default='0'),
            sa.Column('invalid_types_detected', sa.Integer(), nullable=False, server_default='0'),
            sa.Column('missing_provenance_detected', sa.Integer(), nullable=False, server_default='0'),
            sa.Column('stale_conclusions_detected', sa.Integer(), nullable=False, server_default='0'),
            sa.Column('scope_violations_detected', sa.Integer(), nullable=False, server_default='0'),
            sa.Column('contradictions_detected', sa.Integer(), nullable=False, server_default='0'),
            sa.Column('auto_repaired_count', sa.Integer(), nullable=False, server_default='0'),
            sa.Column('manual_review_required_count', sa.Integer(), nullable=False, server_default='0'),
            sa.Column('reconciliation_log', sa.JSON(), nullable=False, server_default='[]'),
            sa.Column('started_at', sa.DateTime(timezone=True), nullable=False),
            sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
            sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
            sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        )
        op.create_index('ix_knowledge_reconciliation_project', 'knowledge_reconciliation_audits', ['project_id', 'status'])


def downgrade() -> None:
    pass
