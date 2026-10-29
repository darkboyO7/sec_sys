"""prompt33 continuous compliance intelligence

Revision ID: c1d2e3f4a5b6
Revises: f0e1d2c3b4a5
Create Date: 2026-10-29 18:30:00.000000

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'c1d2e3f4a5b6'
down_revision = 'f0e1d2c3b4a5'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'compliance_controls',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('control_id', sa.String(length=50), nullable=False),
        sa.Column('version', sa.String(length=20), nullable=False, server_default='1.0.0'),
        sa.Column('category', sa.String(length=50), nullable=False),
        sa.Column('title', sa.String(length=255), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('requirement_statement', sa.Text(), nullable=False),
        sa.Column('framework', sa.String(length=100), nullable=False, server_default='NIST_CSF_2.0'),
        sa.Column('framework_reference', sa.String(length=50), nullable=True),
        sa.Column('applicability_criteria', sa.JSON(), nullable=False),
        sa.Column('required_evidence_types', sa.JSON(), nullable=False),
        sa.Column('evaluation_rule', sa.String(length=100), nullable=False),
        sa.Column('severity', sa.String(length=20), nullable=False, server_default='HIGH'),
        sa.Column('remediation_guidance', sa.Text(), nullable=False),
        sa.Column('evaluation_limitations', sa.Text(), nullable=False),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default=sa.text('1')),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('control_id', 'version', name='uq_compliance_controls_control_version')
    )
    op.create_index('ix_compliance_controls_control_id', 'compliance_controls', ['control_id'])
    op.create_index('ix_compliance_controls_category', 'compliance_controls', ['category'])
    op.create_index('ix_compliance_controls_framework', 'compliance_controls', ['framework'])

    op.create_table(
        'compliance_baseline_profiles',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('project_id', sa.String(length=36), nullable=False),
        sa.Column('profile_key', sa.String(length=100), nullable=False),
        sa.Column('version', sa.String(length=20), nullable=False, server_default='1.0.0'),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('target_applicability', sa.String(length=100), nullable=False, server_default='WEB_APPLICATION'),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default=sa.text('1')),
        sa.Column('control_ids', sa.JSON(), nullable=False),
        sa.Column('parameters', sa.JSON(), nullable=False),
        sa.Column('created_by_id', sa.String(length=36), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['created_by_id'], ['users.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['project_id'], ['projects.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('project_id', 'profile_key', 'version', name='uq_compliance_baselines_proj_key_version')
    )
    op.create_index('ix_compliance_baseline_profiles_project_id', 'compliance_baseline_profiles', ['project_id'])
    op.create_index('ix_compliance_baseline_profiles_profile_key', 'compliance_baseline_profiles', ['profile_key'])

    op.create_table(
        'compliance_evaluation_runs',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('project_id', sa.String(length=36), nullable=False),
        sa.Column('baseline_profile_id', sa.String(length=36), nullable=False),
        sa.Column('assessment_id', sa.String(length=36), nullable=True),
        sa.Column('run_status', sa.String(length=50), nullable=False, server_default='COMPLETED'),
        sa.Column('pass_count', sa.Integer(), nullable=False, server_default=sa.text('0')),
        sa.Column('fail_count', sa.Integer(), nullable=False, server_default=sa.text('0')),
        sa.Column('partial_count', sa.Integer(), nullable=False, server_default=sa.text('0')),
        sa.Column('unknown_count', sa.Integer(), nullable=False, server_default=sa.text('0')),
        sa.Column('not_applicable_count', sa.Integer(), nullable=False, server_default=sa.text('0')),
        sa.Column('error_count', sa.Integer(), nullable=False, server_default=sa.text('0')),
        sa.Column('total_controls_evaluated', sa.Integer(), nullable=False, server_default=sa.text('0')),
        sa.Column('provenance_digest', sa.String(length=64), nullable=False),
        sa.Column('evaluated_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('evaluated_by_id', sa.String(length=36), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['assessment_id'], ['assessment_jobs.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['baseline_profile_id'], ['compliance_baseline_profiles.id'], ondelete='RESTRICT'),
        sa.ForeignKeyConstraint(['evaluated_by_id'], ['users.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['project_id'], ['projects.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_compliance_evaluation_runs_project_id', 'compliance_evaluation_runs', ['project_id'])
    op.create_index('ix_compliance_evaluation_runs_baseline_profile_id', 'compliance_evaluation_runs', ['baseline_profile_id'])
    op.create_index('ix_compliance_evaluation_runs_assessment_id', 'compliance_evaluation_runs', ['assessment_id'])
    op.create_index('ix_compliance_evaluation_runs_provenance_digest', 'compliance_evaluation_runs', ['provenance_digest'])

    op.create_table(
        'compliance_control_results',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('run_id', sa.String(length=36), nullable=False),
        sa.Column('project_id', sa.String(length=36), nullable=False),
        sa.Column('control_id', sa.String(length=50), nullable=False),
        sa.Column('control_version', sa.String(length=20), nullable=False, server_default='1.0.0'),
        sa.Column('status', sa.String(length=30), nullable=False),
        sa.Column('asset_id', sa.String(length=36), nullable=True),
        sa.Column('evidence_refs', sa.JSON(), nullable=False),
        sa.Column('evidence_digests', sa.JSON(), nullable=False),
        sa.Column('reasoning', sa.Text(), nullable=False),
        sa.Column('missing_evidence_types', sa.JSON(), nullable=False),
        sa.Column('confidence_score', sa.Float(), nullable=False, server_default=sa.text('1.0')),
        sa.Column('limitations', sa.Text(), nullable=True),
        sa.Column('has_exception', sa.Boolean(), nullable=False, server_default=sa.text('0')),
        sa.Column('exception_id', sa.String(length=36), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['asset_id'], ['assets.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['project_id'], ['projects.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['run_id'], ['compliance_evaluation_runs.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_compliance_control_results_run_id', 'compliance_control_results', ['run_id'])
    op.create_index('ix_compliance_control_results_project_id', 'compliance_control_results', ['project_id'])
    op.create_index('ix_compliance_control_results_control_id', 'compliance_control_results', ['control_id'])
    op.create_index('ix_compliance_control_results_status', 'compliance_control_results', ['status'])
    op.create_index('ix_compliance_control_results_asset_id', 'compliance_control_results', ['asset_id'])

    op.create_table(
        'compliance_drift_events',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('project_id', sa.String(length=36), nullable=False),
        sa.Column('control_id', sa.String(length=50), nullable=False),
        sa.Column('asset_id', sa.String(length=36), nullable=True),
        sa.Column('drift_type', sa.String(length=50), nullable=False),
        sa.Column('previous_status', sa.String(length=30), nullable=False),
        sa.Column('new_status', sa.String(length=30), nullable=False),
        sa.Column('previous_run_id', sa.String(length=36), nullable=True),
        sa.Column('current_run_id', sa.String(length=36), nullable=False),
        sa.Column('reason', sa.Text(), nullable=False),
        sa.Column('detected_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('deduplication_hash', sa.String(length=64), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['asset_id'], ['assets.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['current_run_id'], ['compliance_evaluation_runs.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['project_id'], ['projects.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('deduplication_hash', name='uq_compliance_drift_dedup_hash')
    )
    op.create_index('ix_compliance_drift_events_project_id', 'compliance_drift_events', ['project_id'])
    op.create_index('ix_compliance_drift_events_control_id', 'compliance_drift_events', ['control_id'])
    op.create_index('ix_compliance_drift_events_drift_type', 'compliance_drift_events', ['drift_type'])
    op.create_index('ix_compliance_drift_events_current_run_id', 'compliance_drift_events', ['current_run_id'])

    op.create_table(
        'compliance_exceptions',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('project_id', sa.String(length=36), nullable=False),
        sa.Column('control_id', sa.String(length=50), nullable=False),
        sa.Column('asset_id', sa.String(length=36), nullable=True),
        sa.Column('justification', sa.Text(), nullable=False),
        sa.Column('risk_assessment', sa.Text(), nullable=False),
        sa.Column('compensating_controls', sa.Text(), nullable=False),
        sa.Column('requester_id', sa.String(length=36), nullable=False),
        sa.Column('approver_id', sa.String(length=36), nullable=True),
        sa.Column('status', sa.String(length=30), nullable=False, server_default='REQUESTED'),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('approved_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('revoked_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('review_notes', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['approver_id'], ['users.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['asset_id'], ['assets.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['project_id'], ['projects.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['requester_id'], ['users.id'], ondelete='RESTRICT'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_compliance_exceptions_project_id', 'compliance_exceptions', ['project_id'])
    op.create_index('ix_compliance_exceptions_control_id', 'compliance_exceptions', ['control_id'])
    op.create_index('ix_compliance_exceptions_status', 'compliance_exceptions', ['status'])
    op.create_index('ix_compliance_exceptions_expires_at', 'compliance_exceptions', ['expires_at'])


def downgrade():
    op.drop_table('compliance_exceptions')
    op.drop_table('compliance_drift_events')
    op.drop_table('compliance_control_results')
    op.drop_table('compliance_evaluation_runs')
    op.drop_table('compliance_baseline_profiles')
    op.drop_table('compliance_controls')
