"""prompt39 incident investigation and case management

Revision ID: d6e7f8a9b0c1
Revises: c5d6e7f8a9b0
Create Date: 2026-10-29 21:26:00.000000

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'd6e7f8a9b0c1'
down_revision = 'c5d6e7f8a9b0'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'incident_cases',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('project_id', sa.String(length=36), nullable=False),
        sa.Column('case_number', sa.String(length=64), nullable=False),
        sa.Column('title', sa.String(length=255), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('severity', sa.Enum('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL', name='caseseverity'), nullable=False),
        sa.Column('status', sa.Enum('OPEN', 'TRIAGED', 'INVESTIGATING', 'CONTAINED', 'CLOSED', 'REOPENED', name='casestatus'), nullable=False),
        sa.Column('lead_investigator_id', sa.String(length=36), nullable=True),
        sa.Column('assigned_team', sa.String(length=128), nullable=True),
        sa.Column('opened_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('closed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('reopened_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('root_cause_hypothesis', sa.Text(), nullable=True),
        sa.Column('alternative_explanations', sa.JSON(), nullable=False),
        sa.Column('is_containment_verified', sa.Boolean(), nullable=False),
        sa.Column('closure_summary', sa.Text(), nullable=True),
        sa.Column('closure_approved_by_id', sa.String(length=36), nullable=True),
        sa.Column('reopening_rationale', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['project_id'], ['projects.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['lead_investigator_id'], ['users.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['closure_approved_by_id'], ['users.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_case_proj_status', 'incident_cases', ['project_id', 'status'])
    op.create_index('ix_case_proj_severity', 'incident_cases', ['project_id', 'severity'])
    op.create_index('ix_case_number', 'incident_cases', ['case_number'])

    op.create_table(
        'incident_case_assets',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('case_id', sa.String(length=36), nullable=False),
        sa.Column('asset_id', sa.String(length=36), nullable=False),
        sa.Column('relationship_type', sa.Enum('PRIMARY_TARGET', 'PIVOT_VECTOR', 'IMPACTED_DEPENDENCY', 'OBSERVED_CORRELATION', name='relationshiptype'), nullable=False),
        sa.Column('confidence', sa.Float(), nullable=False),
        sa.Column('is_contradictory', sa.Boolean(), nullable=False),
        sa.Column('notes', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['case_id'], ['incident_cases.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['asset_id'], ['assets.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_case_asset_uniq', 'incident_case_assets', ['case_id', 'asset_id'], unique=True)

    op.create_table(
        'incident_case_findings',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('case_id', sa.String(length=36), nullable=False),
        sa.Column('finding_id', sa.String(length=36), nullable=False),
        sa.Column('correlation_type', sa.Enum('CONFIRMED_CAUSATION', 'PROBABLE_CORRELATION', 'TEMPORAL_COINCIDENCE', 'CONTRADICTORY_EVIDENCE', name='correlationtype'), nullable=False),
        sa.Column('confidence', sa.Float(), nullable=False),
        sa.Column('rationale', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['case_id'], ['incident_cases.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['finding_id'], ['vulnerability_findings.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_case_finding_uniq', 'incident_case_findings', ['case_id', 'finding_id'], unique=True)

    op.create_table(
        'incident_case_evidence',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('case_id', sa.String(length=36), nullable=False),
        sa.Column('finding_evidence_id', sa.String(length=36), nullable=True),
        sa.Column('evidence_digest', sa.String(length=64), nullable=False),
        sa.Column('evidence_summary', sa.Text(), nullable=False),
        sa.Column('is_contradictory', sa.Boolean(), nullable=False),
        sa.Column('provenance_details', sa.JSON(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['case_id'], ['incident_cases.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['finding_evidence_id'], ['finding_evidence.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_case_evidence_case_id', 'incident_case_evidence', ['case_id'])

    op.create_table(
        'incident_case_transitions',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('case_id', sa.String(length=36), nullable=False),
        sa.Column('from_status', sa.Enum('OPEN', 'TRIAGED', 'INVESTIGATING', 'CONTAINED', 'CLOSED', 'REOPENED', name='casestatus'), nullable=False),
        sa.Column('to_status', sa.Enum('OPEN', 'TRIAGED', 'INVESTIGATING', 'CONTAINED', 'CLOSED', 'REOPENED', name='casestatus'), nullable=False),
        sa.Column('transitioned_by_id', sa.String(length=36), nullable=True),
        sa.Column('reason', sa.Text(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['case_id'], ['incident_cases.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['transitioned_by_id'], ['users.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_case_transition_case_id', 'incident_case_transitions', ['case_id'])

    op.create_table(
        'incident_case_notes',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('case_id', sa.String(length=36), nullable=False),
        sa.Column('author_id', sa.String(length=36), nullable=True),
        sa.Column('note_type', sa.String(length=64), nullable=False),
        sa.Column('content', sa.Text(), nullable=False),
        sa.Column('is_alternative_hypothesis', sa.Boolean(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['case_id'], ['incident_cases.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['author_id'], ['users.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_case_note_case_id', 'incident_case_notes', ['case_id'])


def downgrade():
    op.drop_table('incident_case_notes')
    op.drop_table('incident_case_transitions')
    op.drop_table('incident_case_evidence')
    op.drop_table('incident_case_findings')
    op.drop_table('incident_case_assets')
    op.drop_table('incident_cases')
