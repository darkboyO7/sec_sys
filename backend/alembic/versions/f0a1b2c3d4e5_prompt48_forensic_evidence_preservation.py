"""prompt48_forensic_evidence_preservation

Revision ID: f0a1b2c3d4e5
Revises: e9f0a1b2c3d4
Create Date: 2026-10-30 07:20:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'f0a1b2c3d4e5'
down_revision: Union[str, None] = 'e9f0a1b2c3d4'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Forensic Evidence Records
    op.create_table(
        'forensic_evidence_records',
        sa.Column('id', sa.String(length=36), primary_key=True, nullable=False),
        sa.Column('finding_id', sa.String(length=36), sa.ForeignKey('assessment_findings.id', ondelete='SET NULL'), nullable=True),
        sa.Column('job_id', sa.String(length=36), sa.ForeignKey('assessment_jobs.id', ondelete='SET NULL'), nullable=True),
        sa.Column('project_id', sa.String(length=36), nullable=False),
        sa.Column('evidence_type', sa.String(length=100), nullable=False),
        sa.Column('raw_payload', sa.Text(), nullable=False),
        sa.Column('raw_digest_sha256', sa.String(length=64), nullable=False),
        sa.Column('normalized_payload', sa.JSON(), nullable=True),
        sa.Column('normalized_digest_sha256', sa.String(length=64), nullable=True),
        sa.Column('source_identity', sa.String(length=255), nullable=False),
        sa.Column('adapter_version', sa.String(length=100), nullable=False),
        sa.Column('collection_time', sa.DateTime(timezone=True), nullable=False),
        sa.Column('ingestion_time', sa.DateTime(timezone=True), nullable=False),
        sa.Column('assessment_context', sa.JSON(), nullable=False),
        sa.Column('transformation_history', sa.JSON(), nullable=False),
        sa.Column('origin_signature', sa.String(length=512), nullable=False),
        sa.Column('signing_key_id', sa.String(length=128), nullable=False),
        sa.Column('signature_algorithm', sa.String(length=64), nullable=False),
        sa.Column('lifecycle_state', sa.String(length=50), nullable=False, server_default='INGESTED'),
        sa.Column('last_verification_status', sa.String(length=50), nullable=False, server_default='NOT_CHECKED'),
        sa.Column('last_verified_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_verified_by', sa.String(length=255), nullable=True),
        sa.Column('verification_details', sa.JSON(), nullable=True),
        sa.Column('contradiction_status', sa.String(length=50), nullable=False, server_default='SUPPORTING'),
        sa.Column('superseded_by_id', sa.String(length=36), nullable=True),
        sa.Column('prior_evidence_id', sa.String(length=36), nullable=True),
        sa.Column('is_contradictory', sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column('contradiction_notes', sa.Text(), nullable=True),
        sa.Column('classification', sa.String(length=50), nullable=False, server_default='RESTRICTED'),
        sa.Column('is_redacted', sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column('is_archived', sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column('is_deleted', sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column('deleted_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('deleted_by', sa.String(length=255), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index('ix_forensic_evidence_project_id', 'forensic_evidence_records', ['project_id'])
    op.create_index('ix_forensic_evidence_raw_digest', 'forensic_evidence_records', ['raw_digest_sha256'])
    op.create_index('ix_forensic_evidence_finding_id', 'forensic_evidence_records', ['finding_id'])
    op.create_index('ix_forensic_evidence_job_id', 'forensic_evidence_records', ['job_id'])

    # 2. Evidence Custody Events
    op.create_table(
        'evidence_custody_events',
        sa.Column('id', sa.String(length=36), primary_key=True, nullable=False),
        sa.Column('evidence_id', sa.String(length=36), sa.ForeignKey('forensic_evidence_records.id', ondelete='CASCADE'), nullable=False),
        sa.Column('event_type', sa.String(length=100), nullable=False),
        sa.Column('actor_id', sa.String(length=255), nullable=False),
        sa.Column('actor_role', sa.String(length=100), nullable=False),
        sa.Column('timestamp', sa.DateTime(timezone=True), nullable=False),
        sa.Column('action_details', sa.JSON(), nullable=False),
        sa.Column('prev_custody_hash', sa.String(length=64), nullable=False),
        sa.Column('custody_hash', sa.String(length=64), nullable=False),
    )
    op.create_index('ix_custody_events_evidence_id', 'evidence_custody_events', ['evidence_id'])
    op.create_index('ix_custody_events_timestamp', 'evidence_custody_events', ['timestamp'])


def downgrade() -> None:
    op.drop_table('evidence_custody_events')
    op.drop_table('forensic_evidence_records')
