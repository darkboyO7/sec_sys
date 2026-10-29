"""prompt32_evidence_backed_reporting

Revision ID: f0e1d2c3b4a5
Revises: e4f5a6b7c8d9
Create Date: 2026-10-29 18:00:00.000000
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = 'f0e1d2c3b4a5'
down_revision: Union[str, None] = 'e4f5a6b7c8d9'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Add nullable assessment_id column to report_records for assessment-specific canonical reports
    with op.batch_alter_table("report_records") as batch_op:
        batch_op.add_column(sa.Column("assessment_id", sa.String(length=36), nullable=True))
        batch_op.create_foreign_key("fk_report_records_assessment_id", "assessment_jobs", ["assessment_id"], ["id"], ondelete="SET NULL")
        batch_op.create_index("ix_report_records_assessment_id", ["assessment_id"])


def downgrade() -> None:
    with op.batch_alter_table("report_records") as batch_op:
        batch_op.drop_index("ix_report_records_assessment_id")
        batch_op.drop_constraint("fk_report_records_assessment_id", type_="foreignkey")
        batch_op.drop_column("assessment_id")
