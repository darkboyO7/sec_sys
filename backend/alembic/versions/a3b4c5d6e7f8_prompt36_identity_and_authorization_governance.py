"""prompt36 identity security authorization consistency and privileged action governance

Revision ID: a3b4c5d6e7f8
Revises: f2a3b4c5d6e7
Create Date: 2026-10-29 20:10:00.000000

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'a3b4c5d6e7f8'
down_revision = 'f2a3b4c5d6e7'
branch_labels = None
depends_on = None


def upgrade():
    # 1. Add token_revoked_before to users
    with op.batch_alter_table('users') as batch_op:
        batch_op.add_column(sa.Column('token_revoked_before', sa.DateTime(timezone=True), nullable=True))

    # 2. Token Revocations table
    op.create_table(
        'token_revocations',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('token_jti', sa.String(length=64), nullable=False),
        sa.Column('user_id', sa.String(length=36), nullable=False),
        sa.Column('revoked_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('reason', sa.String(length=100), nullable=False, server_default='USER_LOGOUT'),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('token_jti', name='uq_token_revocations_jti')
    )
    op.create_index('ix_token_revocations_user_id', 'token_revocations', ['user_id'])
    op.create_index('ix_token_revocations_expires_at', 'token_revocations', ['expires_at'])

    # 3. Access Denial Audit Records table
    op.create_table(
        'access_denial_audit_records',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('user_id', sa.String(length=36), nullable=True),
        sa.Column('user_email', sa.String(length=255), nullable=True),
        sa.Column('project_id', sa.String(length=36), nullable=True),
        sa.Column('endpoint', sa.String(length=255), nullable=False),
        sa.Column('http_method', sa.String(length=10), nullable=False),
        sa.Column('required_privilege', sa.String(length=100), nullable=False),
        sa.Column('held_privilege', sa.String(length=100), nullable=True),
        sa.Column('denial_reason', sa.Text(), nullable=False),
        sa.Column('client_ip', sa.String(length=50), nullable=True),
        sa.Column('denied_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_access_denials_user_id', 'access_denial_audit_records', ['user_id'])
    op.create_index('ix_access_denials_project_id', 'access_denial_audit_records', ['project_id'])
    op.create_index('ix_access_denials_endpoint', 'access_denial_audit_records', ['endpoint'])
    op.create_index('ix_access_denials_denied_at', 'access_denial_audit_records', ['denied_at'])


def downgrade():
    op.drop_table('access_denial_audit_records')
    op.drop_table('token_revocations')
    with op.batch_alter_table('users') as batch_op:
        batch_op.drop_column('token_revoked_before')
