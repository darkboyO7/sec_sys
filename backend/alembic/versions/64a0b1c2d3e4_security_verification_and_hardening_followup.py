"""security_verification_and_hardening_followup

Revision ID: 64a0b1c2d3e4
Revises: 63a0b1c2d3e4
Create Date: 2026-10-31 15:45:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from datetime import datetime, timezone


# revision identifiers, used by Alembic.
revision: str = '64a0b1c2d3e4'
down_revision: Union[str, None] = '63a0b1c2d3e4'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    now = datetime.now(timezone.utc)

    # 1. Create system_bootstrap_state table for race-safe atomic initial admin bootstrap
    op.create_table(
        'system_bootstrap_state',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('is_bootstrapped', sa.Boolean(), nullable=False, default=True),
        sa.Column('bootstrap_user_id', sa.String(length=36), nullable=False),
        sa.Column('bootstrapped_at', sa.DateTime(timezone=True), nullable=False),
    )

    # 2. Create audit_chain_heads table for deterministic multi-process append serialization
    op.create_table(
        'audit_chain_heads',
        sa.Column('partition_key', sa.String(length=100), primary_key=True),
        sa.Column('last_sequence_number', sa.Integer(), nullable=False, default=0),
        sa.Column('last_event_hash', sa.String(length=64), nullable=True),
        sa.Column('last_event_timestamp', sa.DateTime(timezone=True), nullable=True),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
    )

    # 3. Add is_deactivated column to worker_nodes table
    with op.batch_alter_table('worker_nodes', schema=None) as batch_op:
        batch_op.add_column(sa.Column('is_deactivated', sa.Boolean(), nullable=False, server_default='0'))

    # 4. Deterministic Backfill:
    # A. If existing users exist in the database, close bootstrap explicitly
    conn = op.get_bind()
    try:
        user_rows = conn.execute(sa.text("SELECT id, system_role FROM users ORDER BY created_at ASC")).fetchall()
        if user_rows:
            admin_user = next((u for u in user_rows if u[1] == 'ADMIN'), user_rows[0])
            conn.execute(
                sa.text(
                    "INSERT INTO system_bootstrap_state (id, is_bootstrapped, bootstrap_user_id, bootstrapped_at) "
                    "VALUES (1, 1, :uid, :ts)"
                ),
                {"uid": admin_user[0], "ts": now}
            )
    except Exception:
        pass

    # B. Deterministic Backfill for audit events:
    # Deterministically assign sequence_number to any existing events missing sequence numbers
    try:
        events = conn.execute(
            sa.text("SELECT id, project_id, timestamp, event_hash, sequence_number FROM audit_events ORDER BY timestamp ASC, id ASC")
        ).fetchall()
        
        partition_counters = {}
        for ev in events:
            eid, pid, ts, eh, snum = ev[0], ev[1], ev[2], ev[3], ev[4]
            pk = str(pid) if pid else "__GLOBAL__"
            cur_seq = partition_counters.get(pk, 0) + 1
            partition_counters[pk] = cur_seq

            if snum is None:
                conn.execute(
                    sa.text("UPDATE audit_events SET sequence_number = :seq WHERE id = :id"),
                    {"seq": cur_seq, "id": eid}
                )
            
            # Upsert into audit_chain_heads
            head_exists = conn.execute(
                sa.text("SELECT partition_key FROM audit_chain_heads WHERE partition_key = :pk"),
                {"pk": pk}
            ).fetchone()
            if head_exists:
                conn.execute(
                    sa.text(
                        "UPDATE audit_chain_heads SET last_sequence_number = :seq, last_event_hash = :eh, "
                        "last_event_timestamp = :ts, updated_at = :upd WHERE partition_key = :pk"
                    ),
                    {"seq": cur_seq, "eh": eh, "ts": ts, "upd": now, "pk": pk}
                )
            else:
                conn.execute(
                    sa.text(
                        "INSERT INTO audit_chain_heads (partition_key, last_sequence_number, last_event_hash, last_event_timestamp, updated_at) "
                        "VALUES (:pk, :seq, :eh, :ts, :upd)"
                    ),
                    {"pk": pk, "seq": cur_seq, "eh": eh, "ts": ts, "upd": now}
                )
    except Exception:
        pass


def downgrade() -> None:
    with op.batch_alter_table('worker_nodes', schema=None) as batch_op:
        batch_op.drop_column('is_deactivated')

    op.drop_table('audit_chain_heads')
    op.drop_table('system_bootstrap_state')
