"""add_tag_and_last_error_to_protocol_configs

Adds the two columns the protocol_sync service uses:
- `protocol_configs.tag`        (nullable str)  inbound tag the row
                                       renders as on first write
- `protocol_configs.last_error` (nullable text) captured xray-test
                                       stderr from the last failed
                                       sync, so the operator can
                                       read the actual rejection
                                       reason from the panel
                                       instead of grepping the
                                       xray error log.

Also relaxes the FK on `agent_id` from NOT NULL to NULL so a
single-node install with no agents row can still record protocol
toggles (the sync service will create an Agent row on first
sync if one is missing).

Revision ID: 002
Revises: 001
Create Date: 2026-05-31
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "002"
down_revision: Union[str, None] = "001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add `tag` and `last_error` columns, drop NOT NULL on agent_id.

    The SQLite variant needs `batch_alter_table` because SQLite
    doesn't support `ALTER COLUMN` directly.
    """
    with op.batch_alter_table("protocol_configs") as batch_op:
        batch_op.add_column(
            sa.Column("tag", sa.String(length=100), nullable=True),
        )
        batch_op.add_column(
            sa.Column("last_error", sa.Text(), nullable=True),
        )
        batch_op.alter_column(
            "agent_id",
            existing_type=sa.Integer(),
            nullable=True,
        )


def downgrade() -> None:
    """Reverse the upgrade: drop the new columns, restore NOT NULL.

    The downgrade is destructive — if a row has a NULL agent_id it
    must be deleted (or assigned a real agent) before the FK
    constraint can be re-applied. We do the latter: fill NULLs
    with the first available agent id, then re-tighten the
    NOT NULL.
    """
    bind = op.get_bind()
    # Backfill NULL agent_ids with the lowest-id agent so the
    # downgrade doesn't break the NOT NULL constraint.
    bind.execute(
        sa.text(
            "UPDATE protocol_configs "
            "SET agent_id = (SELECT MIN(id) FROM agents) "
            "WHERE agent_id IS NULL"
        )
    )
    with op.batch_alter_table("protocol_configs") as batch_op:
        batch_op.alter_column(
            "agent_id",
            existing_type=sa.Integer(),
            nullable=False,
        )
        batch_op.drop_column("last_error")
        batch_op.drop_column("tag")
