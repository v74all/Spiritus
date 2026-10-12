"""reseller tree (parent_id), wallet ledger and Telegram chat binding

Revision ID: 005
Revises: 004
Create Date: 2026-10-01
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "005"
down_revision: str | None = "004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    tables = set(inspector.get_table_names())
    if "resellers" in tables:
        columns = {c["name"] for c in inspector.get_columns("resellers")}
        if "parent_id" not in columns:
            with op.batch_alter_table("resellers") as batch_op:
                batch_op.add_column(sa.Column("parent_id", sa.Integer(), nullable=True))
                batch_op.create_foreign_key(
                    "fk_resellers_parent_id", "resellers", ["parent_id"], ["id"]
                )
                batch_op.create_index("ix_resellers_parent_id", ["parent_id"])
    if "vpn_users" in tables:
        user_columns = {c["name"] for c in inspector.get_columns("vpn_users")}
        if "telegram_chat_id" not in user_columns:
            with op.batch_alter_table("vpn_users") as batch_op:
                batch_op.add_column(sa.Column("telegram_chat_id", sa.String(length=32), nullable=True))
                batch_op.create_index("ix_vpn_users_telegram_chat_id", ["telegram_chat_id"])
    if "reseller_ledger" not in tables:
        op.create_table(
            "reseller_ledger",
            sa.Column("id", sa.BigInteger().with_variant(sa.Integer(), "sqlite"), primary_key=True),
            sa.Column("reseller_id", sa.Integer(), sa.ForeignKey("resellers.id"), nullable=False),
            sa.Column("payment_id", sa.Integer(), sa.ForeignKey("payments.id"), nullable=True),
            sa.Column("kind", sa.String(length=20), nullable=False),
            sa.Column("amount", sa.BigInteger(), nullable=False),
            sa.Column("balance_after", sa.BigInteger(), nullable=False),
            sa.Column("note", sa.String(length=255), nullable=True),
            sa.Column("created_at", sa.DateTime(), server_default=sa.func.now()),
            sa.UniqueConstraint("payment_id", "reseller_id", "kind", name="uq_reseller_ledger_payment"),
        )
        op.create_index("ix_reseller_ledger_reseller_id", "reseller_ledger", ["reseller_id"])


def downgrade() -> None:
    with op.batch_alter_table("vpn_users") as batch_op:
        batch_op.drop_index("ix_vpn_users_telegram_chat_id")
        batch_op.drop_column("telegram_chat_id")
    op.drop_index("ix_reseller_ledger_reseller_id", table_name="reseller_ledger")
    op.drop_table("reseller_ledger")
    with op.batch_alter_table("resellers") as batch_op:
        batch_op.drop_index("ix_resellers_parent_id")
        batch_op.drop_constraint("fk_resellers_parent_id", type_="foreignkey")
        batch_op.drop_column("parent_id")
