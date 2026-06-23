"""add USDT replay protection

Revision ID: 003
Revises: 002
Create Date: 2026-06-22
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "003"
down_revision: Union[str, None] = "002"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "payments" not in inspector.get_table_names():
        return
    columns = {column["name"] for column in inspector.get_columns("payments")}
    if "usdt_expected_amount_micro" not in columns:
        with op.batch_alter_table("payments") as batch_op:
            batch_op.add_column(sa.Column("usdt_expected_amount_micro", sa.BigInteger(), nullable=True))
    constraints = {item.get("name") for item in inspector.get_unique_constraints("payments")}
    if "uq_payments_usdt_tx_hash" not in constraints:
        op.execute(
            "UPDATE payments SET usdt_tx_hash = NULL "
            "WHERE usdt_tx_hash IS NOT NULL AND id NOT IN "
            "(SELECT MIN(id) FROM payments WHERE usdt_tx_hash IS NOT NULL GROUP BY usdt_tx_hash)"
        )
        with op.batch_alter_table("payments") as batch_op:
            batch_op.create_unique_constraint("uq_payments_usdt_tx_hash", ["usdt_tx_hash"])
    indexes = {item.get("name") for item in inspector.get_indexes("payments")}
    if "uq_payments_pending_usdt_amount" not in indexes:
        op.create_index(
            "uq_payments_pending_usdt_amount",
            "payments",
            ["usdt_expected_amount_micro"],
            unique=True,
            postgresql_where=sa.text("status = 'pending' AND usdt_expected_amount_micro IS NOT NULL"),
            sqlite_where=sa.text("status = 'pending' AND usdt_expected_amount_micro IS NOT NULL"),
        )


def downgrade() -> None:
    op.drop_index("uq_payments_pending_usdt_amount", table_name="payments")
    with op.batch_alter_table("payments") as batch_op:
        batch_op.drop_constraint("uq_payments_usdt_tx_hash", type_="unique")
        batch_op.drop_column("usdt_expected_amount_micro")
