"""per-user daily traffic, written by the traffic collector

Revision ID: 007
Revises: 006
Create Date: 2026-10-20
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "007"
down_revision: str | None = "006"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    if "traffic_daily" in set(sa.inspect(op.get_bind()).get_table_names()):
        return
    op.create_table(
        "traffic_daily",
        sa.Column("id", sa.BigInteger().with_variant(sa.Integer(), "sqlite"), primary_key=True, autoincrement=True),
        sa.Column("day", sa.Date(), nullable=False),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("vpn_users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("upload", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("download", sa.BigInteger(), nullable=False, server_default="0"),
        sa.UniqueConstraint("day", "user_id", name="uq_traffic_daily_day_user"),
    )
    op.create_index("ix_traffic_daily_day", "traffic_daily", ["day"])


def downgrade() -> None:
    op.drop_index("ix_traffic_daily_day", table_name="traffic_daily")
    op.drop_table("traffic_daily")
