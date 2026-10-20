"""edge nodes (reachability monitoring) and in-country probe reports

Revision ID: 006
Revises: 005
Create Date: 2026-10-18
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "006"
down_revision: str | None = "005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    tables = set(sa.inspect(op.get_bind()).get_table_names())
    if "edge_nodes" not in tables:
        op.create_table(
            "edge_nodes",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("name", sa.String(length=100), nullable=False),
            sa.Column("address", sa.String(length=255), nullable=False),
            sa.Column("port", sa.Integer(), nullable=False, server_default="443"),
            sa.Column("location", sa.String(length=100), nullable=True),
            sa.Column("reachable", sa.Boolean(), nullable=True),
            sa.Column("rtt_ms", sa.Float(), nullable=True),
            sa.Column("last_error", sa.String(length=120), nullable=True),
            sa.Column("last_checked_at", sa.DateTime(), nullable=True),
            sa.Column("created_at", sa.DateTime(), server_default=sa.func.now()),
        )
        op.create_index("ix_edge_nodes_id", "edge_nodes", ["id"])
    if "probe_agents" not in tables:
        op.create_table(
            "probe_agents",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("name", sa.String(length=100), nullable=False),
            sa.Column("token_hash", sa.String(length=64), nullable=False),
            sa.Column("token_prefix", sa.String(length=8), nullable=False),
            sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()),
            sa.Column("last_seen_at", sa.DateTime(), nullable=True),
            sa.Column("last_carrier", sa.String(length=100), nullable=True),
            sa.Column("last_asn", sa.String(length=20), nullable=True),
            sa.Column("created_at", sa.DateTime(), server_default=sa.func.now()),
        )
        op.create_index("ix_probe_agents_id", "probe_agents", ["id"])
        op.create_index("ix_probe_agents_token_hash", "probe_agents", ["token_hash"], unique=True)
    if "probe_reports" not in tables:
        op.create_table(
            "probe_reports",
            sa.Column("id", sa.BigInteger().with_variant(sa.Integer(), "sqlite"), primary_key=True),
            sa.Column(
                "probe_id", sa.Integer(),
                sa.ForeignKey("probe_agents.id", ondelete="CASCADE"), nullable=False,
            ),
            sa.Column("carrier", sa.String(length=100), nullable=False),
            sa.Column("asn", sa.String(length=20), nullable=True),
            sa.Column("protocol", sa.String(length=40), nullable=False),
            sa.Column("method", sa.String(length=10), nullable=False),
            sa.Column("ok", sa.Boolean(), nullable=False),
            sa.Column("latency_ms", sa.Float(), nullable=True),
            sa.Column("error", sa.String(length=120), nullable=True),
            sa.Column("created_at", sa.DateTime(), server_default=sa.func.now()),
        )
        op.create_index("ix_probe_reports_created_at", "probe_reports", ["created_at"])
        op.create_index("ix_probe_reports_probe_id", "probe_reports", ["probe_id"])


def downgrade() -> None:
    op.drop_index("ix_probe_reports_probe_id", table_name="probe_reports")
    op.drop_index("ix_probe_reports_created_at", table_name="probe_reports")
    op.drop_table("probe_reports")
    op.drop_index("ix_probe_agents_token_hash", table_name="probe_agents")
    op.drop_index("ix_probe_agents_id", table_name="probe_agents")
    op.drop_table("probe_agents")
    op.drop_index("ix_edge_nodes_id", table_name="edge_nodes")
    op.drop_table("edge_nodes")
