"""add audit log hash chain columns

Revision ID: 004
Revises: 003
Create Date: 2026-10-01
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "004"
down_revision: str | None = "003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "audit_log" not in inspector.get_table_names():
        return
    columns = {column["name"] for column in inspector.get_columns("audit_log")}
    with op.batch_alter_table("audit_log") as batch_op:
        if "prev_hash" not in columns:
            batch_op.add_column(sa.Column("prev_hash", sa.String(length=64), nullable=True))
        if "entry_hash" not in columns:
            batch_op.add_column(sa.Column("entry_hash", sa.String(length=64), nullable=True))
    indexes = {index["name"] for index in sa.inspect(bind).get_indexes("audit_log")}
    if "ix_audit_log_entry_hash" not in indexes:
        op.create_index("ix_audit_log_entry_hash", "audit_log", ["entry_hash"])


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    if "audit_log" not in inspector.get_table_names():
        return
    op.drop_index("ix_audit_log_entry_hash", table_name="audit_log")
    with op.batch_alter_table("audit_log") as batch_op:
        batch_op.drop_column("entry_hash")
        batch_op.drop_column("prev_hash")
