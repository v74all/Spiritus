# Initial migration - empty (tables created by init_db)
# Tables will be managed by SQLAlchemy create_all on first run
# Future schema changes should use: alembic revision --autogenerate

"""initial schema

Revision ID: 001
Revises: None
Create Date: 2024-01-01 00:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = '001'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    pass  # Tables created by init_db() on first run


def downgrade() -> None:
    pass