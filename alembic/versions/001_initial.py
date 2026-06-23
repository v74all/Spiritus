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
    # The historical application used metadata.create_all without Alembic.
    # checkfirst keeps this baseline compatible with those installations while
    # also making `alembic upgrade head` sufficient for a fresh database.
    from app.database import Base
    import app.models  # noqa: F401

    Base.metadata.create_all(bind=op.get_bind(), checkfirst=True)


def downgrade() -> None:
    from app.database import Base
    import app.models  # noqa: F401

    Base.metadata.drop_all(bind=op.get_bind(), checkfirst=True)
