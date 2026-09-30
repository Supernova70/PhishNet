"""campaigns.notes (analyst case notes for PATCH /campaigns/{id})

Revision ID: 0009
Revises: 0008
Create Date: 2026-09-29

Guarded with an existence check so it is safe on fresh and existing DBs.
"""
from typing import Sequence, Union

from sqlalchemy import inspect

from alembic import op
import sqlalchemy as sa

revision: str = '0009'
down_revision: Union[str, None] = '0008'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)
    tables = set(inspector.get_table_names())
    if "campaigns" not in tables:
        return
    cols = {c["name"] for c in inspector.get_columns("campaigns")}
    if "notes" not in cols:
        op.add_column("campaigns", sa.Column("notes", sa.Text(), nullable=True))


def downgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)
    if "campaigns" in set(inspector.get_table_names()):
        cols = {c["name"] for c in inspector.get_columns("campaigns")}
        if "notes" in cols:
            op.drop_column("campaigns", "notes")
