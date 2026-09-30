"""alerts (global notification feed)

Revision ID: 0008
Revises: 0007
Create Date: 2026-09-29

Guarded with existence checks so it is safe on fresh and existing DBs.
"""
from typing import Sequence, Union

from sqlalchemy import inspect

from alembic import op
import sqlalchemy as sa

revision: str = '0008'
down_revision: Union[str, None] = '0007'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)
    tables = set(inspector.get_table_names())

    if "alerts" not in tables:
        op.create_table(
            "alerts",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("scan_id", sa.Integer(), nullable=False),
            sa.Column("email_id", sa.Integer(), nullable=True),
            sa.Column("score", sa.Float(), nullable=False),
            sa.Column("classification", sa.String(length=32), nullable=False),
            sa.Column("reasons", sa.JSON(), nullable=True),
            sa.Column("subject", sa.String(length=1024), nullable=True),
            sa.Column("sender", sa.String(length=512), nullable=True),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.Column("read_at", sa.DateTime(), nullable=True),
            sa.ForeignKeyConstraint(["scan_id"], ["scans.id"]),
            sa.ForeignKeyConstraint(["email_id"], ["emails.id"]),
        )
        op.create_index("ix_alerts_scan_id", "alerts", ["scan_id"])
        op.create_index("ix_alerts_email_id", "alerts", ["email_id"])
        op.create_index("ix_alerts_read_at", "alerts", ["read_at"])


def downgrade() -> None:
    op.drop_table("alerts")
