"""user_permissions — RBAC capability grants (R1).

Adds the ``user_permissions`` table: per-user capability strings granted by
an admin. ``users.role`` remains the baseline tier (admin = superuser,
user = baseline); effective permissions = role defaults ∪ grants.

No backfill: role=admin is implicit and needs no rows.

Revision ID: 0012
Revises: 0011
Create Date: 2026-10-02
"""
from typing import Sequence, Union

from sqlalchemy import inspect

from alembic import op
import sqlalchemy as sa

revision: str = '0012'
down_revision: Union[str, None] = '0011'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)
    if "user_permissions" in inspector.get_table_names():
        return

    op.create_table(
        "user_permissions",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id", ondelete="CASCADE"),
                  nullable=False),
        sa.Column("permission", sa.String(length=64), nullable=False),
        sa.Column("granted_by", sa.Integer(), sa.ForeignKey("users.id", ondelete="SET NULL"),
                  nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.UniqueConstraint("user_id", "permission", name="uq_user_permissions_user_perm"),
    )
    op.create_index("ix_user_permissions_user_id", "user_permissions", ["user_id"])


def downgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)
    if "user_permissions" not in inspector.get_table_names():
        return
    op.drop_index("ix_user_permissions_user_id", table_name="user_permissions")
    op.drop_table("user_permissions")
