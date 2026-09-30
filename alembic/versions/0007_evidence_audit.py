"""evidence_chain + audit_log (compliance)

Revision ID: 0007
Revises: 0006
Create Date: 2026-09-29

Adds:
  - evidence_chain: append-only, hash-chained custody log
  - audit_log: append-only record of sensitive access

Guarded with existence checks so it is safe on fresh and existing DBs.
"""
from typing import Sequence, Union

from sqlalchemy import inspect

from alembic import op
import sqlalchemy as sa

revision: str = '0007'
down_revision: Union[str, None] = '0006'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)
    tables = set(inspector.get_table_names())

    if "evidence_chain" not in tables:
        op.create_table(
            "evidence_chain",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("email_id", sa.Integer(), nullable=True),
            sa.Column("scan_id", sa.Integer(), nullable=True),
            sa.Column("raw_sha256", sa.String(length=64), nullable=True),
            sa.Column("report_sha256", sa.String(length=64), nullable=True),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.Column("actor", sa.String(length=64), nullable=False),
            sa.Column("prev_hash", sa.String(length=64), nullable=False),
            sa.Column("row_hash", sa.String(length=64), nullable=False),
            sa.ForeignKeyConstraint(["email_id"], ["emails.id"]),
            sa.ForeignKeyConstraint(["scan_id"], ["scans.id"]),
        )
        op.create_index("ix_evidence_chain_email_id", "evidence_chain", ["email_id"])
        op.create_index("ix_evidence_chain_scan_id", "evidence_chain", ["scan_id"])

    if "audit_log" not in tables:
        op.create_table(
            "audit_log",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.Column("actor", sa.String(length=64), nullable=False),
            sa.Column("action", sa.String(length=64), nullable=False),
            sa.Column("entity_type", sa.String(length=32), nullable=True),
            sa.Column("entity_id", sa.Integer(), nullable=True),
            sa.Column("detail_json", sa.JSON(), nullable=True),
        )
        op.create_index("ix_audit_log_action", "audit_log", ["action"])
        op.create_index("ix_audit_log_created_at", "audit_log", ["created_at"])


def downgrade() -> None:
    op.drop_table("audit_log")
    op.drop_table("evidence_chain")
