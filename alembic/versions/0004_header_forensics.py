"""header forensics: email_sources, received_hops, auth_results, verdicts.header_score

Revision ID: 0004
Revises: 0003
Create Date: 2026-09-29

SIH 26106 — Email Header and Protocol Analysis Module.

Guarded with existence checks (same pattern as 0001/0002) so the
migration is safe on fresh and existing databases.
"""
from typing import Sequence, Union

from sqlalchemy import inspect
from alembic import op
import sqlalchemy as sa

revision: str = '0004'
down_revision: Union[str, None] = '0003'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)
    existing_tables = inspector.get_table_names()

    existing_indexes = {
        idx["name"]
        for table in existing_tables
        for idx in inspector.get_indexes(table)
    }

    # ── email_sources: preserved raw RFC822 + full header block ──
    if "email_sources" not in existing_tables:
        op.create_table(
            "email_sources",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("email_id", sa.Integer(), nullable=False),
            sa.Column("raw_path", sa.String(length=1024), nullable=True),
            sa.Column("raw_sha256", sa.String(length=64), nullable=True),
            sa.Column("size_bytes", sa.Integer(), nullable=False),
            sa.Column("headers_json", sa.JSON(), nullable=True),
            sa.Column("fetched_at", sa.DateTime(), nullable=False),
            sa.ForeignKeyConstraint(["email_id"], ["emails.id"]),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint("email_id"),
        )
    if "ix_email_sources_id" not in existing_indexes:
        op.create_index(op.f("ix_email_sources_id"), "email_sources", ["id"], unique=False)
    if "ix_email_sources_email_id" not in existing_indexes:
        op.create_index(op.f("ix_email_sources_email_id"), "email_sources", ["email_id"], unique=False)

    # ── received_hops: one row per Received header (parsed trace) ──
    if "received_hops" not in existing_tables:
        op.create_table(
            "received_hops",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("email_id", sa.Integer(), nullable=False),
            sa.Column("hop_index", sa.Integer(), nullable=False),
            sa.Column("raw", sa.Text(), nullable=True),
            sa.Column("from_host", sa.String(length=512), nullable=True),
            sa.Column("from_ip", sa.String(length=64), nullable=True),
            sa.Column("helo", sa.String(length=512), nullable=True),
            sa.Column("by_host", sa.String(length=512), nullable=True),
            sa.Column("via", sa.String(length=128), nullable=True),
            sa.Column("protocol", sa.String(length=128), nullable=True),
            sa.Column("timestamp_raw", sa.String(length=256), nullable=True),
            sa.Column("timestamp_utc", sa.DateTime(), nullable=True),
            sa.Column("ptr_host", sa.String(length=512), nullable=True),
            sa.Column("is_internal", sa.Boolean(), nullable=False),
            sa.Column("parse_confidence", sa.Float(), nullable=False),
            sa.ForeignKeyConstraint(["email_id"], ["emails.id"]),
            sa.PrimaryKeyConstraint("id"),
        )
    if "ix_received_hops_id" not in existing_indexes:
        op.create_index(op.f("ix_received_hops_id"), "received_hops", ["id"], unique=False)
    if "ix_received_hops_email_id" not in existing_indexes:
        op.create_index(op.f("ix_received_hops_email_id"), "received_hops", ["email_id"], unique=False)
    if "ix_received_hops_email_hop" not in existing_indexes:
        op.create_index(
            "ix_received_hops_email_hop",
            "received_hops",
            ["email_id", "hop_index"],
            unique=False,
        )

    # ── auth_results: SPF / DKIM / DMARC outcome ──
    if "auth_results" not in existing_tables:
        op.create_table(
            "auth_results",
            sa.Column("id", sa.Integer(), nullable=False),
            sa.Column("email_id", sa.Integer(), nullable=False),
            sa.Column("spf_result", sa.String(length=32), nullable=True),
            sa.Column("spf_domain", sa.String(length=256), nullable=True),
            sa.Column("dkim_result", sa.String(length=32), nullable=True),
            sa.Column("dkim_domain", sa.String(length=256), nullable=True),
            sa.Column("dkim_selector", sa.String(length=128), nullable=True),
            sa.Column("dmarc_result", sa.String(length=32), nullable=True),
            sa.Column("dmarc_domain", sa.String(length=256), nullable=True),
            sa.Column("alignment", sa.String(length=32), nullable=True),
            sa.Column("source", sa.String(length=16), nullable=True),
            sa.Column("detail_json", sa.JSON(), nullable=True),
            sa.Column("checked_at", sa.DateTime(), nullable=False),
            sa.ForeignKeyConstraint(["email_id"], ["emails.id"]),
            sa.PrimaryKeyConstraint("id"),
            sa.UniqueConstraint("email_id"),
        )
    if "ix_auth_results_id" not in existing_indexes:
        op.create_index(op.f("ix_auth_results_id"), "auth_results", ["id"], unique=False)
    if "ix_auth_results_email_id" not in existing_indexes:
        op.create_index(op.f("ix_auth_results_email_id"), "auth_results", ["email_id"], unique=False)

    # ── verdicts.header_score: fourth engine score ──
    verdict_cols = {
        c["name"] for c in inspector.get_columns("verdicts")
    } if "verdicts" in existing_tables else set()
    if "header_score" not in verdict_cols:
        op.add_column(
            "verdicts",
            sa.Column("header_score", sa.Float(), nullable=False, server_default="0"),
        )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)
    tables = inspector.get_table_names()
    if "verdicts" in tables:
        cols = {c["name"] for c in inspector.get_columns("verdicts")}
        if "header_score" in cols:
            op.drop_column("verdicts", "header_score")
    if "auth_results" in tables:
        op.drop_table("auth_results")
    if "received_hops" in tables:
        op.drop_table("received_hops")
    if "email_sources" in tables:
        op.drop_table("email_sources")
