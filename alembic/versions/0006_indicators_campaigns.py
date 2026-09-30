"""indicators + campaigns (correlation & attribution)

Revision ID: 0006
Revises: 0005
Create Date: 2026-09-29

Adds:
  - indicators: deduplicated IoCs shared across scans (graph source)
  - campaigns: clustered phishing runs
  - scans.campaign_id: nullable membership link

Guarded with existence checks so it is safe on fresh and existing DBs.
"""
from typing import Sequence, Union

from sqlalchemy import inspect

from alembic import op
import sqlalchemy as sa

revision: str = '0006'
down_revision: Union[str, None] = '0005'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)
    tables = set(inspector.get_table_names())

    if "indicators" not in tables:
        op.create_table(
            "indicators",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("scan_id", sa.Integer(), nullable=True),
            sa.Column("type", sa.String(length=32), nullable=False),
            sa.Column("value", sa.String(length=512), nullable=False),
            sa.Column("first_seen", sa.DateTime(), nullable=False),
            sa.Column("last_seen", sa.DateTime(), nullable=False),
            sa.Column("sighting_count", sa.Integer(), nullable=False,
                      server_default="1"),
            sa.UniqueConstraint(
                "scan_id", "type", "value",
                name="uq_indicator_scan_type_value",
            ),
        )
        op.create_index("ix_indicators_scan_id", "indicators", ["scan_id"])

    if "campaigns" not in tables:
        op.create_table(
            "campaigns",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("name", sa.String(length=256), nullable=False),
            sa.Column("first_seen", sa.DateTime(), nullable=True),
            sa.Column("last_seen", sa.DateTime(), nullable=True),
            sa.Column("email_count", sa.Integer(), nullable=False,
                      server_default="0"),
            sa.Column("avg_score", sa.Float(), nullable=False,
                      server_default="0"),
            sa.Column("status", sa.String(length=32), nullable=False,
                      server_default="open"),
            sa.Column("confidence", sa.Float(), nullable=False,
                      server_default="0"),
            sa.Column("summary_json", sa.JSON(), nullable=True),
        )
        op.create_index("ix_campaigns_status", "campaigns", ["status"])

    if "scans" in tables:
        scan_cols = {c["name"] for c in inspector.get_columns("scans")}
        if "campaign_id" not in scan_cols:
            op.add_column(
                "scans",
                sa.Column("campaign_id", sa.Integer(), nullable=True),
            )
            op.create_index("ix_scans_campaign_id", "scans", ["campaign_id"])


def downgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)
    tables = set(inspector.get_table_names())

    if "scans" in tables:
        scan_cols = {c["name"] for c in inspector.get_columns("scans")}
        if "campaign_id" in scan_cols:
            op.drop_index("ix_scans_campaign_id", table_name="scans")
            op.drop_column("scans", "campaign_id")

    if "campaigns" in tables:
        op.drop_index("ix_campaigns_status", table_name="campaigns")
        op.drop_table("campaigns")

    if "indicators" in tables:
        op.drop_index("ix_indicators_scan_id", table_name="indicators")
        op.drop_table("indicators")
