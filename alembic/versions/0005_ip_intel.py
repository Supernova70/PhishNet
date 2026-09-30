"""ip_intel: cached geolocation / ASN / reputation per IP

Revision ID: 0005
Revises: 0004
Create Date: 2026-09-29

SIH 26106 — Origin Traceability and Location Analysis.
Guarded with existence checks so it is safe on fresh and existing databases.
"""
from typing import Sequence, Union

from sqlalchemy import inspect
from alembic import op
import sqlalchemy as sa

revision: str = '0005'
down_revision: Union[str, None] = '0004'
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

    if "ip_intel" not in existing_tables:
        op.create_table(
            "ip_intel",
            sa.Column("ip", sa.String(length=64), nullable=False),
            sa.Column("country", sa.String(length=128), nullable=True),
            sa.Column("country_code", sa.String(length=8), nullable=True),
            sa.Column("region", sa.String(length=128), nullable=True),
            sa.Column("city", sa.String(length=128), nullable=True),
            sa.Column("lat", sa.Float(), nullable=True),
            sa.Column("lon", sa.Float(), nullable=True),
            sa.Column("asn", sa.Integer(), nullable=True),
            sa.Column("asn_org", sa.String(length=256), nullable=True),
            sa.Column("isp", sa.String(length=256), nullable=True),
            sa.Column("ptr_host", sa.String(length=512), nullable=True),
            sa.Column("is_vpn", sa.Boolean(), nullable=False),
            sa.Column("is_tor", sa.Boolean(), nullable=False),
            sa.Column("is_proxy", sa.Boolean(), nullable=False),
            sa.Column("is_hosting", sa.Boolean(), nullable=False),
            sa.Column("is_dnsbl_listed", sa.Boolean(), nullable=False),
            sa.Column("dnsbl_json", sa.JSON(), nullable=True),
            sa.Column("raw_json", sa.JSON(), nullable=True),
            sa.Column("source", sa.String(length=64), nullable=True),
            sa.Column("fetched_at", sa.DateTime(), nullable=False),
            sa.Column("expires_at", sa.DateTime(), nullable=True),
            sa.PrimaryKeyConstraint("ip"),
        )
    if "ix_ip_intel_expires_at" not in existing_indexes:
        op.create_index(op.f("ix_ip_intel_expires_at"), "ip_intel", ["expires_at"], unique=False)


def downgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)
    if "ip_intel" in inspector.get_table_names():
        op.drop_index(op.f("ix_ip_intel_expires_at"), table_name="ip_intel")
        op.drop_table("ip_intel")
