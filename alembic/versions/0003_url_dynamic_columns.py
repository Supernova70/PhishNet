"""add dynamic URL analysis columns (schema-drift fix)

Revision ID: 0003
Revises: 0002
Create Date: 2026-09-29

scan_service.py has been reading dynamic_status, dynamic_flags,
dynamic_error, final_url, external_form_action, download_attempted,
popup_attempted and dynamic_elapsed_ms from in-memory results since the
dynamic URL engine shipped, but no migration added the matching columns
and UrlResult persistence silently dropped them. This migration closes
that gap.

Guarded with per-column existence checks so it is safe on both a fresh
database and an existing one.
"""
from typing import Sequence, Union

from sqlalchemy import inspect, Boolean, Integer, JSON, String

from alembic import op
import sqlalchemy as sa

revision: str = '0003'
down_revision: Union[str, None] = '0002'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_NEW_COLUMNS = [
    ("dynamic_status", String(length=32)),
    ("dynamic_flags", JSON()),
    ("dynamic_error", String(length=512)),
    ("final_url", String(length=2048)),
    ("external_form_action", Boolean()),
    ("download_attempted", Boolean()),
    ("popup_attempted", Boolean()),
    ("dynamic_elapsed_ms", Integer()),
]


def upgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)
    if "url_results" not in inspector.get_table_names():
        return
    existing = {c["name"] for c in inspector.get_columns("url_results")}
    for name, col_type in _NEW_COLUMNS:
        if name not in existing:
            op.add_column("url_results", sa.Column(name, col_type, nullable=True))


def downgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)
    if "url_results" not in inspector.get_table_names():
        return
    existing = {c["name"] for c in inspector.get_columns("url_results")}
    for name, _ in reversed(_NEW_COLUMNS):
        if name in existing:
            op.drop_column("url_results", name)
