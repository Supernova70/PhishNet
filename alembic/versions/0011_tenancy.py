"""tenancy — per-user ownership columns on all content tables (P2).

Adds nullable ``user_id`` (FK -> users.id) to: emails, scans, alerts,
campaigns, indicators, evidence_chain, audit_log, fetch_state.

Backfills every existing row to the first admin user (existing data
belongs to the operator per the multi-tenant plan). Rows left NULL when
no admin exists are invisible to content queries (safe default).

fetch_state: swaps the global unique(mailbox) cursor for
unique(user_id, mailbox) so each account has its own fetch cursor.

Revision ID: 0011
Revises: 0010
Create Date: 2026-10-01
"""
from typing import Sequence, Union

from sqlalchemy import inspect

from alembic import op
import sqlalchemy as sa

revision: str = '0011'
down_revision: Union[str, None] = '0010'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

CONTENT_TABLES = (
    "emails",
    "scans",
    "alerts",
    "campaigns",
    "indicators",
    "evidence_chain",
    "audit_log",
    "fetch_state",
)


def upgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)
    tables = inspector.get_table_names()

    # NOTE: SQLAlchemy inspectors cache table/column introspection — a
    # second get_columns() call in the same migration would return the
    # pre-add_column state. Track the qualifying tables in a plain list
    # instead of re-inspecting (re-inspecting silently skipped the
    # backfill and constraint swaps on Postgres).
    with_user: list[str] = []
    for table in CONTENT_TABLES:
        if table not in tables:
            continue
        cols = {c["name"] for c in inspector.get_columns(table)}
        if "user_id" not in cols:
            op.add_column(
                table,
                sa.Column("user_id", sa.Integer(), nullable=True),
            )
            op.create_foreign_key(
                f"fk_{table}_user_id", table, "users",
                ["user_id"], ["id"],
            )
            op.create_index(f"ix_{table}_user_id", table, ["user_id"])
        with_user.append(table)

    # emails.message_id: global unique → unique per (user, message)
    if "emails" in with_user:
        bind.execute(sa.text(
            "DROP INDEX IF EXISTS ix_emails_message_id"
        ))
        bind.execute(sa.text(
            "CREATE INDEX IF NOT EXISTS ix_emails_message_id "
            "ON emails (message_id)"
        ))
        bind.execute(sa.text(
            "CREATE UNIQUE INDEX IF NOT EXISTS uq_emails_user_message "
            "ON emails (user_id, message_id)"
        ))

    # fetch_state: one cursor per (user, mailbox) instead of per mailbox.
    if "fetch_state" in with_user:
        if bind.dialect.name == "postgresql":
            bind.execute(sa.text(
                "ALTER TABLE fetch_state "
                "DROP CONSTRAINT IF EXISTS fetch_state_mailbox_key"
            ))
            bind.execute(sa.text(
                "ALTER TABLE fetch_state "
                "ADD CONSTRAINT uq_fetch_state_user_mailbox "
                "UNIQUE (user_id, mailbox)"
            ))
        else:
            # SQLite cannot drop the inline unique auto-index —
            # rebuild the table with the composite constraint.
            op.create_table(
                "fetch_state_new",
                sa.Column("id", sa.Integer(), primary_key=True),
                sa.Column("user_id", sa.Integer(), nullable=True),
                sa.Column("mailbox", sa.String(length=256)),
                sa.Column("last_uid", sa.Integer()),
                sa.Column("last_fetched_at", sa.DateTime(), nullable=True),
                sa.UniqueConstraint(
                    "user_id", "mailbox",
                    name="uq_fetch_state_user_mailbox",
                ),
            )
            bind.execute(sa.text(
                "INSERT INTO fetch_state_new "
                "(id, user_id, mailbox, last_uid, last_fetched_at) "
                "SELECT id, user_id, mailbox, last_uid, last_fetched_at "
                "FROM fetch_state"
            ))
            op.drop_table("fetch_state")
            op.execute("ALTER TABLE fetch_state_new RENAME TO fetch_state")

    # Existing data belongs to the first admin account.
    admin = bind.execute(sa.text(
        "SELECT id FROM users WHERE role = 'admin' ORDER BY id LIMIT 1"
    )).scalar()
    if admin is None:
        return
    for table in with_user:
        bind.execute(
            sa.text(
                f"UPDATE {table} SET user_id = :uid WHERE user_id IS NULL"
            ),
            {"uid": admin},
        )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = inspect(bind)
    tables = inspector.get_table_names()

    if "fetch_state" in tables:
        fcols = {c["name"] for c in inspector.get_columns("fetch_state")}
        if "user_id" in fcols and bind.dialect.name == "postgresql":
            bind.execute(sa.text(
                "ALTER TABLE fetch_state "
                "DROP CONSTRAINT IF EXISTS uq_fetch_state_user_mailbox"
            ))
            bind.execute(sa.text(
                "ALTER TABLE fetch_state "
                "ADD CONSTRAINT fetch_state_mailbox_key UNIQUE (mailbox)"
            ))

    if "emails" in tables:
        bind.execute(sa.text("DROP INDEX IF EXISTS uq_emails_user_message"))
        bind.execute(sa.text(
            "DROP INDEX IF EXISTS ix_emails_message_id"
        ))
        # Restoring the global uniqueness is impossible once two accounts
        # ingested the same message-id (the normal multi-tenant state) —
        # fall back to a plain index so downgrade never destroys rows.
        try:
            with bind.begin_nested():
                bind.execute(sa.text(
                    "CREATE UNIQUE INDEX ix_emails_message_id "
                    "ON emails (message_id)"
                ))
        except Exception:
            bind.execute(sa.text(
                "CREATE INDEX IF NOT EXISTS ix_emails_message_id "
                "ON emails (message_id)"
            ))

    for table in CONTENT_TABLES:
        if table not in tables:
            continue
        cols = {c["name"] for c in inspector.get_columns(table)}
        if "user_id" not in cols:
            continue
        op.drop_index(f"ix_{table}_user_id", table_name=table)
        op.drop_constraint(f"fk_{table}_user_id", table, type_="foreignkey")
        op.drop_column(table, "user_id")
