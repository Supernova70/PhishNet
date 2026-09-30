#!/usr/bin/env python3
"""Backfill raw RFC822 evidence for emails ingested before retention.

Plan §4, B6. Emails imported before `PRESERVE_RAW_EMAIL` existed (or
before raw retention was enabled) have an `email_sources` row with no
`raw_sha256` — or no row at all. When the mailbox still holds them,
this script re-fetches the original bytes over IMAP (searched by
Message-ID) and rebuilds the full evidence set:

  - gzipped raw bytes         → settings.raw_email_dir/{email_id}.eml.gz
  - email_sources row         (upsert: raw_path / raw_sha256 / headers)
  - received_hops + auth_results (rebuilt from the fetched headers)

Behaviour:
  - one mailbox connection for the whole run; Message-IDs absent from
    the mailbox are counted as "not found" (corpus imports, expired
    mail) and never fatal;
  - per-email failures are logged and counted, the run continues;
  - `--dry-run` reports what would change without writing anything.

Run inside the backend container (needs DATABASE_URL + IMAP creds):

    docker compose -f docker-compose.prod.yml exec backend \\
        python scripts/backfill_raw_email.py --limit 50
"""

from __future__ import annotations

import argparse
import sys
from email import policy
from email.parser import BytesParser
from typing import Dict, List, Optional

from imapclient import IMAPClient

from app.config import get_settings
from app.dependencies import SessionLocal
from app.models.email import Email
from app.models.email_source import AuthResult, EmailSource, ReceivedHop
from app.services.email_service import EmailService

settings = get_settings()


def _normalize_message_id(value: str) -> str:
    value = (value or "").strip()
    if value and not value.startswith("<"):
        value = f"<{value}>"
    return value


def _headers_map(parsed) -> Dict[str, List[str]]:
    """{lowercase-name: [values...]} — same shape as EmailService stores."""
    headers: Dict[str, List[str]] = {}
    for name, value in parsed.items():
        headers.setdefault(name.lower(), []).append(str(value))
    return headers


def _targets(db, limit: Optional[int], email_ids: List[int]):
    """Emails missing raw evidence (no source row / no sha256)."""
    rows = (
        db.query(Email, EmailSource)
        .outerjoin(EmailSource, EmailSource.email_id == Email.id)
        .filter(
            (EmailSource.id.is_(None)) | (EmailSource.raw_sha256.is_(None))
        )
        .order_by(Email.id)
    )
    if email_ids:
        rows = rows.filter(Email.id.in_(email_ids))
    if limit:
        rows = rows.limit(limit)
    return [email for email, _ in rows.all()]


def _clear_evidence(db, email_id: int) -> None:
    """Remove prior (incomplete) evidence rows before rebuilding."""
    db.query(AuthResult).filter(AuthResult.email_id == email_id).delete(
        synchronize_session=False
    )
    db.query(ReceivedHop).filter(ReceivedHop.email_id == email_id).delete(
        synchronize_session=False
    )
    db.query(EmailSource).filter(EmailSource.email_id == email_id).delete(
        synchronize_session=False
    )


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--limit", type=int, default=0,
        help="max emails to process (0 = all missing evidence)",
    )
    parser.add_argument(
        "--message-id", action="append", default=[],
        help="backfill only this Message-ID (repeatable)",
    )
    parser.add_argument(
        "--email-id", action="append", type=int, default=[],
        help="backfill only this email id (repeatable)",
    )
    parser.add_argument(
        "--mailbox", default="INBOX", help="IMAP mailbox (default: INBOX)",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="report targets and IMAP matches without writing",
    )
    args = parser.parse_args(argv)

    db = SessionLocal()
    service = EmailService(db)
    stats = {"backfilled": 0, "not_found": 0, "no_message_id": 0, "failed": 0}

    try:
        wanted_mids = {
            _normalize_message_id(mid) for mid in args.message_id
        }
        targets = _targets(db, args.limit or None, args.email_id)
        if wanted_mids:
            targets = [
                e for e in targets
                if _normalize_message_id(e.message_id or "") in wanted_mids
            ] or [
                e for e in db.query(Email)
                .filter(Email.message_id.in_(wanted_mids)).all()
            ]

        print(f"backfill_raw_email: {len(targets)} email(s) missing raw evidence")

        if not targets:
            return 0

        client = IMAPClient(
            settings.EMAIL_HOST,
            port=settings.EMAIL_PORT,
            ssl=True,
            use_uid=True,
        )
        try:
            client.login(settings.EMAIL_ADDRESS, settings.EMAIL_PASSWORD)
            client.select_folder(args.mailbox, readonly=True)
        except Exception as exc:  # noqa: BLE001 — mailbox down is fatal here
            print(f"ERROR: IMAP connection failed: {exc}", file=sys.stderr)
            client.logout()
            return 1

        try:
            for email_obj in targets:
                mid = _normalize_message_id(email_obj.message_id or "")
                if not mid:
                    stats["no_message_id"] += 1
                    print(f"  email {email_obj.id}: no Message-ID — skipped")
                    continue

                try:
                    uids = client.search(["HEADER", "Message-ID", mid])
                except Exception as exc:  # noqa: BLE001
                    stats["failed"] += 1
                    print(f"  email {email_obj.id}: search failed: {exc}")
                    continue

                if not uids:
                    stats["not_found"] += 1
                    print(f"  email {email_obj.id}: not in mailbox ({mid})")
                    continue

                try:
                    payload = client.fetch([uids[0]], ["RFC822"])[uids[0]]
                    raw_bytes = payload[b"RFC822"]
                except Exception as exc:  # noqa: BLE001
                    stats["failed"] += 1
                    print(f"  email {email_obj.id}: fetch failed: {exc}")
                    continue

                if args.dry_run:
                    print(
                        f"  email {email_obj.id}: WOULD backfill "
                        f"{len(raw_bytes)} bytes from uid {uids[0]}"
                    )
                    stats["backfilled"] += 1
                    continue

                try:
                    parsed = BytesParser(policy=policy.default).parsebytes(
                        raw_bytes
                    )
                    _clear_evidence(db, email_obj.id)
                    service._store_email_source(  # noqa: SLF001 — same writer
                        email_obj, raw_bytes, _headers_map(parsed)
                    )
                    db.commit()

                    check = (
                        db.query(EmailSource)
                        .filter(EmailSource.email_id == email_obj.id)
                        .first()
                    )
                    if check is not None and check.raw_sha256:
                        stats["backfilled"] += 1
                        print(
                            f"  email {email_obj.id}: backfilled "
                            f"({check.size_bytes} bytes, headers restored)"
                        )
                    else:
                        stats["failed"] += 1
                        db.rollback()
                        print(
                            f"  email {email_obj.id}: evidence row not "
                            "written (PRESERVE_RAW_EMAIL off?)"
                        )
                except Exception as exc:  # noqa: BLE001 — per-email failure
                    db.rollback()
                    stats["failed"] += 1
                    print(f"  email {email_obj.id}: failed: {exc}")
        finally:
            try:
                client.logout()
            except Exception:  # noqa: BLE001
                pass

        print(
            "done: "
            f"backfilled={stats['backfilled']} "
            f"not_found={stats['not_found']} "
            f"no_message_id={stats['no_message_id']} "
            f"failed={stats['failed']}"
            + (" (dry-run: nothing written)" if args.dry_run else "")
        )
        return 0 if stats["failed"] == 0 else 1
    finally:
        db.close()


if __name__ == "__main__":
    raise SystemExit(main())
