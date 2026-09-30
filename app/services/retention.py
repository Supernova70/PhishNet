"""Retention purge — enforces RETENTION_DAYS on evidence artifacts.

Policy (plan §Compliance):
- deletes raw `.eml.gz` files and URL screenshots older than the cutoff
- nulls `email_sources.raw_path` for purged files (headers JSON stays)
- removes expired `ip_intel` cache rows (derived data)
- keeps verdicts/scans/emails unless `include_verdicts=True`
- appends an audit row for every non-dry-run purge
"""

import os
import shutil
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

from sqlalchemy.orm import Session

from app.config import get_settings
from app.models.audit_log import AuditLog
from app.models.email import Email
from app.models.email_source import EmailSource
from app.models.ip_intel import IpIntel
from app.models.scan import Scan, Verdict


def purge(
    db: Session,
    *,
    retention_days: Optional[int] = None,
    now: Optional[datetime] = None,
    dry_run: bool = False,
    include_verdicts: bool = False,
    screenshot_dir: Optional[Path] = None,
) -> dict:
    """Run one retention pass. Returns a summary dict; in dry-run mode
    nothing is deleted or written."""
    settings = get_settings()
    days = retention_days if retention_days is not None else settings.RETENTION_DAYS
    now = now or datetime.utcnow()
    cutoff = now - timedelta(days=days)
    summary = {
        "cutoff": cutoff.isoformat(),
        "retention_days": days,
        "dry_run": dry_run,
        "raw_files_deleted": 0,
        "raw_paths_cleared": 0,
        "screenshots_deleted": 0,
        "ip_intel_rows_deleted": 0,
        "verdicts_deleted": 0,
        "emails_affected": 0,
    }

    # ── raw message files for emails past the cutoff ───────────
    old_emails = db.query(Email).filter(Email.fetched_at < cutoff).all()
    summary["emails_affected"] = len(old_emails)
    for email in old_emails:
        source = email.source
        if source is None or not source.raw_path:
            continue
        path = Path(source.raw_path)
        if path.is_file():
            summary["raw_files_deleted"] += 1
            if not dry_run:
                path.unlink(missing_ok=True)
        if source.raw_path:
            summary["raw_paths_cleared"] += 1
            if not dry_run:
                source.raw_path = None

    # ── screenshots (mtime-based; derived browser evidence) ────
    shot_dir = screenshot_dir or Path(settings.DYNAMIC_URL_SCREENSHOT_DIR)
    if shot_dir.is_dir():
        cutoff_ts = cutoff.timestamp()
        for root, _dirs, files in os.walk(shot_dir):
            for name in files:
                p = Path(root) / name
                try:
                    if p.stat().st_mtime < cutoff_ts:
                        summary["screenshots_deleted"] += 1
                        if not dry_run:
                            p.unlink(missing_ok=True)
                except OSError:
                    continue
        if not dry_run:  # prune emptied directories
            shutil.rmtree(shot_dir, ignore_errors=True)
            shot_dir.mkdir(parents=True, exist_ok=True)

    # ── expired geo/ASN cache rows (always regenerable) ────────
    expired = db.query(IpIntel).filter(IpIntel.expires_at < now)
    summary["ip_intel_rows_deleted"] = expired.count()
    if not dry_run:
        expired.delete(synchronize_session=False)

    # ── verdicts: never touched without the explicit flag ──────
    if include_verdicts and old_emails:
        old_ids = [e.id for e in old_emails]
        scan_ids = [
            sid
            for (sid,) in db.query(Scan.id).filter(Scan.email_id.in_(old_ids)).all()
        ]
        if scan_ids:
            victims = db.query(Verdict).filter(Verdict.scan_id.in_(scan_ids))
            summary["verdicts_deleted"] = victims.count()
            if not dry_run:
                victims.delete(synchronize_session=False)

    if dry_run:
        return summary

    if any(
        summary[k]
        for k in (
            "raw_files_deleted",
            "raw_paths_cleared",
            "screenshots_deleted",
            "ip_intel_rows_deleted",
            "verdicts_deleted",
        )
    ):
        db.add(
            AuditLog(
                actor="retention",
                action="retention_purge",
                entity_type="system",
                detail_json={k: v for k, v in summary.items()},
            )
        )
    db.commit()
    return summary
