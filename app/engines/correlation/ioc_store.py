"""Indicator extraction — the IoCs each scan contributes to correlation.

`extract_indicators` is pure (email fields + engine outputs in,
(type, value) pairs out) so tests need no database. `store_indicators`
upserts the pairs into the global `indicators` table: first sighting
creates the row, later sightings bump count/last_seen.
"""

from __future__ import annotations

from datetime import datetime
from typing import Iterable, List, Optional, Sequence, Tuple

from app.engines.headers.common import domain_of, registrable_domain
from app.models.indicator import Indicator

IndicatorPair = Tuple[str, str]  # (type, value)


def extract_indicators(
    *,
    sender: Optional[str] = None,
    headers: Optional[dict] = None,
    subject: str = "",
    attachments: Sequence = (),
    url_domains: Sequence[str] = (),
    origin_ip: Optional[str] = None,
    lookalike_brand: Optional[str] = None,
) -> List[IndicatorPair]:
    """Pull correlation-ready IoCs out of one email's scan results."""
    headers = headers or {}
    pairs: List[IndicatorPair] = []
    seen = set()

    def add(kind: str, value: Optional[str]) -> None:
        if not value:
            return
        value = str(value).strip().lower()
        if not value or (kind, value) in seen:
            return
        seen.add((kind, value))
        pairs.append((kind, value))

    add("sender_domain", domain_of(sender))

    reply_to = (headers.get("reply-to") or [None])[0]
    if reply_to:
        add("replyto_domain", domain_of(reply_to))

    if origin_ip:
        add("origin_ip", origin_ip)

    for raw in url_domains:
        host = domain_of(str(raw))
        reg = registrable_domain(host) if host else None
        add("url_domain", reg)

    for att in attachments:
        sha = getattr(att, "sha256_hash", None)
        if isinstance(att, dict):
            sha = att.get("sha256")
        if sha:
            add("attachment_hash", sha)

    if lookalike_brand:
        add("lookalike_brand", lookalike_brand)

    return pairs


def store_indicators(
    db,
    scan_id: int,
    pairs: Iterable[IndicatorPair],
    now: Optional[datetime] = None,
) -> List[Indicator]:
    """
    Upsert indicator rows for one scan (per-scan unique). Re-storing the
    same scan bumps sighting_count; other scans get their own rows.
    """
    now = now or datetime.utcnow()
    touched: List[Indicator] = []
    for kind, value in pairs:
        row = (
            db.query(Indicator)
            .filter(
                Indicator.scan_id == scan_id,
                Indicator.type == kind,
                Indicator.value == value,
            )
            .first()
        )
        if row is None:
            row = Indicator(
                scan_id=scan_id,
                type=kind,
                value=value,
                first_seen=now,
                last_seen=now,
                sighting_count=1,
            )
            db.add(row)
        else:
            row.last_seen = now
            row.sighting_count += 1
        touched.append(row)
    return touched
