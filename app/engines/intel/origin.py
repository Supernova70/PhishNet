"""Origin trace: earliest external hop of a Received chain.

Hop rows are stored chronological (hop 0 = earliest, closest to the
origin MTA / sender infrastructure). The origin IP is the first hop
that left a private network — that is the address geo/ASN/reputation
intelligence should target.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Iterable, Optional


@dataclass
class OriginTrace:
    ip: str
    hop_index: int
    from_host: Optional[str]
    helo: Optional[str]
    by_host: Optional[str]
    timestamp_utc: Optional[datetime]
    is_internal: bool

    def to_dict(self) -> dict:
        ts = self.timestamp_utc
        if isinstance(ts, datetime):
            ts = ts.isoformat()  # accepts pre-serialized strings too
        return {
            "ip": self.ip,
            "hop_index": self.hop_index,
            "from_host": self.from_host,
            "helo": self.helo,
            "by_host": self.by_host,
            "timestamp_utc": ts,
            "is_internal": self.is_internal,
        }


def build_origin_trace(hops: Iterable[Any]) -> Optional[OriginTrace]:
    """
    Accepts ParsedHop instances, ReceivedHop ORM rows, or dicts with the
    same field names (chronological order, hop 0 earliest).
    """
    ordered = list(hops)
    fallback: Optional[OriginTrace] = None
    for index, hop in enumerate(ordered):
        ip = _get(hop, "from_ip")
        if not ip:
            continue
        trace = OriginTrace(
            ip=ip,
            hop_index=index,
            from_host=_get(hop, "from_host"),
            helo=_get(hop, "helo"),
            by_host=_get(hop, "by_host"),
            timestamp_utc=_get(hop, "timestamp_utc"),
            is_internal=bool(_get(hop, "is_internal", False)),
        )
        if not trace.is_internal:
            return trace  # first external hop wins
        if fallback is None:
            fallback = trace
    return fallback  # chain is entirely internal — still report something


def _get(obj: Any, name: str, default: Any = None) -> Any:
    if isinstance(obj, dict):
        return obj.get(name, default)
    return getattr(obj, name, default)
