"""Campaign clustering — union-find over shared high-value IoCs.

Plan §Week 2: union scans sharing any of origin_ip / replyto_domain /
lookalike_brand / url registrable domain, then an optional subject-
similarity pass (TF-IDF cosine ≥ 0.72) among scans impersonating the
same brand.

`cluster_scans` is pure (plain dicts in → clusters out); `save_clusters`
persists results into `campaigns` + `scans.campaign_id`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Sequence, Tuple

HIGH_VALUE_IOC_TYPES = ("origin_ip", "replyto_domain", "lookalike_brand", "url_domain")
# Brands alone do not merge campaigns (two unrelated PayPal lures are two
# campaigns); brand-linked joining additionally requires subject similarity.
LINKING_IOC_TYPES = ("origin_ip", "replyto_domain", "url_domain")
SUBJECT_SIMILARITY_THRESHOLD = 0.72

# Subject → tactic vocabulary for self-explanatory campaign names.
# Order matters: ties in the vote are broken by pattern order.
_TACTIC_PATTERNS: Tuple[Tuple[str, str], ...] = (
    (
        r"\b(invoice|payment|payout|refund|receipt|billing|paypal|venmo|zelle|"
        r"wire transfer|bank transfer|payroll|card ending)\b",
        "payment lure",
    ),
    (
        r"\b(password|credential|verify|verification|sign\s*[- ]?in|signin|"
        r"login|log[- ]?in|unlock|suspended|locked|deactivat\w*|otp|2fa|mfa|"
        r"confirm your (account|identity)|validate your)\b",
        "credential phishing",
    ),
    (
        r"\b(delivery|parcel|package|shipping|tracking number|dhl|fedex|usps|"
        r"ups mail|customs)\b",
        "delivery notice",
    ),
    (
        r"\b(documents?|shared? (a|the) file|google docs?|dropbox|onedrive|"
        r"attachment|view (the )?file|open (the )?attachment|docusign|esign)\b",
        "document share lure",
    ),
    (
        r"\b(job|hiring|interview|recruitment|salary|vacancy|apply now)\b",
        "job offer scam",
    ),
    (
        r"\b(urgent|ceo|wire|funds? transfer|bank details|approve|authoriz\w+)\b",
        "CEO/wire fraud",
    ),
    (
        r"\b(security alert|unusual (sign-?in|activity)|suspicious (activity|"
        r"login)|compromised|unauthori[sz]ed|action required)\b",
        "security alert lure",
    ),
    (
        r"\b(kyc|tax return|irs|government|ministry|official notice)\b",
        "official impersonation",
    ),
    (
        r"\b(update your|renewal|expir\w+|reactivate|restore your)\b",
        "account update lure",
    ),
)


@dataclass
class ScanInput:
    id: int
    subject: str = ""
    score: float = 0.0
    indicators: Sequence[Tuple[str, str]] = ()  # (type, value)
    sent_at: Optional[datetime] = None

    @property
    def high_value(self) -> Dict[str, set]:
        out: Dict[str, set] = {}
        for kind, value in self.indicators:
            if kind in HIGH_VALUE_IOC_TYPES:
                out.setdefault(kind, set()).add(str(value).lower())
        return out

    @property
    def linking_iocs(self) -> Dict[str, set]:
        out: Dict[str, set] = {}
        for kind, value in self.indicators:
            if kind in LINKING_IOC_TYPES:
                out.setdefault(kind, set()).add(str(value).lower())
        return out


@dataclass
class CampaignCluster:
    scan_ids: List[int]
    name: str
    confidence: float
    shared_iocs: Dict[str, List[str]] = field(default_factory=dict)
    avg_score: float = 0.0
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None

    @property
    def email_count(self) -> int:
        return len(self.scan_ids)


class _UnionFind:
    def __init__(self, ids: Sequence[int]):
        self.parent = {i: i for i in ids}

    def find(self, x: int) -> int:
        root = x
        while self.parent[root] != root:
            root = self.parent[root]
        while self.parent[x] != root:  # path compression
            self.parent[x], x = root, self.parent[x]
        return root

    def union(self, a: int, b: int) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[rb] = ra


def _subject_cosine(subjects: List[str]) -> List[List[float]]:
    """TF-IDF cosine similarity matrix (sklearn imported lazily)."""
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.metrics.pairwise import cosine_similarity

    if not subjects:
        return []
    vectorizer = TfidfVectorizer(stop_words="english", lowercase=True)
    try:
        matrix = vectorizer.fit_transform(subjects)
    except ValueError:
        # e.g. every subject empty → all similarities 0
        return [[0.0] * len(subjects) for _ in subjects]
    sim = cosine_similarity(matrix)
    return sim.tolist()


def cluster_scans(
    scans: Sequence[ScanInput],
    subject_similarity_threshold: float = SUBJECT_SIMILARITY_THRESHOLD,
) -> List[CampaignCluster]:
    if not scans:
        return []

    uf = _UnionFind([s.id for s in scans])

    # ── Pass 1: shared high-value IoCs (non-brand) ────────────────────
    # value → list of scan ids holding it (per type)
    ioc_index: Dict[Tuple[str, str], List[int]] = {}
    for scan in scans:
        for kind, values in scan.linking_iocs.items():
            for v in values:
                ioc_index.setdefault((kind, v), []).append(scan.id)

    for (kind, value), holder_ids in ioc_index.items():
        for other in holder_ids[1:]:
            uf.union(holder_ids[0], other)

    # ── Pass 2: same-brand subject similarity ────────────────────────
    brand_of = {s.id: s.high_value.get("lookalike_brand", set()) for s in scans}
    subjects = [s.subject or "" for s in scans]
    similarity = _subject_cosine(subjects)
    index_by_id = {s.id: i for i, s in enumerate(scans)}

    for i, a in enumerate(scans):
        for b in scans[i + 1:]:
            if uf.find(a.id) == uf.find(b.id):
                continue
            shared_brands = brand_of[a.id] & brand_of[b.id]
            if not shared_brands:
                continue
            sim = similarity[index_by_id[a.id]][index_by_id[b.id]]
            if sim >= subject_similarity_threshold:
                uf.union(a.id, b.id)

    # ── Materialize clusters ─────────────────────────────────────────
    groups: Dict[int, List[ScanInput]] = {}
    for scan in scans:
        groups.setdefault(uf.find(scan.id), []).append(scan)

    clusters: List[CampaignCluster] = []
    for members in groups.values():
        if len(members) < 1:
            continue
        clusters.append(_build_cluster(members, subject_similarity_threshold))

    # Stable output order: biggest / riskiest first
    clusters.sort(key=lambda c: (c.email_count, c.avg_score), reverse=True)
    return clusters


def _build_cluster(
    members: List[ScanInput], subject_sim_threshold: float
) -> CampaignCluster:
    # Shared IoCs = present in every member
    shared: Dict[str, List[str]] = {}
    per_scan = [m.high_value for m in members]
    for kind in HIGH_VALUE_IOC_TYPES:
        common = set.intersection(
            *(s.get(kind, set()) for s in per_scan)
        ) if per_scan else set()
        if common:
            shared[kind] = sorted(common)

    scores = [m.score for m in members]
    dates = [m.sent_at for m in members if m.sent_at]

    # Confidence: IOC breadth dominates; subject similarity is a bonus
    confidence = 0.4 + 0.2 * len(shared)
    if len(members) > 1 and not shared:
        # Joined purely via same-brand subject similarity
        confidence = 0.55
    confidence = min(0.95, confidence)

    name = _derive_name(shared, members)
    return CampaignCluster(
        scan_ids=sorted(m.id for m in members),
        name=name,
        confidence=round(confidence, 2),
        shared_iocs=shared,
        avg_score=round(sum(scores) / len(scores), 1) if scores else 0.0,
        first_seen=min(dates) if dates else None,
        last_seen=max(dates) if dates else None,
    )


def _derive_tactic(members: Sequence["ScanInput"]) -> Optional[str]:
    """Most frequent tactic keyword group across member subjects."""
    text = " ".join((m.subject or "") for m in members).lower()
    if not text.strip():
        return None
    votes: Dict[str, int] = {}
    for pattern, label in _TACTIC_PATTERNS:
        n = len(re.findall(pattern, text))
        if n:
            votes[label] = votes.get(label, 0) + n
    if not votes:
        return None
    # dict order == pattern order → ties resolved toward the earlier pattern
    return max(votes.items(), key=lambda kv: kv[1])[0]


def _derive_name(shared: Dict[str, List[str]], members: List[ScanInput]) -> str:
    tactic = _derive_tactic(members)
    brand = (shared.get("lookalike_brand") or [None])[0]
    infra = (shared.get("replyto_domain") or shared.get("url_domain") or [None])[0]

    if brand and tactic:
        return f"{brand} {tactic}"
    if brand:
        return f"{brand} impersonation"
    if tactic and infra:
        return f"{tactic} via {infra}"
    if tactic:
        return f"{tactic} campaign"
    # No brand/tactic signal — fall back to the linking infrastructure
    if shared.get("replyto_domain"):
        return f"replies → {shared['replyto_domain'][0]}"
    if shared.get("origin_ip"):
        return f"origin {shared['origin_ip'][0]}"
    if shared.get("url_domain"):
        return f"links → {shared['url_domain'][0]}"
    return f"campaign {min(m.id for m in members)}"


def save_clusters(
    db, clusters: Sequence[CampaignCluster], user_id: Optional[int] = None
) -> list:
    """
    Persist clusters (campaign rows + scan membership). Clears old links.

    Only multi-scan clusters become campaigns — a singleton is just one
    email, not a campaign, and stays with campaign_id = NULL.
    user_id scopes the rebuild to one account (tenancy).
    """
    from app.models.campaign import Campaign
    from app.models.scan import Scan

    detach = db.query(Scan).filter(Scan.campaign_id.isnot(None))
    purge = db.query(Campaign)
    if user_id is not None:
        detach = detach.filter(Scan.user_id == user_id)
        purge = purge.filter(Campaign.user_id == user_id)
    detach.update({Scan.campaign_id: None}, synchronize_session=False)
    for campaign in purge.all():
        db.delete(campaign)
    db.flush()

    created = []
    for cluster in clusters:
        if cluster.email_count < 2:
            continue
        campaign = Campaign(
            user_id=user_id,
            name=cluster.name,
            first_seen=cluster.first_seen,
            last_seen=cluster.last_seen,
            email_count=cluster.email_count,
            avg_score=cluster.avg_score,
            status="open",
            confidence=cluster.confidence,
            summary_json={"shared_iocs": cluster.shared_iocs},
        )
        db.add(campaign)
        db.flush()
        membership = db.query(Scan).filter(Scan.id.in_(cluster.scan_ids))
        if user_id is not None:
            membership = membership.filter(Scan.user_id == user_id)
        membership.update(
            {Scan.campaign_id: campaign.id}, synchronize_session=False
        )
        created.append(campaign)
    return created
