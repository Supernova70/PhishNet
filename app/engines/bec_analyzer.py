"""BEC (Business Email Compromise) category engine — rules, not ML.

Pure, offline, deterministic. Each category aggregates weighted
regex/keyword signals from subject, body, and header values; a category
is reported when its confidence reaches CATEGORY_THRESHOLD (40). The
email-level `bec_score` is the strongest category confidence.

This is the rule/weak-supervision layer approved for Week 2; the
4-class ML retrain consumes the labels it produces (`export_bec_labels`)
and remains a stretch goal.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

CATEGORY_THRESHOLD = 40.0
SCORE_CAP = 100.0

# (pattern, weight, evidence label)
Rule = Tuple[str, float, str]


@dataclass
class BecCategoryMatch:
    category: str
    confidence: float
    evidence: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "category": self.category,
            "confidence": round(self.confidence, 1),
            "evidence": self.evidence,
        }


@dataclass
class BecResult:
    bec_score: float = 0.0
    categories: List[BecCategoryMatch] = field(default_factory=list)
    flags: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "bec_score": round(self.bec_score, 1),
            "categories": [c.to_dict() for c in self.categories],
            "flags": list(self.flags),
        }


# ── Rule tables (single source of truth; unit-tested directly) ───────

PAYMENT_DIVERSION: List[Rule] = [
    (r"\bnew\s+(bank\s+)?account\s+(details|number|info)", 30, "new bank account details"),
    (r"\b(beneficiary|iban|swift|bic|routing)\b", 20, "bank transfer identifiers"),
    (r"\b(update|change|changed|updated|changing)\b[^.]{0,40}\bbank\b", 25, "bank detail change"),
    (r"\baccount\s+details?\s+(have\s+)?(changed|updated|been updated)\b", 30, "account details changed"),
    (r"\bwire\s+(?:the\s+)?(transfer|payment|sum|amount)s?\b", 20, "wire transfer request"),
    (r"\bkindly\s+(make|process|send)\s+(the\s+)?payment\b", 25, "payment instruction"),
    (r"\b(payment|transfer)\s+(to\s+the\s+)?new\s+account\b", 30, "payment to new account"),
]

FAKE_INVOICE: List[Rule] = [
    (r"\binvoice\b", 15, "invoice mentioned"),
    (r"\b(purchase\s+order|po\s*#?\s*\d+)\b", 15, "purchase order reference"),
    (r"(?:\$|usd|eur|gbp|inr|₹)\s?[\d,]+(?:\.\d{2})?", 20, "monetary amount"),
    (r"\b(overdue|past\s+due|due\s+date|payment\s+due|kindly\s+pay)\b", 25, "payment deadline"),
    (r"\bquotation|quote\b", 10, "quote mentioned"),
    (r"\b(balance\s+due|outstanding\s+amount|amount\s+payable)\b", 25, "balance due"),
]

CREDENTIAL_HARVEST: List[Rule] = [
    (r"\b(verify|confirm)\b.{0,40}\b(account|identity|details|information)\b", 25,
     "account verification request"),
    (r"\b(suspended|suspension|locked|deactivated|disabled)\b.{0,40}\b(account|access|profile)\b", 30,
     "suspended/locked account"),
    (r"\b(sign\s?-?\s?in|log\s?-?\s?in|re-?authenticate|re-?verify)\b", 25,
     "login/re-authentication prompt"),
    (r"\b(update|change|reset)\b.{0,20}\b(password|credential)s?\b", 25,
     "password change request"),
    (r"\b(unusual\s+(sign-?in|activity)|verify\s+your\s+mailbox)\b", 30,
     "unusual activity claim"),
    (r"https?://\S+", 10, "contains link"),
]

EXECUTIVE_IMPERSONATION: List[Rule] = [
    # Title comes from the display name / From header — matched separately.
    (r"\b(asap|immediately|urgent(ly)?|top\s+priority)\b", 20, "urgency cue"),
    (r"\bconfidential(ly)?\b", 15, "confidentiality demand"),
    (r"\b(do\s+not\s+(discuss|share|tell|mention)|between\s+us|keep\s+this\s+between)\b", 30,
     "secrecy instruction"),
    (r"\b(only\s+you|picked\s+you|trusted\s+you)\b", 15, "exclusivity cue"),
    (r"\bon\s+behalf\s+of\b", 15, "on-behalf-of claim"),
]

_URGENCY_THREAT: List[Rule] = [
    (r"\bwithin\s+(24|48|12|72)\s+hours?\b", 30, "short deadline"),
    (r"\b(legal\s+action|lawsuit|court\s+(order|notice)|attorney)\b", 25, "legal threat"),
    (r"\b(account|subscription|membership)\b[^.]{0,30}\b(closed|closure|terminate|termination|suspend|suspension)\b", 30,
     "account closure threat"),
    (r"\bfinal\s+warning|last\s+(notice|reminder)\b", 25, "final warning"),
    (r"\bexpire[sd]?\b[^.]{0,25}\b(hours|days)\b", 25, "expiry countdown"),
    (r"\b(failure\s+to\s+(comply|respond|act)|non-?compliance)\b", 25, "non-compliance consequence"),
    (r"\bimmediately\b", 15, "immediacy demand"),
]

EXEC_TITLES_RE = re.compile(
    r"\b(ceo|cfo|cto|coo|cio|md|managing\s+director|president|founder|"
    r"head\s+of\s+(finance|sales|operations)|finance\s+director|"
    r"chairman|principal)\b",
    re.IGNORECASE,
)

RULE_TABLE: Dict[str, List[Rule]] = {
    "payment_diversion": PAYMENT_DIVERSION,
    "fake_invoice": FAKE_INVOICE,
    "credential_harvest": CREDENTIAL_HARVEST,
    "executive_impersonation": EXECUTIVE_IMPERSONATION,
    "urgency_threat": _URGENCY_THREAT,
}


def _matches(pattern: str, text: str) -> bool:
    return re.search(pattern, text, re.IGNORECASE) is not None


def _domain_of_header(value: Optional[str]) -> Optional[str]:
    from app.engines.headers.common import domain_of

    return domain_of(value)


def analyze_bec(
    subject: str = "",
    body: str = "",
    headers: Optional[Dict[str, List[str]]] = None,
) -> BecResult:
    """
    Score BEC categories for one email.

    `headers` is the lowercased header map from ingestion (may be empty
    for transient emails — executive_impersonation then relies on body
    cues only).
    """
    headers = headers or {}
    subj = subject or ""
    text = body or ""
    combined = f"{subj}\n{text}"
    combined_lower = combined.lower()

    from_value = (headers.get("from") or [""])[0]
    reply_to = (headers.get("reply-to") or [None])[0]
    from_domain = _domain_of_header(from_value)
    reply_domain = _domain_of_header(reply_to) if reply_to else None
    display_name = _display_name(from_value)

    result = BecResult()

    for category, rules in RULE_TABLE.items():
        evidence: List[str] = []
        score = 0.0

        for pattern, weight, label in rules:
            if _matches(pattern, combined_lower):
                score += weight
                evidence.append(label)

        if category == "executive_impersonation":
            # Header-driven signals (checked even without body hits)
            if display_name and EXEC_TITLES_RE.search(display_name):
                score += 30
                evidence.append(f"display name bears executive title: {display_name!r}")
            if from_domain and reply_domain and from_domain != reply_domain:
                score += 35
                evidence.append(
                    f"Reply-To domain {reply_domain} differs from From domain {from_domain}"
                )

        if score <= 0:
            continue
        confidence = min(score, SCORE_CAP)
        if confidence >= CATEGORY_THRESHOLD:
            match = BecCategoryMatch(
                category=category,
                confidence=confidence,
                evidence=evidence,
            )
            result.categories.append(match)
            result.flags.append(f"bec:{category}({int(confidence)})")

    result.bec_score = max(
        (c.confidence for c in result.categories), default=0.0
    )
    return result


def _display_name(from_value: str) -> str:
    if "<" in from_value:
        return from_value[: from_value.find("<")].strip()
    return from_value.strip()


# ── Weak-supervision label export (for the optional 4-class retrain) ──

def export_bec_labels(rows: Sequence[dict], path: str) -> int:
    """
    Write weak-supervision labels to CSV for `train_model.py --multiclass`.

    Each row: {"text": ..., "category": ...}. Returns rows written.
    Categories present → that label; otherwise "benign" (only callers
    who screened for low scores should pass those rows).
    """
    import csv

    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=["text", "category"])
        writer.writeheader()
        count = 0
        for row in rows:
            writer.writerow(
                {"text": row["text"], "category": row.get("category", "benign")}
            )
            count += 1
    return count
