"""Lookalike / typosquat domain detection against known brands.

Checks From, Reply-To, and URL registrable domains against a brand
watchlist using four signals (plan §Week 2):

  1. homoglyph        — Cyrillic/zero/one substitutions that render
                        visually identical to the brand ("раypal")
  2. typosquat        — Levenshtein distance ≤ 2 after normalization
  3. brand embedded   — brand glued/hyphenated into another label
                        ("paypal-login.tk", "login-paypal.com")
  4. brand in subdomain — "paypal.secure-login.tk" while the registrable
                        domain is NOT the real brand domain

Legit brand domains (registrable label == brand, e.g. paypal.com) are
never flagged: that is alignment, not impersonation.

Pure/offline — no DNS, no network.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional, Sequence

from app.engines.headers.common import KNOWN_BRANDS, registrable_domain

# Visual-lookalief substitutions applied before comparison.
HOMOGLYPH_MAP = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "і": "i",
    "ѕ": "s", "у": "y", "х": "x", "ԁ": "d", "ɡ": "g", "ɩ": "i",
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t",
    "8": "b", "@": "a",
}

# Extra brands not in the header-anomaly watchlist.
EXTRA_BRANDS = (
    "wellsfargo", "bankofamerica", "paypal", "sbi", "hdfc",
    "icici", "axisbank", "phonepe", "gpay",
)

BRANDS: tuple[str, ...] = tuple(dict.fromkeys(KNOWN_BRANDS + EXTRA_BRANDS))

# Known-legitimate domains where a brand is embedded in the registrable
# label ("microsoftonline.com", "googlemail.com") — never lookalikes.
# Also brand-owned infrastructure where the registrable label is a
# product word rather than the brand itself ("googleapis.com" for
# google, "apple.com" for the appleid product brand): an attacker
# cannot host content under any of these, so nothing here is an
# impersonation.
LEGIT_EMBEDDED: frozenset[str] = frozenset({
    "microsoftonline.com", "microsoftonline.de", "microsoftonline.fr",
    "microsoftonline.co.uk", "googlemail.com", "windows.com",
    "windows.net", "live.com", "office.com", "office.net",
    # Google-owned label families
    "googleapis.com", "googleapis.dev", "gstatic.com",
    "googleusercontent.com", "googletagmanager.com",
    "googletagservices.com", "google-analytics.com",
    "googleadservices.com", "googlevideo.com", "googlesource.com",
    # Apple-owned label families (covers the appleid product brand)
    "apple.com", "icloud.com", "itunes.com", "applestore.com",
})

# Product / service brands whose owning registrable label differs from
# the brand itself ("appleid" lives under apple.com, "gpay" under
# google.com) — checked like the plain "reg_label == brand" rule.
BRAND_OWNER: dict[str, str] = {
    "appleid": "apple",
    "gpay": "google",
    "googlepay": "google",
    "gmail": "google",
    "youtube": "google",
    "outlook": "microsoft",
    "office": "microsoft",
    "onedrive": "microsoft",
    "xbox": "microsoft",
    "aws": "amazon",
    "amazonaws": "amazon",
    "prime": "amazon",
}

SCORES = {
    "homoglyph": 85.0,
    "typosquat": 75.0,
    "brand_in_subdomain": 70.0,
    "brand_embedded": 65.0,
}


@dataclass
class LookalikeMatch:
    domain: str
    brand: str
    reason: str
    score: float

    def to_dict(self) -> dict:
        return {
            "domain": self.domain,
            "brand": self.brand,
            "reason": self.reason,
            "score": round(self.score, 1),
        }


@dataclass
class LookalikeResult:
    score: float = 0.0
    matched_brand: Optional[str] = None
    matches: List[LookalikeMatch] = field(default_factory=list)
    flags: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "score": round(self.score, 1),
            "matched_brand": self.matched_brand,
            "matches": [m.to_dict() for m in self.matches],
            "flags": list(self.flags),
        }


def normalize_label(label: str) -> str:
    """Lowercase + transliterate homoglyphs + drop separators."""
    out = []
    for ch in label.lower():
        out.append(HOMOGLYPH_MAP.get(ch, ch))
    return "".join(c for c in out if c.isalnum())


def levenshtein(a: str, b: str, max_dist: int = 3) -> int:
    """Classic DP edit distance with early exit above max_dist."""
    if abs(len(a) - len(b)) > max_dist:
        return max_dist + 1
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        best = i
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            val = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            cur.append(val)
            if val < best:
                best = val
        if best > max_dist:
            return max_dist + 1
        prev = cur
    return prev[-1]


def _candidate_labels(host: str) -> List[str]:
    """All dot-separated labels of a host (subdomains + registrable)."""
    host = host.lower().strip(".")
    return [lbl for lbl in host.split(".") if lbl and lbl != "www"]


def check_domain(host: str) -> List[LookalikeMatch]:
    """Return every lookalike match for one host/domain string."""
    if not host or "@" in host:
        return []
    host = host.lower().strip().strip(".")
    if not host:
        return []

    reg = registrable_domain(host) or host
    if reg in LEGIT_EMBEDDED:
        return []
    reg_label = (reg.split(".")[0] if "." in reg else reg).lower()
    labels = _candidate_labels(host)
    # Subdomain labels = every label except those of the registrable domain
    reg_labels_set = set(_candidate_labels(reg))
    subdomain_labels = [lbl for lbl in labels if lbl not in reg_labels_set]

    matches: List[LookalikeMatch] = []
    seen = set()

    def add(brand: str, reason: str):
        key = (host, brand, reason)
        if key in seen:
            return
        seen.add(key)
        matches.append(
            LookalikeMatch(
                domain=host, brand=brand, reason=reason, score=SCORES[reason]
            )
        )

    for brand in BRANDS:
        if len(brand) < 3:
            continue

        # 1) Legit brand domain → alignment, not impersonation
        if reg_label == brand or reg == f"{brand}.com":
            continue

        # 1b) Product brand on its parent company's domain
        #     (appleid on apple.com, gpay on google.com)
        if reg_label == BRAND_OWNER.get(brand, ""):
            continue

        norm_brand = normalize_label(brand)

        # 2) Brand occupying a subdomain of someone else's domain
        if any(brand in normalize_label(lbl) for lbl in subdomain_labels):
            add(brand, "brand_in_subdomain")

        # 3) Homoglyph: looks identical after normalization but raw differs
        norm_reg = normalize_label(reg_label)
        if norm_reg == norm_brand and reg_label != brand:
            add(brand, "homoglyph")
            continue

        # 4) Typosquat: small edit distance after normalization
        if len(norm_brand) >= 4:
            dist = levenshtein(norm_reg, norm_brand, max_dist=2)
            if 0 < dist <= 2:
                add(brand, "typosquat")
                continue

        # 5) Brand embedded with separators: paypal-login, loginpaypal
        if len(norm_brand) >= 4 and norm_brand in norm_reg and norm_reg != norm_brand:
            add(brand, "brand_embedded")

    return matches


def _normalize_input(raw: str) -> str:
    """Accept bare domains, hosts with ports, and full URLs."""
    from urllib.parse import urlparse

    value = str(raw).strip()
    if "://" in value:
        parsed = urlparse(value)
        value = parsed.netloc or value
    return value.split("/")[0].split(":")[0].strip().lower()


def analyze_lookalike(domains: Optional[Sequence[str]]) -> LookalikeResult:
    """Best (highest-scoring) lookalike match across candidate domains."""
    result = LookalikeResult()
    for raw in domains or []:
        if not raw:
            continue
        host = _normalize_input(raw)
        if not host:
            continue
        for match in check_domain(host):
            result.matches.append(match)
            if match.score > result.score:
                result.score = match.score
                result.matched_brand = match.brand

    # De-duplicate flags while preserving order
    for match in result.matches:
        flag = f"lookalike:{match.brand}:{match.reason}({int(match.score)})"
        if flag not in result.flags:
            result.flags.append(flag)
    return result
