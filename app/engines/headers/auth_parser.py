"""Parse sender-authentication evidence from email headers.

Sources (all header-only — no network):
  - `Authentication-Results:` — added by the receiving MTA, canonical
  - `Received-SPF:`           — legacy SPF result header
  - `DKIM-Signature:`         — signer domain + selector (not the verdict)

Active DNS validation lives in `dns_checks.py` and is merged in by the
HeaderAnalyzer only when HEADER_DNS_CHECKS_ENABLED is set.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional

from app.engines.headers.common import domain_of, registrable_domain

_RESULTS = ("pass", "fail", "softfail", "neutral", "none",
             "temperror", "permerror", "bestguesspass", "unknown")

_SPF_RE = re.compile(
    r"(?:^|[\s;])spf=(?P<result>[a-z]+)(?:\s+[^;]*)?"
    r"(?:[\s;]+)(?:smtp\.mailfrom|envelope-from|envelope-to|helo)=<"
    r"?(?P<domain>[^;>\s]+)",
    re.IGNORECASE,
)
_SPF_RESULT_ONLY_RE = re.compile(r"(?:^|[\s;])spf=(?P<result>[a-z]+)", re.IGNORECASE)
_DKIM_RE = re.compile(r"(?:^|[\s;])dkim=(?P<result>[a-z]+)", re.IGNORECASE)
_DKIM_D_RE = re.compile(r"header\.d=(?P<domain>[^;\s]+)", re.IGNORECASE)
_DKIM_S_RE = re.compile(r"header\.s=(?P<selector>[^;\s]+)", re.IGNORECASE)
_DMARC_RE = re.compile(r"(?:^|[\s;])dmarc=(?P<result>[a-z]+)", re.IGNORECASE)
_DMARC_FROM_RE = re.compile(
    r"header\.(?:from|d)=(?P<domain>[^;\s]+)", re.IGNORECASE
)
_RCV_SPF_RE = re.compile(
    r"^(?P<result>[a-z]+)\s", re.IGNORECASE
)
_DKIM_SIG_D_RE = re.compile(r"(?:^|[\s;])d=(?P<domain>[^;\s]+)", re.IGNORECASE)
_DKIM_SIG_S_RE = re.compile(r"(?:^|[\s;])s=(?P<selector>[^;\s]+)", re.IGNORECASE)


@dataclass
class AuthSummary:
    """Combined sender-authentication outcome for one email."""

    spf_result: Optional[str] = None
    spf_domain: Optional[str] = None
    dkim_result: Optional[str] = None
    dkim_domain: Optional[str] = None
    dkim_selector: Optional[str] = None
    dmarc_result: Optional[str] = None
    dmarc_domain: Optional[str] = None
    # Alignment of SPF/DKIM domains with the From header domain
    alignment: Optional[str] = None  # aligned | mismatched | unknown
    source: str = "none"  # header | dns | both | none
    errors: List[str] = field(default_factory=list)
    raw_results: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def _norm(result: Optional[str]) -> Optional[str]:
    if not result:
        return None
    r = result.lower().strip()
    return r if r in _RESULTS else r  # keep unknown values, lowercased


def parse_auth_headers(headers: Dict[str, List[str]]) -> AuthSummary:
    """
    Extract SPF/DKIM/DMARC verdicts from an email's header map.

    `headers` maps lowercased header name → list of values (order as in
    the message). Multiple Authentication-Results headers may exist;
    we merge, preferring the first non-'none' verdict per mechanism.
    """
    summary = AuthSummary()
    auth_results_values = headers.get("authentication-results", [])
    seen_sources: List[str] = []

    for value in auth_results_values:
        seen_sources.append(value[:200])
        # SPF
        if summary.spf_result is None or summary.spf_result == "none":
            m = _SPF_RE.search(value)
            if m:
                summary.spf_result = _norm(m.group("result"))
                summary.spf_domain = m.group("domain").lower().strip("<>")
            else:
                m2 = _SPF_RESULT_ONLY_RE.search(value)
                if m2:
                    summary.spf_result = _norm(m2.group("result"))
        # DKIM
        if summary.dkim_result is None:
            m = _DKIM_RE.search(value)
            if m:
                summary.dkim_result = _norm(m.group("result"))
                md = _DKIM_D_RE.search(value)
                if md:
                    summary.dkim_domain = md.group("domain").lower().strip("<>")
                ms = _DKIM_S_RE.search(value)
                if ms:
                    summary.dkim_selector = ms.group("selector")
        # DMARC
        if summary.dmarc_result is None:
            m = _DMARC_RE.search(value)
            if m:
                summary.dmarc_result = _norm(m.group("result"))
                mf = _DMARC_FROM_RE.search(value)
                if mf:
                    summary.dmarc_domain = mf.group("domain").lower().strip("<>")

    # Legacy Received-SPF header (older MTAs / forwarders)
    if summary.spf_result is None:
        for value in headers.get("received-spf", []):
            m = _RCV_SPF_RE.match(value.strip())
            if m:
                summary.spf_result = _norm(m.group("result"))
                # 'pass (receiver: domain of a@sender designates ...)'
                # → we want the sender's domain, not the receiver's.
                dm = re.search(r"domain of \S+?@(?P<domain>[^\s>)]+)", value)
                if not dm:
                    dm = re.search(r"\((?P<domain>[^\s:)]+)", value)
                if dm:
                    summary.spf_domain = dm.group("domain").lower()
                break

    # DKIM-Signature gives signer domain/selector even without a verdict
    if summary.dkim_domain is None or summary.dkim_selector is None:
        for value in headers.get("dkim-signature", []):
            md = _DKIM_SIG_D_RE.search(value)
            if md and not summary.dkim_domain:
                summary.dkim_domain = md.group("domain").lower()
            ms = _DKIM_SIG_S_RE.search(value)
            if ms and not summary.dkim_selector:
                summary.dkim_selector = ms.group("selector")
            if md or ms:
                break

    summary.raw_results = seen_sources
    if any([summary.spf_result, summary.dkim_result, summary.dmarc_result]):
        summary.source = "header"
    return summary


def compute_alignment(summary: AuthSummary, from_value: str) -> None:
    """
    Set summary.alignment by comparing authenticated domains with the
    From header domain (relaxed: organizational-domain equality counts,
    matching DMARC's relaxed mode).

    A mechanism only vouches for the From domain when it PASSED: an
    email with spf=pass on attacker.example but dmarc=fail on paypal.com
    is a mismatch, not an alignment. So pass-verdict domains take
    precedence; failing mechanisms fall back to their recorded domain.
    """
    from_domain = domain_of(from_value)
    if not from_domain:
        summary.alignment = "unknown"
        return
    from_reg = registrable_domain(from_domain)

    passed_domains = [
        d for verdict, d in (
            (summary.dmarc_result, summary.dmarc_domain),
            (summary.spf_result, summary.spf_domain),
            (summary.dkim_result, summary.dkim_domain),
        )
        if verdict in ("pass", "bestguesspass") and d
    ]
    candidates = passed_domains or [
        d for d in (
            summary.dmarc_domain, summary.spf_domain, summary.dkim_domain
        ) if d
    ]
    if not candidates:
        summary.alignment = "unknown"
        return

    summary.alignment = (
        "aligned"
        if any(
            from_reg and from_reg == registrable_domain(d)
            for d in candidates
        )
        else "mismatched"
    )
