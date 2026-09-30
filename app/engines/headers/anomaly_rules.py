"""Pure, unit-tested header anomaly rules → explainable header_score.

Every rule adds points AND a human-readable flag. Nothing here touches
the network or the database — inputs are plain parsed values, which is
what makes the scoring deterministic and easy to test.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional

from app.engines.headers.auth_parser import AuthSummary
from app.engines.headers.common import (
    KNOWN_BRANDS,
    display_name_of,
    domain_of,
    registrable_domain,
    same_registrable_domain,
)
from app.engines.headers.received_parser import ParsedHop
from app.engines.lookalike import BRAND_OWNER

# ── Rule weights (sum capped at 100) ──────────────────────────────────
W_SPF_FAIL = 30
W_DKIM_FAIL = 20
W_DMARC_FAIL = 30
W_RETURN_PATH_MISMATCH = 25
W_DISPLAY_NAME_SPOOF = 30
W_REPLY_TO_HIJACK = 25
W_MESSAGE_ID_MISMATCH = 10
W_MISSING_RECEIVED = 20  # no Received chain at all: headers were forged or stripped
W_NON_MONOTONIC = 20
W_HELO_MISMATCH = 15
W_NO_DMARC = 5


@dataclass
class HeaderFlags:
    """Accumulated anomaly evidence."""

    score: float = 0.0
    flags: List[str] = field(default_factory=list)
    rules: List[dict] = field(default_factory=list)

    def add(self, weight: float, rule: str, detail: str) -> None:
        self.score += weight
        self.flags.append(detail)
        self.rules.append({"rule": rule, "weight": weight, "detail": detail})


def score_header_anomalies(
    *,
    headers: dict,
    hops: List[ParsedHop],
    auth: AuthSummary,
    from_value: str,
    return_path: Optional[str],
    reply_to: Optional[str],
    message_id: Optional[str],
) -> HeaderFlags:
    """
    Evaluate all header anomaly rules against one email.

    `headers` is the lowercased-name → values map; the other arguments
    are pre-extracted fields. Absent evidence never adds points (a
    missing Return-Path is not itself a finding).
    """
    out = HeaderFlags()
    from_domain = domain_of(from_value)

    # ── Rule: SPF verdict ────────────────────────────────────────────
    if auth.spf_result in ("fail", "softfail"):
        weight = W_SPF_FAIL if auth.spf_result == "fail" else int(W_SPF_FAIL * 0.6)
        out.add(weight, "spf_fail", f"SPF returned '{auth.spf_result}'")
    # ── Rule: DKIM verdict ───────────────────────────────────────────
    if auth.dkim_result == "fail":
        out.add(W_DKIM_FAIL, "dkim_fail", "DKIM signature verification failed")
    # ── Rule: DMARC verdict ──────────────────────────────────────────
    if auth.dmarc_result in ("fail", "permerror"):
        out.add(W_DMARC_FAIL, "dmarc_fail", f"DMARC returned '{auth.dmarc_result}'")

    # Envelope relationship validated: DMARC passed (alignment with From),
    # or SPF passed for Return-Path AND DKIM passed for From. In that case
    # return-path / Message-ID domain differences are ESP architecture
    # (SES, SendGrid, Mailchimp …), not hijacking — don't score them.
    envelope_validated = auth.dmarc_result == "pass" or (
        auth.spf_result == "pass" and auth.dkim_result == "pass"
    )

    # ── Rule: Return-Path vs From ────────────────────────────────────
    if return_path:
        rp_domain = domain_of(return_path)
        if (
            rp_domain
            and from_domain
            and not same_registrable_domain(rp_domain, from_domain)
            and not envelope_validated
        ):
            out.add(
                W_RETURN_PATH_MISMATCH,
                "return_path_mismatch",
                f"Return-Path domain '{rp_domain}' does not match From '{from_domain}'",
            )

    # ── Rule: display-name brand spoof ───────────────────────────────
    display = display_name_of(from_value).lower()
    if display and from_domain:
        from_reg = registrable_domain(from_domain) or from_domain
        for brand in KNOWN_BRANDS:
            if re.search(rf"\b{re.escape(brand)}\b", display):
                if not _brand_owns_from_domain(brand, from_reg):
                    out.add(
                        W_DISPLAY_NAME_SPOOF,
                        "display_name_spoof",
                        f"Display name mentions '{brand}' but From domain is '{from_reg}'",
                    )
                break

    # ── Rule: Reply-To hijack ────────────────────────────────────────
    if reply_to and from_domain:
        rt_domain = domain_of(reply_to)
        if rt_domain and not same_registrable_domain(rt_domain, from_domain):
            out.add(
                W_REPLY_TO_HIJACK,
                "reply_to_hijack",
                f"Reply-To domain '{rt_domain}' differs from From '{from_domain}'",
            )

    # ── Rule: Message-ID domain mismatch ─────────────────────────────
    if message_id and from_domain:
        mid_match = re.search(r"@([A-Za-z0-9.-]+)>?\s*$", message_id.strip())
        if mid_match:
            mid_domain = mid_match.group(1).lower()
            if not same_registrable_domain(mid_domain, from_domain) and not envelope_validated:
                out.add(
                    W_MESSAGE_ID_MISMATCH,
                    "message_id_mismatch",
                    f"Message-ID domain '{mid_domain}' differs from From '{from_domain}'",
                )

    # ── Rule: missing Received chain ─────────────────────────────────
    if not hops:
        out.add(W_MISSING_RECEIVED, "missing_received", "No Received headers found")

    # ── Rule: non-monotonic relay timestamps ─────────────────────────
    if hops:
        times = [h.timestamp_utc for h in hops if h.timestamp_utc]
        if any(a > b for a, b in zip(times, times[1:])):
            out.add(
                W_NON_MONOTONIC,
                "non_monotonic",
                "Received timestamps are not increasing toward the receiver",
            )

    # ── Rule: HELO/EHLO vs connecting host ───────────────────────────
    for hop in hops:
        if hop.helo and hop.from_host:
            helo = hop.helo.lower().rstrip(".")
            fhost = hop.from_host.lower().rstrip(".")
            if (
                helo != fhost
                and not fhost.endswith("." + helo)
                and not helo.endswith("." + fhost)
                and _looks_like_hostname(helo)
                and _looks_like_hostname(fhost)
            ):
                out.add(
                    W_HELO_MISMATCH,
                    "helo_mismatch",
                    f"HELO '{hop.helo}' differs from connecting host '{hop.from_host}'",
                )
                break

    # ── Rule: From domain publishes no DMARC ─────────────────────────
    if (
        from_domain
        and auth.dmarc_result is None
        and auth.source != "dns"  # dns check would have found/confirmed absence
        and not _headers_indicate_dmarc_checked(headers)
    ):
        out.add(
            W_NO_DMARC,
            "no_dmarc_evidence",
            f"No DMARC result available for '{from_domain}'",
        )

    out.score = min(out.score, 100.0)
    return out


def _brand_owns_from_domain(brand: str, from_reg: str) -> bool:
    """True when the From registrable domain is legitimately the brand's.

    Covers the plain match ("paypal" in "paypal.com"), product domains on
    the parent brand (From aws.com while the display name says Amazon) and
    parent-company domains for product brands (display Outlook sent from
    microsoft.com). Reuses the lookalike engine's child→parent map.
    """
    if brand in from_reg.replace("-", ""):
        return True
    label = from_reg.split(".", 1)[0].replace("-", "")
    # Product brand is the From domain ("aws.com" is amazon's)
    if BRAND_OWNER.get(label, "") == brand:
        return True
    # From sits on the brand's parent-company domain
    parent = BRAND_OWNER.get(brand, "")
    if parent and (label == parent or parent in from_reg):
        return True
    return False


def _looks_like_hostname(value: str) -> bool:
    """True for names that look like real hosts (have a dot or are localhost)."""
    if value in ("localhost", "127.0.0.1"):
        return True
    return "." in value


def _headers_indicate_dmarc_checked(headers: dict) -> bool:
    """True when any header proves a receiver actually evaluated DMARC."""
    for value in headers.get("authentication-results", []):
        if re.search(r"dmarc=", value, re.IGNORECASE):
            return True
    return False
