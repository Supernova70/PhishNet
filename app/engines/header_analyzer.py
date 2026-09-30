"""HeaderAnalyzer — orchestrates Received-chain, auth, and anomaly analysis.

Input:  the full header map of one email {lowercase-name: [values]}.
Output: an explainable HeaderAnalysisResult (score + flags + trace + auth).

The analyzer is pure w.r.t. I/O: persistence (EmailSource/ReceivedHop/
AuthResult rows) happens in EmailService at ingestion, and optional DNS
validation is injected. When no header evidence exists (emails fetched
before raw retention), the result is score 0 with an explanatory flag —
absent evidence must never look like a threat.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

from app.config import Settings, get_settings
from app.engines.headers.anomaly_rules import HeaderFlags, score_header_anomalies
from app.engines.headers.auth_parser import AuthSummary, compute_alignment, parse_auth_headers
from app.engines.headers.common import domain_of
from app.engines.headers.received_parser import (
    ParsedHop,
    origin_hop,
    parse_received_chain,
)

Resolver = Callable[[str, str], List[str]]


@dataclass
class HeaderAnalysisResult:
    """Full outcome of header forensics for one email."""

    present: bool = False
    score: float = 0.0
    flags: List[str] = field(default_factory=list)
    rules: List[dict] = field(default_factory=list)
    hops: List[ParsedHop] = field(default_factory=list)
    auth: AuthSummary = field(default_factory=AuthSummary)
    origin_ip: Optional[str] = None
    origin_host: Optional[str] = None
    errors: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "present": self.present,
            "score": self.score,
            "flags": self.flags,
            "rules": self.rules,
            "hops": [h.to_dict() for h in self.hops],
            "auth": self.auth.to_dict(),
            "origin_ip": self.origin_ip,
            "origin_host": self.origin_host,
            "errors": self.errors,
        }


class HeaderAnalyzer:
    """Analyze an email's raw headers for forensic scoring."""

    def __init__(
        self,
        settings: Optional[Settings] = None,
        resolver: Optional[Resolver] = None,
    ):
        self._settings = settings or get_settings()
        self._resolver = resolver  # None → live DNS only if enabled

    # ── Public API ───────────────────────────────────────────────────

    def analyze(self, headers: Optional[Dict[str, List[str]]]) -> HeaderAnalysisResult:
        """
        Run the full header pipeline on a stored header map.

        `headers` keys must be lowercase (EmailService stores them that
        way); we normalize anyway to be forgiving.
        """
        if not headers:
            return HeaderAnalysisResult(
                present=False,
                flags=["No raw header evidence retained for this email"],
            )

        norm = {str(k).lower(): [str(v) for v in _as_list(val)]
                for k, val in headers.items()}

        result = HeaderAnalysisResult(present=True)

        # 1. Received chain (chronological)
        received = norm.get("received", [])
        result.hops = parse_received_chain(received)
        origin = origin_hop(result.hops)
        if origin:
            result.origin_ip = origin.from_ip
            result.origin_host = origin.from_host or origin.helo

        # 2. Auth headers
        from_value = (norm.get("from") or [""])[0]
        result.auth = parse_auth_headers(norm)
        compute_alignment(result.auth, from_value)

        # 3. Optional active DNS validation
        if self._settings.HEADER_DNS_CHECKS_ENABLED:
            self._apply_dns_checks(result, from_value)

        # 4. Anomaly scoring (pure)
        score: HeaderFlags = score_header_anomalies(
            headers=norm,
            hops=result.hops,
            auth=result.auth,
            from_value=from_value,
            return_path=(norm.get("return-path") or [None])[0],
            reply_to=(norm.get("reply-to") or [None])[0],
            message_id=(norm.get("message-id") or [None])[0],
        )
        result.score = score.score
        result.flags = score.flags
        result.rules = score.rules
        return result

    # ── Internal ─────────────────────────────────────────────────────

    def _apply_dns_checks(
        self, result: HeaderAnalysisResult, from_value: str
    ) -> None:
        from app.engines.headers.common import registrable_domain
        from app.engines.headers.dns_checks import (
            check_alignment,
            merge_dns_into_summary,
            run_dns_checks,
        )

        if self._resolver is None:
            try:
                import dns.resolver  # noqa: F401

                def live_resolver(domain: str, rdtype: str) -> List[str]:
                    answers = dns.resolver.resolve(domain, rdtype, lifetime=5.0)
                    return [r.to_text().strip('"') for r in answers]

                resolver: Resolver = live_resolver
            except Exception as exc:  # dnspython missing → graceful
                result.errors.append(f"dns_unavailable: {exc}")
                return
        else:
            resolver = self._resolver

        from_domain = domain_of(from_value)
        dns = run_dns_checks(
            from_domain=from_domain,
            sender_ip=result.origin_ip,
            dkim_domain=result.auth.dkim_domain,
            dkim_selector=result.auth.dkim_selector,
            resolver=resolver,
        )
        merge_dns_into_summary(result.auth, dns)

        # When a DMARC policy exists but no receiver reported a verdict,
        # derive the outcome ourselves: pass iff SPF or DKIM is passing
        # AND aligned with the From domain (RFC 7489 §6).
        if dns.dmarc_record and from_domain and result.auth.dmarc_result in (None, "none"):
            spf_ok = result.auth.spf_result == "pass" and check_alignment(
                result.auth.spf_domain, from_domain
            )
            dkim_ok = result.auth.dkim_result == "pass" and check_alignment(
                result.auth.dkim_domain, from_domain
            )
            result.auth.dmarc_result = "pass" if (spf_ok or dkim_ok) else "fail"
            result.auth.dmarc_domain = result.auth.dmarc_domain or registrable_domain(from_domain)


def _as_list(value) -> List[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return [str(v) for v in value]
    return [str(value)]
