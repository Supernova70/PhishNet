"""Optional active DNS validation of SPF / DMARC / DKIM records.

Disabled by default (HEADER_DNS_CHECKS_ENABLED=False): unit tests,
offline demos, and CI must never depend on live DNS. The resolver is
injectable so tests can drive full SPF pass/fail/include scenarios with
a fake in-memory zone.

SPF evaluation implements a pragmatic subset of RFC 7208:
ip4 / ip6 / a / mx / exists / include / all with qualifiers, a 10-lookup
budget, and explicit handling of +all / -all / ~all / ?all.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

from app.engines.headers.auth_parser import AuthSummary
from app.engines.headers.common import registrable_domain

# resolver(domain, rdtype) -> list[str] (TXT strings)
Resolver = Callable[[str, str], List[str]]

SPF_MAX_LOOKUPS = 10


@dataclass
class DnsCheckResult:
    spf_result: Optional[str] = None   # pass/fail/softfail/neutral/none/permerror
    spf_record: Optional[str] = None
    dmarc_result: Optional[str] = None  # pass/fail (alignment outcome)
    dmarc_record: Optional[str] = None
    dmarc_policy: Optional[str] = None  # none/quarantine/reject
    dkim_key_present: Optional[bool] = None
    errors: List[str] = field(default_factory=list)


def _default_resolver(domain: str, rdtype: str) -> List[str]:
    """Live dnspython resolver. Imported lazily so tests never touch DNS."""
    import dns.resolver  # noqa: WPS433 (lazy by design)

    answers = dns.resolver.resolve(domain, rdtype, lifetime=5.0)
    return [r.to_text().strip('"') for r in answers]


# ── SPF evaluation ────────────────────────────────────────────────────

def _match_ip(ip: ipaddress._BaseAddress, mechanism: str) -> bool:
    try:
        network = ipaddress.ip_network(mechanism, strict=False)
    except ValueError:
        return False
    return ip in network


def _resolve_hosts(resolver: Resolver, name: str) -> List[str]:
    ips: List[str] = []
    for rdtype in ("A", "AAAA"):
        try:
            ips.extend(resolver(name, rdtype))
        except Exception:
            continue
    return ips


def _evaluate_mechanisms(
    record: str,
    sender_ip: ipaddress._BaseAddress,
    resolver: Resolver,
    depth: int,
    budget: List[int],
) -> Tuple[str, str]:
    """Return (result, detail) for one SPF record against sender_ip."""
    terms = record.split()[1:]  # drop 'v=spf1'
    # First pass: evaluate non-'all' mechanisms in order.
    for term in terms:
        if term.lower() == "all":
            break
        qualifier = "+"
        mech = term
        if term[0] in "+-~?":
            qualifier, mech = term[0], term[1:]

        kind, _, arg = mech.partition(":")
        kind = kind.lower()
        matched = False

        if kind in ("ip4", "ip6"):
            matched = _match_ip(sender_ip, arg)
        elif kind == "include":
            if depth >= SPF_MAX_LOOKUPS or budget[0] >= SPF_MAX_LOOKUPS:
                return "permerror", "SPF include lookup budget exceeded"
            budget[0] += 1
            try:
                included = resolver(arg, "TXT")
            except Exception:
                # RFC 7208 §6.2: include of an unresolvable domain = permerror
                return "permerror", f"include:{arg} could not be resolved"
            spf_txt = next((t for t in included if t.lower().startswith("v=spf1")), None)
            if spf_txt is None:
                return "permerror", f"include:{arg} has no SPF record"
            sub, detail = _evaluate_mechanisms(spf_txt, sender_ip, resolver, depth + 1, budget)
            if sub == "pass":
                matched = True
            elif sub in ("fail", "softfail", "neutral"):
                # Non-match continues evaluation (per RFC, only 'pass' ends)
                matched = False
            else:
                return sub, detail
        elif kind in ("a", "mx"):
            names = [arg] if arg else []
            if not names:
                continue
            for name in names:
                hosts = _resolve_hosts(resolver, name) if kind == "a" else []
                if kind == "mx":
                    try:
                        mx_records = resolver(name, "MX")
                    except Exception:
                        mx_records = []
                    for mx in mx_records:
                        mx_host = mx.split()[-1].rstrip(".")
                        hosts.extend(_resolve_hosts(resolver, mx_host))
                for host_ip in hosts:
                    try:
                        if ipaddress.ip_address(host_ip) == sender_ip:
                            matched = True
                            break
                    except ValueError:
                        continue
                if matched:
                    break
        elif kind == "exists":
            try:
                matched = bool(resolver(arg, "A"))
            except Exception:
                matched = False
        elif kind == "ptr":
            matched = False  # deprecated mechanism; treat as no-match
        # Unknown mechanisms (e.g. 'exp=', 'redirect=') are ignored for matching.

        if matched:
            if qualifier == "-":
                return "fail", f"matched -{mech}"
            if qualifier == "~":
                return "softfail", f"matched ~{mech}"
            if qualifier == "?":
                return "neutral", f"matched ?{mech}"
            return "pass", f"matched +{mech}"

    # No mechanism matched: fall back to trailing 'all'
    for term in reversed(terms):
        if term.lower().endswith("all") or term.lower() == "all":
            raw = term
            qualifier = raw[0] if raw[0] in "+-~?" else "+"
            body = raw[1:] if raw[0] in "+-~?" else raw
            if body.lower() != "all":
                continue
            if qualifier == "-":
                return "fail", "matched -all"
            if qualifier == "~":
                return "softfail", "matched ~all"
            if qualifier == "?":
                return "neutral", "matched ?all"
            return "pass", "matched +all"
    return "neutral", "no terminating all mechanism"


def evaluate_spf(
    spf_record: str,
    sender_ip: str,
    resolver: Resolver,
) -> Tuple[str, str]:
    """Public entry: (result, detail)."""
    try:
        ip = ipaddress.ip_address(sender_ip)
    except ValueError:
        return "permerror", f"invalid sender IP {sender_ip}"
    if not spf_record.lower().startswith("v=spf1"):
        return "permerror", "record does not start with v=spf1"
    budget = [0]
    return _evaluate_mechanisms(spf_record, ip, resolver, 0, budget)


def parse_dmarc_record(txt: str) -> Optional[Dict[str, str]]:
    """Parse a DMARC TXT record into {tag: value} (tags uppercased)."""
    if "v=DMARC1" not in txt.upper().replace(" ", ""):
        # tolerate 'v=DMARC1' with normal spacing
        if not re.search(r"\bv\s*=\s*DMARC1\b", txt, re.IGNORECASE):
            return None
    tags: Dict[str, str] = {}
    for part in txt.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip().lower()] = v.strip()
    return tags


def check_alignment(
    auth_domain: Optional[str],
    from_domain: Optional[str],
    strict: bool = False,
) -> bool:
    """DMARC domain alignment (relaxed by default: org-domain match)."""
    if not auth_domain or not from_domain:
        return False
    if strict:
        return auth_domain.lower() == from_domain.lower()
    a = registrable_domain(auth_domain)
    f = registrable_domain(from_domain)
    return bool(a and f and a == f)


def ptr_lookup(ip: str, resolver: Optional[Resolver] = None) -> Optional[str]:
    """Reverse DNS (PTR) for an IP — None when unset, non-IPv4, or NXDOMAIN."""
    import ipaddress

    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if not isinstance(addr, ipaddress.IPv4Address):
        return None
    name = ".".join(reversed(str(addr).split("."))) + ".in-addr.arpa"
    resolve = resolver or _default_resolver
    try:
        names = resolve(name, "PTR")
    except Exception:
        return None
    return names[0].rstrip(".") if names else None


# ── Top-level check used by HeaderAnalyzer ────────────────────────────

def run_dns_checks(
    *,
    from_domain: Optional[str],
    sender_ip: Optional[str],
    dkim_domain: Optional[str],
    dkim_selector: Optional[str],
    resolver: Resolver = _default_resolver,
) -> DnsCheckResult:
    """Fetch and evaluate SPF/DMARC/DKIM records over DNS."""
    result = DnsCheckResult()
    if from_domain:
        # SPF (per RFC, evaluated against envelope sender — we approximate
        # with the From domain when Return-Path is absent)
        try:
            txts = resolver(from_domain, "TXT")
            spf = next((t for t in txts if t.lower().startswith("v=spf1")), None)
            result.spf_record = spf
            if spf is None:
                result.spf_result = "none"
            elif sender_ip:
                result.spf_result, _ = evaluate_spf(spf, sender_ip, resolver)
            else:
                result.spf_result = "none"  # record exists, no IP to test
        except Exception as exc:  # DNS failure must never block a scan
            result.errors.append(f"spf_lookup_failed: {exc}")

        # DMARC
        try:
            txts = resolver(f"_dmarc.{from_domain}", "TXT")
            dmarc = next(
                (t for t in txts if re.search(r"v\s*=\s*DMARC1", t, re.IGNORECASE)),
                None,
            )
            result.dmarc_record = dmarc
            if dmarc:
                tags = parse_dmarc_record(dmarc) or {}
                result.dmarc_policy = tags.get("p")
            else:
                result.dmarc_result = "none"
        except Exception as exc:
            result.errors.append(f"dmarc_lookup_failed: {exc}")

    # DKIM public key presence (verification itself needs the raw body —
    # the stored header evidence only proves the key exists)
    if dkim_domain and dkim_selector:
        try:
            txts = resolver(f"{dkim_selector}._domainkey.{dkim_domain}", "TXT")
            result.dkim_key_present = any("p=" in t for t in txts)
        except Exception as exc:
            result.errors.append(f"dkim_key_lookup_failed: {exc}")

    return result


def merge_dns_into_summary(summary: AuthSummary, dns: DnsCheckResult) -> None:
    """Merge DNS findings into a header-derived AuthSummary (DNS wins on conflict)."""
    if dns.spf_result and summary.spf_result != dns.spf_result:
        summary.errors.append(
            f"header spf={summary.spf_result} vs dns spf={dns.spf_result}"
        )
    if dns.spf_result:
        summary.spf_result = dns.spf_result
    if dns.dmarc_result:
        summary.dmarc_result = dns.dmarc_result
    if dns.dkim_key_present is not None:
        summary.dkim_result = summary.dkim_result or (
            "pass" if dns.dkim_key_present else "none"
        )
    summary.errors.extend(dns.errors)
    summary.source = "both" if summary.source == "header" else "dns"
