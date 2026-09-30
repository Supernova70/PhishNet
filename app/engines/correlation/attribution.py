"""Attribution — confidence-based verdict with explainable evidence.

Pure function over evidence already gathered by other engines (no
network, no DB). Weights live in one table (`KIND_WEIGHTS`) so the
scoring is unit-testable and honest about why a verdict was chosen.

Verdict kinds (plan §Week 2):
  spoofed_domain            auth failures + display/reply-to mismatches
  compromised_account       auth passes + internal sender + BEC content
  anonymized_infrastructure origin IP behind VPN/TOR/proxy/hosting/DNSBL
  direct_actor              attacker's freshly-registered domain sent
                             straight from hosting, transported in clear
  unknown                   evidence insufficient (always valid output)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

VERDICT_UNKNOWN = "unknown"


@dataclass
class AttributionInputs:
    # Header auth evidence
    spf_result: Optional[str] = None
    dkim_result: Optional[str] = None
    dmarc_result: Optional[str] = None
    alignment: Optional[str] = None
    display_name_spoof: bool = False
    replyto_mismatch: bool = False
    internal_sender: bool = False
    # Content engines
    bec_score: float = 0.0
    lookalike_score: float = 0.0
    # Origin intel (IpIntel row fields)
    origin_is_vpn: bool = False
    origin_is_tor: bool = False
    origin_is_proxy: bool = False
    origin_is_hosting: bool = False
    origin_dnsbl_listed: bool = False
    # Domain intel (plan B1 — sender domain registered < 30 days ago)
    young_domain: bool = False
    # Transport: Received chain known but no hop negotiated TLS
    no_tls: bool = False


# kind → [(condition_label, weight), ...] and minimum score to emit.
# confidence = score / sum(weights) for the emitting kind.
KIND_WEIGHTS: Dict[str, Dict] = {
    "spoofed_domain": {
        "threshold": 55,
        "conditions": [
            ("spf_result", 25, "SPF returned fail"),
            ("dkim_result", 20, "DKIM returned fail"),
            ("dmarc_result", 25, "DMARC returned fail"),
            ("alignment_mismatched", 15, "authenticated domain misaligned with From"),
            ("display_name_spoof", 15, "display name impersonates a known brand"),
            ("replyto_mismatch", 15, "Reply-To points at a different domain"),
        ],
    },
    "compromised_account": {
        "threshold": 60,
        # A "compromised account" verdict implies the sender mailbox is
        # ours/internal — without that, the same evidence means something
        # else (or nothing) and this kind must not be emitted.
        "requires": ("internal_sender",),
        "conditions": [
            ("auth_pass", 25, "SPF/DKIM authentication passes"),
            ("dmarc_pass", 10, "DMARC passes"),
            ("internal_sender", 25, "sender is an internal/known address"),
            ("bec_content", 20, "BEC category content detected"),
            ("lookalike", 15, "lookalike domain present"),
            ("replyto_mismatch", 15, "Reply-To redirected away from From domain"),
        ],
    },
    "anonymized_infrastructure": {
        # A Tor exit alone (35) is already decisive; VPN/DNSBL need a pair.
        "threshold": 35,
        "conditions": [
            ("origin_is_tor", 35, "origin IP is a Tor exit node"),
            ("origin_is_vpn", 25, "origin IP belongs to a VPN provider"),
            ("origin_is_proxy", 20, "origin IP is an open proxy"),
            ("origin_dnsbl_listed", 30, "origin IP appears on a DNSBL"),
            ("origin_is_hosting", 15, "origin IP is rented hosting infrastructure"),
        ],
    },
    "direct_actor": {
        # Freshly-registered sender domain (B1, hard precondition — no
        # RDAP evidence ⇒ this kind stays off), sent from hosting
        # infrastructure, failing auth, and never encrypted in transit.
        "threshold": 55,
        "requires": ("young_domain",),
        "conditions": [
            ("young_domain", 25, "sender domain registered < 30 days ago"),
            ("auth_fail", 25, "SPF/DKIM/DMARC authentication fails"),
            ("origin_is_hosting", 15, "origin IP is rented hosting infrastructure"),
            ("no_tls", 15, "no hop negotiated transport TLS (message sent in clear)"),
        ],
    },
}


@dataclass
class AttributionResult:
    kind: str = VERDICT_UNKNOWN
    confidence: float = 0.0
    evidence: List[str] = field(default_factory=list)
    scores: Dict[str, float] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "kind": self.kind,
            "confidence": round(self.confidence, 2),
            "evidence": list(self.evidence),
            "scores": {k: round(v, 1) for k, v in self.scores.items()},
        }


def _condition_holds(name: str, inputs: AttributionInputs) -> bool:
    if name == "spf_result":
        return inputs.spf_result == "fail"
    if name == "dkim_result":
        return inputs.dkim_result == "fail"
    if name == "dmarc_result":
        return inputs.dmarc_result == "fail"
    if name == "alignment_mismatched":
        return inputs.alignment == "mismatched"
    if name == "auth_pass":
        return inputs.spf_result == "pass" or inputs.dkim_result == "pass"
    if name == "dmarc_pass":
        return inputs.dmarc_result == "pass"
    if name == "bec_content":
        return inputs.bec_score >= 40.0
    if name == "lookalike":
        return inputs.lookalike_score >= 65.0
    if name == "internal_sender":
        return inputs.internal_sender
    if name == "display_name_spoof":
        return inputs.display_name_spoof
    if name == "replyto_mismatch":
        return inputs.replyto_mismatch
    if name == "origin_is_tor":
        return inputs.origin_is_tor
    if name == "origin_is_vpn":
        return inputs.origin_is_vpn
    if name == "origin_is_proxy":
        return inputs.origin_is_proxy
    if name == "origin_is_hosting":
        return inputs.origin_is_hosting
    if name == "origin_dnsbl_listed":
        return inputs.origin_dnsbl_listed
    if name == "young_domain":
        return inputs.young_domain
    if name == "auth_fail":
        return (
            inputs.spf_result == "fail"
            or inputs.dkim_result == "fail"
            or inputs.dmarc_result == "fail"
        )
    if name == "no_tls":
        return inputs.no_tls
    return False


def attribute(inputs: AttributionInputs) -> AttributionResult:
    result = AttributionResult()
    best_score = 0.0

    for kind, spec in KIND_WEIGHTS.items():
        score = 0.0
        evidence: List[str] = []
        total_weight = sum(w for _, w, _ in spec["conditions"])

        for name, weight, label in spec["conditions"]:
            if _condition_holds(name, inputs):
                score += weight
                evidence.append(f"{label} (+{weight})")

        result.scores[kind] = score
        if score < spec["threshold"] or score <= best_score:
            continue
        if any(
            not _condition_holds(name, inputs)
            for name in spec.get("requires", ())
        ):
            continue  # hard precondition unmet → kind cannot be emitted
        best_score = score
        result.kind = kind
        result.confidence = min(1.0, score / total_weight) if total_weight else 0.0
        result.evidence = evidence

    if result.kind != VERDICT_UNKNOWN:
        result.confidence = round(result.confidence, 2)
    return result
