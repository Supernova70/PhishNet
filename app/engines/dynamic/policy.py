"""Pure policy deciding whether browser analysis is justified."""

from dataclasses import dataclass


@dataclass(frozen=True)
class DynamicUrlDecision:
    should_run: bool
    reason: str


HIGH_VALUE_FLAGS = (
    "URL shortener detected",
    "URL contains embedded redirect",
    "Brand impersonation",
    "IP address used as hostname",
    "@ symbol in URL",
)


def should_run_dynamic_url(
    *,
    enabled: bool,
    static_score: float,
    vt_malicious: int,
    is_shortener: bool,
    heuristic_flags: list[str],
    within_budget: bool = True,
) -> DynamicUrlDecision:
    if not enabled:
        return DynamicUrlDecision(False, "disabled")
    if not within_budget:
        return DynamicUrlDecision(False, "budget_exhausted")
    if vt_malicious > 0:
        return DynamicUrlDecision(False, "already_malicious_in_virustotal")
    if static_score >= 70:
        return DynamicUrlDecision(False, "already_high_risk")
    if 20 <= static_score < 70:
        return DynamicUrlDecision(True, "ambiguous_static_score")
    if is_shortener:
        return DynamicUrlDecision(True, "url_shortener")
    if any(
        any(flag.startswith(prefix) for prefix in HIGH_VALUE_FLAGS)
        for flag in heuristic_flags
    ):
        return DynamicUrlDecision(True, "high_value_static_flag")
    return DynamicUrlDecision(False, "low_static_risk")
