import pytest

from app.engines.dynamic.policy import should_run_dynamic_url


@pytest.mark.parametrize(
    ("kwargs", "expected", "reason"),
    [
        ({"enabled": False, "static_score": 40}, False, "disabled"),
        (
            {"enabled": True, "static_score": 40, "vt_malicious": 1},
            False,
            "already_malicious_in_virustotal",
        ),
        ({"enabled": True, "static_score": 75}, False, "already_high_risk"),
        ({"enabled": True, "static_score": 35}, True, "ambiguous_static_score"),
        (
            {"enabled": True, "static_score": 0, "is_shortener": True},
            True,
            "url_shortener",
        ),
        (
            {
                "enabled": True,
                "static_score": 0,
                "heuristic_flags": ["URL contains embedded redirect"],
            },
            True,
            "high_value_static_flag",
        ),
        ({"enabled": True, "static_score": 0}, False, "low_static_risk"),
        (
            {"enabled": True, "static_score": 35, "within_budget": False},
            False,
            "budget_exhausted",
        ),
    ],
)
def test_dynamic_policy(kwargs, expected, reason):
    defaults = {
        "enabled": True,
        "static_score": 0,
        "vt_malicious": 0,
        "is_shortener": False,
        "heuristic_flags": [],
        "within_budget": True,
    }
    decision = should_run_dynamic_url(**(defaults | kwargs))
    assert decision.should_run is expected
    assert decision.reason == reason
