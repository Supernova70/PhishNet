"""Attribution engine: weighted verdicts with explainable evidence."""

import pytest

from app.engines.correlation.attribution import (
    KIND_WEIGHTS,
    VERDICT_UNKNOWN,
    AttributionInputs,
    attribute,
)


class TestSpoofedDomain:
    def test_auth_failures_and_mismatch_win(self):
        result = attribute(AttributionInputs(
            spf_result="fail",
            dkim_result="fail",
            dmarc_result="fail",
            alignment="mismatched",
            display_name_spoof=True,
            replyto_mismatch=True,
        ))
        assert result.kind == "spoofed_domain"
        assert result.confidence > 0.5
        assert any("SPF" in e for e in result.evidence)
        assert any("display name" in e for e in result.evidence)

    def test_below_threshold_stays_unknown(self):
        result = attribute(AttributionInputs(spf_result="fail"))
        assert result.kind == VERDICT_UNKNOWN
        assert result.scores["spoofed_domain"] < KIND_WEIGHTS["spoofed_domain"]["threshold"]


class TestCompromisedAccount:
    def test_auth_pass_internal_with_bec_content(self):
        result = attribute(AttributionInputs(
            spf_result="pass",
            dmarc_result="pass",
            internal_sender=True,
            bec_score=85.0,
            replyto_mismatch=True,
        ))
        assert result.kind == "compromised_account"
        assert any("internal" in e for e in result.evidence)
        assert any("BEC" in e for e in result.evidence)

    def test_external_sender_insufficient(self):
        # Same auth/content evidence but sender is NOT internal
        result = attribute(AttributionInputs(
            spf_result="pass",
            bec_score=85.0,
            replyto_mismatch=True,
        ))
        assert result.kind != "compromised_account" or result.scores[
            "compromised_account"
        ] < KIND_WEIGHTS["compromised_account"]["threshold"]


class TestAnonymizedInfrastructure:
    @pytest.mark.parametrize(
        "kwargs,should_emit,min_confidence",
        [
            ({"origin_is_tor": True}, True, 0.25),          # tor alone: 35/125
            ({"origin_is_vpn": True, "origin_dnsbl_listed": True}, True, 0.4),
            ({"origin_is_hosting": True}, False, 0.0),       # 15 < threshold 35
        ],
    )
    def test_infrastructure_signals(self, kwargs, should_emit, min_confidence):
        result = attribute(AttributionInputs(**kwargs))
        if not should_emit:
            assert result.kind != "anonymized_infrastructure"
        else:
            assert result.kind == "anonymized_infrastructure"
            assert result.confidence >= min_confidence


class TestStructure:
    def test_unknown_when_no_evidence(self):
        result = attribute(AttributionInputs())
        assert result.kind == VERDICT_UNKNOWN
        assert result.confidence == 0.0
        assert result.evidence == []

    def test_all_scores_always_reported(self):
        result = attribute(AttributionInputs())
        assert set(result.scores) == set(KIND_WEIGHTS)

    def test_best_kind_selected_by_score(self):
        # Strong anonymization (0.9) beats a weak spoof trace (0.25)
        result = attribute(AttributionInputs(
            spf_result="fail",
            origin_is_tor=True,
            origin_dnsbl_listed=True,
        ))
        assert result.kind == "anonymized_infrastructure"
        assert result.scores["spoofed_domain"] > 0  # still explained

    def test_evidence_weights_sum_matches_kind_total(self):
        for kind, spec in KIND_WEIGHTS.items():
            total = sum(w for _, w, _ in spec["conditions"])
            assert total > spec["threshold"]

    def test_to_dict_serializable(self):
        d = attribute(AttributionInputs(spf_result="fail", origin_is_tor=True)).to_dict()
        assert set(d) == {"kind", "confidence", "evidence", "scores"}
        assert isinstance(d["confidence"], float)


class TestDirectActor:
    def test_young_domain_is_hard_precondition(self):
        # Full non-domain evidence but no RDAP young-domain proof:
        # the kind must not be emitted (score is still explained).
        result = attribute(AttributionInputs(
            spf_result="fail",
            origin_is_hosting=True,
            no_tls=True,
        ))
        assert result.kind != "direct_actor"
        assert result.scores["direct_actor"] == 55  # auth+hosting+no_tls

    def test_full_evidence_emits_direct_actor(self):
        result = attribute(AttributionInputs(
            young_domain=True,
            spf_result="fail",
            origin_is_hosting=True,
            no_tls=True,
        ))
        assert result.kind == "direct_actor"
        assert result.confidence > 0
        assert any("< 30 days" in e for e in result.evidence)
        assert any("authentication fails" in e for e in result.evidence)
        assert any("TLS" in e for e in result.evidence)

    def test_below_threshold_with_only_auth_fail(self):
        result = attribute(AttributionInputs(
            young_domain=True,
            spf_result="fail",
        ))
        assert result.kind != "direct_actor"
        assert result.scores["direct_actor"] == 50

    def test_to_dict_includes_new_kind(self):
        result = attribute(AttributionInputs(young_domain=True, no_tls=True))
        assert "direct_actor" in result.scores
