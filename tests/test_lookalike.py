"""Tests for lookalike / typosquat domain detection (pure, offline)."""

from app.engines.lookalike import (
    analyze_lookalike,
    check_domain,
    levenshtein,
    normalize_label,
)


class TestHelpers:
    def test_homoglyph_normalization(self):
        # Cyrillic а and о → latin
        assert normalize_label("раypal") == "paypal"
        assert normalize_label("g00gle") == "google"
        assert normalize_label("Pay-Pal") == "paypal"

    def test_levenshtein(self):
        assert levenshtein("paypal", "paypal") == 0
        assert levenshtein("paypa1", "paypal") == 1
        assert levenshtein("paypal", "amazn") > 2
        assert levenshtein("paypal", "x" * 30) == 4  # early exit > max


class TestCheckDomain:
    def test_legit_brand_domain_not_flagged(self):
        assert check_domain("paypal.com") == []
        assert check_domain("www.paypal.com") == []
        assert check_domain("mail.google.com") == []

    def test_typosquat_detected(self):
        # 0/1 digit swaps normalize to the brand → homoglyph class
        matches = check_domain("paypa1.com")
        assert any(m.reason == "homoglyph" for m in matches)
        assert matches[0].brand == "paypal"

    def test_typosquat_edit_distance(self):
        matches = check_domain("amazan.com")
        assert any(m.reason == "typosquat" for m in matches)

    def test_homoglyph_detected(self):
        # Cyrillic 'а' in the registrable label
        matches = check_domain("раypal.com")
        assert any(m.reason == "homoglyph" for m in matches)

    def test_brand_in_subdomain(self):
        matches = check_domain("paypal.secure-login.tk")
        assert any(m.reason == "brand_in_subdomain" for m in matches)

    def test_brand_embedded_with_hyphen(self):
        matches = check_domain("paypal-login.xyz")
        assert any(m.reason == "brand_embedded" for m in matches)

    def test_brand_embedded_glued(self):
        matches = check_domain("paypalshop.xyz")
        assert any(m.reason == "brand_embedded" for m in matches)

    def test_known_legit_embeddings_not_flagged(self):
        assert check_domain("microsoftonline.com") == []
        assert check_domain("googlemail.com") == []

    def test_unrelated_domain_clean(self):
        assert check_domain("example.org") == []
        assert check_domain("my-company-blog.example") == []

    def test_garbage_inputs(self):
        assert check_domain("") == []
        assert check_domain(None) == []
        assert check_domain("user@example.com") == []  # '@' rejected


class TestAnalyzeLookalike:
    def test_best_match_wins(self):
        result = analyze_lookalike(
            ["example.org", "paypa1.com", "mail.google.com"]
        )
        assert result.score > 0
        assert result.matched_brand == "paypal"
        assert any("lookalike:paypal" in f for f in result.flags)

    def test_accepts_full_urls_and_ports(self):
        result = analyze_lookalike(["https://paypa1.com/login?x=1"])
        assert result.matched_brand == "paypal"

    def test_no_domains_returns_empty(self):
        result = analyze_lookalike([])
        assert result.score == 0.0
        assert result.matched_brand is None
        result = analyze_lookalike(None)
        assert result.to_dict()["matches"] == []

    def test_all_clean_domains_zero(self):
        result = analyze_lookalike(["google.com", "example.org"])
        assert result.score == 0.0
        assert result.flags == []
