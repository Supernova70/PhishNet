"""Body-text YARA (plan §5, B7) — flags only, fail-graceful."""

from app.engines.text_analyzer import scan_body_yara

URGENCY_BODY = (
    "Dear user, your account has been suspended. "
    "Please verify your account immediately to restore access."
)

BENIGN_BODY = "Lunch is at noon in the usual room. See you there."


class TestScanBodyYara:
    def test_urgency_rule_flags_body(self):
        flags = scan_body_yara(URGENCY_BODY)
        assert "yara:PhishingUrgencyLanguage" in flags

    def test_benign_body_no_flags(self):
        assert scan_body_yara(BENIGN_BODY) == []

    def test_empty_inputs(self):
        assert scan_body_yara("") == []
        assert scan_body_yara("   \n") == []
        assert scan_body_yara(None) == []

    def test_fail_graceful_on_scanner_error(self, monkeypatch):
        class _Boom:
            def scan(self, *args, **kwargs):
                raise RuntimeError("yara unavailable")

        monkeypatch.setattr(
            "app.engines.analyzers.yara_scanner.YaraScanner", _Boom
        )
        assert scan_body_yara(URGENCY_BODY) == []

    def test_flags_are_plain_strings(self):
        flags = scan_body_yara(URGENCY_BODY)
        assert all(isinstance(f, str) and f.startswith("yara:") for f in flags)
