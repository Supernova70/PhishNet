from app.engines.analyzers.yara_scanner import YaraScanner


def _load() -> YaraScanner:
    YaraScanner._rules_loaded = False
    YaraScanner._compiled_rules = None
    YaraScanner._rules_error = None
    return YaraScanner()


def test_repository_yara_rules_compile():
    YaraScanner._rules_loaded = False
    YaraScanner._compiled_rules = None
    YaraScanner._rules_error = None

    assert YaraScanner._load_rules() is True
    assert YaraScanner._compiled_rules is not None
    assert YaraScanner._rules_error is None


# ─── FP tuning regression tests ───────────────────────────────────────────────

# A PNG image containing the exact byte sequence that caused a real-world
# false positive (email id 85 / attachment 001.png): the 4-byte sequence
# "-eC " inside compressed image data matched the old `-ec ` PowerShell flag.
PNG_WITH_COINCIDENTAL_FLAG = (
    b"\x89PNG\r\n\x1a\n"
    + b"\x00\x00\x00\rIHDR\x00\x00\x04\x00\x00\x00\x06\x00"
    + b"junkdata" * 200
    + b"-eC "
    + b"morejunk" * 200
)


def test_png_with_lone_short_ps_flag_does_not_match():
    """A single 4-char flag in binary data must NOT trigger a CRITICAL rule."""
    scanner = _load()
    result = scanner.scan(PNG_WITH_COINCIDENTAL_FLAG, "photo.png", bucket="image")
    assert result.matched is False
    assert result.matches == []


def test_strong_ps_indicator_in_png_suppressed_by_file_type():
    """Rule applicability: PowerShell indicators in images are suppressed."""
    scanner = _load()
    data = b"\x89PNG\r\n\x1a\n" + b"x" * 64 + b"-ExecutionPolicy Bypass" + b"y" * 64

    # No bucket → old behaviour, rule matches raw bytes
    untyped = scanner.scan(data, "tricky.png")
    assert untyped.matched is True
    assert any(m.rule_name == "SuspiciousPowerShellEncoded" for m in untyped.matches)

    # image bucket → suppressed with a transparent note
    typed = scanner.scan(data, "tricky.png", bucket="image")
    assert typed.matched is False
    assert typed.matches == []
    assert len(typed.suppressed) == 1
    assert "suppressed" in typed.suppressed[0]
    assert "image" in typed.suppressed[0]


def test_real_ps_payload_still_matches_with_evidence():
    """Detection must survive the tuning: real dropper payloads still fire."""
    scanner = _load()
    data = b'powershell -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA'
    result = scanner.scan(data, "payload.ps1", bucket="script")

    assert result.matched is True
    assert result.yara_score >= 85.0
    match = result.matches[0]
    assert match.rule_name == "SuspiciousPowerShellEncoded"
    assert match.severity == "critical"
    assert match.evidence, "evidence (offset + preview) must be captured"
    assert match.evidence[0]["string"].startswith("$")
    assert match.evidence[0]["offset"] == data.lower().find(b"-encodedcommand")
    assert "-EncodedCommand" in match.evidence[0]["preview"]
    assert match.explanation, "rule meta explanation must be exposed"


def test_two_short_flags_together_still_match():
    scanner = _load()
    data = b"launcher -enc SGVsbG8= -ec SGVsbG8= padding"
    result = scanner.scan(data, "run.bat", bucket="script")
    assert result.matched is True
