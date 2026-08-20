from app.engines.analyzers.yara_scanner import YaraScanner


def test_repository_yara_rules_compile():
    YaraScanner._rules_loaded = False
    YaraScanner._compiled_rules = None
    YaraScanner._rules_error = None

    assert YaraScanner._load_rules() is True
    assert YaraScanner._compiled_rules is not None
    assert YaraScanner._rules_error is None
