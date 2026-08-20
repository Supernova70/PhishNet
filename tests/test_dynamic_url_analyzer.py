import asyncio

from app.config import Settings
from app.engines.dynamic.dynamic_url_analyzer import DynamicUrlAnalyzer
from app.engines.dynamic.models import BrowserObservation


class FakeBrowserAdapter:
    def __init__(self, observation):
        self.observation = observation
        self.calls = []

    async def observe(self, url: str, *, scan_id: int | None = None):
        self.calls.append((url, scan_id))
        return self.observation


def test_analyzer_uses_adapter_and_scores_observation():
    adapter = FakeBrowserAdapter(
        BrowserObservation(
            attempted=True,
            final_url="https://collector.example.net/login",
            redirect_chain=[
                "https://short.example",
                "https://collector.example.net/login",
            ],
            has_password_input=True,
            has_login_form=True,
            external_form_action=True,
        )
    )
    settings = Settings(
        _env_file=None,
        VIRUSTOTAL_API_KEYS="",
        DYNAMIC_URL_ENABLED=True,
    )
    analyzer = DynamicUrlAnalyzer(adapter, settings)

    result = asyncio.run(
        analyzer.analyze(
            "https://short.example",
            static_score=35,
            vt_malicious=0,
            is_shortener=False,
            heuristic_flags=[],
            scan_id=11,
        )
    )

    assert result.status == "complete"
    assert result.dynamic_score == 85
    assert adapter.calls == [("https://short.example", 11)]


def test_analyzer_does_not_open_already_malicious_url():
    adapter = FakeBrowserAdapter(BrowserObservation())
    settings = Settings(
        _env_file=None,
        VIRUSTOTAL_API_KEYS="",
        DYNAMIC_URL_ENABLED=True,
    )
    analyzer = DynamicUrlAnalyzer(adapter, settings)

    result = asyncio.run(
        analyzer.analyze(
            "https://malicious.example",
            static_score=20,
            vt_malicious=3,
            is_shortener=False,
            heuristic_flags=[],
        )
    )

    assert result.status == "skipped:already_malicious_in_virustotal"
    assert adapter.calls == []
