from unittest.mock import AsyncMock, MagicMock, patch

from app.config import Settings
from app.engines.dynamic.models import BrowserObservation, DynamicUrlResult
from app.engines.url_analyzer import UrlAnalyzer


def settings(**overrides) -> Settings:
    values = {"VIRUSTOTAL_API_KEYS": ""}
    values.update(overrides)
    return Settings(_env_file=None, **values)


class TestUrlAnalyzer:
    def test_heuristic_checks(self):
        analyzer = UrlAnalyzer(settings())

        result = analyzer.analyze("http://8.8.8.8/login", "")
        assert any(
            "IP address" in flag for flag in result.per_url_results[0].heuristic_flags
        )

        result = analyzer.analyze("http://bit.ly/xyz", "")
        assert any(
            "shortener" in flag for flag in result.per_url_results[0].heuristic_flags
        )

        result = analyzer.analyze("http://paypa1.com/login", "")
        assert any(
            "Brand impersonation" in flag
            for flag in result.per_url_results[0].heuristic_flags
        )

        result = analyzer.analyze("http://paypal.com/login", "")
        assert not any(
            "Brand impersonation" in flag
            for flag in result.per_url_results[0].heuristic_flags
        )

    @patch("app.engines.url_analyzer.httpx.Client")
    def test_vt_responses(self, mock_client):
        analyzer = UrlAnalyzer(settings(VIRUSTOTAL_API_KEYS="mock"))

        response_ok = MagicMock()
        response_ok.status_code = 200
        response_ok.json.return_value = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 5,
                        "suspicious": 2,
                        "harmless": 50,
                    }
                }
            }
        }
        mock_client.return_value.__enter__.return_value.get.side_effect = [response_ok]
        result = analyzer.analyze("http://evil.example", "")
        assert result.per_url_results[0].vt_malicious == 5

        response_limited = MagicMock()
        response_limited.status_code = 429
        mock_client.return_value.__enter__.return_value.get.side_effect = [
            response_limited
        ]
        result = analyzer.analyze("http://busy.example", "")
        assert "rate limit" in result.per_url_results[0].vt_error

    def test_dynamic_result_is_merged_without_lowering_static_score(self):
        dynamic_analyzer = MagicMock()
        dynamic_analyzer.analyze = AsyncMock(
            return_value=DynamicUrlResult(
                status="complete",
                dynamic_score=60,
                dynamic_flags=["Password input found in rendered DOM"],
                observation=BrowserObservation(
                    attempted=True,
                    final_url="https://landing.example/login",
                    redirect_chain=[
                        "http://bit.ly/test",
                        "https://landing.example/login",
                    ],
                    has_password_input=True,
                    has_login_form=True,
                    screenshot_path="/tmp/demo.png",
                    elapsed_ms=120,
                ),
            )
        )
        analyzer = UrlAnalyzer(
            settings(DYNAMIC_URL_ENABLED=True),
            dynamic_analyzer=dynamic_analyzer,
        )

        result = analyzer.analyze("http://bit.ly/test", "", scan_id=7)
        per_url = result.per_url_results[0]

        assert per_url.dynamic_status == "complete"
        assert per_url.dynamic_score == 60
        assert per_url.final_score >= per_url.heuristic_score
        assert per_url.dom_has_login_form is True
        assert per_url.redirect_chain[-1] == "https://landing.example/login"

    def test_html_resource_src_is_not_a_url_candidate(self):
        analyzer = UrlAnalyzer(settings())
        result = analyzer.analyze(
            "",
            '<a href="https://example.com/account">Account</a>'
            '<img src="https://cdn.example.net/tracker.png">',
        )
        assert [item.original_url for item in result.per_url_results] == [
            "https://example.com/account"
        ]

    def test_dynamic_analysis_runs_once_per_registered_domain(self):
        dynamic_analyzer = MagicMock()
        dynamic_analyzer.analyze = AsyncMock(
            return_value=DynamicUrlResult(
                status="complete",
                dynamic_score=0,
                dynamic_flags=[],
                observation=BrowserObservation(
                    attempted=True,
                    final_url="https://example.com/home",
                ),
            )
        )
        analyzer = UrlAnalyzer(
            settings(DYNAMIC_URL_ENABLED=True, DYNAMIC_URL_MAX_PER_SCAN=3),
            dynamic_analyzer=dynamic_analyzer,
        )
        result = analyzer.analyze(
            "https://example.com/one https://www.example.com/two", ""
        )

        assert dynamic_analyzer.analyze.await_count == 1
        assert sorted(item.dynamic_status for item in result.per_url_results) == [
            "complete",
            "skipped:duplicate_domain",
        ]

    @patch("app.engines.url_analyzer.httpx.Client")
    def test_vt_auth_failure_stops_more_requests_in_same_scan(self, mock_client):
        unauthorized = MagicMock(status_code=401)
        mock_client.return_value.__enter__.return_value.get.return_value = unauthorized
        analyzer = UrlAnalyzer(settings(VIRUSTOTAL_API_KEYS="bad-key"))

        result = analyzer.analyze(
            "https://one.example https://two.example.net", ""
        )

        assert mock_client.return_value.__enter__.return_value.get.call_count == 1
        assert result.vt_checked_urls == 1
        assert all(
            item.vt_error == "VT authentication failed — check VIRUSTOTAL_API_KEYS"
            for item in result.per_url_results
        )
