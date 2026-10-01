"""
Tests for the VirusTotal multi-key rotation client.

All HTTP is mocked — no network access. Each test resets the module-level
cooldown table so key state never leaks between tests.
"""

from unittest.mock import MagicMock, patch

import pytest

from app.integrations.virustotal import (
    AUTH_ERROR,
    NO_KEYS_ERROR,
    VirusTotalClient,
    reset_vt_state,
)


@pytest.fixture(autouse=True)
def _clean_state():
    reset_vt_state()
    yield
    reset_vt_state()


def _response(status: int, json_data: dict | None = None, headers: dict | None = None):
    resp = MagicMock()
    resp.status_code = status
    resp.headers = headers or {}
    resp.json.return_value = json_data or {}
    return resp


def _client_returns(*responses):
    """Patch httpx.Client so request() walks through the given responses."""
    mock = patch(
        "app.integrations.virustotal.httpx.Client",
        return_value=MagicMock(
            __enter__=MagicMock(
                return_value=MagicMock(request=MagicMock(side_effect=list(responses)))
            ),
            __exit__=MagicMock(return_value=False),
        ),
    )
    return mock


OK_BODY = {
    "data": {"attributes": {"last_analysis_stats": {"malicious": 1, "harmless": 70}}}
}


class TestKeyRotation:
    def test_no_keys_returns_clear_error(self):
        status, data, err = VirusTotalClient(keys=[]).get("/files/abc")
        assert status == 0
        assert data is None
        assert err == NO_KEYS_ERROR

    def test_single_key_success(self):
        with _client_returns(_response(200, OK_BODY)) as mock:
            status, data, err = VirusTotalClient(keys=["k1"]).get("/files/abc")
        assert status == 200
        assert data["data"]["attributes"]["last_analysis_stats"]["malicious"] == 1
        assert err is None

    def test_429_rotates_to_next_key(self):
        """Key 1 is quota-exhausted → key 2 answers in the SAME call."""
        with _client_returns(
            _response(429),
            _response(200, OK_BODY),
        ) as mock:
            status, data, err = VirusTotalClient(keys=["k1", "k2"]).get("/files/abc")
        assert status == 200
        assert err is None
        req = mock.return_value.__enter__.return_value.request
        assert req.call_count == 2
        # Second request carried key 2
        assert req.call_args_list[1].kwargs["headers"]["x-apikey"] == "k2"

    def test_exhausted_keys_return_429_with_message(self):
        with _client_returns(_response(429), _response(429)):
            status, data, err = VirusTotalClient(keys=["k1", "k2"]).get("/files/abc")
        assert status == 429
        assert data is None
        assert "rate limit" in err
        assert "2 API key(s)" in err

    def test_cooled_key_skipped_without_http_call(self):
        """After 429 the key is cooling — next call with same key does no HTTP."""
        with _client_returns(_response(429)) as mock:
            VirusTotalClient(keys=["k1"]).get("/files/abc")
            status, _, err = VirusTotalClient(keys=["k1"]).get("/files/abc")
        assert status == 429  # synthesised — no live request attempted
        req = mock.return_value.__enter__.return_value.request
        assert req.call_count == 1

    def test_retry_after_header_honored(self):
        with _client_returns(
            _response(429, headers={"Retry-After": "77"}),
            _response(200, OK_BODY),
        ):
            VirusTotalClient(keys=["k1", "k2"]).get("/files/abc")
        # key k1 must now be in cooldown; a k1-only call skips HTTP
        with _client_returns() as mock:
            status, _, _ = VirusTotalClient(keys=["k1"]).get("/files/abc")
        assert status == 429
        mock.return_value.__enter__.return_value.request.assert_not_called()

    def test_401_marks_key_invalid_and_uses_next(self):
        with _client_returns(
            _response(401),
            _response(200, OK_BODY),
        ) as mock:
            status, _, err = VirusTotalClient(keys=["bad", "good"]).get("/files/abc")
        assert status == 200
        req = mock.return_value.__enter__.return_value.request
        assert req.call_args_list[1].kwargs["headers"]["x-apikey"] == "good"

    def test_all_keys_invalid_returns_auth_error(self):
        with _client_returns(_response(401), _response(403)):
            status, _, err = VirusTotalClient(keys=["a", "b"]).get("/files/abc")
        assert status == 401
        assert err == AUTH_ERROR

    def test_404_is_returned_to_caller(self):
        with _client_returns(_response(404)):
            status, data, err = VirusTotalClient(keys=["k"]).get("/files/abc")
        assert (status, data, err) == (404, None, None)

    def test_transport_error_does_not_rotate(self):
        with patch(
            "app.integrations.virustotal.httpx.Client",
            side_effect=RuntimeError("boom"),
        ):
            status, _, err = VirusTotalClient(keys=["k1", "k2"]).get("/files/abc")
        assert status == 0
        assert "boom" in err

    def test_status_snapshot(self):
        with _client_returns(_response(429), _response(200, OK_BODY)):
            VirusTotalClient(keys=["cool", "ok"]).get("/files/abc")
        st = VirusTotalClient(keys=["cool", "ok"]).status()
        assert st["key_count"] == 2
        assert st["cooling_down"] == 1
        assert st["available"] == 1
        assert st["invalid"] == 0
        assert st["total_calls"] == 2
        by_id = {k["id"]: k for k in st["keys"]}
        assert by_id[1]["state"] == "cooldown"
        assert by_id[1]["masked"] == "cool…"
        assert by_id[1]["calls"] == 1
        assert by_id[1]["cooldown_remaining"] > 0
        assert by_id[2]["state"] == "ready"
        assert by_id[2]["calls"] == 1
        assert by_id[2]["cooldown_remaining"] == 0
