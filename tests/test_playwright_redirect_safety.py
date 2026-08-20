import asyncio
import socket

import httpx
import pytest

from app.integrations.playwright_browser import PlaywrightBrowserAdapter
from app.security.url_safety import UnsafeUrlError, UrlSafetyValidator


def public_resolver(*_args, **_kwargs):
    return [
        (
            socket.AF_INET,
            socket.SOCK_STREAM,
            6,
            "",
            ("93.184.216.34", 80),
        )
    ]


def test_preflight_blocks_redirect_to_private_address(tmp_path):
    requests: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(str(request.url))
        return httpx.Response(
            302,
            headers={"Location": "http://127.0.0.1/private"},
            request=request,
        )

    adapter = PlaywrightBrowserAdapter(
        validator=UrlSafetyValidator(resolver=public_resolver),
        screenshot_dir=str(tmp_path),
        navigation_timeout_seconds=5,
        total_timeout_seconds=10,
        max_redirects=4,
        render_delay_ms=0,
        user_agent="PhishingGuardTest/1.0",
        http_transport=httpx.MockTransport(handler),
    )

    with pytest.raises(UnsafeUrlError) as exc:
        asyncio.run(adapter._resolve_server_redirects("http://public.example/start"))

    assert exc.value.code == "non_public_ip"
    assert requests == ["http://public.example/start"]
