"""Harmless local integration test for rendered DOM and redirect capture.

The production validator intentionally blocks loopback. This test injects a
loopback-only validator and never contacts an external server.
"""

import asyncio
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

import pytest

from app.integrations.playwright_browser import PlaywrightBrowserAdapter
from app.security.url_safety import SafeUrl


class DemoHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/start":
            self.send_response(302)
            self.send_header("Location", "/login")
            self.end_headers()
            return

        body = b"""<!doctype html>
        <html><head><title>Controlled Login Demo</title></head>
        <body><div id='root'></div>
        <script>
          const form = document.createElement('form');
          form.action = 'https://collector.example.net/submit';
          const password = document.createElement('input');
          password.type = 'password';
          form.appendChild(password);
          document.querySelector('#root').appendChild(form);
        </script></body></html>"""
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format, *_args):
        return


class LoopbackOnlyTestValidator:
    """Explicit test-only validator; production never allows loopback."""

    def validate(self, url: str) -> SafeUrl:
        parts = urlsplit(url)
        if parts.hostname != "127.0.0.1":
            raise AssertionError(f"Unexpected test request: {url}")
        return SafeUrl(
            normalized_url=url,
            hostname="127.0.0.1",
            port=parts.port or 80,
            resolved_ips=("127.0.0.1",),
        )


def test_playwright_captures_redirect_and_javascript_login_form(tmp_path):
    server = ThreadingHTTPServer(("127.0.0.1", 0), DemoHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        start_url = f"http://127.0.0.1:{server.server_port}/start"
        adapter = PlaywrightBrowserAdapter(
            validator=LoopbackOnlyTestValidator(),
            screenshot_dir=str(tmp_path),
            navigation_timeout_seconds=5,
            total_timeout_seconds=10,
            max_redirects=4,
            render_delay_ms=100,
            user_agent="PhishingGuardTest/1.0",
        )
        observation = asyncio.run(adapter.observe(start_url, scan_id=1))
        if observation.error_code == "browser_failure" and "Executable" in (
            observation.error_detail or ""
        ):
            pytest.skip("Playwright Chromium binary is not installed")

        assert observation.error_code is None
        assert observation.final_url.endswith("/login")
        assert observation.redirect_chain == [
            start_url,
            start_url.replace("/start", "/login"),
        ]
        assert observation.page_title == "Controlled Login Demo"
        assert observation.has_password_input is True
        assert observation.has_login_form is True
        assert observation.external_form_action is True
        assert Path(observation.screenshot_path).is_file()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
