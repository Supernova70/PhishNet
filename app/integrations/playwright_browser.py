"""Playwright adapter for non-interactive, policy-gated URL observation."""

from __future__ import annotations

import asyncio
import hashlib
import logging
import time
from pathlib import Path
from urllib.parse import urljoin

import httpx

from app.engines.dynamic.models import BrowserObservation
from app.engines.dynamic.scoring import registrable_domain
from app.security.url_safety import UnsafeUrlError, UrlSafetyValidator

logger = logging.getLogger(__name__)


class PlaywrightBrowserAdapter:
    """Collect rendered-page facts without clicking, typing, or submitting."""

    def __init__(
        self,
        *,
        validator: UrlSafetyValidator,
        screenshot_dir: str,
        navigation_timeout_seconds: int,
        total_timeout_seconds: int,
        max_redirects: int,
        render_delay_ms: int,
        user_agent: str,
        http_transport: httpx.AsyncBaseTransport | None = None,
    ):
        self.validator = validator
        self.screenshot_dir = Path(screenshot_dir)
        self.navigation_timeout_ms = navigation_timeout_seconds * 1000
        self.total_timeout_seconds = total_timeout_seconds
        self.max_redirects = max_redirects
        self.render_delay_ms = render_delay_ms
        self.user_agent = user_agent
        self._http_transport = http_transport

    async def _resolve_server_redirects(self, url: str) -> tuple[str, list[str]]:
        """Validate every HTTP Location before allowing the browser to follow it."""
        chain: list[str] = []
        current = url
        timeout = min(self.navigation_timeout_ms / 1000, self.total_timeout_seconds)
        async with httpx.AsyncClient(
            follow_redirects=False,
            timeout=timeout,
            headers={"User-Agent": self.user_agent},
            transport=self._http_transport,
            trust_env=False,
        ) as client:
            for _ in range(self.max_redirects + 1):
                safe = await asyncio.to_thread(self.validator.validate, current)
                current = safe.normalized_url
                if not chain or chain[-1] != current:
                    chain.append(current)
                async with client.stream("GET", current) as response:
                    location = response.headers.get("location")
                    if (
                        response.status_code not in {301, 302, 303, 307, 308}
                        or not location
                    ):
                        return current, chain
                    current = urljoin(current, location)

        raise UnsafeUrlError("redirect_limit", "Maximum redirect count exceeded")

    async def observe(
        self, url: str, *, scan_id: int | None = None
    ) -> BrowserObservation:
        started = time.monotonic()
        observation = BrowserObservation(attempted=True)

        try:
            safe_target = await asyncio.to_thread(self.validator.validate, url)
            navigation_target, preflight_chain = await self._resolve_server_redirects(
                safe_target.normalized_url
            )
        except UnsafeUrlError as exc:
            observation.attempted = False
            observation.error_code = "unsafe_target"
            observation.error_detail = f"{exc.code}: {exc.detail}"
            observation.elapsed_ms = int((time.monotonic() - started) * 1000)
            return observation
        except httpx.HTTPError as exc:
            observation.error_code = "preflight_error"
            observation.error_detail = str(exc)[:300]
            observation.elapsed_ms = int((time.monotonic() - started) * 1000)
            return observation

        try:
            from playwright.async_api import (
                Error as PlaywrightError,
            )
            from playwright.async_api import (
                TimeoutError as PlaywrightTimeoutError,
            )
            from playwright.async_api import (
                async_playwright,
            )
        except ImportError:
            observation.error_code = "browser_unavailable"
            observation.error_detail = "Playwright is not installed"
            observation.elapsed_ms = int((time.monotonic() - started) * 1000)
            return observation

        browser = None
        context = None
        page = None
        navigation_urls: list[str] = list(preflight_chain)

        try:
            async with asyncio.timeout(self.total_timeout_seconds):
                async with async_playwright() as playwright:
                    browser = await playwright.chromium.launch(headless=True)
                    context = await browser.new_context(
                        accept_downloads=False,
                        service_workers="block",
                        ignore_https_errors=False,
                        user_agent=self.user_agent,
                        viewport={"width": 1365, "height": 768},
                    )
                    page = await context.new_page()

                    async def handle_route(route) -> None:
                        request = route.request
                        is_main_document = (
                            request.resource_type == "document"
                            and request.frame == page.main_frame
                        )
                        try:
                            await asyncio.to_thread(
                                self.validator.validate, request.url
                            )
                        except UnsafeUrlError as exc:
                            if is_main_document:
                                observation.error_code = "unsafe_target"
                                observation.error_detail = f"{exc.code}: {exc.detail}"
                            await route.abort("blockedbyclient")
                            return

                        if is_main_document:
                            if (
                                not navigation_urls
                                or navigation_urls[-1] != request.url
                            ):
                                navigation_urls.append(request.url)
                            if len(navigation_urls) > self.max_redirects + 1:
                                observation.error_code = "redirect_limit"
                                observation.error_detail = (
                                    "Maximum redirect count exceeded"
                                )
                                await route.abort("blockedbyclient")
                                return
                        await route.continue_()

                    await context.route("**/*", handle_route)

                    async def close_popup(popup) -> None:
                        if popup != page:
                            observation.popup_attempted = True
                            await popup.close()

                    async def cancel_download(download) -> None:
                        observation.download_attempted = True
                        await download.cancel()

                    context.on("page", close_popup)
                    page.on(
                        "dialog", lambda dialog: asyncio.create_task(dialog.dismiss())
                    )
                    page.on("download", cancel_download)

                    try:
                        await page.goto(
                            navigation_target,
                            wait_until="domcontentloaded",
                            timeout=self.navigation_timeout_ms,
                        )
                        await page.wait_for_timeout(self.render_delay_ms)
                    except PlaywrightTimeoutError:
                        observation.error_code = "navigation_timeout"
                        observation.error_detail = "Navigation exceeded its timeout"
                    except PlaywrightError as exc:
                        message = str(exc)
                        if "ERR_CERT_" in message or "SSL" in message.upper():
                            observation.tls_error = True
                            observation.error_code = "tls_error"
                            observation.error_detail = (
                                "TLS/certificate navigation failed"
                            )
                        elif observation.error_code is None:
                            observation.error_code = "navigation_error"
                            observation.error_detail = message[:300]

                    observation.redirect_chain = navigation_urls
                    observation.final_url = (
                        page.url if page.url != "about:blank" else None
                    )

                    if observation.final_url and observation.error_code not in {
                        "unsafe_target",
                        "redirect_limit",
                    }:
                        observation.page_title = (await page.title())[:512]
                        password_fields = page.locator('input[type="password"]')
                        observation.has_password_input = (
                            await password_fields.count() > 0
                        )
                        observation.has_login_form = (
                            await page.locator(
                                'form:has(input[type="password"])'
                            ).count()
                            > 0
                        )
                        actions = await page.locator(
                            'form:has(input[type="password"])'
                        ).evaluate_all(
                            "forms => forms.map(form => form.action).filter(Boolean)"
                        )
                        final_domain = registrable_domain(observation.final_url)
                        observation.external_form_action = any(
                            registrable_domain(action) not in {None, final_domain}
                            for action in actions
                        )

                        screenshot_root = self.screenshot_dir / str(
                            scan_id or "standalone"
                        )
                        screenshot_root.mkdir(parents=True, exist_ok=True)
                        digest = hashlib.sha256(
                            safe_target.normalized_url.encode()
                        ).hexdigest()
                        screenshot_path = screenshot_root / f"{digest}.png"
                        await page.screenshot(
                            path=str(screenshot_path), full_page=False
                        )
                        observation.screenshot_path = str(screenshot_path)

        except TimeoutError:
            observation.error_code = "total_timeout"
            observation.error_detail = "Dynamic URL analysis exceeded its total budget"
        except Exception as exc:  # browser startup/crash must not fail the static scan
            logger.warning("Dynamic browser observation failed: %s", exc)
            observation.error_code = observation.error_code or "browser_failure"
            observation.error_detail = observation.error_detail or str(exc)[:300]
        finally:
            # Playwright's own async context may already have closed these after an
            # error or timeout. Cleanup therefore has to be safely repeatable.
            try:
                if page is not None and not page.is_closed():
                    await page.close()
            except Exception:
                pass
            try:
                if context is not None:
                    await context.close()
            except Exception:
                pass
            try:
                if browser is not None and browser.is_connected():
                    await browser.close()
            except Exception:
                pass
            observation.elapsed_ms = int((time.monotonic() - started) * 1000)

        return observation
