"""Policy and scoring orchestration for dynamic URL analysis."""

from __future__ import annotations

from app.config import Settings, get_settings
from app.engines.dynamic.models import BrowserAdapter, DynamicUrlResult
from app.engines.dynamic.policy import should_run_dynamic_url
from app.engines.dynamic.scoring import score_observation
from app.integrations.playwright_browser import PlaywrightBrowserAdapter
from app.security.url_safety import UrlSafetyValidator


class DynamicUrlAnalyzer:
    def __init__(self, adapter: BrowserAdapter, settings: Settings | None = None):
        self.settings = settings or get_settings()
        self.adapter = adapter

    @classmethod
    def from_settings(cls, settings: Settings | None = None) -> DynamicUrlAnalyzer:
        settings = settings or get_settings()
        validator = UrlSafetyValidator(settings.dynamic_url_allowed_ports)
        adapter = PlaywrightBrowserAdapter(
            validator=validator,
            screenshot_dir=settings.DYNAMIC_URL_SCREENSHOT_DIR,
            navigation_timeout_seconds=settings.DYNAMIC_URL_NAVIGATION_TIMEOUT_SECONDS,
            total_timeout_seconds=settings.DYNAMIC_URL_TOTAL_TIMEOUT_SECONDS,
            max_redirects=settings.DYNAMIC_URL_MAX_REDIRECTS,
            render_delay_ms=settings.DYNAMIC_URL_RENDER_DELAY_MS,
            user_agent=settings.DYNAMIC_URL_USER_AGENT,
        )
        return cls(adapter, settings)

    async def analyze(
        self,
        url: str,
        *,
        static_score: float,
        vt_malicious: int,
        is_shortener: bool,
        heuristic_flags: list[str],
        scan_id: int | None = None,
        within_budget: bool = True,
    ) -> DynamicUrlResult:
        decision = should_run_dynamic_url(
            enabled=self.settings.DYNAMIC_URL_ENABLED,
            static_score=static_score,
            vt_malicious=vt_malicious,
            is_shortener=is_shortener,
            heuristic_flags=heuristic_flags,
            within_budget=within_budget,
        )
        if not decision.should_run:
            return DynamicUrlResult(status=f"skipped:{decision.reason}")

        observation = await self.adapter.observe(url, scan_id=scan_id)
        score, flags = score_observation(observation, url)
        if observation.error_code == "unsafe_target":
            status = "blocked"
        elif observation.error_code in {"navigation_timeout", "total_timeout"}:
            status = "timeout"
        elif observation.error_code and not observation.tls_error:
            status = "error"
        else:
            status = "complete"
        return DynamicUrlResult(
            status=status,
            dynamic_score=score,
            dynamic_flags=flags,
            observation=observation,
        )
