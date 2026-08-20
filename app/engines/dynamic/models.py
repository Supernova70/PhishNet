"""Plain result contracts for dynamic URL analysis."""

from dataclasses import dataclass, field
from typing import Protocol


@dataclass
class BrowserObservation:
    attempted: bool = False
    final_url: str | None = None
    redirect_chain: list[str] = field(default_factory=list)
    page_title: str | None = None
    has_password_input: bool = False
    has_login_form: bool = False
    external_form_action: bool = False
    download_attempted: bool = False
    popup_attempted: bool = False
    tls_error: bool = False
    screenshot_path: str | None = None
    elapsed_ms: int = 0
    error_code: str | None = None
    error_detail: str | None = None


@dataclass
class DynamicUrlResult:
    status: str
    dynamic_score: float = 0.0
    dynamic_flags: list[str] = field(default_factory=list)
    observation: BrowserObservation = field(default_factory=BrowserObservation)


class BrowserAdapter(Protocol):
    async def observe(
        self, url: str, *, scan_id: int | None = None
    ) -> BrowserObservation:
        """Open a URL without interaction and return structured observations."""
