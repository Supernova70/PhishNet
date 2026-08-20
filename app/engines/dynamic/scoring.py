"""Explainable, deterministic scoring for browser observations."""

from urllib.parse import urlsplit

import tldextract

from app.engines.dynamic.models import BrowserObservation

_extract = tldextract.TLDExtract(suffix_list_urls=())


def registrable_domain(url: str | None) -> str | None:
    if not url:
        return None
    host = urlsplit(url).hostname
    if not host:
        return None
    result = _extract(host)
    return result.top_domain_under_public_suffix or host.lower()


def score_observation(
    observation: BrowserObservation,
    original_url: str,
) -> tuple[float, list[str]]:
    score = 0.0
    flags: list[str] = []

    original_domain = registrable_domain(original_url)
    final_domain = registrable_domain(observation.final_url)
    if original_domain and final_domain and original_domain != final_domain:
        score += 25
        flags.append(f"Redirect ended on different domain: {final_domain}")
    if len(observation.redirect_chain) >= 4:
        score += 10
        flags.append("Three or more redirects observed")
    if observation.has_password_input:
        score += 30
        flags.append("Password input found in rendered DOM")
    if observation.external_form_action:
        score += 30
        flags.append("Credential form submits to another domain")
    if observation.tls_error:
        score += 20
        flags.append("TLS/certificate navigation error")
    if observation.download_attempted:
        score += 25
        flags.append("Download attempted without user interaction")
    if observation.popup_attempted:
        score += 10
        flags.append("Popup attempted without user interaction")

    return min(score, 100.0), flags
