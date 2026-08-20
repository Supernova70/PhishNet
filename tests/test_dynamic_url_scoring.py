from app.engines.dynamic.models import BrowserObservation
from app.engines.dynamic.scoring import registrable_domain, score_observation


def test_public_suffix_aware_registered_domain():
    assert registrable_domain("https://login.example.co.uk/path") == "example.co.uk"


def test_explainable_score_and_cap():
    observation = BrowserObservation(
        final_url="https://collector.example.net/login",
        redirect_chain=[
            "https://a.example",
            "https://b.example",
            "https://c.example",
            "https://collector.example.net/login",
        ],
        has_password_input=True,
        external_form_action=True,
        tls_error=True,
        download_attempted=True,
        popup_attempted=True,
    )
    score, flags = score_observation(observation, "https://start.example.com")
    assert score == 100
    assert len(flags) == 7


def test_clean_observation_scores_zero():
    score, flags = score_observation(
        BrowserObservation(final_url="https://www.example.com/home"),
        "https://example.com",
    )
    assert score == 0
    assert flags == []
