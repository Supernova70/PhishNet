"""Auth core tests — Google combined consent + session cookies.

Google is fully mocked (no network): build_authorization_url runs for real
(pure), fetch_token / verify_google_id_token are patched.
SQLite + isolated FastAPI app, offline.
"""

from datetime import datetime

import jwt as pyjwt
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from unittest.mock import patch

from app.auth.crypto import decrypt_secret
from app.auth.session import COOKIE_NAME, create_session_token
from app.api.auth import STATE_COOKIE, router as auth_router
from app.config import get_settings
from app.dependencies import get_db
from app.models import Base
from app.models.user import User

CLIENT_ID = "test-client-id.apps.googleusercontent.com"
ID_PAYLOAD = {
    "sub": "google-sub-123",
    "email": "alice@gmail.com",
    "email_verified": True,
    "name": "Alice",
    "picture": "https://example.org/a.png",
}
TOKEN = {
    "access_token": "ya29.access",
    "refresh_token": "1/refresh-secret",
    "id_token": "fake.signed.jwt",
}


@pytest.fixture()
def env(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path}/auth.db")
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    app = FastAPI()
    app.include_router(auth_router)
    app.dependency_overrides[get_db] = lambda: session
    settings = get_settings()
    yield {
        "app": app,
        "client": TestClient(app),
        "db": session,
        "settings": settings,
    }
    session.close()


@pytest.fixture(autouse=True)
def google_config(env, monkeypatch):
    """Point settings at a fake OAuth client (restored after each test)."""
    s = env["settings"]
    monkeypatch.setattr(s, "GOOGLE_CLIENT_ID", CLIENT_ID)
    monkeypatch.setattr(s, "GOOGLE_CLIENT_SECRET", "test-secret")
    monkeypatch.setattr(s, "ADMIN_EMAILS", "")
    monkeypatch.setattr(s, "SESSION_COOKIE_SECURE", False)
    return s


def _start_sign_in(client: TestClient) -> str:
    """Drive GET /auth/google, return the state it sent to Google."""
    resp = client.get("/auth/google", follow_redirects=False)
    assert resp.status_code == 302
    location = resp.headers["location"]
    assert location.startswith("https://accounts.google.com/o/oauth2/v2/auth?")
    assert CLIENT_ID in location
    assert "gmail.readonly" in location
    assert "access_type=offline" in location
    assert "prompt=consent" in location
    assert "response_type=code" in location
    # state present in URL and mirrored in the csrf cookie
    from urllib.parse import parse_qs, urlparse
    state = parse_qs(urlparse(location).query)["state"][0]
    assert client.cookies.get(STATE_COOKIE) == state
    return state


# ── /auth/config ───────────────────────────────────────────────────────

def test_config_reports_client_id(env):
    resp = env["client"].get("/auth/config")
    assert resp.status_code == 200
    assert resp.json() == {
        "google_client_id": CLIENT_ID, "configured": True, "one_tap": True,
    }


def test_config_unconfigured(env, monkeypatch):
    monkeypatch.setattr(env["settings"], "GOOGLE_CLIENT_ID", "")
    assert env["client"].get("/auth/config").json()["configured"] is False


# ── /auth/google ───────────────────────────────────────────────────────

def test_sign_in_redirects_to_google(env):
    _start_sign_in(env["client"])


def test_sign_in_503_without_client_id(env, monkeypatch):
    monkeypatch.setattr(env["settings"], "GOOGLE_CLIENT_ID", "")
    resp = env["client"].get("/auth/google", follow_redirects=False)
    assert resp.status_code == 503


# ── /auth/callback ─────────────────────────────────────────────────────

def test_callback_creates_user_and_session(env):
    client = env["client"]
    state = _start_sign_in(client)
    with patch("app.auth.google_oauth.fetch_token", return_value=TOKEN), patch(
        "app.auth.google_oauth.verify_google_id_token", return_value=ID_PAYLOAD
    ):
        resp = client.get(
            f"/auth/callback?code=abc&state={state}", follow_redirects=False
        )
    assert resp.status_code == 302
    assert resp.headers["location"] == "/"
    assert COOKIE_NAME in client.cookies

    user = env["db"].query(User).one()
    assert user.google_sub == "google-sub-123"
    assert user.email == "alice@gmail.com"
    assert user.gmail_connected is True
    assert decrypt_secret(user.gmail_refresh_token_enc) == "1/refresh-secret"
    assert user.last_login_at is not None

    me = client.get("/auth/me")
    assert me.status_code == 200
    assert me.json()["email"] == "alice@gmail.com"
    assert me.json()["needs_gmail"] is False
    assert me.json()["gmail_connected"] is True


def test_callback_grants_admin_from_admin_emails(env, monkeypatch):
    monkeypatch.setattr(env["settings"], "ADMIN_EMAILS", "Alice@Gmail.com")
    client = env["client"]
    state = _start_sign_in(client)
    with patch("app.auth.google_oauth.fetch_token", return_value=TOKEN), patch(
        "app.auth.google_oauth.verify_google_id_token", return_value=ID_PAYLOAD
    ):
        client.get(f"/auth/callback?code=abc&state={state}", follow_redirects=False)
    assert env["db"].query(User).one().role == "admin"


def test_callback_rejects_missing_or_wrong_state(env):
    client = env["client"]
    # no state cookie at all
    resp = client.get("/auth/callback?code=abc&state=x", follow_redirects=False)
    assert resp.status_code == 302
    assert resp.headers["location"].startswith("/login?error=invalid_state")
    # mismatched state
    _start_sign_in(client)
    resp = client.get("/auth/callback?code=abc&state=WRONG", follow_redirects=False)
    assert "invalid_state" in resp.headers["location"]


def test_callback_token_exchange_failure(env):
    client = env["client"]
    state = _start_sign_in(client)
    with patch(
        "app.auth.google_oauth.fetch_token", side_effect=RuntimeError("boom")
    ):
        resp = client.get(
            f"/auth/callback?code=abc&state={state}", follow_redirects=False
        )
    assert "token_exchange_failed" in resp.headers["location"]
    assert COOKIE_NAME not in client.cookies


def test_callback_bad_id_token(env):
    client = env["client"]
    state = _start_sign_in(client)
    with patch("app.auth.google_oauth.fetch_token", return_value=TOKEN), patch(
        "app.auth.google_oauth.verify_google_id_token",
        side_effect=ValueError("bad sig"),
    ):
        resp = client.get(
            f"/auth/callback?code=abc&state={state}", follow_redirects=False
        )
    assert "invalid_id_token" in resp.headers["location"]
    assert env["db"].query(User).count() == 0


def test_google_error_param_maps_to_login_error(env):
    resp = env["client"].get(
        "/auth/callback?error=access_denied", follow_redirects=False
    )
    assert "google%3Aaccess_denied" in resp.headers["location"]


# ── /auth/me + sessions ────────────────────────────────────────────────

def test_me_401_anonymous(env):
    assert env["client"].get("/auth/me").status_code == 401


def test_me_401_tampered_cookie(env):
    env["client"].cookies.set(COOKIE_NAME, "not-a-real-token")
    assert env["client"].get("/auth/me").status_code == 401


def test_me_401_expired_cookie(env):
    settings = env["settings"]
    now = int(__import__("time").time())
    expired = pyjwt.encode(
        {"uid": 1, "sub": "x", "email": "x@y.z", "role": "user",
         "iat": now - 9999, "exp": now - 1},
        settings.SESSION_SECRET, algorithm="HS256",
    )
    env["client"].cookies.set(COOKIE_NAME, expired)
    assert env["client"].get("/auth/me").status_code == 401


def test_me_401_unknown_user(env):
    # well-formed session whose uid has no row (deleted account)
    settings = env["settings"]
    now = int(__import__("time").time())
    token = pyjwt.encode(
        {"uid": 99999, "sub": "ghost", "email": "ghost@example.com",
         "role": "user", "iat": now, "exp": now + 3600},
        settings.SESSION_SECRET, algorithm="HS256",
    )
    env["client"].cookies.set(COOKIE_NAME, token)
    assert env["client"].get("/auth/me").status_code == 401


def test_logout_clears_session(env):
    client = env["client"]
    state = _start_sign_in(client)
    with patch("app.auth.google_oauth.fetch_token", return_value=TOKEN), patch(
        "app.auth.google_oauth.verify_google_id_token", return_value=ID_PAYLOAD
    ):
        client.get(f"/auth/callback?code=abc&state={state}", follow_redirects=False)
    assert client.get("/auth/me").status_code == 200

    resp = client.post("/auth/logout")
    assert resp.status_code == 200
    # starlette's client jar drops the cookie on deletion
    assert client.get("/auth/me").status_code == 401


# ── /auth/credential (One Tap) ─────────────────────────────────────────

def _seed_user(db, sub="google-sub-123", email="alice@gmail.com", connected=False):
    user = User(google_sub=sub, email=email, gmail_connected=connected)
    db.add(user)
    db.commit()
    return user


def test_credential_csrf_enforced(env):
    client = env["client"]
    # no g_csrf cookie/body
    resp = client.post("/auth/credential", json={"credential": "tok"})
    assert resp.status_code == 403
    # body/cookie mismatch
    client.cookies.set("g_csrf_token", "server-value")
    resp = client.post(
        "/auth/credential",
        json={"credential": "tok", "g_csrf_token": "other-value"},
    )
    assert resp.status_code == 403


def test_credential_rejects_unknown_account(env):
    client = env["client"]
    client.cookies.set("g_csrf_token", "csrf-1")
    with patch(
        "app.auth.google_oauth.verify_google_id_token",
        return_value={"sub": "never-seen", "email": "x@y.z",
                      "email_verified": True},
    ):
        resp = client.post(
            "/auth/credential",
            json={"credential": "tok", "g_csrf_token": "csrf-1"},
        )
    assert resp.status_code == 401


def test_credential_invalid_token(env):
    client = env["client"]
    client.cookies.set("g_csrf_token", "csrf-1")
    with patch(
        "app.auth.google_oauth.verify_google_id_token",
        side_effect=ValueError("bad"),
    ):
        resp = client.post(
            "/auth/credential",
            json={"credential": "tok", "g_csrf_token": "csrf-1"},
        )
    assert resp.status_code == 401


def test_credential_signs_in_existing_user(env):
    client = env["client"]
    _seed_user(env["db"], connected=False)
    client.cookies.set("g_csrf_token", "csrf-1")
    with patch(
        "app.auth.google_oauth.verify_google_id_token", return_value=ID_PAYLOAD
    ):
        resp = client.post(
            "/auth/credential",
            json={"credential": "tok", "g_csrf_token": "csrf-1"},
        )
    assert resp.status_code == 200
    body = resp.json()
    assert body["email"] == "alice@gmail.com"
    assert body["needs_gmail"] is True
    assert COOKIE_NAME in client.cookies
    assert client.get("/auth/me").status_code == 200
