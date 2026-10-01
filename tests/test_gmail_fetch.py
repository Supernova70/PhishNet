"""Per-account mailbox fetch (P3 fix) — Gmail API vs shared IMAP.

Guards the cross-account leak: Fetch Emails must pull the signed-in
account's own Gmail (OAuth refresh token), never the shared operator
IMAP mailbox configured in env.
"""

import base64
from unittest.mock import MagicMock, patch

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.api.email import router as email_router
from app.auth.crypto import encrypt_secret
from app.auth.session import COOKIE_NAME, create_session_token
from app.dependencies import get_current_user, get_db
from app.models import Base
from app.models.email import Email
from app.models.fetch_state import FetchState
from app.models.user import User
from app.services import email_service as email_service_mod
from app.services.email_service import EmailService
from app.services.gmail_fetch import (
    GmailAuthFailed,
    GmailNotConnected,
    exchange_access_token,
    fetch_recent_raw_messages,
)

RAW_OLD = b"From: a@x.test\r\nSubject: older\r\n\r\nold\r\n"
RAW_NEW = b"From: b@x.test\r\nSubject: newer\r\n\r\nnew\r\n"


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode()


def _resp(status: int, body: dict) -> MagicMock:
    r = MagicMock(spec=httpx.Response)
    r.status_code = status
    r.json.return_value = body
    return r


# ── token exchange ─────────────────────────────────────────────────────

class TestTokenExchange:
    def test_success(self):
        client = MagicMock(spec=httpx.Client)
        client.post.return_value = _resp(200, {"access_token": "at-1"})
        token = exchange_access_token(client, "rt", "cid", "cs")
        assert token == "at-1"
        kwargs = client.post.call_args.kwargs
        assert kwargs["data"]["refresh_token"] == "rt"
        assert kwargs["data"]["grant_type"] == "refresh_token"

    def test_invalid_grant_raises_auth_failed(self):
        client = MagicMock(spec=httpx.Client)
        client.post.return_value = _resp(
            400, {"error": "invalid_grant", "error_description": "Token has been revoked."}
        )
        with pytest.raises(GmailAuthFailed):
            exchange_access_token(client, "rt", "cid", "cs")

    def test_missing_client_config_raises(self):
        client = MagicMock(spec=httpx.Client)
        with pytest.raises(GmailAuthFailed):
            exchange_access_token(client, "rt", "", "")
        client.post.assert_not_called()

    def test_server_error_is_generic_fetch_error(self):
        from app.services.gmail_fetch import GmailFetchError

        client = MagicMock(spec=httpx.Client)
        client.post.return_value = _resp(503, {})
        with pytest.raises(GmailFetchError):
            exchange_access_token(client, "rt", "cid", "cs")


# ── message download ───────────────────────────────────────────────────

class TestFetchRecentRaw:
    def test_decodes_sorts_and_limits(self):
        client = MagicMock(spec=httpx.Client)
        client.post.return_value = _resp(200, {"access_token": "at"})
        client.get.side_effect = [
            # list: unsorted on purpose — result must come back newest-first
            _resp(200, {"messages": [{"id": "m-old"}, {"id": "m-new"}]}),
            _resp(200, {"payload": {"raw": _b64(RAW_OLD)}, "internalDate": "1000"}),
            _resp(200, {"payload": {"raw": _b64(RAW_NEW)}, "internalDate": "2000"}),
        ]
        out = fetch_recent_raw_messages("rt", "cid", "cs", limit=5, client=client)
        assert out == [RAW_NEW, RAW_OLD]
        # every message GET is read-only format=raw
        for call in client.get.call_args_list[1:]:
            assert call.kwargs["params"] == {"format": "raw"}

    def test_list_401_raises_auth_failed(self):
        client = MagicMock(spec=httpx.Client)
        client.post.return_value = _resp(200, {"access_token": "at"})
        client.get.return_value = _resp(401, {})
        with pytest.raises(GmailAuthFailed):
            fetch_recent_raw_messages("rt", "cid", "cs", limit=5, client=client)

    def test_fetch_token_via_env_client_config(self):
        client = MagicMock(spec=httpx.Client)
        client.post.return_value = _resp(200, {"access_token": "at"})
        client.get.return_value = _resp(200, {"messages": []})
        out = fetch_recent_raw_messages("rt", "cid", "cs", limit=5, client=client)
        assert out == []


# ── EmailService mailbox selection ─────────────────────────────────────

@pytest.fixture()
def db(tmp_path):
    engine = create_engine(
        f"sqlite:///{tmp_path}/fetch.db",
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    yield session
    session.close()


def _user(db, uid, email, connected=True, with_token=True):
    user = User(
        id=uid, google_sub=f"sub-{uid}", email=email, name=f"u{uid}",
        role="admin" if uid == 1 else "user",
        gmail_connected=connected,
        gmail_refresh_token_enc=encrypt_secret("rt-secret") if with_token else None,
    )
    db.add(user)
    db.commit()
    return user


class TestMailboxSelection:
    def test_connected_user_fetches_own_gmail_not_imap(self, db, tmp_path):
        user = _user(db, 1, "alice@example.com")
        with patch.object(
            email_service_mod.settings, "EMAIL_ADDRESS", "demo@shared.test"
        ), patch.object(
            email_service_mod.settings, "ATTACHMENT_DIR", str(tmp_path / "att")
        ), patch.object(
            email_service_mod, "fetch_recent_raw_messages", return_value=[RAW_NEW]
        ) as gmail, patch.object(
            email_service_mod, "IMAPClient"
        ) as imap:
            new, total = EmailService(db, user_id=user.id).fetch_and_store(limit=5)

        assert (new, total) == (1, 1)
        # refresh token decrypted and handed to the Gmail API
        assert gmail.call_args.args[0] == "rt-secret"
        assert not imap.called
        row = db.query(Email).one()
        assert row.user_id == user.id
        assert row.subject == "newer"
        # Gmail path has no IMAP UIDs → no fetch cursor written
        assert db.query(FetchState).count() == 0

    def test_unlinked_user_cannot_read_shared_mailbox(self, db):
        user = _user(db, 2, "bob@example.com", connected=False, with_token=False)
        with patch.object(
            email_service_mod.settings, "EMAIL_ADDRESS", "demo@shared.test"
        ), patch.object(email_service_mod, "IMAPClient") as imap:
            with pytest.raises(GmailNotConnected):
                EmailService(db, user_id=user.id).fetch_and_store(limit=5)
            assert not imap.called
        assert db.query(Email).count() == 0

    def test_operator_own_mailbox_still_uses_legacy_imap(self, db, tmp_path):
        user = _user(db, 3, "demo@shared.test", connected=False, with_token=False)
        client = MagicMock()
        client.search.return_value = [7]
        client.fetch.return_value = {7: {b"RFC822": RAW_NEW}}
        with patch.object(
            email_service_mod.settings, "EMAIL_ADDRESS", "demo@shared.test"
        ), patch.object(email_service_mod.settings, "EMAIL_PASSWORD", "pw"), \
                patch.object(
                    email_service_mod.settings, "ATTACHMENT_DIR",
                    str(tmp_path / "att"),
                ), patch.object(email_service_mod, "IMAPClient", return_value=client):
            new, total = EmailService(db, user_id=user.id).fetch_and_store(limit=5)
        assert (new, total) == (1, 1)
        client.login.assert_called_once()
        assert db.query(Email).one().user_id == user.id

    def test_revoked_token_no_cross_mailbox_fallback(self, db):
        user = _user(db, 4, "carol@example.com")
        with patch.object(
            email_service_mod.settings, "EMAIL_ADDRESS", "demo@shared.test"
        ), patch.object(
            email_service_mod,
            "fetch_recent_raw_messages",
            side_effect=GmailAuthFailed("revoked"),
        ), patch.object(email_service_mod, "IMAPClient") as imap:
            with pytest.raises(GmailAuthFailed):
                EmailService(db, user_id=user.id).fetch_and_store(limit=5)
            assert not imap.called

    def test_script_context_without_user_keeps_legacy_path(self, db):
        with patch.object(email_service_mod, "IMAPClient") as imap:
            client = MagicMock()
            client.search.return_value = []
            imap.return_value = client
            new, total = EmailService(db).fetch_and_store(limit=5)
        assert (new, total) == (0, 0)
        imap.assert_called_once()


# ── API surface ────────────────────────────────────────────────────────

@pytest.fixture()
def api(db):
    user = _user(db, 10, "dave@example.com", connected=False, with_token=False)
    app = FastAPI()
    app.include_router(email_router)
    app.dependency_overrides[get_db] = lambda: db
    app.dependency_overrides[get_current_user] = lambda: user
    client = TestClient(app)
    client.cookies.set(COOKIE_NAME, create_session_token(user))
    yield {"client": client, "db": db, "user": user}
    app.dependency_overrides.clear()


class TestFetchEndpoint:
    def test_403_with_actionable_detail_when_not_connected(self, api):
        with patch.object(
            email_service_mod.settings, "EMAIL_ADDRESS", "demo@shared.test"
        ):
            resp = api["client"].post("/emails/fetch")
        assert resp.status_code == 403
        assert "sign in" in resp.json()["detail"].lower()

    def test_403_reconnect_detail_on_auth_failure(self, api):
        api["user"].gmail_connected = True
        api["user"].gmail_refresh_token_enc = encrypt_secret("rt")
        api["db"].commit()
        with patch.object(
            email_service_mod,
            "fetch_recent_raw_messages",
            side_effect=GmailAuthFailed("revoked"),
        ):
            resp = api["client"].post("/emails/fetch")
        assert resp.status_code == 403
        assert "reconnect" in resp.json()["detail"].lower()

    def test_200_fetches_own_mail(self, api, tmp_path):
        api["user"].gmail_connected = True
        api["user"].gmail_refresh_token_enc = encrypt_secret("rt")
        api["db"].commit()
        with patch.object(
            email_service_mod.settings, "ATTACHMENT_DIR", str(tmp_path / "att")
        ), patch.object(
            email_service_mod, "fetch_recent_raw_messages", return_value=[RAW_NEW]
        ):
            resp = api["client"].post("/emails/fetch?limit=5")
        assert resp.status_code == 200
        body = resp.json()
        assert body["new_emails"] == 1
        row = api["db"].query(Email).one()
        assert row.user_id == api["user"].id
