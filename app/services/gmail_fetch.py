"""Fetch a signed-in account's own mailbox via the Gmail API.

The legacy IMAP path logs into ONE configured mailbox
(``settings.EMAIL_ADDRESS``) — correct only for the operator who owns
that address. When a different account hits Fetch Emails, that path
would download the shared/demo mailbox and file it under the other
account (cross-account data leak). This module instead uses the
refresh token stored at consent (combined scope includes
``gmail.readonly``) so each account fetches only its own Gmail.

Read-only: we list + download messages; nothing is ever sent,
modified, or deleted.
"""

from __future__ import annotations

import base64
import logging
from typing import List, Optional

import httpx

logger = logging.getLogger(__name__)

TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"
MESSAGES_ENDPOINT = "https://gmail.googleapis.com/gmail/v1/users/me/messages"


class GmailFetchError(Exception):
    """Generic fetch failure after successful authorization."""


class GmailNotConnected(GmailFetchError):
    """This account has no Gmail grant — must sign in with Google again."""


class GmailAuthFailed(GmailFetchError):
    """Refresh token rejected (revoked, expired, or wrong client)."""


def exchange_access_token(
    client: httpx.Client, refresh_token: str, client_id: str, client_secret: str
) -> str:
    """Refresh-token grant → short-lived access token."""
    if not client_id or not client_secret:
        raise GmailAuthFailed("Google OAuth client is not configured")
    try:
        resp = client.post(
            TOKEN_ENDPOINT,
            data={
                "client_id": client_id,
                "client_secret": client_secret,
                "refresh_token": refresh_token,
                "grant_type": "refresh_token",
            },
        )
    except httpx.HTTPError as exc:
        raise GmailFetchError(f"token endpoint unreachable: {exc}") from exc
    if resp.status_code in (400, 401, 403):
        detail = ""
        try:
            detail = (resp.json() or {}).get("error", "")
        except ValueError:
            pass
        raise GmailAuthFailed(
            f"refresh rejected ({resp.status_code}{': ' + detail if detail else ''})"
        )
    if resp.status_code >= 500:
        raise GmailFetchError(f"token endpoint error ({resp.status_code})")
    try:
        payload = resp.json()
    except ValueError as exc:
        raise GmailFetchError("token endpoint returned non-JSON") from exc
    token = payload.get("access_token")
    if not token:
        raise GmailFetchError("token endpoint response missing access_token")
    return token


def fetch_recent_raw_messages(
    refresh_token: str,
    client_id: str,
    client_secret: str,
    limit: int = 20,
    client: Optional[httpx.Client] = None,
) -> List[bytes]:
    """Newest ``limit`` INBOX messages as raw RFC 822 bytes (newest first)."""
    owns_client = client is None
    client = client or httpx.Client(timeout=30.0)
    try:
        access = exchange_access_token(client, refresh_token, client_id, client_secret)
        headers = {"Authorization": f"Bearer {access}"}
        try:
            listed = client.get(
                MESSAGES_ENDPOINT,
                headers=headers,
                params={"labelIds": "INBOX", "maxResults": max(limit, 1)},
            )
        except httpx.HTTPError as exc:
            raise GmailFetchError(f"messages list unreachable: {exc}") from exc
        if listed.status_code in (401, 403):
            raise GmailAuthFailed(f"list rejected ({listed.status_code})")
        if listed.status_code >= 400:
            raise GmailFetchError(f"messages list failed ({listed.status_code})")
        entries = (listed.json() or {}).get("messages") or []

        fetched: list[tuple[int, bytes]] = []
        for entry in entries[:limit]:
            msg_id = entry.get("id")
            if not msg_id:
                continue
            try:
                resp = client.get(
                    f"{MESSAGES_ENDPOINT}/{msg_id}",
                    headers=headers,
                    params={"format": "raw"},
                )
            except httpx.HTTPError as exc:
                logger.warning("gmail message %s unreachable: %s", msg_id, exc)
                continue
            if resp.status_code in (401, 403):
                raise GmailAuthFailed(f"message get rejected ({resp.status_code})")
            if resp.status_code >= 400:
                logger.warning(
                    "gmail message %s failed (%s)", msg_id, resp.status_code
                )
                continue
            payload = resp.json() or {}
            raw_b64 = (payload.get("payload") or {}).get("raw")
            if not raw_b64:
                continue
            try:
                raw = base64.urlsafe_b64decode(raw_b64 + "=" * (-len(raw_b64) % 4))
            except (ValueError, TypeError) as exc:
                logger.warning("gmail message %s undecodable: %s", msg_id, exc)
                continue
            try:
                when = int(payload.get("internalDate") or 0)
            except (TypeError, ValueError):
                when = 0
            fetched.append((when, raw))

        # Gmail's list order is not contractual — pin newest-first.
        fetched.sort(key=lambda pair: pair[0], reverse=True)
        return [raw for _, raw in fetched]
    finally:
        if owns_client:
            client.close()
