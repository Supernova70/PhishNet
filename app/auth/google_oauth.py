"""Google OAuth helpers — authorization-code flow + ID-token verification.

Implemented directly on httpx (already a core dependency): Authlib's httpx
integration is deprecated upstream, and the flow is two HTTP calls plus a
JWKS signature check.

All three entry points are patchable in tests (no network in unit tests):
  - build_authorization_url  (pure)
  - fetch_token              (POST oauth2.googleapis.com/token)
  - verify_google_id_token   (JWKS via PyJWT PyJWKClient)
"""

import logging
import threading
from typing import Any, Dict, Optional
from urllib.parse import urlencode

import httpx
import jwt as pyjwt

from app.config import get_settings

logger = logging.getLogger(__name__)

AUTH_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"
JWKS_URL = "https://www.googleapis.com/oauth2/v3/certs"
GOOGLE_ISSUERS = ("accounts.google.com", "https://accounts.google.com")

_jwks_lock = threading.Lock()
_jwks_client: Optional[pyjwt.PyJWKClient] = None


def build_authorization_url(state: str) -> str:
    """Full-page consent URL — one combined scope (sign-in + gmail.readonly)."""
    settings = get_settings()
    params = {
        "client_id": settings.GOOGLE_CLIENT_ID,
        "response_type": "code",
        "redirect_uri": settings.GOOGLE_REDIRECT_URI,
        "scope": settings.GOOGLE_SCOPES,
        "access_type": "offline",   # issue a refresh token
        "prompt": "consent",        # force the consent screen (refresh token guaranteed)
        "state": state,             # CSRF
    }
    return f"{AUTH_ENDPOINT}?{urlencode(params)}"


def fetch_token(code: str) -> Dict[str, Any]:
    """Exchange the authorization code (server-side only).

    Returns the token dict: access_token, refresh_token, id_token, ...
    Raises httpx.HTTPStatusError on failure (bad/expired code, mismatch).
    """
    settings = get_settings()
    with httpx.Client(timeout=15.0) as client:
        resp = client.post(
            TOKEN_ENDPOINT,
            data={
                "grant_type": "authorization_code",
                "code": code,
                "client_id": settings.GOOGLE_CLIENT_ID,
                "client_secret": settings.GOOGLE_CLIENT_SECRET,
                "redirect_uri": settings.GOOGLE_REDIRECT_URI,
            },
        )
        resp.raise_for_status()
        return resp.json()


def _get_jwks_client() -> pyjwt.PyJWKClient:
    global _jwks_client
    if _jwks_client is None:
        with _jwks_lock:
            if _jwks_client is None:
                _jwks_client = pyjwt.PyJWKClient(JWKS_URL)
    return _jwks_client


def verify_google_id_token(id_token: str) -> Dict[str, Any]:
    """Verify signature (Google JWKS), aud, iss, exp, email_verified.

    Raises pyjwt.PyJWTError / ValueError on any failure.
    """
    settings = get_settings()
    signing_key = _get_jwks_client().get_signing_key_from_jwt(id_token)
    payload = pyjwt.decode(
        id_token,
        signing_key.key,
        algorithms=["RS256"],
        audience=settings.GOOGLE_CLIENT_ID,
        issuer=GOOGLE_ISSUERS,
    )
    if payload.get("email_verified") is not True:
        raise ValueError("Google email_verified is not true")
    return payload
