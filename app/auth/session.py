"""Own session JWTs in an httpOnly cookie.

The browser never sees the token (XSS-safe); axios sends the cookie
same-origin automatically. Signed with SESSION_SECRET so any uvicorn
worker validates any session (stateless, no server-side session store).
"""

import time
from typing import Any, Dict

import jwt
from fastapi import Response

from app.config import get_settings

COOKIE_NAME = "phishing_guard_session"
ALGORITHM = "HS256"


class SessionError(Exception):
    """Session token missing, malformed, tampered, or expired."""


def create_session_token(user: Any) -> str:
    """Encode a session for `app.models.user.User`."""
    settings = get_settings()
    now = int(time.time())
    payload: Dict[str, Any] = {
        "uid": user.id,
        "sub": user.google_sub,
        "email": user.email,
        "role": user.role,
        "iat": now,
        "exp": now + settings.SESSION_TTL_HOURS * 3600,
    }
    return jwt.encode(payload, settings.SESSION_SECRET, algorithm=ALGORITHM)


def decode_session_token(token: str) -> Dict[str, Any]:
    """Verify signature + expiry. Raises SessionError on any failure."""
    settings = get_settings()
    try:
        return jwt.decode(
            token, settings.SESSION_SECRET, algorithms=[ALGORITHM]
        )
    except jwt.PyJWTError as exc:
        raise SessionError(str(exc)) from exc


def set_session_cookie(response: Response, token: str) -> None:
    settings = get_settings()
    response.set_cookie(
        COOKIE_NAME,
        token,
        max_age=settings.SESSION_TTL_HOURS * 3600,
        httponly=True,
        samesite="lax",
        secure=settings.SESSION_COOKIE_SECURE,
        path="/",
    )


def clear_session_cookie(response: Response) -> None:
    settings = get_settings()
    response.delete_cookie(
        COOKIE_NAME,
        path="/",
        samesite="lax",
        secure=settings.SESSION_COOKIE_SECURE,
    )
