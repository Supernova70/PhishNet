"""
VirusTotal v3 API client with multi-key rotation.

Why this exists
---------------
Free VT accounts are metered (e.g. 4 req/min, 500 calls/day per account).
When a quota is exhausted the API answers ``429 Quota Exceeded`` and that key
is useless until the next metering period. Phishing Guard 2.0 therefore
accepts any
number of keys in ``VIRUSTOTAL_API_KEYS`` (comma-separated, one key per VT
account) and this client rotates through them automatically:

  * ``429``        → key goes into cooldown (``Retry-After`` honored, else an
                     escalating backoff 2m → 10m → 30m → 1h → 4h) and the
                     NEXT key is tried inside the same call.
  * ``401``/``403`` → key is marked invalid (permanent) and the next key is
                     tried.
  * all keys exhausted → the call returns a synthesised 429/401 plus a clear
                     message so callers fall back to heuristic-only scoring.

Cooldown state lives in a module-level table keyed by the key string, shared
by every engine (URL analyzer, attachment analyzer). State is in-memory and
per-process: with multiple uvicorn workers each worker rotates on its own —
harmless (worst case one extra 429 before a worker learns the key is capped).

Usage:
    from app.integrations.virustotal import VirusTotalClient

    status, data, err = VirusTotalClient().get(f"/files/{sha256}")
    # status: 200/404/429/401/... ; 0 = transport error or no keys
"""

import logging
import threading
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

import httpx

from app.config import get_settings

logger = logging.getLogger(__name__)

VT_BASE = "https://www.virustotal.com/api/v3"

# Cooldown applied per 429 strike when the server sends no Retry-After header.
# A daily-quota key keeps 429-ing; escalating keeps it quiet without hiding it
# from the UI (the key is retried later the same day).
_COOLDOWN_STEPS = (120, 600, 1800, 3600, 14400)
_DEFAULT_RETRY_AFTER = 300

NO_KEYS_ERROR = "No VT API keys configured — set VIRUSTOTAL_API_KEYS in .env"
AUTH_ERROR = "VT authentication failed — check VIRUSTOTAL_API_KEYS"


@dataclass
class _KeyState:
    """Per-key rotation bookkeeping (shared across client instances)."""

    key: str
    cooldown_until: float = 0.0
    strikes: int = 0
    invalid: bool = False
    last_used: float = 0.0
    calls: int = 0


_STATE: Dict[str, _KeyState] = {}
_LOCK = threading.Lock()


def reset_vt_state() -> None:
    """Drop all rotation state (test helper — never call from app code)."""
    with _LOCK:
        _STATE.clear()


def _state_for(key: str) -> _KeyState:  # caller holds _LOCK
    st = _STATE.get(key)
    if st is None:
        st = _KeyState(key=key)
        _STATE[key] = st
    return st


class VirusTotalClient:
    """Thin VT v3 client that rotates across all configured API keys."""

    def __init__(self, keys: Optional[List[str]] = None):
        # Explicit keys (tests) > application settings.
        self._keys: List[str] = (
            list(keys) if keys is not None else get_settings().vt_api_keys
        )

    # ── Public API ─────────────────────────────────────────────────────────────

    def get(self, path: str) -> Tuple[int, Optional[dict], Optional[str]]:
        """GET /api/v3{path}. Returns (status, data, error)."""
        return self.request("GET", path)

    def post(self, path: str, data: Optional[dict] = None) -> Tuple[int, Optional[dict], Optional[str]]:
        """POST /api/v3{path}. Returns (status, data, error)."""
        return self.request("POST", path, data=data)

    def request(
        self, method: str, path: str, *, data: Optional[dict] = None
    ) -> Tuple[int, Optional[dict], Optional[str]]:
        """
        Perform a VT request, rotating keys on 429/401.

        Returns:
            (200, json, None)          — success
            (404, None, None)          — resource not found (caller decides)
            (429, None, message)       — every key rate-limited/cooled down
            (401, None, message)       — every key invalid (or none configured)
            (0,   None, message)       — transport error / no keys configured
            (HTTP, None, message)      — other terminal HTTP status
        """
        if not self._keys:
            return 0, None, NO_KEYS_ERROR

        saw_auth_failure = False
        attempts = 0

        while attempts < len(self._keys):
            key = self._acquire_key()
            if key is None:
                break
            attempts += 1

            try:
                with httpx.Client(timeout=10.0) as client:
                    resp = client.request(
                        method,
                        f"{VT_BASE}{path}",
                        headers={"x-apikey": key},
                        data=data,
                    )
            except Exception as e:
                # Transport problems are not the key's fault — do not rotate.
                return 0, None, f"VT connection failed: {str(e)[:80]}"

            if resp.status_code == 200:
                try:
                    return 200, resp.json(), None
                except Exception:
                    return 200, {}, None

            if resp.status_code == 404:
                return 404, None, None

            if resp.status_code in (401, 403):
                self._mark_invalid(key)
                saw_auth_failure = True
                logger.warning(
                    "VT rejected key #%s (%s…): HTTP %d — marked invalid, trying next key",
                    self._key_index(key), key[:6], resp.status_code,
                )
                continue

            if resp.status_code == 429:
                self._mark_cooldown(key, resp)
                logger.warning(
                    "VT rate limit (429) for key #%s (%s…) — cooling down, trying next key",
                    self._key_index(key), key[:6],
                )
                continue

            # Any other status is terminal for this call.
            return resp.status_code, None, f"VT HTTP {resp.status_code}"

        # ── All keys consumed ──────────────────────────────────────────────
        if saw_auth_failure:
            return 401, None, AUTH_ERROR
        if self._all_keys_invalid():
            return 401, None, AUTH_ERROR
        return (
            429,
            None,
            f"VT rate limit — all {len(self._keys)} API key(s) exhausted (429)",
        )

    def status(self) -> dict:
        """Key-pool health snapshot for the health endpoint."""
        now = time.time()
        with _LOCK:
            states = [_state_for(k) for k in self._keys]
            available = sum(
                1 for s in states if not s.invalid and s.cooldown_until <= now
            )
            cooling = sum(
                1 for s in states if not s.invalid and s.cooldown_until > now
            )
            invalid = sum(1 for s in states if s.invalid)
            calls = sum(s.calls for s in states)
            keys = [
                {
                    "id": i + 1,
                    "masked": f"{s.key[:6]}…",
                    "state": (
                        "invalid"
                        if s.invalid
                        else "cooldown"
                        if s.cooldown_until > now
                        else "ready"
                    ),
                    "cooldown_remaining": max(0, int(s.cooldown_until - now)),
                    "calls": s.calls,
                }
                for i, s in enumerate(states)
            ]
        return {
            "key_count": len(self._keys),
            "available": available,
            "cooling_down": cooling,
            "invalid": invalid,
            "total_calls": calls,
            "keys": keys,
        }

    # ── Key pool internals ─────────────────────────────────────────────────────

    def _acquire_key(self) -> Optional[str]:
        """Pick the least-recently-used usable key and stamp its last_used."""
        if not self._keys:
            return None
        now = time.time()
        with _LOCK:
            usable = [
                _state_for(k)
                for k in self._keys
                # invalid keys and keys in cooldown are unusable
            ]
            usable = [
                s for s in usable if not s.invalid and s.cooldown_until <= now
            ]
            if not usable:
                return None
            chosen = min(usable, key=lambda s: s.last_used)
            chosen.last_used = now
            chosen.calls += 1
            return chosen.key

    def _mark_invalid(self, key: str) -> None:
        with _LOCK:
            st = _state_for(key)
            st.invalid = True

    def _mark_cooldown(self, key: str, resp: httpx.Response) -> None:
        with _LOCK:
            st = _state_for(key)
            delay = None
            header = resp.headers.get("Retry-After", "")
            try:
                if header:
                    delay = max(1, int(header))
            except ValueError:
                delay = None
            if delay is None:
                step = _COOLDOWN_STEPS[min(st.strikes, len(_COOLDOWN_STEPS) - 1)]
                delay = step
                st.strikes += 1
            st.cooldown_until = time.time() + delay
            logger.info(
                "VT key #%s cooling down for %ds (strikes=%d)",
                self._key_index(key), delay, st.strikes,
            )

    def _all_keys_invalid(self) -> bool:
        if not self._keys:
            return False
        with _LOCK:
            return all(_state_for(k).invalid for k in self._keys)

    def _key_index(self, key: str) -> int:
        try:
            return self._keys.index(key) + 1
        except ValueError:
            return 0
