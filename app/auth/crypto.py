"""Fernet encryption for secrets at rest (OAuth refresh tokens, bodies).

Key resolution: TOKEN_ENCRYPTION_KEY from settings. When unset, an
ephemeral per-process key is generated — fine for tests/dev, but stored
secrets become unreadable after restart (logged loudly as a warning).
"""

import logging
import threading

from cryptography.fernet import Fernet, InvalidToken

from app.config import get_settings

logger = logging.getLogger(__name__)

_lock = threading.Lock()
_ephemeral_key: bytes | None = None


def _fernet() -> Fernet:
    key = get_settings().TOKEN_ENCRYPTION_KEY.strip()
    if key:
        return Fernet(key.encode())
    global _ephemeral_key
    with _lock:
        if _ephemeral_key is None:
            _ephemeral_key = Fernet.generate_key()
            logger.warning(
                "TOKEN_ENCRYPTION_KEY not set — using an ephemeral key; "
                "stored encrypted secrets will be unreadable after restart"
            )
        return Fernet(_ephemeral_key)


def encrypt_secret(plaintext: str) -> str:
    """Encrypt a secret → str (urlsafe base64)."""
    return _fernet().encrypt(plaintext.encode()).decode()


def decrypt_secret(ciphertext: str) -> str:
    """Decrypt. Raises cryptography InvalidToken if wrong key/corrupt."""
    return _fernet().decrypt(ciphertext.encode()).decode()


def decrypt_secret_safe(ciphertext: str | None) -> str | None:
    """Best-effort decrypt — None on missing/undecryptable input."""
    if not ciphertext:
        return None
    try:
        return decrypt_secret(ciphertext)
    except InvalidToken:
        logger.error("decrypt_secret failed — wrong TOKEN_ENCRYPTION_KEY?")
        return None
