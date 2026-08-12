"""Encrypting GitHub access tokens at rest.

A stored OAuth token is a live credential for someone's GitHub account. Holding
it in plaintext would make a database leak strictly worse than a leak of our own
data — so it is encrypted with a key that lives only in the environment.

The key is deliberately its own setting rather than derived from a session
secret: rotating one must not force rotating the other.
"""

from __future__ import annotations

import logging

from cryptography.fernet import Fernet, InvalidToken

from app.config import Settings

logger = logging.getLogger(__name__)


class TokenCipherUnavailable(RuntimeError):
    """No usable TOKEN_ENCRYPTION_KEY. Callers must not fall back to plaintext."""


def _cipher(settings: Settings) -> Fernet:
    key = settings.token_encryption_key
    if not key:
        raise TokenCipherUnavailable("TOKEN_ENCRYPTION_KEY is not set.")
    try:
        return Fernet(key.encode("utf-8"))
    except (ValueError, TypeError) as exc:
        raise TokenCipherUnavailable(
            "TOKEN_ENCRYPTION_KEY is not a valid Fernet key. Generate one with: "
            "python -c \"from cryptography.fernet import Fernet; "
            'print(Fernet.generate_key().decode())"'
        ) from exc


def encrypt_token(token: str, settings: Settings) -> str:
    return _cipher(settings).encrypt(token.encode("utf-8")).decode("ascii")


def decrypt_token(ciphertext: str, settings: Settings) -> str | None:
    """Return the token, or ``None`` if it cannot be read.

    A key rotation leaves rows that no longer decrypt. That is recoverable — the
    user signs in again — so it is logged and reported as "no token" rather than
    raised into a request handler.
    """
    try:
        return _cipher(settings).decrypt(ciphertext.encode("ascii")).decode("utf-8")
    except InvalidToken:
        logger.warning(
            "A stored GitHub token could not be decrypted; the encryption key "
            "has probably been rotated. The user will need to sign in again."
        )
        return None
    except TokenCipherUnavailable:
        raise
    except Exception:
        logger.exception("Unexpected failure decrypting a stored token")
        return None
