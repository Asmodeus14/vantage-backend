"""Account and session persistence.

Sessions are opaque random tokens; only their SHA-256 is stored, so a database
leak does not hand over live sessions. The token itself exists in exactly two
places: the user's cookie, and the response that set it.
"""

from __future__ import annotations

import hashlib
import logging
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, select

from app.auth.models import SessionRow, UserRow
from app.auth.tokens import decrypt_token, encrypt_token
from app.config import Settings
from app.db import get_sessionmaker

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class AuthenticatedUser:
    """The caller's identity, as request handlers see it."""

    id: str
    github_id: int
    login: str
    name: str | None
    avatar_url: str | None
    scopes: tuple[str, ...]
    # Decrypted lazily by `github_token_for`, never carried around in the clear
    # more than it has to be.
    _token_ciphertext: str

    @property
    def can_read_private_repositories(self) -> bool:
        return "repo" in self.scopes


class AuthUnavailable(RuntimeError):
    """Sign-in is not configured or has no database. Never raised into a 500."""


def _now() -> datetime:
    return datetime.now(timezone.utc)


def hash_session_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def new_user_id() -> str:
    return secrets.token_urlsafe(9)


async def upsert_user(
    *,
    github_id: int,
    login: str,
    name: str | None,
    avatar_url: str | None,
    access_token: str,
    scopes: str,
    settings: Settings,
) -> str:
    """Create or refresh an account, returning its id.

    Signing in again replaces the stored token — GitHub issues a new one each
    time, and the old one may already have been revoked.
    """
    maker = get_sessionmaker()
    if maker is None:
        raise AuthUnavailable("No database configured.")

    ciphertext = encrypt_token(access_token, settings)
    now = _now()

    async with maker() as session:
        existing = (
            await session.execute(select(UserRow).where(UserRow.github_id == github_id))
        ).scalar_one_or_none()

        if existing is None:
            user_id = new_user_id()
            session.add(
                UserRow(
                    id=user_id,
                    github_id=github_id,
                    login=login,
                    name=name,
                    avatar_url=avatar_url,
                    access_token_encrypted=ciphertext,
                    scopes=scopes,
                    created_at=now,
                    updated_at=now,
                )
            )
        else:
            user_id = existing.id
            existing.login = login
            existing.name = name
            existing.avatar_url = avatar_url
            existing.access_token_encrypted = ciphertext
            # Scopes can only be observed, not assumed: GitHub grants what the
            # user approved, which may be less than was requested.
            existing.scopes = scopes
            existing.updated_at = now

        await session.commit()

    return user_id


async def create_session(user_id: str, settings: Settings) -> str:
    """Issue a session token. Only its hash is persisted."""
    maker = get_sessionmaker()
    if maker is None:
        raise AuthUnavailable("No database configured.")

    token = secrets.token_urlsafe(32)
    now = _now()

    async with maker() as session:
        session.add(
            SessionRow(
                token_hash=hash_session_token(token),
                user_id=user_id,
                created_at=now,
                expires_at=now + timedelta(days=settings.session_ttl_days),
                last_seen_at=now,
            )
        )
        # Sweep here, in the same transaction, because this is the one moment
        # the table is known to be growing and there is nowhere to run a cron
        # job — the free tier has no scheduler and the process sleeps when idle.
        #
        # `resolve_session` alone was not enough: it only deletes the row it was
        # asked about, so a session that expires and is never presented again
        # stays for ever. This is what `ix_sessions_expires_at` was created for,
        # and until now nothing used it.
        await session.execute(
            delete(SessionRow).where(SessionRow.expires_at <= now)
        )
        await session.commit()

    return token


async def resolve_session(token: str) -> AuthenticatedUser | None:
    """The user behind a session token, or ``None``.

    An expired row is deleted rather than merely ignored, so the table does not
    accumulate dead sessions without a separate sweep.
    """
    maker = get_sessionmaker()
    if maker is None:
        return None

    token_hash = hash_session_token(token)

    async with maker() as db:
        row = await db.get(SessionRow, token_hash)
        if row is None:
            return None

        if row.expires_at <= _now():
            await db.delete(row)
            await db.commit()
            return None

        user = await db.get(UserRow, row.user_id)
        if user is None:  # pragma: no cover - FK makes this unreachable
            return None

        # Cheap enough to be worth having, and it is what makes "last active"
        # possible later without a second write path.
        row.last_seen_at = _now()
        await db.commit()

        return AuthenticatedUser(
            id=user.id,
            github_id=user.github_id,
            login=user.login,
            name=user.name,
            avatar_url=user.avatar_url,
            scopes=tuple(s for s in user.scopes.split() if s),
            _token_ciphertext=user.access_token_encrypted,
        )


async def revoke_session(token: str) -> None:
    maker = get_sessionmaker()
    if maker is None:
        return
    async with maker() as db:
        await db.execute(
            delete(SessionRow).where(SessionRow.token_hash == hash_session_token(token))
        )
        await db.commit()


async def revoke_all_sessions(user_id: str) -> int:
    """Sign out everywhere. Returns how many sessions were ended."""
    maker = get_sessionmaker()
    if maker is None:
        return 0
    async with maker() as db:
        result = await db.execute(
            delete(SessionRow).where(SessionRow.user_id == user_id)
        )
        await db.commit()
        return result.rowcount or 0


def github_token_for(user: AuthenticatedUser, settings: Settings) -> str | None:
    """The user's GitHub token, or ``None`` if it can no longer be read."""
    return decrypt_token(user._token_ciphertext, settings)
