"""Request-scoped identity.

Identity arrives as ``Authorization: Bearer <session>``, forwarded by the
frontend's server-side route handlers from a first-party cookie. The backend
never sets a cookie itself: in production the two live on different sites
(Vercel and Render), and a cookie set across sites is blocked outright by Safari
and by Firefox in strict mode — a failure that passes every test in Chrome.

Every dependency here is optional-by-default. Anonymous use is a supported mode,
not an error path.
"""

from __future__ import annotations

import hmac
import logging

from fastapi import Depends, Header, Request

from app.auth.store import AuthenticatedUser, resolve_session
from app.config import Settings, get_settings
from app.errors import VantageError

logger = logging.getLogger(__name__)


class NotAuthenticated(VantageError):
    status_code = 401
    code = "not_authenticated"


class NotAuthorised(VantageError):
    status_code = 403
    code = "not_authorised"


def _bearer(authorization: str | None) -> str | None:
    if not authorization:
        return None
    scheme, _, value = authorization.partition(" ")
    if scheme.lower() != "bearer" or not value.strip():
        return None
    return value.strip()


async def current_user(
    authorization: str | None = Header(default=None),
    settings: Settings = Depends(get_settings),
) -> AuthenticatedUser | None:
    """The signed-in user, or ``None``. Never raises for anonymous callers."""
    if not settings.auth_configured:
        return None
    token = _bearer(authorization)
    if token is None:
        return None
    try:
        return await resolve_session(token)
    except Exception:
        # A database blip must not turn every request into a 500; it degrades
        # to anonymous, which every endpoint already handles.
        logger.exception("Session lookup failed")
        return None


async def require_user(
    user: AuthenticatedUser | None = Depends(current_user),
    settings: Settings = Depends(get_settings),
) -> AuthenticatedUser:
    if user is None:
        raise NotAuthenticated(
            "You need to be signed in to do that.",
            detail=settings.auth_unavailable_reason,
        )
    return user


async def require_internal_caller(
    request: Request,
    settings: Settings = Depends(get_settings),
) -> None:
    """Authenticate the frontend server, not a user.

    Guards the endpoint that mints a session from a GitHub token. Compared with
    ``hmac.compare_digest`` so a wrong secret cannot be recovered by timing.
    """
    expected = settings.internal_api_secret
    if not expected:
        raise NotAuthenticated("Sign-in is not configured on this server.")

    provided = request.headers.get("x-internal-secret", "")
    if not hmac.compare_digest(provided, expected):
        logger.warning("Rejected an internal call with a bad secret")
        raise NotAuthenticated("Invalid internal credentials.")
