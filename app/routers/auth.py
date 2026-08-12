"""Sessions and account identity.

The OAuth *dance* happens on the frontend server, which owns the client secret
and sets a first-party cookie. This module is the other half: it exchanges a
GitHub access token for a session, and answers who the caller is.

Note for future edits: do not add ``from __future__ import annotations`` here.
FastAPI resolves body models from the annotations at import time, and the string
form breaks it — see tests/test_health.py::test_request_bodies_are_not_embedded.
"""

import logging

import httpx
from fastapi import APIRouter, Depends, Header, Request

from app.auth.dependencies import (
    NotAuthenticated,
    require_internal_caller,
    require_user,
)
from app.auth.store import (
    AuthenticatedUser,
    create_session,
    revoke_all_sessions,
    revoke_session,
    upsert_user,
)
from app.config import Settings, get_settings
from app.errors import VantageError
from app.ingest.github import API_ROOT
from app.limiter import limiter
from app.schemas import (
    AuthStatus,
    CurrentUser,
    SessionCreated,
    SessionRequest,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/auth", tags=["auth"])


class GitHubIdentityError(VantageError):
    status_code = 502
    code = "github_identity_failed"


@router.get("/status", response_model=AuthStatus)
async def auth_status(settings: Settings = Depends(get_settings)) -> AuthStatus:
    """Whether sign-in can be offered, and why not when it cannot.

    The reason is shown to the user verbatim, so the button is disabled with an
    explanation rather than hidden.
    """
    return AuthStatus(
        configured=settings.auth_configured,
        reason=settings.auth_unavailable_reason,
    )


@router.post("/session", response_model=SessionCreated, status_code=201)
@limiter.limit("30/hour")
async def create_user_session(
    request: Request,  # required by slowapi's decorator
    body: SessionRequest,
    _: None = Depends(require_internal_caller),
    settings: Settings = Depends(get_settings),
) -> SessionCreated:
    """Exchange a GitHub access token for a Vantage session.

    Called server-to-server by the frontend's OAuth callback, never by a
    browser — the guard is ``INTERNAL_API_SECRET``, not a user credential.
    """
    profile = await _fetch_github_identity(body.access_token, settings)

    user_id = await upsert_user(
        github_id=profile["id"],
        login=profile["login"],
        name=profile.get("name"),
        avatar_url=profile.get("avatar_url"),
        access_token=body.access_token,
        scopes=body.scopes,
        settings=settings,
    )
    token = await create_session(user_id, settings)

    logger.info("Signed in %s (%s)", profile["login"], user_id)
    return SessionCreated(session_token=token, user=_present(user_id, profile, body.scopes))


@router.get("/me", response_model=CurrentUser)
async def me(user: AuthenticatedUser = Depends(require_user)) -> CurrentUser:
    return CurrentUser(
        id=user.id,
        login=user.login,
        name=user.name,
        avatar_url=user.avatar_url,
        scopes=list(user.scopes),
        can_read_private_repositories=user.can_read_private_repositories,
    )


@router.post("/logout", status_code=204)
async def logout(authorization: str = Header(default="")) -> None:
    """Ends this session. Idempotent — signing out twice is not an error."""
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() == "bearer" and token.strip():
        await revoke_session(token.strip())


@router.post("/logout-everywhere", status_code=200)
async def logout_everywhere(
    user: AuthenticatedUser = Depends(require_user),
) -> dict[str, int]:
    ended = await revoke_all_sessions(user.id)
    return {"sessions_ended": ended}


async def _fetch_github_identity(access_token: str, settings: Settings) -> dict:
    """Confirm the token works and find out who it belongs to."""
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {access_token}",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "Vantage/3.0",
    }
    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(settings.github_timeout_seconds)
        ) as client:
            response = await client.get(f"{API_ROOT}/user", headers=headers)
    except httpx.HTTPError as exc:
        raise GitHubIdentityError(
            "Could not reach GitHub to confirm your identity.", detail=str(exc)
        ) from exc

    if response.status_code == 401:
        raise NotAuthenticated(
            "GitHub rejected that authorisation.",
            detail="The code may have already been used. Try signing in again.",
        )
    if response.status_code >= 400:
        raise GitHubIdentityError(
            f"GitHub returned {response.status_code} when confirming your identity."
        )

    profile = response.json()
    if not isinstance(profile, dict) or "id" not in profile or "login" not in profile:
        raise GitHubIdentityError("GitHub returned an unrecognised profile.")
    return profile


def _present(user_id: str, profile: dict, scopes: str) -> CurrentUser:
    granted = [s for s in scopes.split() if s]
    return CurrentUser(
        id=user_id,
        login=profile["login"],
        name=profile.get("name"),
        avatar_url=profile.get("avatar_url"),
        scopes=granted,
        can_read_private_repositories="repo" in granted,
    )
