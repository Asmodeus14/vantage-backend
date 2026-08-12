"""Fetching a repository from GitHub.

This is the primary ingestion path. Compared with asking the user to zip and
upload a project, it removes the upload entirely, keeps request bodies small
enough to proxy through a serverless frontend, and gives us the commit SHA so a
report can state exactly what was analysed.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

import httpx

from app.config import Settings
from app.errors import (
    ArchiveTooLargeError,
    InvalidRepositoryError,
    RateLimitedError,
    RepositoryFetchError,
    RepositoryNotFoundError,
)

logger = logging.getLogger(__name__)

API_ROOT = "https://api.github.com"
_DOWNLOAD_CHUNK = 128 * 1024

# owner/repo with optional .git, /tree/<ref>, query string or trailing slash.
_URL_PATTERN = re.compile(
    r"""^(?:https?://)?(?:www\.)?github\.com/
        (?P<owner>[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?)/
        (?P<repo>[A-Za-z0-9._-]+?)(?:\.git)?
        (?:/(?:tree|commit)/(?P<ref>[^/?\#]+))?
        /?(?:[?\#].*)?$""",
    re.VERBOSE,
)
_SSH_PATTERN = re.compile(
    r"^git@github\.com:(?P<owner>[A-Za-z0-9-]+)/(?P<repo>[A-Za-z0-9._-]+?)(?:\.git)?/?$"
)
_SHORTHAND = re.compile(
    r"^(?P<owner>[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?)/(?P<repo>[A-Za-z0-9._-]+?)(?:\.git)?$"
)


@dataclass(frozen=True)
class RepositoryRef:
    owner: str
    repo: str
    ref: str | None = None

    @property
    def full_name(self) -> str:
        return f"{self.owner}/{self.repo}"

    @property
    def html_url(self) -> str:
        return f"https://github.com/{self.full_name}"


@dataclass
class FetchedRepository:
    ref: RepositoryRef
    archive_path: Path
    resolved_ref: str
    commit: str | None
    description: str | None
    default_branch: str


def parse_repository_url(value: str) -> RepositoryRef:
    """Accept the URL shapes a developer is likely to paste."""
    candidate = value.strip()
    if not candidate:
        raise InvalidRepositoryError("No repository URL provided.")

    for pattern in (_URL_PATTERN, _SSH_PATTERN, _SHORTHAND):
        match = pattern.match(candidate)
        if match:
            groups = match.groupdict()
            return RepositoryRef(
                owner=groups["owner"],
                repo=groups["repo"],
                ref=groups.get("ref"),
            )

    raise InvalidRepositoryError(
        "That doesn't look like a GitHub repository URL.",
        detail="Expected something like https://github.com/owner/repository.",
    )


@dataclass(frozen=True)
class GitHubCredentials:
    """Which GitHub identity a request is made as.

    A signed-in user's own token is preferred over the server's: it carries
    their 5000-per-hour budget rather than sharing one pool between everybody,
    and it can reach their private repositories if they granted that.
    """

    token: str | None = None
    source: Literal["user", "server", "anonymous"] = "anonymous"

    @classmethod
    def for_server(cls, settings: Settings) -> "GitHubCredentials":
        if settings.github_token:
            return cls(token=settings.github_token, source="server")
        return cls()

    @property
    def authenticated(self) -> bool:
        return bool(self.token)


def build_headers(
    settings: Settings, credentials: GitHubCredentials | None = None
) -> dict[str, str]:
    """Headers for any GitHub API call. Shared with `ingest/history.py`.

    Falls back to the server token when no per-user credentials are supplied,
    which keeps every existing call site working unchanged.
    """
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "Vantage/3.0",
    }
    token = (credentials.token if credentials else None) or settings.github_token
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _raise_for_status(response: httpx.Response, ref: RepositoryRef, settings: Settings) -> None:
    if response.status_code == 404:
        raise RepositoryNotFoundError(
            f"Repository {ref.full_name} was not found.",
            detail=(
                "Check the spelling. Private repositories require a "
                "GITHUB_TOKEN with access to them."
            ),
        )
    if response.status_code in (403, 429):
        remaining = response.headers.get("x-ratelimit-remaining")
        if remaining == "0":
            hint = (
                "The server's GitHub API rate limit is exhausted. "
                + (
                    "It resets hourly."
                    if settings.github_token
                    else "Setting GITHUB_TOKEN raises the limit from 60 to 5000 requests per hour."
                )
            )
            raise RateLimitedError("GitHub API rate limit reached.", detail=hint)
        raise RepositoryFetchError(
            "GitHub refused the request.",
            detail="The repository may be private or access-restricted.",
        )
    if response.status_code >= 400:
        raise RepositoryFetchError(
            f"GitHub returned {response.status_code}.",
            detail="Try again shortly.",
        )


async def fetch_repository(
    ref: RepositoryRef,
    destination: Path,
    settings: Settings,
    credentials: GitHubCredentials | None = None,
) -> FetchedRepository:
    """Download a repository tarball, enforcing the archive size cap.

    ``credentials`` defaults to the server's token, so existing callers are
    unaffected; passing a signed-in user's credentials is what makes private
    repositories reachable.
    """
    headers = build_headers(settings, credentials)
    timeout = httpx.Timeout(settings.github_timeout_seconds)

    async with httpx.AsyncClient(
        headers=headers, timeout=timeout, follow_redirects=True
    ) as client:
        meta_response = await client.get(f"{API_ROOT}/repos/{ref.owner}/{ref.repo}")
        _raise_for_status(meta_response, ref, settings)
        meta = meta_response.json()

        default_branch = meta.get("default_branch") or "main"
        resolved_ref = ref.ref or default_branch

        # `size` is in KB and reflects the whole repository. Reject obvious
        # non-starters before spending bandwidth on them.
        size_kb = meta.get("size") or 0
        if size_kb * 1024 > settings.max_archive_bytes * 4:
            raise ArchiveTooLargeError(
                f"{ref.full_name} is too large to analyse.",
                detail=(
                    f"GitHub reports {size_kb // 1024}MB; the limit is roughly "
                    f"{(settings.max_archive_bytes * 4) // (1024 * 1024)}MB."
                ),
            )

        commit: str | None = None
        try:
            commit_response = await client.get(
                f"{API_ROOT}/repos/{ref.owner}/{ref.repo}/commits/{resolved_ref}"
            )
            if commit_response.status_code == 200:
                commit = commit_response.json().get("sha")
        except httpx.HTTPError:
            pass  # provenance is a nicety, not a requirement

        archive_path = destination / "repository.tar.gz"
        archive_path.parent.mkdir(parents=True, exist_ok=True)
        tarball_url = f"{API_ROOT}/repos/{ref.owner}/{ref.repo}/tarball/{resolved_ref}"

        written = 0
        try:
            async with client.stream("GET", tarball_url) as response:
                _raise_for_status(response, ref, settings)
                with archive_path.open("wb") as out:
                    async for chunk in response.aiter_bytes(_DOWNLOAD_CHUNK):
                        written += len(chunk)
                        if written > settings.max_archive_bytes:
                            out.close()
                            archive_path.unlink(missing_ok=True)
                            raise ArchiveTooLargeError(
                                f"{ref.full_name} exceeds the download limit.",
                                detail=(
                                    f"Stopped after "
                                    f"{settings.max_archive_bytes // (1024 * 1024)}MB."
                                ),
                            )
                        out.write(chunk)
        except httpx.HTTPError as exc:
            archive_path.unlink(missing_ok=True)
            raise RepositoryFetchError(
                "Could not download the repository archive.", detail=str(exc)
            ) from exc

    logger.info(
        "Fetched %s@%s (%.1fMB)", ref.full_name, resolved_ref, written / (1024 * 1024)
    )

    return FetchedRepository(
        ref=ref,
        archive_path=archive_path,
        resolved_ref=resolved_ref,
        commit=commit,
        description=meta.get("description"),
        default_branch=default_branch,
    )
