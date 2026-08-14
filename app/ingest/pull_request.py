"""Pull requests: resolving one, and leaving exactly one comment on it.

Deliberately built on the OAuth token the user already granted rather than on a
GitHub App. An App would be better — only an App can create a *check run*, the
pass/fail entry in the Checks tab — but it needs a registration, a webhook
endpoint, an installation-token flow and three new deployment secrets, and the
webhook path additionally needs job persistence that does not exist yet: a
free-tier instance that sleeps will drop an in-flight analysis with nothing to
resume from, and GitHub will have had its 10-second acknowledgement long ago.

So this is the smaller thing that works today. The user triggers it, it runs on
their own token and their own rate limit, and it reaches exactly the private
repositories they already granted. The upgrade path to an App is additive:
`upsert_comment` is the only piece that would be replaced by a check run.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

import httpx

from app.config import Settings
from app.errors import VantageError
from app.export.pr_comment import MARKER
from app.ingest.github import API_ROOT, GitHubCredentials, build_headers

_PR_URL = re.compile(
    r"""^(?:https?://)?(?:www\.)?github\.com/
        (?P<owner>[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?)/
        (?P<repo>[A-Za-z0-9._-]+?)(?:\.git)?
        /pull/(?P<number>\d+)
        /?(?:[?\#].*)?$""",
    re.VERBOSE,
)


class InvalidPullRequestError(VantageError):
    status_code = 400
    code = "invalid_pull_request"


class PullRequestAccessError(VantageError):
    status_code = 502
    code = "pull_request_unavailable"


@dataclass(frozen=True)
class PullRequestRef:
    owner: str
    repo: str
    number: int

    @property
    def full_name(self) -> str:
        return f"{self.owner}/{self.repo}"


@dataclass(frozen=True)
class PullRequestInfo:
    ref: PullRequestRef
    head_sha: str
    head_ref: str
    base_ref: str
    title: str
    state: str
    html_url: str


def parse_pull_request_url(value: str) -> PullRequestRef:
    candidate = (value or "").strip()
    if not candidate:
        raise InvalidPullRequestError("No pull request URL provided.")

    match = _PR_URL.match(candidate)
    if not match:
        raise InvalidPullRequestError(
            "That doesn't look like a GitHub pull request URL.",
            detail="Expected something like https://github.com/owner/repo/pull/123.",
        )

    groups = match.groupdict()
    return PullRequestRef(
        owner=groups["owner"],
        repo=groups["repo"],
        number=int(groups["number"]),
    )


async def fetch_pull_request(
    ref: PullRequestRef,
    settings: Settings,
    credentials: GitHubCredentials | None = None,
    *,
    client: httpx.AsyncClient | None = None,
) -> PullRequestInfo:
    """Resolve a PR to the commit that should actually be analysed.

    The head **SHA**, not the head branch name. A branch moves while the
    analysis runs, and a report that says "main" cannot be reproduced; a report
    pinned to a commit can. It is also what makes the comment honest — it names
    the commit it describes, so a reader can tell whether it is stale.
    """
    url = f"{API_ROOT}/repos/{ref.owner}/{ref.repo}/pulls/{ref.number}"
    headers = build_headers(settings, credentials)

    async def _get(session: httpx.AsyncClient) -> httpx.Response:
        return await session.get(url, headers=headers, timeout=15.0)

    if client is not None:
        response = await _get(client)
    else:
        async with httpx.AsyncClient() as session:
            response = await _get(session)

    if response.status_code == 404:
        raise InvalidPullRequestError(
            "That pull request could not be found.",
            detail=(
                "It may be private, or in a repository this account cannot "
                "see. Signing in with access to it would let Vantage read it."
            ),
        )
    if response.status_code >= 400:
        raise PullRequestAccessError(
            "GitHub refused the pull request lookup.",
            detail=f"HTTP {response.status_code}.",
        )

    body = response.json()
    head = body.get("head") or {}
    base = body.get("base") or {}
    if not head.get("sha"):
        raise PullRequestAccessError(
            "GitHub returned a pull request with no head commit."
        )

    return PullRequestInfo(
        ref=ref,
        head_sha=head["sha"],
        head_ref=head.get("ref") or "",
        base_ref=base.get("ref") or "",
        title=body.get("title") or "",
        state=body.get("state") or "",
        html_url=body.get("html_url") or "",
    )


async def upsert_comment(
    ref: PullRequestRef,
    body: str,
    settings: Settings,
    credentials: GitHubCredentials | None = None,
    *,
    client: httpx.AsyncClient | None = None,
) -> str:
    """Post the comment, or edit the one already there. Returns its URL.

    The brief is explicit that this must not spam, and a branch that gets
    pushed twelve times is where a naive implementation leaves twelve
    comments. Existing comments are searched for `MARKER` — an HTML comment,
    invisible in the rendered result — and the first match is edited in place.

    Only comments this account wrote are considered, so two people running
    Vantage on the same PR do not fight over one comment.
    """
    headers = build_headers(settings, credentials)
    issues = f"{API_ROOT}/repos/{ref.owner}/{ref.repo}/issues/{ref.number}"

    async def _run(session: httpx.AsyncClient) -> str:
        existing_id: int | None = None
        viewer: str | None = None

        me = await session.get(f"{API_ROOT}/user", headers=headers, timeout=15.0)
        if me.status_code < 400:
            viewer = (me.json() or {}).get("login")

        listing = await session.get(
            f"{issues}/comments",
            headers=headers,
            params={"per_page": 100},
            timeout=15.0,
        )
        if listing.status_code < 400:
            for comment in listing.json() or []:
                author = (comment.get("user") or {}).get("login")
                if MARKER in (comment.get("body") or "") and (
                    viewer is None or author == viewer
                ):
                    existing_id = comment.get("id")
                    break

        if existing_id is not None:
            response = await session.patch(
                f"{API_ROOT}/repos/{ref.owner}/{ref.repo}/issues/comments/{existing_id}",
                headers=headers,
                json={"body": body},
                timeout=15.0,
            )
        else:
            response = await session.post(
                f"{issues}/comments",
                headers=headers,
                json={"body": body},
                timeout=15.0,
            )

        if response.status_code == 403:
            raise PullRequestAccessError(
                "This account cannot comment on that pull request.",
                detail="Commenting needs write access to the repository.",
            )
        if response.status_code >= 400:
            raise PullRequestAccessError(
                "GitHub refused the comment.",
                detail=f"HTTP {response.status_code}.",
            )
        return (response.json() or {}).get("html_url", "")

    if client is not None:
        return await _run(client)
    async with httpx.AsyncClient() as session:
        return await _run(session)
