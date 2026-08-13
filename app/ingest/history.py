"""Commit history for a repository.

The analyser works from a tarball, which GitHub builds without a ``.git``
directory — and ``ingest/filter.py`` drops ``.git`` from uploads too. So none of
this is derivable from the snapshot; it comes from the REST API.

Everything here is best-effort. A repository's history is context on top of the
findings, never a precondition for them, so ``collect_activity`` never raises:
it returns partial data with a reason attached.
"""

from __future__ import annotations

import asyncio
import logging
import re
from collections import defaultdict
from datetime import UTC, datetime, timedelta

import httpx

from app.config import Settings
from app.ingest.github import (
    API_ROOT,
    GitHubCredentials,
    RepositoryRef,
    build_headers,
)
from app.schemas import ChurnEntry, Finding, RepositoryActivity, Severity

logger = logging.getLogger(__name__)

# How far back churn is measured. Long enough to cover a release cycle, short
# enough that "changes often" still means "recently".
WINDOW_DAYS = 90

# One request per file, so this is a direct cost against the caller's GitHub
# budget — 60 requests an hour unauthenticated, 5000 signed in.
MAX_CHURN_FILES = 25

# Bursting 25 parallel requests is how you get secondary-rate-limited.
MAX_CONCURRENCY = 5

# `rel="last"` carries the page count, which equals the commit count when the
# page size is 1. Reading it avoids paging through the history to count it.
_LAST_PAGE = re.compile(r'[?&]page=(\d+)[^>]*>;\s*rel="last"')

_SEVERITY_ORDER = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
]


class HistoryUnavailable(Exception):
    """GitHub will not answer. Caught by ``collect_activity``."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def _check(response: httpx.Response, *, authenticated: bool = False) -> None:
    """Translate the failures worth telling the user about."""
    if response.status_code in (403, 429):
        if response.headers.get("x-ratelimit-remaining") == "0":
            # Churn costs one request per file, so an unauthenticated server
            # burns a third of its hourly budget on a single analysis. Say so,
            # rather than leaving the user to guess why this keeps happening.
            raise HistoryUnavailable(
                "GitHub's API rate limit was reached while reading commit "
                "history. "
                + (
                    "It resets hourly."
                    if authenticated
                    else "Setting GITHUB_TOKEN raises the limit from 60 to 5000 "
                    "requests an hour; without it a single analysis can use most "
                    "of the budget."
                )
            )
        raise HistoryUnavailable("GitHub refused to serve this repository's history.")
    if response.status_code == 409:
        # GitHub's documented response for a repository with no commits.
        raise HistoryUnavailable("This repository has no commits yet.")
    if response.status_code >= 400:
        raise HistoryUnavailable(
            f"GitHub returned {response.status_code} for this repository's history."
        )


async def file_change_counts(
    client: httpx.AsyncClient,
    ref: RepositoryRef,
    paths: list[str],
    *,
    authenticated: bool = False,
) -> dict[str, int]:
    """Commits touching each path within the window.

    Asks for one commit per page and reads the page count out of the ``Link``
    header, so each file costs a single small response rather than paging its
    whole history. GitHub omits the header when there is only one page, in which
    case the returned commits are counted directly.
    """
    since = (datetime.now(UTC) - timedelta(days=WINDOW_DAYS)).isoformat()
    semaphore = asyncio.Semaphore(MAX_CONCURRENCY)
    counts: dict[str, int] = {}

    async def count(path: str) -> None:
        params: dict[str, str | int] = {
            "path": path,
            "per_page": 1,
            "since": since,
        }
        if ref.ref:
            params["sha"] = ref.ref

        async with semaphore:
            response = await client.get(
                f"{API_ROOT}/repos/{ref.owner}/{ref.repo}/commits", params=params
            )
        _check(response, authenticated=authenticated)

        match = _LAST_PAGE.search(response.headers.get("link", ""))
        if match:
            counts[path] = int(match.group(1))
            return
        payload = response.json()
        counts[path] = len(payload) if isinstance(payload, list) else 0

    results = await asyncio.gather(
        *(count(path) for path in paths[:MAX_CHURN_FILES]),
        return_exceptions=True,
    )

    # One file failing should not lose the other twenty-four, but a rate limit
    # affects every subsequent call and is worth surfacing.
    for result in results:
        if isinstance(result, HistoryUnavailable):
            raise result
        if isinstance(result, BaseException):
            logger.debug("Churn lookup failed for one path: %s", result)

    return counts


async def weekly_activity(
    client: httpx.AsyncClient, ref: RepositoryRef, *, authenticated: bool = False
) -> list[int]:
    """Commits per week for the last year, oldest first.

    GitHub computes this asynchronously and answers ``202`` with an empty body
    while it does. One retry is worth it because the second call usually lands;
    polling past that would hold up an analysis for a nice-to-have.
    """
    url = f"{API_ROOT}/repos/{ref.owner}/{ref.repo}/stats/commit_activity"

    for attempt in range(2):
        response = await client.get(url)
        if response.status_code == 202:
            if attempt == 0:
                await asyncio.sleep(2.0)
                continue
            raise HistoryUnavailable(
                "GitHub is still computing this repository's commit statistics. "
                "Re-run the analysis in a moment and they will be included."
            )
        _check(response, authenticated=authenticated)

        payload = response.json()
        if not isinstance(payload, list):
            return []
        # Entries arrive oldest-first; `total` is that week's commit count.
        return [int(week.get("total", 0)) for week in payload if isinstance(week, dict)]

    return []


def _candidates(findings: list[Finding]) -> list[tuple[str, int, Severity]]:
    """Files worth asking about, worst first.

    Only files that carry a finding are queried — the cost is one request each,
    so it must be bounded by what the report is actually about rather than by
    the size of the repository.
    """
    grouped: dict[str, list[Finding]] = defaultdict(list)
    for finding in findings:
        if finding.file:
            grouped[finding.file].append(finding)

    entries = [
        (
            path,
            len(items),
            min(items, key=lambda f: _SEVERITY_ORDER.index(f.severity)).severity,
        )
        for path, items in grouped.items()
    ]
    # Most-affected files first, so a truncated list is still the useful one.
    entries.sort(key=lambda e: (-_severity_rank(e[2]), -e[1], e[0]))
    return entries


def _severity_rank(severity: Severity) -> int:
    """Higher is worse, for sorting."""
    return len(_SEVERITY_ORDER) - _SEVERITY_ORDER.index(severity)


async def collect_activity(
    ref: RepositoryRef,
    findings: list[Finding],
    settings: Settings,
    credentials: GitHubCredentials | None = None,
) -> RepositoryActivity | None:
    """Commit activity and churn for the files this report has findings in.

    Returns ``None`` only when there is nothing at all to say. Any partial
    result carries ``partial=True`` and a reason, so the UI can state what is
    missing instead of quietly showing less.
    """
    candidates = _candidates(findings)

    weekly: list[int] = []
    churn: list[ChurnEntry] = []
    reason: str | None = None

    authenticated = bool(
        (credentials.token if credentials else None) or settings.github_token
    )
    timeout = httpx.Timeout(settings.github_timeout_seconds)
    try:
        async with httpx.AsyncClient(
            headers=build_headers(settings, credentials),
            timeout=timeout,
            follow_redirects=True,
        ) as client:
            try:
                weekly = await weekly_activity(
                    client, ref, authenticated=authenticated
                )
            except HistoryUnavailable as exc:
                reason = exc.reason

            if candidates:
                try:
                    counts = await file_change_counts(
                        client,
                        ref,
                        [path for path, _, _ in candidates],
                        authenticated=authenticated,
                    )
                    churn = [
                        ChurnEntry(
                            file=path,
                            changes=counts[path],
                            findings=count,
                            top_severity=severity,
                        )
                        for path, count, severity in candidates
                        if path in counts
                    ]
                    # The point of the panel: files that both change often and
                    # carry problems, worst combination first.
                    churn.sort(key=lambda e: (-(e.changes * e.findings), e.file))
                except HistoryUnavailable as exc:
                    reason = reason or exc.reason
    except httpx.HTTPError as exc:
        logger.warning("Commit history fetch failed for %s: %s", ref.full_name, exc)
        reason = "Could not reach GitHub to read this repository's commit history."

    if not weekly and not churn:
        if reason is None:
            return None
        return RepositoryActivity(
            window_days=WINDOW_DAYS,
            files_with_findings=len(candidates),
            partial=True,
            unavailable_reason=reason,
        )

    # Hitting MAX_CHURN_FILES is the designed bound, not a degradation, so it
    # does not set `partial`. `files_with_findings` lets the UI state the cap
    # as a footnote rather than as a warning.
    return RepositoryActivity(
        window_days=WINDOW_DAYS,
        weekly_commits=weekly,
        churn=churn,
        files_with_findings=len(candidates),
        partial=reason is not None,
        unavailable_reason=reason,
    )
