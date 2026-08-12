"""Commit history enrichment.

`fetch_repository` had no respx coverage at all before this; these tests
establish the pattern of mocking the GitHub API for the whole ingest package.
"""

from __future__ import annotations

import httpx
import pytest
import respx

from app.config import Settings
from app.ingest.github import RepositoryRef
from app.ingest.history import (
    MAX_CHURN_FILES,
    HistoryUnavailable,
    collect_activity,
    file_change_counts,
    weekly_activity,
)
from app.schemas import Category, Confidence, Finding, Severity

REF = RepositoryRef(owner="acme", repo="widget")
COMMITS = "https://api.github.com/repos/acme/widget/commits"
STATS = "https://api.github.com/repos/acme/widget/stats/commit_activity"


def settings(**overrides) -> Settings:
    return Settings(database_url=None, gemini_api_key=None, **overrides)


def finding(file: str, severity: Severity = Severity.MEDIUM, index: int = 0) -> Finding:
    return Finding(
        id=f"{file}-{index}",
        rule_id="test/rule",
        title="t",
        description="d",
        category=Category.QUALITY,
        severity=severity,
        confidence=Confidence.HIGH,
        file=file,
    )


async def client() -> httpx.AsyncClient:
    return httpx.AsyncClient(follow_redirects=True)


# --------------------------------------------------------------------------
# Counting commits per file
# --------------------------------------------------------------------------

@respx.mock
async def test_reads_the_commit_count_from_the_link_header():
    """One request per file, not one request per page of history."""
    respx.get(COMMITS).mock(
        return_value=httpx.Response(
            200,
            json=[{"sha": "a"}],
            headers={
                "link": (
                    '<https://api.github.com/repos/acme/widget/commits?page=2>; rel="next", '
                    '<https://api.github.com/repos/acme/widget/commits?page=37>; rel="last"'
                )
            },
        )
    )

    async with await client() as http:
        counts = await file_change_counts(http, REF, ["src/app.js"])

    assert counts == {"src/app.js": 37}
    assert respx.calls.call_count == 1


@respx.mock
async def test_falls_back_to_counting_when_there_is_one_page():
    """GitHub omits the Link header entirely for a single page of results."""
    respx.get(COMMITS).mock(return_value=httpx.Response(200, json=[{"sha": "a"}]))

    async with await client() as http:
        counts = await file_change_counts(http, REF, ["src/app.js"])

    assert counts == {"src/app.js": 1}


@respx.mock
async def test_a_file_with_no_recent_commits_counts_zero():
    respx.get(COMMITS).mock(return_value=httpx.Response(200, json=[]))

    async with await client() as http:
        counts = await file_change_counts(http, REF, ["stale.js"])

    assert counts == {"stale.js": 0}


@respx.mock
async def test_churn_is_bounded_by_the_file_cap():
    """The cost is one request per file, so it must not scale with repo size."""
    respx.get(COMMITS).mock(return_value=httpx.Response(200, json=[]))
    paths = [f"file{i}.js" for i in range(MAX_CHURN_FILES + 20)]

    async with await client() as http:
        counts = await file_change_counts(http, REF, paths)

    assert len(counts) == MAX_CHURN_FILES
    assert respx.calls.call_count == MAX_CHURN_FILES


@respx.mock
async def test_rate_limit_is_reported_rather_than_swallowed():
    respx.get(COMMITS).mock(
        return_value=httpx.Response(403, headers={"x-ratelimit-remaining": "0"})
    )

    async with await client() as http:
        with pytest.raises(HistoryUnavailable) as exc:
            await file_change_counts(http, REF, ["a.js"])

    assert "rate limit" in exc.value.reason.lower()


# --------------------------------------------------------------------------
# Weekly activity
# --------------------------------------------------------------------------

@respx.mock
async def test_weekly_activity_returns_totals_oldest_first():
    respx.get(STATS).mock(
        return_value=httpx.Response(
            200, json=[{"total": 3, "week": 1}, {"total": 0, "week": 2}, {"total": 9}]
        )
    )

    async with await client() as http:
        weeks = await weekly_activity(http, REF)

    assert weeks == [3, 0, 9]


@respx.mock
async def test_retries_once_while_github_computes_statistics():
    """202 with an empty body means "computing"; the retry usually lands."""
    route = respx.get(STATS).mock(
        side_effect=[
            httpx.Response(202),
            httpx.Response(200, json=[{"total": 5}]),
        ]
    )

    async with await client() as http:
        weeks = await weekly_activity(http, REF)

    assert weeks == [5]
    assert route.call_count == 2


@respx.mock
async def test_gives_up_rather_than_polling_forever():
    respx.get(STATS).mock(return_value=httpx.Response(202))

    async with await client() as http:
        with pytest.raises(HistoryUnavailable) as exc:
            await weekly_activity(http, REF)

    assert "still computing" in exc.value.reason


# --------------------------------------------------------------------------
# The public entry point
# --------------------------------------------------------------------------

@respx.mock
async def test_collect_ranks_by_change_times_findings():
    """The whole point: files that change often *and* carry problems."""
    respx.get(STATS).mock(return_value=httpx.Response(200, json=[{"total": 4}]))

    def by_path(request: httpx.Request) -> httpx.Response:
        path = request.url.params["path"]
        pages = {"hot.js": 20, "cold.js": 1}[path]
        return httpx.Response(
            200,
            json=[{"sha": "a"}],
            headers={"link": f'<https://x?page={pages}>; rel="last"'},
        )

    respx.get(COMMITS).mock(side_effect=by_path)

    activity = await collect_activity(
        REF,
        [finding("cold.js", index=0), finding("cold.js", index=1), finding("hot.js")],
        settings(),
    )

    assert activity is not None
    # cold.js has more findings, hot.js changes far more often: 20 beats 2.
    assert [entry.file for entry in activity.churn] == ["hot.js", "cold.js"]
    assert activity.partial is False
    assert activity.files_with_findings == 2


@respx.mock
async def test_the_file_cap_is_not_reported_as_a_failure():
    """Capping churn at 25 files is the designed bound, not a degradation."""
    respx.get(STATS).mock(return_value=httpx.Response(200, json=[{"total": 1}]))
    respx.get(COMMITS).mock(return_value=httpx.Response(200, json=[]))

    findings = [finding(f"file{i}.js", index=i) for i in range(MAX_CHURN_FILES + 10)]
    activity = await collect_activity(REF, findings, settings())

    assert activity is not None
    assert activity.partial is False
    assert activity.unavailable_reason is None
    # The UI needs both numbers to say "25 of 35 measured".
    assert len(activity.churn) == MAX_CHURN_FILES
    assert activity.files_with_findings == MAX_CHURN_FILES + 10


@respx.mock
async def test_collect_reports_partial_instead_of_failing():
    """A rate limit must degrade the panel, never the analysis."""
    respx.get(STATS).mock(return_value=httpx.Response(200, json=[{"total": 2}]))
    respx.get(COMMITS).mock(
        return_value=httpx.Response(403, headers={"x-ratelimit-remaining": "0"})
    )

    activity = await collect_activity(REF, [finding("a.js")], settings())

    assert activity is not None
    assert activity.partial is True
    assert "rate limit" in (activity.unavailable_reason or "").lower()
    # The half that succeeded is still returned.
    assert activity.weekly_commits == [2]


@respx.mock
async def test_collect_survives_a_total_github_outage():
    respx.get(STATS).mock(side_effect=httpx.ConnectError("down"))
    respx.get(COMMITS).mock(side_effect=httpx.ConnectError("down"))

    activity = await collect_activity(REF, [finding("a.js")], settings())

    assert activity is not None
    assert activity.partial is True
    assert activity.churn == []


@respx.mock
async def test_findings_without_a_file_are_not_queried():
    """Project-wide findings have no path to ask GitHub about."""
    respx.get(STATS).mock(return_value=httpx.Response(200, json=[{"total": 1}]))
    route = respx.get(COMMITS).mock(return_value=httpx.Response(200, json=[]))

    project_wide = Finding(
        id="p1",
        rule_id="test/rule",
        title="t",
        description="d",
        category=Category.TESTING,
        severity=Severity.LOW,
        confidence=Confidence.HIGH,
    )
    activity = await collect_activity(REF, [project_wide], settings())

    assert activity is not None
    assert activity.churn == []
    assert route.call_count == 0


@respx.mock
async def test_empty_repository_is_explained_not_hidden():
    respx.get(STATS).mock(return_value=httpx.Response(409))
    respx.get(COMMITS).mock(return_value=httpx.Response(409))

    activity = await collect_activity(REF, [finding("a.js")], settings())

    assert activity is not None
    assert "no commits" in (activity.unavailable_reason or "")
