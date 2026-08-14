"""Pull request resolution and the one comment left on it.

The comment is the product's whole claim expressed in the place a developer
actually works: not "here is a scan", but "here is what *this branch* changed".
So the tests are mostly about what it says and how many of it there are.
"""

from __future__ import annotations

from datetime import UTC, datetime

import httpx
import pytest
import respx

from app.config import Settings
from app.export.pr_comment import MARKER, MAX_LISTED, render_comment
from app.ingest.pull_request import (
    InvalidPullRequestError,
    PullRequestRef,
    fetch_pull_request,
    parse_pull_request_url,
    upsert_comment,
)
from app.schemas import (
    Category,
    Confidence,
    Finding,
    FindingDelta,
    IngestStats,
    ProjectInfo,
    Report,
    ResolvedFinding,
    Score,
    Severity,
    SeverityCounts,
    SourceInfo,
    SourceKind,
)

API = "https://api.github.com"
REF = PullRequestRef(owner="acme", repo="app", number=42)


def finding(**overrides) -> Finding:
    base = {
        "id": "f1",
        "fingerprint": "fp1",
        "rule_id": "security/sql-injection",
        "title": "SQL statement assembled from an interpolated value",
        "description": "d",
        "category": Category.SECURITY,
        "severity": Severity.CRITICAL,
        "confidence": Confidence.HIGH,
        "file": "api/users.js",
        "line": 42,
        "priority": 100,
    }
    return Finding(**{**base, **overrides})


def report(findings: list[Finding], delta: FindingDelta | None = None, **overrides) -> Report:
    base = {
        "id": "rep123",
        "created_at": datetime.now(UTC),
        "duration_seconds": 1.0,
        "source": SourceInfo(kind=SourceKind.REPOSITORY, repository="acme/app"),
        "project": ProjectInfo(analysed_files=10, total_lines=1000),
        "score": Score(value=72, grade="C", categories=[], summary="s"),
        "severity_counts": SeverityCounts(),
        "findings": findings,
        "ingest": IngestStats(),
        "delta": delta,
    }
    return Report(**{**base, **overrides})


# --------------------------------------------------------------------------
# URL parsing
# --------------------------------------------------------------------------

@pytest.mark.parametrize(
    "url",
    [
        "https://github.com/acme/app/pull/42",
        "http://github.com/acme/app/pull/42",
        "github.com/acme/app/pull/42",
        "https://www.github.com/acme/app/pull/42/",
        "https://github.com/acme/app/pull/42#issuecomment-1",
        "https://github.com/acme/app/pull/42?diff=split",
    ],
)
def test_pull_request_urls_a_developer_would_paste(url):
    ref = parse_pull_request_url(url)
    assert ref == PullRequestRef(owner="acme", repo="app", number=42)


@pytest.mark.parametrize(
    "url",
    [
        "",
        "https://github.com/acme/app",
        "https://github.com/acme/app/issues/42",
        "https://gitlab.com/acme/app/pull/42",
        "not a url",
    ],
)
def test_non_pull_request_urls_are_rejected(url):
    with pytest.raises(InvalidPullRequestError):
        parse_pull_request_url(url)


# --------------------------------------------------------------------------
# Resolution
# --------------------------------------------------------------------------

@respx.mock
async def test_a_pull_request_resolves_to_its_head_commit():
    """The SHA, not the branch. A branch moves while the analysis runs, so a
    report pinned to a branch cannot be reproduced or checked for staleness."""
    respx.get(f"{API}/repos/acme/app/pulls/42").mock(
        return_value=httpx.Response(
            200,
            json={
                "head": {"sha": "a" * 40, "ref": "feature/x"},
                "base": {"ref": "main"},
                "title": "Add a thing",
                "state": "open",
                "html_url": "https://github.com/acme/app/pull/42",
            },
        )
    )
    info = await fetch_pull_request(REF, Settings())
    assert info.head_sha == "a" * 40
    assert info.head_ref == "feature/x"
    assert info.base_ref == "main"


@respx.mock
async def test_a_missing_pull_request_says_it_might_be_private():
    respx.get(f"{API}/repos/acme/app/pulls/42").mock(
        return_value=httpx.Response(404, json={"message": "Not Found"})
    )
    with pytest.raises(InvalidPullRequestError) as excinfo:
        await fetch_pull_request(REF, Settings())
    assert "private" in (excinfo.value.detail or "")


# --------------------------------------------------------------------------
# What the comment says
# --------------------------------------------------------------------------

def test_the_comment_leads_with_what_changed():
    """The one thing Vantage knows that a first-time scanner does not. A PR
    author already knows the repository has debt."""
    delta = FindingDelta(
        previous_report_id="prev",
        previous_created_at=datetime.now(UTC),
        new=["fp1"],
        resolved=[
            ResolvedFinding(
                fingerprint="old",
                rule_id="security/ssrf",
                title="Outbound request to a URL from the request",
                file="proxy.js",
                severity=Severity.HIGH,
            )
        ],
        unchanged=12,
    )
    body = render_comment(
        report([finding()], delta), report_url="https://v/r/rep123", head_sha="b" * 40
    )

    assert body.startswith(MARKER)
    assert "1 new · 1 resolved · 12 unchanged" in body
    assert "#### New in this branch (1)" in body
    assert "`api/users.js:42`" in body
    assert "#### Resolved (1)" in body
    assert "Outbound request to a URL" in body
    assert "https://v/r/rep123" in body
    # Names the commit it describes, so a reader can tell if it is stale.
    assert "bbbbbbb" in body


def test_a_first_analysis_does_not_claim_nothing_changed():
    """No previous report means everything is new. "0 new" would be false and
    silence would be worse."""
    body = render_comment(report([finding()]), report_url="https://v/r/rep123")
    assert "First analysis" in body
    assert "new ·" not in body


def test_a_new_rule_is_disclosed_rather_than_blamed_on_the_branch():
    """Otherwise "12 new findings" reads as a regression the author caused."""
    delta = FindingDelta(
        previous_report_id="p",
        previous_created_at=datetime.now(UTC),
        new=["fp1"],
        unchanged=0,
        new_rules=["security/sql-injection"],
    )
    body = render_comment(report([finding()], delta), report_url="https://v/r/x")
    assert "added since the previous analysis" in body


def test_a_long_finding_list_is_capped_with_a_link_to_the_rest():
    """A comment that reproduces the whole report is a comment people
    collapse."""
    findings = [
        finding(id=f"f{i}", fingerprint=f"fp{i}", file=f"src/{i}.js")
        for i in range(MAX_LISTED + 5)
    ]
    delta = FindingDelta(
        previous_report_id="p",
        previous_created_at=datetime.now(UTC),
        new=[f.fingerprint for f in findings],
        unchanged=0,
    )
    body = render_comment(report(findings, delta), report_url="https://v/r/x")

    assert body.count("| critical |") == MAX_LISTED
    assert "…and 5 more" in body
    assert "tab=findings&new=1" in body


def test_truncation_is_disclosed():
    delta = FindingDelta(
        previous_report_id="p",
        previous_created_at=datetime.now(UTC),
        new=[],
        unchanged=1,
    )
    body = render_comment(
        report([finding()], delta, truncated=True), report_url="https://v/r/x"
    )
    assert "not " in body and "exhaustive" in body


def test_the_comment_preserves_the_servers_ordering():
    """The runner already sorted worst-first. Re-sorting here would let the
    comment and the report page disagree about what matters."""
    a = finding(id="a", fingerprint="a", title="Worst", priority=100)
    b = finding(id="b", fingerprint="b", title="Milder", priority=20, file="b.js")
    delta = FindingDelta(
        previous_report_id="p",
        previous_created_at=datetime.now(UTC),
        new=["a", "b"],
        unchanged=0,
    )
    body = render_comment(report([a, b], delta), report_url="https://v/r/x")
    assert body.index("Worst") < body.index("Milder")


# --------------------------------------------------------------------------
# Exactly one comment
# --------------------------------------------------------------------------

@respx.mock
async def test_the_first_run_posts_a_new_comment():
    respx.get(f"{API}/user").mock(
        return_value=httpx.Response(200, json={"login": "octocat"})
    )
    respx.get(f"{API}/repos/acme/app/issues/42/comments").mock(
        return_value=httpx.Response(200, json=[])
    )
    posted = respx.post(f"{API}/repos/acme/app/issues/42/comments").mock(
        return_value=httpx.Response(
            201, json={"html_url": "https://github.com/acme/app/pull/42#c1"}
        )
    )

    url = await upsert_comment(REF, f"{MARKER}\nbody", Settings())
    assert posted.called
    assert url.endswith("#c1")


@respx.mock
async def test_a_re_run_edits_the_same_comment_instead_of_adding_one():
    """The brief is explicit that this must not spam, and a branch pushed
    twelve times is where a naive implementation leaves twelve comments."""
    respx.get(f"{API}/user").mock(
        return_value=httpx.Response(200, json={"login": "octocat"})
    )
    respx.get(f"{API}/repos/acme/app/issues/42/comments").mock(
        return_value=httpx.Response(
            200,
            json=[
                {"id": 1, "body": "unrelated review note", "user": {"login": "someone"}},
                {"id": 2, "body": f"{MARKER}\nold", "user": {"login": "octocat"}},
            ],
        )
    )
    patched = respx.patch(f"{API}/repos/acme/app/issues/comments/2").mock(
        return_value=httpx.Response(
            200, json={"html_url": "https://github.com/acme/app/pull/42#c2"}
        )
    )
    posted = respx.post(f"{API}/repos/acme/app/issues/42/comments").mock(
        return_value=httpx.Response(201, json={})
    )

    await upsert_comment(REF, f"{MARKER}\nnew", Settings())
    assert patched.called
    assert not posted.called


@respx.mock
async def test_someone_elses_vantage_comment_is_not_hijacked():
    """Two people running Vantage on the same PR must not fight over one
    comment."""
    respx.get(f"{API}/user").mock(
        return_value=httpx.Response(200, json={"login": "octocat"})
    )
    respx.get(f"{API}/repos/acme/app/issues/42/comments").mock(
        return_value=httpx.Response(
            200,
            json=[{"id": 9, "body": f"{MARKER}\ntheirs", "user": {"login": "someone-else"}}],
        )
    )
    posted = respx.post(f"{API}/repos/acme/app/issues/42/comments").mock(
        return_value=httpx.Response(201, json={"html_url": "u"})
    )
    patched = respx.patch(f"{API}/repos/acme/app/issues/comments/9").mock(
        return_value=httpx.Response(200, json={})
    )

    await upsert_comment(REF, f"{MARKER}\nmine", Settings())
    assert posted.called
    assert not patched.called
