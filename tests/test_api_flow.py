"""API-level tests for the analysis flow, scoring, and the report store."""

from __future__ import annotations

import io
import zipfile
from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient

from app.analysis.scoring import compute_score, severity_counts
from app.config import Settings, get_settings
from app.main import app
from app.routers import health as health_module
from app.schemas import (
    Category,
    Confidence,
    Finding,
    Report,
    Severity,
    SourceInfo,
    SourceKind,
)
from app.store import InMemoryReportStore, reset_store


@pytest.fixture(autouse=True)
def in_memory(monkeypatch):
    """Keep every API test off the network and off the real database."""
    app.dependency_overrides[get_settings] = lambda: Settings(
        database_url=None, gemini_api_key=None
    )

    async def fake_probe():
        return False, "No DATABASE_URL configured."

    monkeypatch.setattr(health_module, "probe_database", fake_probe)
    health_module._db_cache = None
    health_module._schema_cache = None

    store = InMemoryReportStore()
    monkeypatch.setattr("app.store._store", store)
    monkeypatch.setattr("app.routers.reports.get_store", lambda: store)
    yield store

    app.dependency_overrides.clear()
    health_module._db_cache = None
    health_module._schema_cache = None
    reset_store()


def make_finding(**kwargs) -> Finding:
    defaults = {
        "id": "f1",
        "rule_id": "test/rule",
        "title": "Test finding",
        "description": "d",
        "category": Category.QUALITY,
        "severity": Severity.MEDIUM,
        "confidence": Confidence.HIGH,
    }
    defaults.update(kwargs)
    return Finding(**defaults)


# --------------------------------------------------------------------------
# Scoring
# --------------------------------------------------------------------------

def test_clean_project_scores_100():
    score = compute_score([], analysed_files=50)
    assert score.value == 100
    assert score.grade == "A"
    assert "No issues" in score.summary


def test_score_never_collapses_to_zero_from_a_few_findings():
    """v2's formula hit 0 after ten high-severity findings."""
    findings = [
        make_finding(id=str(i), severity=Severity.HIGH, category=Category.QUALITY)
        for i in range(10)
    ]
    score = compute_score(findings, analysed_files=100)
    assert score.value > 0
    assert score.value < 100


def test_score_is_stable_across_project_size():
    """The same defect density should score similarly at any scale."""
    def density_score(files: int) -> int:
        findings = [
            make_finding(id=str(i), severity=Severity.LOW, category=Category.QUALITY)
            for i in range(files // 10)
        ]
        return compute_score(findings, analysed_files=files).value

    small, large = density_score(50), density_score(2000)
    assert abs(small - large) <= 12, (small, large)


def test_confidence_reduces_penalty():
    high = compute_score(
        [make_finding(severity=Severity.HIGH, confidence=Confidence.HIGH)], 20
    ).value
    low = compute_score(
        [make_finding(severity=Severity.HIGH, confidence=Confidence.LOW)], 20
    ).value
    assert low > high, "a low-confidence finding should cost less"


def test_critical_security_outweighs_many_style_issues():
    security = compute_score(
        [make_finding(severity=Severity.CRITICAL, category=Category.SECURITY)], 100
    ).value
    style = compute_score(
        [
            make_finding(id=str(i), severity=Severity.LOW, category=Category.QUALITY)
            for i in range(15)
        ],
        100,
    ).value
    assert security < style


def test_score_breakdown_covers_every_scored_category():
    """Every category that carries weight appears, even with no findings, so
    the UI can show a full picture rather than a ragged one.

    `METRIC` is deliberately absent: it is weighted zero, and a breakdown row
    showing it a score next to a total it contributed nothing to would invite
    a conclusion the number cannot support. Updated from "every category" when
    metrics were split out of quality.
    """
    score = compute_score([make_finding(category=Category.SECURITY)], 10)
    scored = {c for c in Category if c is not Category.METRIC}
    assert {c.category for c in score.categories} == scored


def test_severity_counts_are_accurate():
    counts = severity_counts(
        [
            make_finding(id="a", severity=Severity.CRITICAL),
            make_finding(id="b", severity=Severity.HIGH),
            make_finding(id="c", severity=Severity.HIGH),
            make_finding(id="d", severity=Severity.LOW),
        ]
    )
    assert (counts.critical, counts.high, counts.low, counts.total) == (1, 2, 1, 4)


# --------------------------------------------------------------------------
# Report store
# --------------------------------------------------------------------------

def make_report(report_id: str = "r1", repository: str | None = "a/b") -> Report:
    findings = [make_finding()]
    return Report(
        id=report_id,
        created_at=datetime.now(UTC),
        duration_seconds=1.5,
        source=SourceInfo(
            kind=SourceKind.REPOSITORY, repository=repository, ref="main"
        ),
        project={},
        score=compute_score(findings, 10),
        severity_counts=severity_counts(findings),
        findings=findings,
        ingest={},
    )


async def test_store_round_trips_a_report(in_memory):
    report = make_report()
    await in_memory.save(report)
    loaded = await in_memory.get("r1")
    assert loaded.id == "r1"
    assert loaded.source.repository == "a/b"


async def test_reading_a_report_cannot_scribble_on_the_store(in_memory):
    """The Postgres store returns a freshly validated object every read, so this
    one must too. Handing out the stored instance let a request handler mutate
    it — marking suppressed findings on read persisted, and unsuppressing then
    appeared to do nothing until a restart."""
    await in_memory.save(make_report("r1"))

    loaded = await in_memory.get("r1")
    loaded.findings[0].suppressed = True
    loaded.suppressed_count = 99

    fresh = await in_memory.get("r1")
    assert fresh.findings[0].suppressed is False
    assert fresh.suppressed_count == 0


async def test_missing_report_explains_the_memory_backend(in_memory):
    from app.errors import ReportNotFoundError

    with pytest.raises(ReportNotFoundError) as exc:
        await in_memory.get("nope")
    assert "memory" in (exc.value.detail or "")


async def test_sub_second_durations_survive_a_round_trip(in_memory):
    """`duration_seconds` was an Integer column, so Postgres truncated 0.42 to
    0 while the in-memory store kept it — the two backends disagreed about the
    same report, and the UI showed "analysed in 0.0s" for anything fast."""
    report = make_report("fast")
    report.duration_seconds = 0.42
    await in_memory.save(report)

    assert (await in_memory.get("fast")).duration_seconds == 0.42
    assert (await in_memory.list())[0].duration_seconds == 0.42


async def test_latest_for_returns_the_most_recent_run_of_that_repository(in_memory):
    await in_memory.save(make_report("old", repository="a/b"))
    await in_memory.save(make_report("other", repository="c/d"))
    await in_memory.save(make_report("new", repository="a/b"))

    latest = await in_memory.latest_for("a/b")
    assert latest is not None and latest.id == "new"
    assert await in_memory.latest_for("nobody/here") is None


async def test_latest_for_never_crosses_owners(in_memory):
    """Report diffing reads this. Scoped wrongly, a signed-in user's report
    would be compared against a stranger's run of the same project — and the
    resolved list would name findings from it."""
    await in_memory.save(make_report("mine", repository="a/b"), owner_id="u1")
    await in_memory.save(make_report("theirs", repository="a/b"), owner_id="u2")
    await in_memory.save(make_report("anon", repository="a/b"))

    assert (await in_memory.latest_for("a/b", owner_id="u1")).id == "mine"
    assert (await in_memory.latest_for("a/b", owner_id="u2")).id == "theirs"
    # None means *no owner*, not *any owner* — the same rule `list()` follows.
    assert (await in_memory.latest_for("a/b")).id == "anon"
    assert await in_memory.latest_for("a/b", owner_id="u3") is None


async def test_memory_store_is_bounded():
    store = InMemoryReportStore(capacity=3)
    for i in range(5):
        await store.save(make_report(f"r{i}"))
    listing = await store.list()
    assert len(listing) == 3
    assert [r.id for r in listing] == ["r4", "r3", "r2"]


async def test_list_filters_by_repository(in_memory):
    await in_memory.save(make_report("r1", repository="a/b"))
    await in_memory.save(make_report("r2", repository="c/d"))
    await in_memory.save(make_report("r3", repository="a/b"))

    assert [r.id for r in await in_memory.list(repository="a/b")] == ["r3", "r1"]
    assert [r.id for r in await in_memory.list(repository="c/d")] == ["r2"]
    assert len(await in_memory.list()) == 3


async def test_list_of_an_unknown_repository_is_empty_not_everything(in_memory):
    """The filter must never silently fall back to listing every report."""
    await in_memory.save(make_report("r1", repository="a/b"))
    assert await in_memory.list(repository="nobody/here") == []


async def test_uploads_are_never_matched_by_a_repository_filter(in_memory):
    await in_memory.save(make_report("r1", repository=None))
    assert await in_memory.list(repository="a/b") == []
    assert len(await in_memory.list()) == 1


async def test_repository_filter_applies_the_limit_after_filtering(in_memory):
    """A limit of 2 must mean two matches, not two rows scanned."""
    await in_memory.save(make_report("r1", repository="a/b"))
    for i in range(5):
        await in_memory.save(make_report(f"other{i}", repository="c/d"))
    await in_memory.save(make_report("r2", repository="a/b"))

    listing = await in_memory.list(limit=2, repository="a/b")
    assert [r.id for r in listing] == ["r2", "r1"]


# --------------------------------------------------------------------------
# HTTP surface
# --------------------------------------------------------------------------

def test_report_endpoints(in_memory):
    import asyncio

    asyncio.get_event_loop_policy().new_event_loop()
    with TestClient(app) as client:
        assert client.get("/api/reports").json() == []
        assert client.get("/api/reports/does-not-exist").status_code == 404
        body = client.get("/api/reports/does-not-exist").json()
        assert body["code"] == "report_not_found"


def test_invalid_repository_url_is_rejected_with_a_code(in_memory):
    with TestClient(app) as client:
        response = client.post(
            "/api/analyze/repository", json={"url": "https://example.com/not/github"}
        )
    # Pydantic accepts the URL shape; the runner rejects the host. Either way
    # the client must get a structured error rather than a stack trace.
    assert response.status_code in (202, 400, 422)


def test_upload_rejects_non_zip(in_memory):
    with TestClient(app) as client:
        response = client.post(
            "/api/analyze/upload",
            files={"file": ("project.tar", b"data", "application/x-tar")},
        )
    assert response.status_code == 400
    assert response.json()["code"] == "invalid_archive"


def test_upload_rejects_empty_file(in_memory):
    with TestClient(app) as client:
        response = client.post(
            "/api/analyze/upload",
            files={"file": ("project.zip", b"", "application/zip")},
        )
    assert response.status_code == 400


def test_upload_accepts_a_zip_and_returns_a_job(in_memory):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as zf:
        zf.writestr("package.json", '{"name":"demo","dependencies":{}}')
        zf.writestr("src/index.js", "const a = 1;\n")
    buffer.seek(0)

    with TestClient(app) as client:
        response = client.post(
            "/api/analyze/upload",
            files={"file": ("project.zip", buffer.read(), "application/zip")},
        )
    assert response.status_code == 202
    assert "job_id" in response.json()


def _zip_bytes() -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as zf:
        zf.writestr("package.json", '{"name":"demo","dependencies":{}}')
    buffer.seek(0)
    return buffer.read()


def test_an_upload_ticket_attributes_the_analysis(in_memory, monkeypatch):
    """The gap this closes: a signed-in user's upload posts directly to the API
    to clear the frontend's body cap, so it cannot carry the session cookie and
    was recorded as anonymous — never appearing in their own History."""
    from app.auth.tickets import issue_upload_ticket

    settings = Settings(
        database_url=None, gemini_api_key=None,
        token_encryption_key="8ZQZ3xw1n0m6Q3kY0d0m2y7cQxq3d2XwqZ8b8dJc0mY=",
    )
    app.dependency_overrides[get_settings] = lambda: settings

    captured: dict[str, object] = {}

    async def fake_run_upload(self, job, archive, filename, *, owner_id=None):
        captured["owner_id"] = owner_id
        await job.close()

    monkeypatch.setattr("app.analysis.runner.AnalysisRunner.run_upload", fake_run_upload)

    with TestClient(app) as client:
        response = client.post(
            "/api/analyze/upload",
            files={"file": ("project.zip", _zip_bytes(), "application/zip")},
            data={"ticket": issue_upload_ticket("u1", settings)},
        )

    assert response.status_code == 202
    assert captured["owner_id"] == "u1"


def test_an_unusable_ticket_uploads_anonymously_rather_than_failing(
    in_memory, monkeypatch
):
    """Refusing an archive someone just spent a minute uploading, because a
    credential expired while they chose a file, is a worse answer."""
    captured: dict[str, object] = {}

    async def fake_run_upload(self, job, archive, filename, *, owner_id=None):
        captured["owner_id"] = owner_id
        await job.close()

    monkeypatch.setattr("app.analysis.runner.AnalysisRunner.run_upload", fake_run_upload)

    with TestClient(app) as client:
        response = client.post(
            "/api/analyze/upload",
            files={"file": ("project.zip", _zip_bytes(), "application/zip")},
            data={"ticket": "forged"},
        )

    assert response.status_code == 202
    assert captured["owner_id"] is None


def test_unknown_job_stream_reports_failure_rather_than_hanging(in_memory):
    with TestClient(app) as client, client.stream(
        "GET", "/api/analyze/nope/events"
    ) as response:
            assert response.status_code == 200
            body = "".join(response.iter_text())
    assert "failed" in body
    assert "no longer available" in body


def test_job_status_polling_fallback(in_memory):
    with TestClient(app) as client:
        assert client.get("/api/analyze/unknown").json()["status"] == "unknown"


# --------------------------------------------------------------------------
# The summary sentence
# --------------------------------------------------------------------------

def test_summary_names_the_work_rather_than_the_weakest_category():
    """It used to end "Dependencies is the weakest area (65/100 across 1
    finding)" — a property of the scoring model, not an instruction. The
    sentence is read in the report header, the pull request comment and the
    `og:description` of a shared link, and all three want the same thing.
    """
    score = compute_score(
        [
            make_finding(
                id="a",
                category=Category.SECRET,
                severity=Severity.CRITICAL,
                title="AWS access key ID committed to the repository",
                file="config/keys.js",
                priority=100,
            )
        ],
        120,
    )
    assert score.summary.startswith("Start with AWS access key ID")
    assert "config/keys.js" in score.summary
    assert "weakest area" not in score.summary


def test_summary_keeps_an_acronym_capitalised():
    """`title[0].lower()` produced "aWS access key ID" and "sQL statement"."""
    from app.analysis.scoring import _decapitalise

    assert _decapitalise("AWS access key ID committed") == "AWS access key ID committed"
    assert _decapitalise("SQL statement assembled") == "SQL statement assembled"
    assert _decapitalise("JWT claims read") == "JWT claims read"
    assert _decapitalise("Shell command built") == "shell command built"


def test_summary_counts_the_rest_without_listing_them():
    score = compute_score(
        [
            make_finding(id=str(i), category=Category.SECURITY, severity=Severity.HIGH,
                         title="Shell command built from an interpolated value",
                         file=f"jobs/{i}.js", priority=90)
            for i in range(3)
        ],
        120,
    )
    assert "then 2 other issues of the same kind" in score.summary


def test_summary_will_not_name_an_unconfirmed_finding():
    """Naming a finding puts it in the report header, the PR comment and the
    preview card. Doing that for something the rules are unsure about is the
    loudest possible place to be wrong."""
    score = compute_score(
        [
            make_finding(
                category=Category.SECURITY,
                severity=Severity.CRITICAL,
                confidence=Confidence.MEDIUM,
                title="SQL statement assembled from an interpolated value",
            )
        ],
        120,
    )
    assert "Start with" not in score.summary
    assert "not confirmed" in score.summary


def test_summary_says_nothing_blocking_without_claiming_safety():
    """"Nothing blocking found" is defensible from a rule set with documented
    limits. "Your app is secure" is not, and no wording here should imply it.
    """
    score = compute_score(
        [
            make_finding(
                category=Category.METRIC,
                severity=Severity.LOW,
                title="app.ts is 1,200 lines long",
            )
        ],
        120,
    )
    assert "Nothing blocking found" in score.summary
    for overclaim in ("secure", "safe", "no vulnerabilities", "clean"):
        assert overclaim not in score.summary.lower()


def test_summary_ignores_an_accepted_finding():
    """A suppressed finding is one the owner has already judged. Leading the
    report with it would re-litigate that on every run."""
    accepted = make_finding(
        category=Category.SECRET,
        severity=Severity.CRITICAL,
        title="AWS access key ID committed to the repository",
        priority=100,
    )
    accepted.suppressed = True
    assert "Start with" not in compute_score([accepted], 120).summary
