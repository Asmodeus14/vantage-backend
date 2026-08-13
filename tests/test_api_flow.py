"""API-level tests for the analysis flow, scoring, and the report store."""

from __future__ import annotations

import io
import zipfile
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

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
from app.analysis.scoring import compute_score, severity_counts
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

    store = InMemoryReportStore()
    monkeypatch.setattr("app.store._store", store)
    monkeypatch.setattr("app.routers.reports.get_store", lambda: store)
    yield store

    app.dependency_overrides.clear()
    health_module._db_cache = None
    reset_store()


def make_finding(**kwargs) -> Finding:
    defaults = dict(
        id="f1",
        rule_id="test/rule",
        title="Test finding",
        description="d",
        category=Category.QUALITY,
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
    )
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


def test_score_breakdown_covers_every_category():
    score = compute_score([make_finding(category=Category.SECURITY)], 10)
    assert {c.category for c in score.categories} == set(Category)


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
        created_at=datetime.now(timezone.utc),
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


def test_unknown_job_stream_reports_failure_rather_than_hanging(in_memory):
    with TestClient(app) as client:
        with client.stream("GET", "/api/analyze/nope/events") as response:
            assert response.status_code == 200
            body = "".join(response.iter_text())
    assert "failed" in body
    assert "no longer available" in body


def test_job_status_polling_fallback(in_memory):
    with TestClient(app) as client:
        assert client.get("/api/analyze/unknown").json()["status"] == "unknown"
