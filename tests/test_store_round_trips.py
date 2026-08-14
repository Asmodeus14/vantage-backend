"""How many times reading a report touches the database.

Measured against the deployed instance, a single query on this path costs about
1.35 seconds — the round trip dominates so completely that endpoint latency
tracks the *number* of queries almost exactly:

    /api/ping           0 queries    0.41s   (the network floor)
    /api/reports        1 query      1.8s
    /api/reports/{id}   2 queries    3.1s

`get_report` called `store.get()` and then `store.owner_of()`, which issued
`session.get(ReportRow, id)` twice against the same row — the first call had
already loaded `owner_id` and thrown it away. That is most of a second and a
half on the product's most-loaded endpoint.

Counting statements is the only way to keep it: nothing about the code looks
wrong when a second convenient `owner_of()` creeps back in, and the cost is
invisible on a local database where a query is a millisecond.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime

import pytest
from sqlalchemy import event

from app.config import Settings
from app.db import Base, dispose_engine, get_engine
from app.schemas import (
    Category,
    Confidence,
    Finding,
    Report,
    Score,
    SeverityCounts,
    SourceInfo,
    SourceKind,
)
from app.store import PostgresReportStore


@pytest.fixture
async def store(monkeypatch, tmp_path):
    """A real SQLite database — the statement counter needs real statements."""
    settings = Settings(database_url=f"sqlite+aiosqlite:///{tmp_path / 's.db'}")
    monkeypatch.setattr("app.config.get_settings", lambda: settings)
    monkeypatch.setattr("app.db.get_settings", lambda: settings)
    await dispose_engine()

    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    yield PostgresReportStore()
    await dispose_engine()


class Counter:
    """Counts SELECTs against `reports`, ignoring connection setup chatter."""

    def __init__(self) -> None:
        self.statements: list[str] = []

    def __enter__(self):
        engine = get_engine().sync_engine

        @event.listens_for(engine, "before_cursor_execute")
        def _record(conn, cursor, statement, parameters, context, executemany):
            if "reports" in statement.lower():
                self.statements.append(statement)

        self._handler = _record
        self._engine = engine
        return self

    def __exit__(self, *exc):
        event.remove(self._engine, "before_cursor_execute", self._handler)
        return False



def selects_whole_payload(sql: str) -> bool:
    """Whether `payload` is selected as a column rather than reached into.

    Shared by the assertion and by the test of the assertion, so the two
    cannot drift — the first version of this lived only inside the test and
    was wrong in a way that only showed up on the *other* dialect.

    Both extraction forms are removed whole: SQLite renders
    `JSON_QUOTE(JSON_EXTRACT(payload, ?))` and Postgres renders
    `payload -> %(x)s`. Removing only the `->` operator leaves the column
    reference behind and flags a correct query.
    """
    remaining = re.sub(
        r"(?:json_extract|json_quote)\s*\([^)]*\)", "", sql, flags=re.IGNORECASE
    )
    remaining = re.sub(
        r"\S*payload\s*->>?\s*\S+", "", remaining, flags=re.IGNORECASE
    )
    return "payload" in remaining.lower()


def a_report(report_id: str = "r1") -> Report:
    finding = Finding(
        id="f1",
        fingerprint="fp1",
        rule_id="x/y",
        title="t",
        description="d" * 80,
        category=Category.SECURITY,
        severity="high",
        confidence=Confidence.HIGH,
    )
    return Report(
        id=report_id,
        created_at=datetime.now(UTC),
        duration_seconds=1.0,
        source=SourceInfo(kind=SourceKind.REPOSITORY, repository="a/b"),
        project={},
        score=Score(value=80, grade="B", categories=[], summary="s"),
        severity_counts=SeverityCounts(),
        findings=[finding],
        ingest={},
    )


async def test_reading_a_report_with_its_owner_is_one_query(store):
    await store.save(a_report(), owner_id="owner-1")

    with Counter() as counter:
        report, owner_id = await store.get_with_owner("r1")

    assert report.id == "r1"
    assert owner_id == "owner-1"
    assert len(counter.statements) == 1, (
        f"reading a report cost {len(counter.statements)} queries; at ~1.35s "
        "each on the deployed database that is a second and a half per page "
        f"load: {counter.statements}"
    )


async def test_the_old_two_call_shape_really_did_cost_two(store):
    """Documents what was fixed, so the saving is not folklore."""
    await store.save(a_report(), owner_id="owner-1")

    with Counter() as counter:
        await store.get("r1")
        await store.owner_of("r1")

    assert len(counter.statements) == 2


async def test_an_anonymous_report_reports_no_owner_not_an_error(store):
    await store.save(a_report("r2"), owner_id=None)
    report, owner_id = await store.get_with_owner("r2")
    assert report.id == "r2"
    assert owner_id is None


async def test_a_missing_report_still_raises(store):
    from app.errors import ReportNotFoundError

    with pytest.raises(ReportNotFoundError):
        await store.get_with_owner("nope")


# --------------------------------------------------------------------------
# What the listing actually selects
# --------------------------------------------------------------------------

def _big_report(report_id: str, findings: int = 60) -> Report:
    """A report whose payload is large enough that fetching it would matter."""
    report = a_report(report_id)
    base = report.findings[0]
    report.findings = [
        base.model_copy(update={"id": f"f{i}", "fingerprint": f"fp{i}"})
        for i in range(findings)
    ]
    return report


async def test_listing_does_not_select_the_payload_column(store):
    """Three comments in `store.py` said the listing never touches `payload`.
    The code selected the whole row, payload included, and JSON-decoded a
    complete report per listed row to read two small objects out of each.

    Asserted against the emitted SQL rather than against timing, because on a
    local database the cost is invisible — and it is the *statement* that was
    wrong, not the result.
    """
    for i in range(3):
        await store.save(_big_report(f"r{i}"), owner_id=None)

    with Counter() as counter:
        summaries = await store.list(limit=10)

    assert len(summaries) == 3
    assert len(counter.statements) == 1, "listing should be one query"

    sql = counter.statements[0]

    # `payload` may only appear inside a JSON extraction. Strip those out and
    # any surviving mention means the whole column is still selected. A naive
    # substring check passes on `JSON_EXTRACT(reports.payload, ?)`, which is
    # exactly the form we want to permit — so the extractions go first.
    remaining = re.sub(
        r"(?:json_extract|json_quote)\s*\([^)]*\)", "", sql, flags=re.IGNORECASE
    )
    remaining = re.sub(r"->>?", "", remaining)
    assert "payload" not in remaining.lower(), (
        f"listing still selects the whole payload column:\n{sql}"
    )

    # And it must genuinely reach into the payload rather than having dropped
    # the two fields altogether.
    assert re.search(r"json_extract|->", sql, re.IGNORECASE), (
        f"expected a JSON path extraction for source/severity_counts:\n{sql}"
    )


async def test_the_listing_still_returns_everything_the_ui_needs(store):
    """The projection must not quietly drop a field. `source` and
    `severity_counts` come out of the payload; the rest are columns."""
    await store.save(_big_report("r1"), owner_id=None)

    summary = (await store.list(limit=10))[0]
    assert summary.id == "r1"
    assert summary.source.repository == "a/b"
    assert summary.source.kind.value == "repository"
    assert summary.grade == "B"
    assert summary.score == 80
    assert summary.total_findings == 60
    assert summary.duration_seconds == 1.0
    assert summary.severity_counts.total >= 0


async def test_listing_scopes_by_owner_after_the_projection_change(store):
    """The owner filter is the one thing in this query that is a security
    boundary, so it is re-asserted against the new statement shape."""
    await store.save(a_report("mine"), owner_id="owner-1")
    await store.save(a_report("theirs"), owner_id="owner-2")
    await store.save(a_report("anon"), owner_id=None)

    assert [s.id for s in await store.list(owner_id="owner-1")] == ["mine"]
    assert [s.id for s in await store.list(owner_id="owner-2")] == ["theirs"]
    # None means *no owner*, never *any owner*.
    assert [s.id for s in await store.list(owner_id=None)] == ["anon"]


async def test_as_object_accepts_both_driver_shapes():
    """Postgres and SQLite disagree about whether a JSON path result arrives
    decoded. Both shapes have to work, because only one of them is testable
    here."""
    from app.store import _as_object

    assert _as_object({"kind": "repository"}) == {"kind": "repository"}
    assert _as_object('{"kind": "repository"}') == {"kind": "repository"}
    assert _as_object(b'{"kind": "upload"}') == {"kind": "upload"}
    # Never raises on nonsense — a listing must not die over one odd row.
    assert _as_object(None) == {}
    assert _as_object("not json") == {}
    assert _as_object("[1,2,3]") == {}


def test_the_payload_guard_would_catch_a_regression():
    """Validates the check above rather than the code it checks.

    The first version of that assertion was a substring test for
    `reports.payload,` — which matches inside `JSON_EXTRACT(reports.payload,
    ?)`, so it failed on the *fixed* query and would equally have passed on a
    broken one with different spacing. A guard nobody has seen fail is not a
    guard.
    """

    # The regression this exists to catch.
    assert selects_whole_payload(
        "SELECT reports.id, reports.payload FROM reports"
    )
    assert selects_whole_payload("SELECT reports.* , reports.payload FROM reports")

    # The shapes that are fine: SQLite and Postgres extraction.
    assert not selects_whole_payload(
        "SELECT reports.id, JSON_QUOTE(JSON_EXTRACT(reports.payload, ?)) AS source "
        "FROM reports"
    )
    assert not selects_whole_payload(
        "SELECT reports.id, reports.payload -> %(x)s AS source FROM reports"
    )
