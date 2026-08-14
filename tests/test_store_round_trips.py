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
