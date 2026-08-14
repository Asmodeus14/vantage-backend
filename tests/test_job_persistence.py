"""Recovering a job the process no longer holds.

The in-memory job log is the right structure for a running analysis and the
wrong one for a client that comes back later. A free-tier instance sleeps when
idle, so an analysis in flight at that moment left the client holding a job id
and the SSE endpoint answering "that analysis is no longer available" — which
was frequently false. The work had finished and the report was in the database
with nobody holding its id.

These tests are about the four things a reconnecting client can be told, and
about the promise that none of this bookkeeping can break an analysis.
"""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from app import jobs as job_records
from app.analysis.runner import jobs as job_manager
from app.config import Settings, get_settings
from app.db import Base, dispose_engine, get_engine
from app.main import app


@pytest.fixture
async def db(monkeypatch, tmp_path):
    """A real SQLite database, so the table and the queries are exercised.

    Mocking the store here would test the mock: the whole feature is "the row
    outlives the process", and an in-memory stand-in cannot demonstrate that.
    """
    url = f"sqlite+aiosqlite:///{tmp_path / 'jobs.db'}"
    settings = Settings(database_url=url, gemini_api_key=None)
    monkeypatch.setattr("app.config.get_settings", lambda: settings)
    monkeypatch.setattr("app.db.get_settings", lambda: settings)
    await dispose_engine()

    engine = get_engine()
    assert engine is not None, "expected a configured engine"
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    yield settings

    await dispose_engine()


async def test_a_recorded_job_survives_the_object_that_created_it(db):
    await job_records.record_started("job_abc", owner_id="owner1")
    record = await job_records.get("job_abc")

    assert record is not None
    assert record.status == "running"
    assert record.report_id is None


async def test_success_records_the_report_id(db):
    """The one thing a reconnecting client cannot reconstruct."""
    await job_records.record_started("job_ok")
    await job_records.record_succeeded("job_ok", "rep_123")

    record = await job_records.get("job_ok")
    assert record.status == "succeeded"
    assert record.report_id == "rep_123"


async def test_failure_records_why(db):
    await job_records.record_started("job_bad")
    await job_records.record_failed("job_bad", "Repository not found.")

    record = await job_records.get("job_bad")
    assert record.status == "failed"
    assert "not found" in record.error


async def test_an_unknown_job_is_none_rather_than_an_error(db):
    assert await job_records.get("job_never_existed") is None


async def test_bookkeeping_never_raises_without_a_database(monkeypatch):
    """The promise the module is built on.

    An analysis is the product; this is notes about it. If recording could
    fail a run, a database blip would cost the user the whole analysis.
    """
    monkeypatch.setattr("app.jobs.get_sessionmaker", lambda: None)

    await job_records.record_started("job_x")
    await job_records.record_succeeded("job_x", "rep")
    await job_records.record_failed("job_x", "boom")
    assert await job_records.get("job_x") is None


# --------------------------------------------------------------------------
# What the stream tells a client that reconnects
# --------------------------------------------------------------------------

def _events(response) -> list[dict]:
    return [
        json.loads(line[len("data: ") :])
        for line in response.text.splitlines()
        if line.startswith("data: ")
    ]


@pytest.fixture
def client(db):
    app.dependency_overrides[get_settings] = lambda: db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


def test_a_finished_job_hands_back_its_report(client):
    """The case that was reported as a failure and was not one."""
    import asyncio

    asyncio.run(job_records.record_started("job_done"))
    asyncio.run(job_records.record_succeeded("job_done", "rep_999"))
    assert job_manager.get("job_done") is None, "must not be in memory"

    events = _events(client.get("/api/analyze/job_done/events"))
    assert len(events) == 1
    assert events[0]["stage"] == "done"
    assert events[0]["report_id"] == "rep_999"


def test_a_failed_job_reports_its_own_reason(client):
    import asyncio

    asyncio.run(job_records.record_started("job_failed"))
    asyncio.run(job_records.record_failed("job_failed", "Archive was not a zip."))

    events = _events(client.get("/api/analyze/job_failed/events"))
    assert events[0]["stage"] == "failed"
    assert "zip" in events[0]["error"]


def test_a_job_interrupted_by_a_restart_says_so_and_says_it_is_safe_to_retry(client):
    """Recorded as running, but no process is running it.

    A spinner that never resolves is the worst answer here. The action this
    implies is "run it again", and that is true — nothing was saved.
    """
    import asyncio

    asyncio.run(job_records.record_started("job_lost"))

    events = _events(client.get("/api/analyze/job_lost/events"))
    assert events[0]["stage"] == "failed"
    assert "interrupted" in events[0]["message"]
    assert "safe" in events[0]["error"]


def test_a_genuinely_unknown_id_still_says_so(client):
    """The recovery path must not turn a typo into a reassuring message."""
    events = _events(client.get("/api/analyze/job_typo/events"))
    assert events[0]["stage"] == "failed"
    assert "no longer available" in events[0]["message"]
