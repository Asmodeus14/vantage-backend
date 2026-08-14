"""Durable job outcomes.

The in-memory `JobManager` in `analysis/runner.py` is the right structure for a
*running* analysis — subscribers wake on a condition and read an event log by
index, which a database cannot do without polling. What it cannot do is survive
the process.

That mattered in two ways. A free-tier instance sleeps when idle, so an analysis
running when it goes down leaves a job id the client is still holding and
nothing on the other end. And job state being per-process is what forced the
deploy down to one worker: the connection that streams progress is not the one
that started the analysis, so with two workers it landed on a process that had
never heard of the job about half the time.

This table is deliberately **not** a second copy of the event log. It records
only what a client needs to recover:

    where did it get to, did it finish, and what is the report id

The event log stays in memory and is lost on restart, which is correct — nobody
needs a replay of a stage that finished twenty minutes ago, they need the link
to the result.

**Every write here is best-effort.** A job that cannot be recorded is still a
job that runs and still produces a stored report; the analysis is the product
and this is bookkeeping about it. Failing an analysis because its progress row
could not be written would be the tail wagging the dog, so every method
swallows and logs.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta

from sqlalchemy import DateTime, String, Text, delete, select, update
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base, get_sessionmaker

logger = logging.getLogger(__name__)

# Long enough that a client which slept through an analysis can still come back
# and find the link; short enough that this never becomes a second reports
# table. Swept on write rather than on a schedule — there is no scheduler, and
# adding one for this would be the most expensive part of the feature.
JOB_RECORD_RETENTION = timedelta(days=2)

TERMINAL = frozenset({"succeeded", "failed"})


class JobRow(Base):
    __tablename__ = "analysis_jobs"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), index=True, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    # queued | running | succeeded | failed
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="queued")
    # Written at the start and at the end, not on every progress event. Per-
    # stage writes would be roughly eight database round-trips per analysis —
    # tens of milliseconds each on a managed instance — to report on something
    # faster than the reporting. A recovering client needs to know whether it
    # finished and where the result is, not which stage it was on.
    stage: Mapped[str | None] = mapped_column(String(24))
    message: Mapped[str | None] = mapped_column(String(500))
    # The whole point of the table.
    report_id: Mapped[str | None] = mapped_column(String(24))
    error: Mapped[str | None] = mapped_column(Text)
    owner_id: Mapped[str | None] = mapped_column(String(24), index=True)


class JobRecord:
    """What a recovering client is told about a job it can no longer stream."""

    def __init__(self, row: JobRow) -> None:
        self.id = row.id
        self.status = row.status
        self.stage = row.stage
        self.message = row.message
        self.report_id = row.report_id
        self.error = row.error
        self.created_at = row.created_at


async def record_started(job_id: str, *, owner_id: str | None = None) -> None:
    maker = get_sessionmaker()
    if maker is None:
        return
    now = datetime.now(UTC)
    try:
        async with maker() as session:
            session.add(
                JobRow(
                    id=job_id,
                    created_at=now,
                    updated_at=now,
                    status="running",
                    stage="queued",
                    owner_id=owner_id,
                )
            )
            await session.commit()
        await _sweep()
    except Exception:  # pragma: no cover - bookkeeping must never fail a run
        logger.warning("Could not record job start for %s", job_id, exc_info=True)


async def record_succeeded(job_id: str, report_id: str) -> None:
    await _update(job_id, status="succeeded", stage="done", report_id=report_id)


async def record_failed(job_id: str, error: str) -> None:
    await _update(job_id, status="failed", stage="failed", error=error[:2000])


async def get(job_id: str) -> JobRecord | None:
    maker = get_sessionmaker()
    if maker is None:
        return None
    try:
        async with maker() as session:
            row = (
                await session.execute(select(JobRow).where(JobRow.id == job_id))
            ).scalar_one_or_none()
            return JobRecord(row) if row is not None else None
    except Exception:  # pragma: no cover
        logger.warning("Could not read job %s", job_id, exc_info=True)
        return None


async def _update(job_id: str, **values) -> None:
    maker = get_sessionmaker()
    if maker is None:
        return
    values["updated_at"] = datetime.now(UTC)
    try:
        async with maker() as session:
            await session.execute(
                update(JobRow).where(JobRow.id == job_id).values(**values)
            )
            await session.commit()
    except Exception:  # pragma: no cover
        logger.warning("Could not update job %s", job_id, exc_info=True)


async def _sweep() -> None:
    """Drop records past retention.

    On write, because there is no scheduler and adding one for this would cost
    more than the feature. A handful of extra deleted rows per analysis is
    cheaper than a background task that has to be supervised.
    """
    maker = get_sessionmaker()
    if maker is None:
        return
    cutoff = datetime.now(UTC) - JOB_RECORD_RETENTION
    try:
        async with maker() as session:
            await session.execute(delete(JobRow).where(JobRow.created_at < cutoff))
            await session.commit()
    except Exception:  # pragma: no cover
        logger.debug("Job sweep failed", exc_info=True)
