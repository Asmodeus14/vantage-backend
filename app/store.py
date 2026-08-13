"""Report persistence.

Two interchangeable implementations behind one protocol. Postgres is used when
``DATABASE_URL`` is set; otherwise reports live in memory for the process
lifetime. The in-memory mode is a real, working fallback — not a stub — and
``/api/health`` reports which one is active so the degradation is never silent.
"""

from __future__ import annotations

import logging
from collections import OrderedDict
from datetime import datetime, timezone
from typing import Protocol

from sqlalchemy import DateTime, Float, Integer, String, Text, select
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.types import JSON

from app.db import Base, get_sessionmaker
from app.errors import ReportNotFoundError
from app.schemas import Report, ReportSummary, SeverityCounts, SourceInfo

logger = logging.getLogger(__name__)

# JSONB on Postgres, plain JSON elsewhere (SQLite in local development).
JSON_TYPE = JSON().with_variant(JSONB(), "postgresql")

MEMORY_CAPACITY = 100


class ReportRow(Base):
    __tablename__ = "reports"

    id: Mapped[str] = mapped_column(String(24), primary_key=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), index=True, nullable=False
    )
    source_kind: Mapped[str] = mapped_column(String(20), nullable=False)
    repository: Mapped[str | None] = mapped_column(String(255), index=True)
    ref: Mapped[str | None] = mapped_column(String(255))
    commit: Mapped[str | None] = mapped_column(String(64))
    score: Mapped[int] = mapped_column(Integer, nullable=False)
    grade: Mapped[str] = mapped_column(String(2), nullable=False)
    total_findings: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    # Float, not Integer. Stored as an integer, a sub-second analysis rounded to
    # 0 on Postgres while the in-memory store kept 0.4 — the two implementations
    # disagreed about the same report, and the UI showed "analysed in 0.0s".
    duration_seconds: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    # Null for anonymous reports, including every row created before sign-in
    # existed. Those stay reachable by id and are never listed.
    owner_id: Mapped[str | None] = mapped_column(String(24), index=True)
    # The full report. Indexed columns above exist so listing never needs to
    # deserialise this.
    payload: Mapped[dict] = mapped_column(JSON_TYPE, nullable=False)


class ReportStore(Protocol):
    backend: str

    async def save(self, report: Report, *, owner_id: str | None = None) -> None: ...
    async def get(self, report_id: str) -> Report: ...
    async def owner_of(self, report_id: str) -> str | None: ...
    async def delete(self, report_id: str) -> None: ...

    async def latest_for(
        self, repository: str, *, owner_id: str | None = None
    ) -> Report | None:
        """The most recent report of ``repository`` belonging to ``owner_id``.

        Used to diff a new analysis against the last one. Scoped by owner on
        exactly the same terms as :meth:`list` — ``None`` means *no owner*, not
        *any owner* — so a signed-in user is never compared against someone
        else's run of the same project.

        Returns the full report, not a summary: the comparison needs every
        fingerprint, and summaries do not carry findings.
        """
        ...

    async def list(
        self,
        limit: int = 25,
        *,
        repository: str | None = None,
        owner_id: str | None = None,
    ) -> list[ReportSummary]:
        """Most recent first.

        ``repository`` is an exact ``owner/name`` match, so a report can show
        how the same project has changed over time; the column is indexed for
        exactly that.

        ``owner_id`` scopes the listing to one account. ``None`` means *no
        owner*, not *any owner* — anonymous reports stay reachable by their
        unguessable id but are never enumerated, which is what stops this
        endpoint handing every caller the index of everyone's analyses.
        """
        ...


def _summarise(report: Report) -> ReportSummary:
    return ReportSummary(
        id=report.id,
        created_at=report.created_at,
        source=report.source,
        score=report.score.value,
        grade=report.score.grade,
        severity_counts=report.severity_counts,
        total_findings=len(report.findings),
        duration_seconds=report.duration_seconds,
    )


class InMemoryReportStore:
    """Bounded LRU of recent reports. Lost on restart, by design."""

    backend = "memory"

    def __init__(self, capacity: int = MEMORY_CAPACITY) -> None:
        self._reports: OrderedDict[str, Report] = OrderedDict()
        # Ownership is not part of the Report payload — it is a property of the
        # row, not of the analysis — so it is tracked alongside.
        self._owners: dict[str, str | None] = {}
        self._capacity = capacity

    async def save(self, report: Report, *, owner_id: str | None = None) -> None:
        self._reports[report.id] = report
        self._owners[report.id] = owner_id
        self._reports.move_to_end(report.id)
        while len(self._reports) > self._capacity:
            evicted, _ = self._reports.popitem(last=False)
            self._owners.pop(evicted, None)

    async def get(self, report_id: str) -> Report:
        report = self._reports.get(report_id)
        if report is None:
            raise ReportNotFoundError(
                "That report is no longer available.",
                detail=(
                    "This server is running without a database, so reports are "
                    "kept in memory and cleared when it restarts."
                ),
            )
        return report

    async def list(
        self,
        limit: int = 25,
        *,
        repository: str | None = None,
        owner_id: str | None = None,
    ) -> list[ReportSummary]:
        reports = reversed(list(self._reports.values()))
        if repository is not None:
            reports = (r for r in reports if r.source.repository == repository)
        reports = (r for r in reports if self._owners.get(r.id) == owner_id)
        return [_summarise(r) for r in reports][:limit]

    async def owner_of(self, report_id: str) -> str | None:
        return self._owners.get(report_id)

    async def latest_for(
        self, repository: str, *, owner_id: str | None = None
    ) -> Report | None:
        for report in reversed(list(self._reports.values())):
            if report.source.repository != repository:
                continue
            if self._owners.get(report.id) != owner_id:
                continue
            return report
        return None

    async def delete(self, report_id: str) -> None:
        self._reports.pop(report_id, None)
        self._owners.pop(report_id, None)


class PostgresReportStore:
    backend = "postgres"

    async def save(self, report: Report, *, owner_id: str | None = None) -> None:
        maker = get_sessionmaker()
        if maker is None:  # pragma: no cover - guarded by get_store()
            raise RuntimeError("Database is not configured")

        row = ReportRow(
            owner_id=owner_id,
            id=report.id,
            created_at=report.created_at,
            source_kind=report.source.kind.value,
            repository=report.source.repository,
            ref=report.source.ref,
            commit=report.source.commit,
            score=report.score.value,
            grade=report.score.grade,
            total_findings=len(report.findings),
            duration_seconds=report.duration_seconds,
            payload=report.model_dump(mode="json"),
        )
        async with maker() as session:
            await session.merge(row)
            await session.commit()

    async def get(self, report_id: str) -> Report:
        maker = get_sessionmaker()
        if maker is None:  # pragma: no cover
            raise RuntimeError("Database is not configured")
        async with maker() as session:
            row = await session.get(ReportRow, report_id)
            if row is None:
                raise ReportNotFoundError("No report with that id.")
            return Report.model_validate(row.payload)

    async def owner_of(self, report_id: str) -> str | None:
        maker = get_sessionmaker()
        if maker is None:  # pragma: no cover
            raise RuntimeError("Database is not configured")
        async with maker() as session:
            row = await session.get(ReportRow, report_id)
            if row is None:
                raise ReportNotFoundError("No report with that id.")
            return row.owner_id

    async def list(
        self,
        limit: int = 25,
        *,
        repository: str | None = None,
        owner_id: str | None = None,
    ) -> list[ReportSummary]:
        maker = get_sessionmaker()
        if maker is None:  # pragma: no cover
            raise RuntimeError("Database is not configured")

        query = select(ReportRow).order_by(ReportRow.created_at.desc())
        if repository is not None:
            # Filters on the indexed column, so this stays a cheap query and
            # never touches `payload`.
            query = query.where(ReportRow.repository == repository)

        # `IS NULL` for anonymous, never "any owner". Signed-out callers see
        # only reports that belong to nobody — and even those are excluded from
        # the listing further up in the router.
        query = query.where(
            ReportRow.owner_id.is_(None)
            if owner_id is None
            else ReportRow.owner_id == owner_id
        )

        async with maker() as session:
            result = await session.execute(query.limit(limit))
            rows = result.scalars().all()

        summaries: list[ReportSummary] = []
        for row in rows:
            payload = row.payload
            summaries.append(
                ReportSummary(
                    id=row.id,
                    created_at=row.created_at,
                    source=SourceInfo.model_validate(payload["source"]),
                    score=row.score,
                    grade=row.grade,
                    severity_counts=SeverityCounts.model_validate(
                        payload.get("severity_counts", {})
                    ),
                    total_findings=row.total_findings,
                    duration_seconds=float(row.duration_seconds),
                )
            )
        return summaries

    async def latest_for(
        self, repository: str, *, owner_id: str | None = None
    ) -> Report | None:
        maker = get_sessionmaker()
        if maker is None:  # pragma: no cover
            raise RuntimeError("Database is not configured")

        query = (
            select(ReportRow)
            .where(ReportRow.repository == repository)
            .where(
                ReportRow.owner_id.is_(None)
                if owner_id is None
                else ReportRow.owner_id == owner_id
            )
            .order_by(ReportRow.created_at.desc())
            .limit(1)
        )
        async with maker() as session:
            row = (await session.execute(query)).scalars().first()
        return Report.model_validate(row.payload) if row is not None else None

    async def delete(self, report_id: str) -> None:
        maker = get_sessionmaker()
        if maker is None:  # pragma: no cover
            raise RuntimeError("Database is not configured")
        async with maker() as session:
            row = await session.get(ReportRow, report_id)
            if row is not None:
                await session.delete(row)
                await session.commit()


_store: ReportStore | None = None


def get_store() -> ReportStore:
    global _store
    if _store is None:
        _store = PostgresReportStore() if get_sessionmaker() else InMemoryReportStore()
        logger.info("Report store backend: %s", _store.backend)
    return _store


def reset_store() -> None:
    """Test hook."""
    global _store
    _store = None
