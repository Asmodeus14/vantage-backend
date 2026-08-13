"""Stored source, for uploads.

An uploaded archive is the one input that cannot be re-fetched: the client sent
bytes, and there is no URL that will produce them again. So the analysable files
are kept, gzipped, one row per file.

Bounded on purpose. A single row per file rather than one archive per report,
because the viewer opens one file at a time and decompressing a whole project to
read a 40-line module is the kind of cost that only shows up under load.
"""

from __future__ import annotations

import gzip
import logging
from datetime import datetime, timezone
from typing import Protocol

from sqlalchemy import (
    DateTime,
    Integer,
    LargeBinary,
    String,
    delete,
    func,
    select,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base, get_sessionmaker
from app.ingest.snapshot import Snapshot
from app.source.base import SourceEntry, SourceUnavailable

logger = logging.getLogger(__name__)

# Per report. Generous for real projects and small enough that one upload cannot
# fill the disk: measured, an average analysis is ~200KB gzipped and the largest
# in this database is ~2MB.
MAX_STORED_BYTES = 8_000_000
MAX_STORED_FILES = 2_000
# Matches the snapshot's own read limit, so nothing is stored that the analysis
# itself declined to read.
MAX_FILE_BYTES = 1_000_000

# The whole point of the retention policy: a ceiling on what stored source may
# ever occupy, across every report.
#
# A per-owner "keep the newest N" quota would be fairer but bounds nothing — N
# uploads *per account* is unbounded in accounts. This is the constraint that
# actually exists, so it is the one enforced. Measured against the deployment
# this was written for, 200 MB leaves the rest of a 0.5 GB allowance for
# reports, which grow at roughly 10 KB each.
MAX_TOTAL_BLOB_BYTES = 200_000_000


class SourceBlobRow(Base):
    __tablename__ = "source_blobs"

    report_id: Mapped[str] = mapped_column(String(24), primary_key=True, index=True)
    path: Mapped[str] = mapped_column(String(1024), primary_key=True)
    size: Mapped[int] = mapped_column(Integer, nullable=False)
    language: Mapped[str | None] = mapped_column(String(40))
    analysable: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    # gzip, not raw text. Source compresses ~3-4x and this is the whole reason
    # storing it is affordable.
    content: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    # Ordering for eviction. `report_id` is a random token and carries no time,
    # so without this there is nothing to sort the oldest upload by — and the
    # report row it belongs to may already be gone.
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )


class BlobStore(Protocol):
    async def put(self, report_id: str, snapshot: Snapshot) -> int: ...
    async def tree(self, report_id: str) -> list[SourceEntry]: ...
    async def read(self, report_id: str, path: str) -> str: ...
    async def delete(self, report_id: str) -> None: ...
    async def prune(self, budget: int = MAX_TOTAL_BLOB_BYTES) -> int: ...


def _storable(snapshot: Snapshot) -> list:
    """Files worth keeping, largest-value first.

    Analysable files lead, because those are the ones findings point at. If the
    budget runs out, what is dropped is a lockfile or a minified vendor bundle
    rather than the module someone is trying to read.
    """
    return sorted(
        (f for f in snapshot.files if f.size <= MAX_FILE_BYTES),
        key=lambda f: (not f.analysable, f.path),
    )


class PostgresBlobStore:
    async def put(self, report_id: str, snapshot: Snapshot) -> int:
        maker = get_sessionmaker()
        if maker is None:  # pragma: no cover - guarded by the caller
            return 0

        rows: list[SourceBlobRow] = []
        now = datetime.now(timezone.utc)
        budget = MAX_STORED_BYTES
        for source in _storable(snapshot):
            if len(rows) >= MAX_STORED_FILES:
                break
            text = source.text()
            if text is None:  # binary or oversized
                continue
            packed = gzip.compress(text.encode("utf-8"), compresslevel=6)
            if len(packed) > budget:
                continue
            budget -= len(packed)
            rows.append(
                SourceBlobRow(
                    created_at=now,
                    report_id=report_id,
                    path=source.path,
                    size=source.size,
                    language=source.language,
                    analysable=1 if source.analysable else 0,
                    content=packed,
                )
            )

        if not rows:
            return 0
        async with maker() as session:
            session.add_all(rows)
            await session.commit()

        # Prune after writing, not before. The new upload is what pushed the
        # total up, and evicting first would let a single oversized one slip in
        # over the ceiling. Failing here must not fail the upload: the source is
        # already stored and the worst case is being briefly over budget.
        try:
            await self.prune()
        except Exception:
            logger.exception("Could not prune stored source")
        return len(rows)

    async def prune(self, budget: int = MAX_TOTAL_BLOB_BYTES) -> int:
        """Evict the oldest uploads until stored source fits in ``budget``.

        Whole reports at a time, never individual files: half a project is a
        broken file tree, which is worse than an absent one that says so.

        Returns the number of reports evicted.
        """
        maker = get_sessionmaker()
        if maker is None:  # pragma: no cover
            return 0

        async with maker() as session:
            total = (
                await session.execute(
                    select(func.coalesce(func.sum(func.length(SourceBlobRow.content)), 0))
                )
            ).scalar_one()
            if total <= budget:
                return 0

            # Oldest first, grouped by report, with each group's size — so the
            # loop below can stop as soon as it is under budget rather than
            # evicting everything old.
            groups = (
                await session.execute(
                    select(
                        SourceBlobRow.report_id,
                        func.sum(func.length(SourceBlobRow.content)).label("bytes"),
                        func.min(SourceBlobRow.created_at).label("stored_at"),
                    )
                    .group_by(SourceBlobRow.report_id)
                    .order_by("stored_at")
                )
            ).all()

            evicted: list[str] = []
            for report_id, size, _ in groups:
                if total <= budget:
                    break
                evicted.append(report_id)
                total -= size or 0

            if evicted:
                await session.execute(
                    delete(SourceBlobRow).where(
                        SourceBlobRow.report_id.in_(evicted)
                    )
                )
                await session.commit()
                logger.info(
                    "Pruned stored source for %d report(s) to stay under %d bytes",
                    len(evicted),
                    budget,
                )
        return len(evicted)

    async def tree(self, report_id: str) -> list[SourceEntry]:
        maker = get_sessionmaker()
        if maker is None:  # pragma: no cover
            raise SourceUnavailable("This server is running without a database.")

        query = select(
            SourceBlobRow.path,
            SourceBlobRow.size,
            SourceBlobRow.language,
            SourceBlobRow.analysable,
        ).where(SourceBlobRow.report_id == report_id)
        async with maker() as session:
            rows = (await session.execute(query)).all()

        return [
            SourceEntry(
                path=path, size=size, language=language, analysable=bool(analysable)
            )
            for path, size, language, analysable in rows
        ]

    async def read(self, report_id: str, path: str) -> str:
        maker = get_sessionmaker()
        if maker is None:  # pragma: no cover
            raise SourceUnavailable("This server is running without a database.")

        query = select(SourceBlobRow.content).where(
            SourceBlobRow.report_id == report_id, SourceBlobRow.path == path
        )
        async with maker() as session:
            packed = (await session.execute(query)).scalar_one_or_none()

        if packed is None:
            raise SourceUnavailable("That file is not part of this report.")
        return gzip.decompress(packed).decode("utf-8", errors="replace")

    async def delete(self, report_id: str) -> None:
        maker = get_sessionmaker()
        if maker is None:  # pragma: no cover
            return
        async with maker() as session:
            await session.execute(
                delete(SourceBlobRow).where(SourceBlobRow.report_id == report_id)
            )
            await session.commit()


class InMemoryBlobStore:
    """Matches the in-memory report store: real, and lost on restart."""

    def __init__(self) -> None:
        self._files: dict[str, dict[str, tuple[SourceEntry, bytes]]] = {}
        # Insertion order is arrival order, which is the eviction order the
        # Postgres store gets from `created_at`. Kept so the two behave the
        # same — a retention policy that only holds on one backend is worse
        # than none, because it is the one nobody tests.
        self._order: list[str] = []

    async def put(self, report_id: str, snapshot: Snapshot) -> int:
        stored: dict[str, tuple[SourceEntry, bytes]] = {}
        budget = MAX_STORED_BYTES
        for source in _storable(snapshot):
            if len(stored) >= MAX_STORED_FILES:
                break
            text = source.text()
            if text is None:
                continue
            packed = gzip.compress(text.encode("utf-8"), compresslevel=6)
            if len(packed) > budget:
                continue
            budget -= len(packed)
            stored[source.path] = (
                SourceEntry(
                    path=source.path,
                    size=source.size,
                    language=source.language,
                    analysable=source.analysable,
                ),
                packed,
            )
        if stored:
            self._files[report_id] = stored
            if report_id not in self._order:
                self._order.append(report_id)
            await self.prune()
        return len(stored)

    async def prune(self, budget: int = MAX_TOTAL_BLOB_BYTES) -> int:
        """Evict oldest-first until under budget. Whole reports at a time."""
        def total() -> int:
            return sum(
                len(packed)
                for files in self._files.values()
                for _, packed in files.values()
            )

        evicted = 0
        while total() > budget and self._order:
            oldest = self._order.pop(0)
            self._files.pop(oldest, None)
            evicted += 1
        return evicted

    async def tree(self, report_id: str) -> list[SourceEntry]:
        return [entry for entry, _ in self._files.get(report_id, {}).values()]

    async def read(self, report_id: str, path: str) -> str:
        found = self._files.get(report_id, {}).get(path)
        if found is None:
            raise SourceUnavailable("That file is not part of this report.")
        return gzip.decompress(found[1]).decode("utf-8", errors="replace")

    async def delete(self, report_id: str) -> None:
        self._files.pop(report_id, None)
        if report_id in self._order:
            self._order.remove(report_id)


_store: BlobStore | None = None


def get_blob_store() -> BlobStore:
    global _store
    if _store is None:
        _store = PostgresBlobStore() if get_sessionmaker() else InMemoryBlobStore()
    return _store


def reset_blob_store() -> None:
    """Test hook."""
    global _store
    _store = None
