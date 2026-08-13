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
from typing import Protocol

from sqlalchemy import Integer, LargeBinary, String, delete, select
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


class BlobStore(Protocol):
    async def put(self, report_id: str, snapshot: Snapshot) -> int: ...
    async def tree(self, report_id: str) -> list[SourceEntry]: ...
    async def read(self, report_id: str, path: str) -> str: ...
    async def delete(self, report_id: str) -> None: ...


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
        return len(rows)

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
        return len(stored)

    async def tree(self, report_id: str) -> list[SourceEntry]:
        return [entry for entry, _ in self._files.get(report_id, {}).values()]

    async def read(self, report_id: str, path: str) -> str:
        found = self._files.get(report_id, {}).get(path)
        if found is None:
            raise SourceUnavailable("That file is not part of this report.")
        return gzip.decompress(found[1]).decode("utf-8", errors="replace")

    async def delete(self, report_id: str) -> None:
        self._files.pop(report_id, None)


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
