"""Accepted findings.

A scanner that reports the same forty-seven unchanging low-severity findings on
every run teaches people to stop reading the list, which quietly removes the
value of the two findings that mattered. Suppressions are how a report stops
being noise on a codebase that already exists.

Three properties, each deliberate:

* **Keyed on fingerprint, not report id.** A suppression is a statement about a
  problem, not about one analysis of it, so it carries forward to every future
  run of that repository. This is only possible because fingerprints survive
  the edits that are not the point — see ``analysis/diffing.py``.
* **Scoped to a repository.** "This hardcoded key is a test fixture" is true of
  one project, not of every project the account ever analyses.
* **Requires an account.** A suppression is a judgement someone made, and an
  unattributable one cannot be reviewed or revoked by the person who has to
  live with it.

Applied when a report is read rather than when it is written, so removing a
suppression restores the finding immediately instead of needing a re-analysis.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Protocol

from sqlalchemy import DateTime, String, Text, delete, select
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base, get_sessionmaker
from app.schemas import Suppression

logger = logging.getLogger(__name__)

MAX_REASON_LENGTH = 500


class SuppressionRow(Base):
    __tablename__ = "suppressions"

    # (owner, repository, fingerprint) is the natural key: the same person
    # accepting the same problem twice is one suppression, not two.
    owner_id: Mapped[str] = mapped_column(String(24), primary_key=True)
    repository: Mapped[str] = mapped_column(String(255), primary_key=True)
    fingerprint: Mapped[str] = mapped_column(String(64), primary_key=True)
    reason: Mapped[str] = mapped_column(Text, nullable=False, default="")
    # Denormalised so a suppression list is readable without joining against a
    # report that may since have been deleted.
    title: Mapped[str] = mapped_column(String(500), nullable=False, default="")
    rule_id: Mapped[str] = mapped_column(String(120), nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )


class SuppressionStore(Protocol):
    async def list(self, owner_id: str, repository: str) -> list[Suppression]: ...
    async def add(self, owner_id: str, repository: str, entry: Suppression) -> None: ...
    async def remove(
        self, owner_id: str, repository: str, fingerprint: str
    ) -> bool: ...


class InMemorySuppressionStore:
    """Matches the in-memory report store: real, and lost on restart."""

    backend = "memory"

    def __init__(self) -> None:
        self._entries: dict[tuple[str, str, str], Suppression] = {}

    async def list(self, owner_id: str, repository: str) -> list[Suppression]:
        return [
            entry
            for (owner, repo, _), entry in self._entries.items()
            if owner == owner_id and repo == repository
        ]

    async def add(self, owner_id: str, repository: str, entry: Suppression) -> None:
        self._entries[(owner_id, repository, entry.fingerprint)] = entry

    async def remove(
        self, owner_id: str, repository: str, fingerprint: str
    ) -> bool:
        return self._entries.pop((owner_id, repository, fingerprint), None) is not None


class PostgresSuppressionStore:
    backend = "postgres"

    async def list(self, owner_id: str, repository: str) -> list[Suppression]:
        maker = get_sessionmaker()
        if maker is None:  # pragma: no cover - guarded by get_suppression_store()
            raise RuntimeError("Database is not configured")

        query = select(SuppressionRow).where(
            SuppressionRow.owner_id == owner_id,
            SuppressionRow.repository == repository,
        )
        async with maker() as session:
            rows = (await session.execute(query)).scalars().all()

        return [
            Suppression(
                fingerprint=row.fingerprint,
                reason=row.reason,
                title=row.title,
                rule_id=row.rule_id,
                created_at=row.created_at,
            )
            for row in rows
        ]

    async def add(self, owner_id: str, repository: str, entry: Suppression) -> None:
        maker = get_sessionmaker()
        if maker is None:  # pragma: no cover
            raise RuntimeError("Database is not configured")
        async with maker() as session:
            # `merge` rather than `add`: suppressing something already suppressed
            # should update the reason, not raise on the primary key.
            await session.merge(
                SuppressionRow(
                    owner_id=owner_id,
                    repository=repository,
                    fingerprint=entry.fingerprint,
                    reason=entry.reason,
                    title=entry.title,
                    rule_id=entry.rule_id,
                    created_at=entry.created_at,
                )
            )
            await session.commit()

    async def remove(
        self, owner_id: str, repository: str, fingerprint: str
    ) -> bool:
        maker = get_sessionmaker()
        if maker is None:  # pragma: no cover
            raise RuntimeError("Database is not configured")
        statement = delete(SuppressionRow).where(
            SuppressionRow.owner_id == owner_id,
            SuppressionRow.repository == repository,
            SuppressionRow.fingerprint == fingerprint,
        )
        async with maker() as session:
            result = await session.execute(statement)
            await session.commit()
        return bool(result.rowcount)


def new_suppression(
    *, fingerprint: str, reason: str, title: str, rule_id: str
) -> Suppression:
    return Suppression(
        fingerprint=fingerprint,
        reason=reason.strip()[:MAX_REASON_LENGTH],
        title=title,
        rule_id=rule_id,
        created_at=datetime.now(timezone.utc),
    )


_store: SuppressionStore | None = None


def get_suppression_store() -> SuppressionStore:
    global _store
    if _store is None:
        _store = (
            PostgresSuppressionStore()
            if get_sessionmaker()
            else InMemorySuppressionStore()
        )
    return _store


def reset_suppression_store() -> None:
    """Test hook."""
    global _store
    _store = None
