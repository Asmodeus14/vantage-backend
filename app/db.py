"""Database engine and session management.

Persistence is optional. With no ``DATABASE_URL`` the service still analyses
code — reports are held in memory for the process lifetime and the degraded
state is reported by ``/api/health`` rather than being hidden.

Nothing here connects at import time; the engine is built on first use.
"""

from __future__ import annotations

import logging
import ssl
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy import text

from app.config import get_settings

logger = logging.getLogger(__name__)


class Base(DeclarativeBase):
    pass


_engine: AsyncEngine | None = None
_sessionmaker: async_sessionmaker[AsyncSession] | None = None


def _connect_args(url: str) -> dict[str, object]:
    """Managed Postgres (Neon, Supabase) requires TLS.

    asyncpg does not understand libpq's ``sslmode`` query parameter, so the
    context is supplied explicitly instead of via the URL.
    """
    if url.startswith("postgresql+asyncpg://"):
        return {"ssl": ssl.create_default_context()}
    return {}


def get_engine() -> AsyncEngine | None:
    global _engine, _sessionmaker

    settings = get_settings()
    if not settings.db_configured:
        return None
    if _engine is not None:
        return _engine

    url = settings.database_url
    assert url is not None
    _engine = create_async_engine(
        url,
        connect_args=_connect_args(url),
        pool_pre_ping=True,      # Neon closes idle connections; revalidate first
        pool_size=5,
        max_overflow=5,
        echo=False,
    )
    _sessionmaker = async_sessionmaker(_engine, expire_on_commit=False)
    return _engine


def get_sessionmaker() -> async_sessionmaker[AsyncSession] | None:
    if get_engine() is None:
        return None
    return _sessionmaker


@asynccontextmanager
async def session_scope() -> AsyncIterator[AsyncSession | None]:
    """Yield a session, or ``None`` when persistence is not configured."""
    maker = get_sessionmaker()
    if maker is None:
        yield None
        return
    async with maker() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def create_tables() -> None:
    """Create any missing tables — development convenience only.

    Alembic owns the schema on Postgres. Letting ``create_all`` also run there
    would race the migrations: it would happily create a table that a pending
    revision is about to create itself, and that revision would then fail.

    On SQLite (local development without a Postgres instance) there is no
    deploy step to run migrations from, so this stays the way tables appear.
    """
    engine = get_engine()
    if engine is None:
        return
    if engine.dialect.name == "postgresql":
        logger.debug("Postgres detected; schema is owned by Alembic.")
        return

    # Import registers the models on Base.metadata.
    from app import store  # noqa: F401

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def schema_state() -> str:
    """``current``, ``behind``, ``unknown`` or ``not-applicable``.

    Surfaced by /api/health so a migration that failed on deploy is visible
    rather than showing up later as a confusing column error.
    """
    engine = get_engine()
    if engine is None:
        return "not-applicable"
    if engine.dialect.name != "postgresql":
        return "not-applicable"

    try:
        from pathlib import Path

        from alembic.config import Config
        from alembic.script import ScriptDirectory

        root = Path(__file__).resolve().parent.parent
        script = ScriptDirectory.from_config(Config(str(root / "alembic.ini")))
        head = script.get_current_head()

        async with engine.connect() as conn:
            applied = (
                await conn.execute(text("SELECT version_num FROM alembic_version"))
            ).scalar()
        return "current" if applied == head else "behind"
    except Exception as exc:
        logger.debug("Could not determine schema state: %s", exc)
        return "unknown"


async def probe_database() -> tuple[bool, str | None]:
    """Cheap liveness check used by /api/health."""
    engine = get_engine()
    if engine is None:
        return False, "No DATABASE_URL configured."
    try:
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        return True, None
    except Exception as exc:  # pragma: no cover - exercised against a live DB
        logger.warning("Database probe failed: %s", exc)
        return False, f"{type(exc).__name__}: {str(exc)[:200]}"


async def dispose_engine() -> None:
    global _engine, _sessionmaker
    if _engine is not None:
        await _engine.dispose()
    _engine = None
    _sessionmaker = None
