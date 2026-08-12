"""Alembic environment.

Two things here are deliberate and easy to get wrong:

* The URL is never written into the Alembic config. ``set_main_option`` runs the
  value through ConfigParser, which treats ``%`` as interpolation — and a Neon
  password containing one would fail in a way that looks like a bad password.
* Connection arguments are taken from ``app.db._connect_args``, so migrations
  negotiate TLS exactly as the application does. Without that, migrations fail
  against managed Postgres while the app connects fine.
"""

from __future__ import annotations

import asyncio
from logging.config import fileConfig

from alembic import context
from sqlalchemy.ext.asyncio import create_async_engine

from app.config import get_settings
from app.db import Base, _connect_args

# Importing the models registers them on Base.metadata. Without this,
# autogenerate would see an empty schema and propose dropping every table.
from app import store  # noqa: F401
from app.auth import models  # noqa: F401

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def _url() -> str:
    settings = get_settings()
    if not settings.database_url:
        raise RuntimeError(
            "DATABASE_URL is not set. Migrations only apply to a real database; "
            "the in-memory store needs none."
        )
    return settings.database_url


def run_migrations_offline() -> None:
    context.configure(
        url=_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def _run(connection) -> None:
    context.configure(
        connection=connection,
        target_metadata=target_metadata,
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


async def run_migrations_online() -> None:
    url = _url()
    engine = create_async_engine(url, connect_args=_connect_args(url), poolclass=None)
    try:
        async with engine.connect() as connection:
            await connection.run_sync(_run)
    finally:
        await engine.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    asyncio.run(run_migrations_online())
