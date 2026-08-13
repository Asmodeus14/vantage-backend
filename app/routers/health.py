"""Health and liveness endpoints.

Two endpoints, because they answer different questions.

``/api/health`` is *readiness*: can this service do useful work, and if not,
which part is missing. It is deliberately cheap — v2's version called
``generate_content("Test")`` on every request while the frontend polled it,
which is what exhausted the Gemini quota and left the AI feature permanently
disabled. This handler performs no LLM traffic at all: provider status is read
from local circuit-breaker state. Database liveness *is* a real check, but it is
cached briefly so a polling frontend cannot turn it into connection-pool
pressure.

``/api/ping`` is *liveness*: is the process running. It touches nothing.
"""

from __future__ import annotations

import time
from datetime import datetime, timezone

from fastapi import APIRouter, Depends

from app import __version__
from app.ai.provider import LLMProvider, provider_dependency
from app.config import Settings, get_settings
from app.db import probe_database
from app.schemas import (
    AIHealth,
    AuthStatus,
    DependencyHealth,
    HealthResponse,
    PingResponse,
)

router = APIRouter(tags=["health"])

_DB_PROBE_TTL_SECONDS = 15.0
_db_cache: tuple[float, bool, str | None] | None = None


async def _database_health(settings: Settings) -> DependencyHealth:
    global _db_cache

    if not settings.db_configured:
        return DependencyHealth(
            configured=False,
            available=False,
            detail="No DATABASE_URL configured; reports are kept in memory only "
            "and are lost when the server restarts.",
        )

    now = time.monotonic()
    if _db_cache is not None and (now - _db_cache[0]) < _DB_PROBE_TTL_SECONDS:
        _, ok, detail = _db_cache
        return DependencyHealth(configured=True, available=ok, detail=detail)

    ok, detail = await probe_database()
    _db_cache = (now, ok, detail)
    return DependencyHealth(configured=True, available=ok, detail=detail)


@router.get("/api/ping", response_model=PingResponse)
async def ping() -> PingResponse:
    """Liveness. Touches no dependency, on purpose.

    This exists for the uptime monitor that stops a free-tier host idling the
    service to sleep. Pointing such a monitor at ``/api/health`` looks like the
    obvious choice and is a trap: that endpoint probes the database on a 15
    second cache, so a ping every few minutes always misses the cache and issues
    a real query. The database would then never auto-suspend either — and on a
    serverless plan billed by compute time, keeping it awake around the clock is
    the expensive half of the mistake.

    Kept as a separate route rather than a flag on ``/api/health`` so a monitor
    cannot be pointed at the cheap behaviour and then be silently reporting
    "up" for a service whose database has been unreachable for a week.
    """
    return PingResponse(version=__version__, timestamp=datetime.now(timezone.utc))


@router.get("/api/health", response_model=HealthResponse)
async def health(
    settings: Settings = Depends(get_settings),
    provider: LLMProvider = Depends(provider_dependency),
) -> HealthResponse:
    ai_status = provider.status()  # local only — never performs I/O
    database = await _database_health(settings)

    # The service is "ok" whenever it can do its core job: analysing code.
    # AI and persistence are enhancements, and their absence is reported
    # explicitly rather than being treated as an outage.
    status = "ok" if (database.available or not database.configured) else "degraded"

    return HealthResponse(
        status=status,
        version=__version__,
        environment=settings.environment,
        timestamp=datetime.now(timezone.utc),
        ai=AIHealth(**ai_status.to_payload()),
        database=database,
        auth=AuthStatus(
            configured=settings.auth_configured,
            reason=settings.auth_unavailable_reason,
        ),
    )
