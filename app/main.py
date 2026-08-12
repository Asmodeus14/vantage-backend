"""FastAPI application entry point.

Startup does no network I/O: no model probing, no eager database connection.
The service must boot fast and degrade honestly, because both the AI provider
and the database are optional.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi.errors import RateLimitExceeded

from app import __version__
from app.config import get_settings
from app.db import create_tables, dispose_engine
from app.errors import VantageError
from app.limiter import limiter
from app.routers import ai, analyze, auth, health, reports

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    logging.basicConfig(
        level=getattr(logging, settings.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
    )
    logger.info(
        "Vantage %s starting (env=%s, ai=%s, db=%s)",
        __version__,
        settings.environment,
        "configured" if settings.ai_configured else "absent",
        "configured" if settings.db_configured else "in-memory",
    )

    if settings.db_configured:
        try:
            await create_tables()
        except Exception:
            # A database that is unreachable at boot must not stop the service;
            # analysis still works and /api/health reports the degradation.
            logger.exception("Could not prepare database schema")

    yield
    await dispose_engine()


def create_app() -> FastAPI:
    settings = get_settings()

    app = FastAPI(
        title="Vantage API",
        version=__version__,
        description=(
            "Static analysis for repositories. Point it at a GitHub URL or "
            "upload an archive and it returns line-anchored findings, a scored "
            "summary, and optional AI explanations."
        ),
        lifespan=lifespan,
    )

    app.state.limiter = limiter

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origin_list,
        allow_credentials=False,
        allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
        allow_headers=["Content-Type", "Authorization"],
    )

    # Domain errors carry their own status and a stable machine-readable code,
    # so the client can branch on failures without matching on prose.
    @app.exception_handler(VantageError)
    async def _domain_error(request: Request, exc: VantageError) -> JSONResponse:
        return JSONResponse(status_code=exc.status_code, content=exc.to_payload())

    @app.exception_handler(RateLimitExceeded)
    async def _rate_limited(request: Request, exc: RateLimitExceeded) -> JSONResponse:
        return JSONResponse(
            status_code=429,
            content={
                "code": "rate_limited",
                "message": "Too many requests.",
                "detail": f"Limit: {exc.detail}. Please retry shortly.",
            },
        )

    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception) -> JSONResponse:
        # Never leak internals to the client; log the detail server-side.
        logger.exception("Unhandled error on %s %s", request.method, request.url.path)
        return JSONResponse(
            status_code=500,
            content={
                "code": "internal_error",
                "message": "An unexpected error occurred.",
            },
        )

    app.include_router(health.router)
    app.include_router(auth.router)
    app.include_router(analyze.router)
    app.include_router(reports.router)
    app.include_router(ai.router)

    @app.get("/", tags=["meta"])
    async def root() -> dict[str, object]:
        return {
            "service": "vantage",
            "version": __version__,
            "docs": "/docs",
            "health": "/api/health",
        }

    return app


app = create_app()
