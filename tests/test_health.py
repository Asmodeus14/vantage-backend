"""Tests for the health endpoint.

The headline regression: v2's ``/api/health`` called ``generate_content("Test")``
on every request, and the frontend polled it. That is what exhausted the Gemini
quota and left the AI feature permanently disabled.
"""

from __future__ import annotations

import types

import pytest
from fastapi.testclient import TestClient

from app.ai.provider import AIStatus, ProviderState, provider_dependency
from app.config import Settings, get_settings
from app.main import app
from app.routers import health as health_module


class SpyProvider:
    """Records any attempt to reach the model."""

    def __init__(self) -> None:
        self.model_calls = 0
        self.status_calls = 0

    def status(self) -> AIStatus:
        self.status_calls += 1
        return AIStatus(
            configured=True,
            available=True,
            state=ProviderState.READY,
            model="test-model",
        )

    async def complete(self, prompt: str, *, system: str | None = None) -> str:
        self.model_calls += 1
        return "should not happen"

    async def stream(self, prompt: str, *, system: str | None = None):
        self.model_calls += 1
        yield ""


@pytest.fixture
def spy(monkeypatch):
    provider = SpyProvider()
    app.dependency_overrides[provider_dependency] = lambda: provider
    app.dependency_overrides[get_settings] = lambda: Settings(
        gemini_api_key="test", database_url=None
    )
    # Avoid a real network round-trip to Neon in unit tests.
    async def fake_probe():
        return True, None

    monkeypatch.setattr(health_module, "probe_database", fake_probe)
    health_module._db_cache = None
    yield provider
    app.dependency_overrides.clear()
    health_module._db_cache = None


def test_health_returns_ok(spy):
    with TestClient(app) as client:
        response = client.get("/api/health")

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["version"]
    assert body["ai"]["available"] is True
    assert body["ai"]["model"] == "test-model"


def test_health_never_calls_the_model(spy):
    """The core v2 regression: polling health must cost zero API calls."""
    with TestClient(app) as client:
        for _ in range(25):
            assert client.get("/api/health").status_code == 200

    assert spy.model_calls == 0, "health must not generate content"
    assert spy.status_calls >= 25, "it should still report provider status"


def test_health_reports_unconfigured_ai_without_failing(monkeypatch):
    """No API key is a normal state, not an outage."""
    from app.ai.provider import NullProvider

    app.dependency_overrides[provider_dependency] = lambda: NullProvider()
    app.dependency_overrides[get_settings] = lambda: Settings(
        gemini_api_key=None, database_url=None
    )
    health_module._db_cache = None
    try:
        with TestClient(app) as client:
            response = client.get("/api/health")

        assert response.status_code == 200
        body = response.json()
        assert body["status"] == "ok", "missing AI must not mark the service down"
        assert body["ai"]["configured"] is False
        assert body["ai"]["available"] is False
        assert "GEMINI_API_KEY" in body["ai"]["reason"]
    finally:
        app.dependency_overrides.clear()
        health_module._db_cache = None


def test_health_explains_missing_database(monkeypatch):
    app.dependency_overrides[get_settings] = lambda: Settings(database_url=None)
    health_module._db_cache = None
    try:
        with TestClient(app) as client:
            body = client.get("/api/health").json()

        assert body["database"]["configured"] is False
        assert "in memory" in body["database"]["detail"]
        assert body["status"] == "ok"
    finally:
        app.dependency_overrides.clear()
        health_module._db_cache = None


def test_database_probe_is_cached(monkeypatch, spy):
    """A polling frontend must not open a connection per request."""
    calls = {"n": 0}

    async def counting_probe():
        calls["n"] += 1
        return True, None

    monkeypatch.setattr(health_module, "probe_database", counting_probe)
    app.dependency_overrides[get_settings] = lambda: Settings(
        database_url="postgresql+asyncpg://u:p@localhost/db"
    )
    health_module._db_cache = None

    with TestClient(app) as client:
        for _ in range(20):
            client.get("/api/health")

    assert calls["n"] == 1, "probe result should be cached within its TTL"


def test_root_endpoint_lists_entry_points():
    with TestClient(app) as client:
        body = client.get("/").json()
    assert body["service"] == "vantage"
    assert body["health"] == "/api/health"


def test_openapi_schema_is_served():
    """/docs is part of the deliverable, so the schema must build."""
    with TestClient(app) as client:
        response = client.get("/openapi.json")
    assert response.status_code == 200
    assert "/api/health" in response.json()["paths"]


def test_request_bodies_are_not_embedded():
    """Regression: a dependency with a Pydantic-typed parameter made FastAPI
    treat it as body content, wrapping the real body under an extra key so
    every POST failed with "field required: body.body".
    """
    with TestClient(app) as client:
        schema = client.get("/openapi.json").json()

    ai_path = "/api/reports/{report_id}/findings/{finding_id}/ai"
    ref = schema["paths"][ai_path]["post"]["requestBody"]["content"][
        "application/json"
    ]["schema"]["$ref"]

    assert ref.endswith("/AIActionRequest"), (
        f"body should be AIActionRequest directly, got {ref}"
    )

    repo_ref = schema["paths"]["/api/analyze/repository"]["post"]["requestBody"][
        "content"
    ]["application/json"]["schema"]["$ref"]
    assert repo_ref.endswith("/AnalyzeRepositoryRequest")
