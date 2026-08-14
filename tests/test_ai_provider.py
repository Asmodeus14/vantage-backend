"""Tests for LLM provider behaviour.

These lock in the fixes for how v2's AI integration destroyed itself:
boot-time probing, status checks that cost API calls, and a transient 429
permanently disabling AI for the process lifetime.
"""

from __future__ import annotations

import asyncio
import types

import pytest

from app.ai.gemini import GeminiProvider
from app.ai.provider import (
    AIStatus,
    CircuitBreaker,
    NullProvider,
    ProviderState,
    get_provider,
    reset_provider,
)
from app.config import Settings
from app.errors import AIUnavailableError


def make_settings(**overrides) -> Settings:
    base = {
        "gemini_api_key": "test-key",
        "gemini_model": "gemini-2.0-flash",
        "ai_circuit_failure_threshold": 3,
        "ai_circuit_cooldown_seconds": 60.0,
        "ai_timeout_seconds": 5.0,
    }
    base.update(overrides)
    return Settings(**base)


class ApiError(Exception):
    """Stand-in for google.genai.errors.APIError, which carries a .code."""

    def __init__(self, code: int, message: str = "boom") -> None:
        super().__init__(message)
        self.code = code


def fake_client(exc: Exception | None = None, text: str = "hello"):
    """A client shaped like google.genai's, that records whether it was called."""

    calls = {"count": 0}

    async def generate_content(**kwargs):
        calls["count"] += 1
        if exc is not None:
            raise exc
        return types.SimpleNamespace(text=text)

    client = types.SimpleNamespace(
        aio=types.SimpleNamespace(models=types.SimpleNamespace(generate_content=generate_content))
    )
    return client, calls


# --------------------------------------------------------------------------
# No key configured
# --------------------------------------------------------------------------

def test_no_api_key_yields_null_provider(monkeypatch):
    reset_provider()
    provider = get_provider(Settings(gemini_api_key=None))
    assert isinstance(provider, NullProvider)

    status = provider.status()
    assert status.configured is False
    assert status.available is False
    assert status.state is ProviderState.UNCONFIGURED
    assert "GEMINI_API_KEY" in (status.reason or "")
    reset_provider()


async def test_null_provider_refuses_rather_than_fabricating():
    """It must raise, never return plausible-looking canned text."""
    provider = NullProvider()
    with pytest.raises(AIUnavailableError):
        await provider.complete("explain this")


# --------------------------------------------------------------------------
# The v2 quota-drain bugs
# --------------------------------------------------------------------------

def test_constructing_provider_performs_no_io():
    """v2 spent up to 4 API calls per boot probing model names."""
    provider = GeminiProvider(make_settings())
    assert provider._client is None, "client must not be built until first use"


def test_status_performs_no_io():
    """v2's /api/health called generate_content on every poll."""
    provider = GeminiProvider(make_settings())
    client, calls = fake_client()
    provider._client = client

    for _ in range(50):
        status = provider.status()

    assert calls["count"] == 0, "status() must never call the model"
    assert status.available is True
    assert status.state is ProviderState.READY


async def test_rate_limit_opens_circuit_immediately_and_stops_traffic():
    """A 429 must stop further requests instead of hammering a limited key."""
    provider = GeminiProvider(make_settings())
    client, calls = fake_client(exc=ApiError(429, "quota exceeded"))
    provider._client = client

    with pytest.raises(AIUnavailableError):
        await provider.complete("hi")
    assert calls["count"] == 1

    status = provider.status()
    assert status.available is False
    assert status.state is ProviderState.COOLING_DOWN
    assert "quota" in (status.reason or "").lower()
    assert status.retry_after_seconds and status.retry_after_seconds > 0

    # Subsequent calls are refused locally — no further API traffic.
    for _ in range(5):
        with pytest.raises(AIUnavailableError):
            await provider.complete("hi again")
    assert calls["count"] == 1, "circuit must prevent further provider calls"


async def test_circuit_closes_after_cooldown():
    """The v2 bug was that a 429 disabled AI until redeploy. It must recover."""
    provider = GeminiProvider(make_settings(ai_circuit_cooldown_seconds=0.05))
    failing, _ = fake_client(exc=ApiError(429))
    provider._client = failing

    with pytest.raises(AIUnavailableError):
        await provider.complete("hi")
    assert provider.status().available is False

    await asyncio.sleep(0.08)

    working, calls = fake_client(text="recovered")
    provider._client = working
    assert provider.status().available is True
    assert await provider.complete("hi") == "recovered"
    assert calls["count"] == 1


async def test_transient_errors_require_threshold_before_opening():
    """One flaky 500 shouldn't disable AI; three consecutive ones should."""
    provider = GeminiProvider(make_settings(ai_circuit_failure_threshold=3))
    client, _ = fake_client(exc=ApiError(500))
    provider._client = client

    for _ in range(2):
        with pytest.raises(AIUnavailableError):
            await provider.complete("hi")
        assert provider.status().available is True, "should still be trying"

    with pytest.raises(AIUnavailableError):
        await provider.complete("hi")
    assert provider.status().available is False


async def test_success_resets_failure_count():
    provider = GeminiProvider(make_settings(ai_circuit_failure_threshold=3))
    provider._client, _ = fake_client(exc=ApiError(500))
    with pytest.raises(AIUnavailableError):
        await provider.complete("hi")

    provider._client, _ = fake_client(text="ok")
    assert await provider.complete("hi") == "ok"

    # Two more transient failures must not open the circuit, because the
    # success reset the counter.
    provider._client, _ = fake_client(exc=ApiError(500))
    for _ in range(2):
        with pytest.raises(AIUnavailableError):
            await provider.complete("hi")
    assert provider.status().available is True


@pytest.mark.parametrize(
    "code,expected_fragment",
    [
        (429, "quota"),
        (403, "rejected"),
        (401, "rejected"),
        (404, "not available"),
    ],
)
async def test_error_reasons_are_actionable(code: int, expected_fragment: str):
    """The UI shows these strings, so they must explain what to actually do."""
    provider = GeminiProvider(make_settings())
    provider._client, _ = fake_client(exc=ApiError(code))

    with pytest.raises(AIUnavailableError):
        await provider.complete("hi")

    assert expected_fragment in (provider.status().reason or "").lower()


async def test_timeout_is_reported_as_such():
    provider = GeminiProvider(make_settings(ai_timeout_seconds=0.05))

    async def slow(**kwargs):
        await asyncio.sleep(1.0)

    provider._client = types.SimpleNamespace(
        aio=types.SimpleNamespace(models=types.SimpleNamespace(generate_content=slow))
    )

    with pytest.raises(AIUnavailableError) as exc:
        await provider.complete("hi")
    assert "timed out" in str(exc.value).lower()


# --------------------------------------------------------------------------
# Circuit breaker unit behaviour
# --------------------------------------------------------------------------

def test_circuit_breaker_opens_and_self_closes():
    breaker = CircuitBreaker(failure_threshold=2, cooldown_seconds=0.05)
    assert breaker.is_open is False

    breaker.record_failure("one")
    assert breaker.is_open is False

    breaker.record_failure("two")
    assert breaker.is_open is True
    assert breaker.retry_after_seconds is not None

    import time as _time

    _time.sleep(0.07)
    assert breaker.is_open is False, "must self-heal after the cooldown"


def test_ai_status_payload_is_json_safe():
    payload = AIStatus(
        configured=True,
        available=False,
        state=ProviderState.COOLING_DOWN,
        model="gemini-2.0-flash",
        reason="quota",
        retry_after_seconds=12.3456,
    ).to_payload()

    assert payload["state"] == "cooling_down"
    assert payload["retry_after_seconds"] == 12.3
    assert set(payload) == {
        "configured",
        "available",
        "state",
        "model",
        "reason",
        "retry_after_seconds",
    }


# --------------------------------------------------------------------------
# Model routing
#
# Measured on the real prompts: flash-lite answers in ~1.5s where 3.6-flash
# took 5-42s, and in one testing session 3.6-flash returned 503 twice and timed
# out three times while flash-lite never failed. Routing exists because a 503
# is a statement about one model's capacity, not about the request.
# --------------------------------------------------------------------------

def routing_settings(**overrides) -> Settings:
    return make_settings(
        gemini_model="primary-model",
        gemini_fallback_models="fallback-model",
        **overrides,
    )


def routing_client(behaviour: dict[str, object]):
    """Client whose response depends on which model was asked, recording order."""

    calls: list[str] = []

    async def generate_content(*, model, **kwargs):
        calls.append(model)
        outcome = behaviour[model]
        if isinstance(outcome, Exception):
            raise outcome
        return types.SimpleNamespace(text=outcome)

    client = types.SimpleNamespace(
        aio=types.SimpleNamespace(
            models=types.SimpleNamespace(generate_content=generate_content)
        )
    )
    return client, calls


def streaming_client(behaviour: dict[str, object]):
    calls: list[str] = []

    async def generate_content_stream(*, model, **kwargs):
        calls.append(model)

        async def chunks():
            for item in behaviour[model]:
                if isinstance(item, Exception):
                    raise item
                yield types.SimpleNamespace(text=item)

        return chunks()

    client = types.SimpleNamespace(
        aio=types.SimpleNamespace(
            models=types.SimpleNamespace(generate_content_stream=generate_content_stream)
        )
    )
    return client, calls


async def test_transient_failure_routes_to_the_next_model():
    """A 503 on the primary is exactly what the fallback is for."""
    provider = GeminiProvider(routing_settings())
    provider._client, calls = routing_client(
        {"primary-model": ApiError(503), "fallback-model": "answered anyway"}
    )

    assert await provider.complete("hi") == "answered anyway"
    assert calls == ["primary-model", "fallback-model"]


async def test_one_model_failing_does_not_count_against_the_breaker():
    """Otherwise a flaky primary opens the circuit on a chain that still serves."""
    provider = GeminiProvider(routing_settings(ai_circuit_failure_threshold=2))
    provider._client, _ = routing_client(
        {"primary-model": ApiError(503), "fallback-model": "fine"}
    )

    for _ in range(5):
        assert await provider.complete("hi") == "fine"

    assert provider.status().available is True


async def test_fatal_failure_does_not_spend_a_fallback_request():
    """A rejected key fails identically on every model — retrying wastes quota."""
    provider = GeminiProvider(routing_settings())
    provider._client, calls = routing_client(
        {"primary-model": ApiError(429), "fallback-model": "unused"}
    )

    with pytest.raises(AIUnavailableError):
        await provider.complete("hi")

    assert calls == ["primary-model"]
    assert "quota" in (provider.status().reason or "").lower()


async def test_unreachable_model_is_skipped_on_subsequent_calls():
    """A 404 is permanent for that model; re-probing it costs a request per call."""
    provider = GeminiProvider(routing_settings())
    provider._client, calls = routing_client(
        {"primary-model": ApiError(404), "fallback-model": "served"}
    )

    assert await provider.complete("one") == "served"
    assert await provider.complete("two") == "served"

    assert calls == ["primary-model", "fallback-model", "fallback-model"]


async def test_every_model_unreachable_latches():
    """Nothing left to route to is a configuration error, and will not self-heal."""
    provider = GeminiProvider(routing_settings())
    provider._client, _ = routing_client(
        {"primary-model": ApiError(404), "fallback-model": ApiError(404)}
    )

    with pytest.raises(AIUnavailableError):
        await provider.complete("hi")

    status = provider.status()
    assert status.available is False
    assert "not available" in (status.reason or "").lower()


async def test_chain_exhaustion_counts_once_not_once_per_model():
    provider = GeminiProvider(routing_settings(ai_circuit_failure_threshold=2))
    provider._client, _ = routing_client(
        {"primary-model": ApiError(503), "fallback-model": ApiError(503)}
    )

    with pytest.raises(AIUnavailableError):
        await provider.complete("hi")
    # One exhausted chain is one failure, so the breaker is not yet open.
    assert provider.status().available is True

    with pytest.raises(AIUnavailableError):
        await provider.complete("hi")
    assert provider.status().available is False


async def test_upstream_outage_reason_tells_the_user_to_retry():
    provider = GeminiProvider(routing_settings())
    provider._client, _ = routing_client(
        {"primary-model": ApiError(503), "fallback-model": ApiError(503)}
    )

    with pytest.raises(AIUnavailableError) as exc:
        await provider.complete("hi")

    assert "try again" in (exc.value.detail or "").lower()


def test_primary_timeout_never_exceeds_the_configured_ceiling():
    """Lowering ai_timeout_seconds must tighten every attempt, including the first."""
    provider = GeminiProvider(routing_settings(ai_timeout_seconds=0.05))
    assert provider._attempts()[0].timeout == 0.05


def test_primary_fails_faster_than_the_fallback_by_default():
    """Asserted against the shipped defaults, not the helper's tighter override.

    ``_env_file=None`` because a developer's local .env sets GEMINI_MODEL, and
    this test is about what the defaults ship as.
    """
    provider = GeminiProvider(Settings(gemini_api_key="test-key", _env_file=None))
    primary, fallback = provider._attempts()
    assert primary.timeout < fallback.timeout


def test_model_chain_dedupes_and_ignores_blanks():
    settings = make_settings(
        gemini_model="a", gemini_fallback_models=" b , , a ,c "
    )
    assert settings.model_chain == ("a", "b", "c")


async def test_stream_routes_before_any_text_is_emitted():
    provider = GeminiProvider(routing_settings())
    provider._client, calls = streaming_client(
        {"primary-model": [ApiError(503)], "fallback-model": ["he", "llo"]}
    )

    chunks = [chunk async for chunk in provider.stream("hi")]

    assert "".join(chunks) == "hello"
    assert calls == ["primary-model", "fallback-model"]


async def test_stream_does_not_restart_after_emitting_text():
    """Restarting mid-stream would splice two different answers together."""
    provider = GeminiProvider(routing_settings())
    provider._client, calls = streaming_client(
        {
            "primary-model": ["partial answer", ApiError(503)],
            "fallback-model": ["a different answer"],
        }
    )

    received: list[str] = []
    with pytest.raises(AIUnavailableError):
        async for chunk in provider.stream("hi"):
            received.append(chunk)

    assert received == ["partial answer"]
    assert calls == ["primary-model"]
