"""LLM provider interface, circuit breaker, and no-op implementation.

Design constraints, all of them reactions to how v2 failed:

* **No network calls at import or startup.** v2 probed four model names with a
  live ``generate_content`` call at module import, spending up to four requests
  per process boot before serving anything.
* **Status is local.** ``status()`` must never make a request. v2's ``/api/health``
  called the model on every poll, and the frontend polled it — which is what
  actually exhausted the quota.
* **Failures must not latch permanently.** v2 swallowed a startup 429 and set
  ``LLM_ENABLED = False`` for the life of the process, so a momentary rate limit
  disabled AI until redeploy. Here a circuit breaker opens for a cooldown and
  then closes again on its own.
* **Absence is a first-class state, not an error.** With no API key the service
  is fully functional; only AI-specific actions are unavailable, and they say so.
"""

from __future__ import annotations

import time
from collections.abc import AsyncIterator
from dataclasses import dataclass
from enum import Enum
from typing import Protocol, runtime_checkable

from app.config import Settings, get_settings
from app.errors import AIUnavailableError


class ProviderState(str, Enum):
    UNCONFIGURED = "unconfigured"
    READY = "ready"
    COOLING_DOWN = "cooling_down"


@dataclass(frozen=True)
class AIStatus:
    """Everything the UI needs to explain the AI state to a user."""

    configured: bool
    available: bool
    state: ProviderState
    model: str | None = None
    reason: str | None = None
    retry_after_seconds: float | None = None

    def to_payload(self) -> dict[str, object]:
        return {
            "configured": self.configured,
            "available": self.available,
            "state": self.state.value,
            "model": self.model,
            "reason": self.reason,
            "retry_after_seconds": (
                round(self.retry_after_seconds, 1)
                if self.retry_after_seconds is not None
                else None
            ),
        }


class CircuitBreaker:
    """Opens after N consecutive failures; closes itself after a cooldown."""

    def __init__(self, *, failure_threshold: int, cooldown_seconds: float) -> None:
        self._threshold = max(1, failure_threshold)
        self._cooldown = cooldown_seconds
        self._consecutive_failures = 0
        self._opened_at: float | None = None
        self._last_reason: str | None = None

    @property
    def is_open(self) -> bool:
        if self._opened_at is None:
            return False
        if (time.monotonic() - self._opened_at) >= self._cooldown:
            # Cooldown elapsed — allow traffic through again.
            self._opened_at = None
            self._consecutive_failures = 0
            return False
        return True

    @property
    def retry_after_seconds(self) -> float | None:
        if self._opened_at is None:
            return None
        return max(0.0, self._cooldown - (time.monotonic() - self._opened_at))

    @property
    def last_reason(self) -> str | None:
        return self._last_reason

    def record_success(self) -> None:
        self._consecutive_failures = 0
        self._opened_at = None
        self._last_reason = None

    def record_failure(self, reason: str) -> None:
        self._consecutive_failures += 1
        self._last_reason = reason
        if self._consecutive_failures >= self._threshold:
            self._opened_at = time.monotonic()

    def trip_now(self, reason: str) -> None:
        """Open immediately — used for an explicit quota/rate-limit signal."""
        self._consecutive_failures = self._threshold
        self._last_reason = reason
        self._opened_at = time.monotonic()


@runtime_checkable
class LLMProvider(Protocol):
    def status(self) -> AIStatus:
        """Local, synchronous, never performs I/O."""
        ...

    async def complete(self, prompt: str, *, system: str | None = None) -> str: ...

    def stream(
        self, prompt: str, *, system: str | None = None
    ) -> AsyncIterator[str]: ...


class NullProvider:
    """Used when no API key is configured.

    Raises a typed error rather than returning canned text — the product must
    never present fabricated output as a model response.
    """

    def status(self) -> AIStatus:
        return AIStatus(
            configured=False,
            available=False,
            state=ProviderState.UNCONFIGURED,
            reason="No GEMINI_API_KEY is configured on the server.",
        )

    async def complete(self, prompt: str, *, system: str | None = None) -> str:
        raise AIUnavailableError(
            "AI features are not configured",
            detail="Set GEMINI_API_KEY on the server to enable AI actions.",
        )

    async def stream(
        self, prompt: str, *, system: str | None = None
    ) -> AsyncIterator[str]:
        raise AIUnavailableError(
            "AI features are not configured",
            detail="Set GEMINI_API_KEY on the server to enable AI actions.",
        )
        yield ""  # pragma: no cover - unreachable, satisfies async-generator typing


_provider: LLMProvider | None = None


def get_provider(settings: Settings | None = None) -> LLMProvider:
    """Return the process-wide provider, constructing it lazily.

    Constructing a provider performs no I/O; the underlying client is built on
    first use.
    """
    global _provider
    if _provider is not None:
        return _provider

    settings = settings or get_settings()
    if not settings.ai_configured:
        _provider = NullProvider()
    else:
        from app.ai.gemini import GeminiProvider

        _provider = GeminiProvider(settings)
    return _provider


def provider_dependency() -> LLMProvider:
    """FastAPI dependency wrapper for :func:`get_provider`.

    Deliberately takes no arguments. FastAPI inspects a dependency's signature
    and treats any Pydantic-model-typed parameter that lacks its own ``Depends``
    as a **request body field** — so injecting ``get_provider`` directly made
    its ``settings: Settings | None`` argument look like body content, which
    forced FastAPI to embed the real body under a wrapper key and broke every
    request with "field required: body.body".
    """
    return get_provider()


def reset_provider() -> None:
    """Test hook — drops the cached provider."""
    global _provider
    _provider = None
