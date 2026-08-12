"""Gemini provider built on the current ``google-genai`` SDK.

v2 used ``google-generativeai==0.3.0`` (December 2023), which cannot reach any
currently-served model: ``gemini-1.5-flash``, ``gemini-1.5-pro`` and
``gemini-pro`` all return 404 from that client. This uses the unified
``google.genai`` client instead, and talks to it asynchronously so a slow
completion doesn't block the event loop.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, AsyncIterator

from app.ai.provider import AIStatus, CircuitBreaker, ProviderState
from app.config import Settings
from app.errors import AIUnavailableError

logger = logging.getLogger(__name__)

# Status codes that mean "stop sending traffic immediately" rather than
# "this one request failed".
_QUOTA_CODES = {429}
_AUTH_CODES = {401, 403}


class GeminiProvider:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._model = settings.gemini_model
        self._client: Any | None = None
        self._breaker = CircuitBreaker(
            failure_threshold=settings.ai_circuit_failure_threshold,
            cooldown_seconds=settings.ai_circuit_cooldown_seconds,
        )
        self._fatal_reason: str | None = None

    # -- client construction is deferred until the first real call -----------

    def _get_client(self) -> Any:
        if self._client is None:
            from google import genai

            self._client = genai.Client(api_key=self._settings.gemini_api_key)
        return self._client

    # -- status is purely local; it never performs I/O -----------------------

    def status(self) -> AIStatus:
        if self._fatal_reason is not None:
            return AIStatus(
                configured=True,
                available=False,
                state=ProviderState.COOLING_DOWN,
                model=self._model,
                reason=self._fatal_reason,
            )
        if self._breaker.is_open:
            return AIStatus(
                configured=True,
                available=False,
                state=ProviderState.COOLING_DOWN,
                model=self._model,
                reason=self._breaker.last_reason
                or "Provider temporarily unavailable after repeated failures.",
                retry_after_seconds=self._breaker.retry_after_seconds,
            )
        return AIStatus(
            configured=True,
            available=True,
            state=ProviderState.READY,
            model=self._model,
        )

    def _guard(self) -> None:
        status = self.status()
        if not status.available:
            raise AIUnavailableError(
                "AI features are temporarily unavailable",
                detail=status.reason,
            )

    def _classify(self, exc: Exception) -> tuple[str, bool]:
        """Map a provider exception to (reason, trip_circuit_immediately)."""
        code = getattr(exc, "code", None)
        if not isinstance(code, int):
            code = getattr(getattr(exc, "response", None), "status_code", None)

        if code in _QUOTA_CODES:
            return (
                "Gemini API quota exceeded or rate limited. "
                "AI actions resume automatically once the limit resets.",
                True,
            )
        if code in _AUTH_CODES:
            return ("The configured GEMINI_API_KEY was rejected by Google.", True)
        if code == 404:
            return (
                f"Model '{self._model}' is not available to this API key.",
                True,
            )
        return (f"Gemini request failed: {type(exc).__name__}", False)

    def _record_failure(self, exc: Exception) -> None:
        reason, trip = self._classify(exc)
        if trip:
            self._breaker.trip_now(reason)
        else:
            self._breaker.record_failure(reason)
        logger.warning("Gemini call failed: %s", reason)

    def _contents(self, prompt: str, system: str | None) -> str:
        return f"{system}\n\n{prompt}" if system else prompt

    # -- calls ---------------------------------------------------------------

    async def complete(self, prompt: str, *, system: str | None = None) -> str:
        self._guard()
        client = self._get_client()
        try:
            response = await asyncio.wait_for(
                client.aio.models.generate_content(
                    model=self._model,
                    contents=self._contents(prompt, system),
                ),
                timeout=self._settings.ai_timeout_seconds,
            )
        except asyncio.TimeoutError as exc:
            self._breaker.record_failure(
                f"Gemini did not respond within {self._settings.ai_timeout_seconds:.0f}s."
            )
            raise AIUnavailableError(
                "The AI provider timed out",
                detail=f"No response within {self._settings.ai_timeout_seconds:.0f} seconds.",
            ) from exc
        except Exception as exc:
            self._record_failure(exc)
            status = self.status()
            raise AIUnavailableError(
                "The AI provider returned an error",
                detail=status.reason,
            ) from exc

        self._breaker.record_success()
        return (getattr(response, "text", None) or "").strip()

    async def stream(
        self, prompt: str, *, system: str | None = None
    ) -> AsyncIterator[str]:
        self._guard()
        client = self._get_client()
        try:
            iterator = await client.aio.models.generate_content_stream(
                model=self._model,
                contents=self._contents(prompt, system),
            )
            async for chunk in iterator:
                text = getattr(chunk, "text", None)
                if text:
                    yield text
        except Exception as exc:
            self._record_failure(exc)
            status = self.status()
            raise AIUnavailableError(
                "The AI provider returned an error",
                detail=status.reason,
            ) from exc

        self._breaker.record_success()
