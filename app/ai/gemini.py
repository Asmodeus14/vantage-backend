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
from collections.abc import AsyncIterator
from dataclasses import dataclass
from enum import Enum
from typing import Any

from app.ai.provider import AIStatus, CircuitBreaker, ProviderState
from app.config import Settings
from app.errors import AIUnavailableError

logger = logging.getLogger(__name__)

# Status codes that mean "stop sending traffic immediately" rather than
# "this one request failed".
_QUOTA_CODES = {429}
_AUTH_CODES = {401, 403}
# Google's own faults. Transient by definition, and the reason routing exists:
# a 503 is a statement about one model's capacity, not about the request.
_UPSTREAM_CODES = {500, 502, 503, 504}


class _Failure(str, Enum):
    """How far a failure generalises — which decides whether to try the next model."""

    FATAL = "fatal"
    """Key-level. Every model would fail identically, so do not spend a retry."""

    MODEL = "model"
    """This model is unusable to this key. Others may still work."""

    TRANSIENT = "transient"
    """This attempt failed. The next model is worth trying."""


@dataclass(frozen=True)
class _Attempt:
    model: str
    timeout: float


class GeminiProvider:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._model = settings.gemini_model
        self._chain = settings.model_chain
        self._client: Any | None = None
        self._config: Any | None = None
        self._breaker = CircuitBreaker(
            failure_threshold=settings.ai_circuit_failure_threshold,
            cooldown_seconds=settings.ai_circuit_cooldown_seconds,
        )
        self._fatal_reason: str | None = None
        # Models this key cannot reach (404). Remembered so a misconfigured
        # entry in the chain costs one request per process, not one per call.
        self._unreachable: set[str] = set()
        if len(self._chain) == 1 and settings.gemini_fallback_models.strip():
            # Pinning GEMINI_MODEL to the same value as the only fallback
            # de-duplicates down to a single entry, which disables routing
            # entirely. Silently losing redundancy is worth one line of log.
            logger.warning(
                "Gemini fallback is disabled: GEMINI_MODEL (%s) is also the only "
                "configured fallback, so there is nothing to route to.",
                self._model,
            )

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

    def _classify(self, exc: Exception, model: str) -> tuple[_Failure, str]:
        """Map a provider exception to (how far it generalises, user-facing reason)."""
        code = getattr(exc, "code", None)
        if not isinstance(code, int):
            code = getattr(getattr(exc, "response", None), "status_code", None)

        if code in _QUOTA_CODES:
            return (
                _Failure.FATAL,
                "Gemini API quota exceeded or rate limited. "
                "AI actions resume automatically once the limit resets.",
            )
        if code in _AUTH_CODES:
            return (
                _Failure.FATAL,
                "The configured GEMINI_API_KEY was rejected by Google.",
            )
        if code == 404:
            return (
                _Failure.MODEL,
                f"Model '{model}' is not available to this API key.",
            )
        if code in _UPSTREAM_CODES:
            return (
                _Failure.TRANSIENT,
                "Google's Gemini API is temporarily unavailable. "
                "This is an outage on their side — try again in a moment.",
            )
        return (_Failure.TRANSIENT, f"Gemini request failed: {type(exc).__name__}")

    def _contents(self, prompt: str, system: str | None) -> str:
        return f"{system}\n\n{prompt}" if system else prompt

    def _request_config(self) -> Any:
        """Disable automatic function calling.

        We declare no tools and pass a plain string prompt, so AFC does nothing
        for us — but it is on by default, warns on every single call, and leaves
        tool-invocation machinery enabled in a path that deliberately treats the
        model's input as untrusted.
        """
        if self._config is None:
            from google.genai import types

            self._config = types.GenerateContentConfig(
                automatic_function_calling=types.AutomaticFunctionCallingConfig(
                    disable=True
                ),
            )
        return self._config

    def _attempts(self) -> tuple[_Attempt, ...]:
        """The routing decision: which models to try, in order, with what patience."""
        usable = [name for name in self._chain if name not in self._unreachable]
        if not usable:
            # Every model 404'd. Try the primary anyway so the user gets the
            # real error rather than a silent empty chain.
            usable = [self._model]
        # Never exceed the configured per-attempt ceiling: lowering
        # ``ai_timeout_seconds`` has to tighten every attempt, including the
        # first, or the knob means something different depending on position.
        primary = min(
            self._settings.ai_primary_timeout_seconds,
            self._settings.ai_timeout_seconds,
        )
        return tuple(
            _Attempt(
                model=name,
                timeout=primary if index == 0 else self._settings.ai_timeout_seconds,
            )
            for index, name in enumerate(usable)
        )

    def _note_unreachable(self, model: str) -> None:
        """Record a 404, and latch if it means nothing is left to try.

        A 404 on one model is routable — that is the point of the chain. A 404
        on *every* model is a configuration error that will not heal on its own,
        so it latches rather than re-spending a request per call forever.
        """
        self._unreachable.add(model)
        if self._unreachable.issuperset(self._chain):
            raise self._fatal(
                f"Model '{model}' is not available to this API key, and no "
                f"configured fallback is either ({', '.join(self._chain)}). "
                "Check GEMINI_MODEL and GEMINI_FALLBACK_MODELS."
            )

    def _fatal(self, reason: str) -> AIUnavailableError:
        self._breaker.trip_now(reason)
        logger.warning("Gemini call failed fatally: %s", reason)
        return AIUnavailableError(
            "AI features are temporarily unavailable", detail=reason
        )

    def _exhausted(self, reason: str, *, timed_out: bool = False) -> AIUnavailableError:
        """Every model in the chain failed — only now does the breaker count it.

        A single model failing is a routing event, not a provider failure, so it
        must not count towards the breaker; otherwise a flaky primary would open
        the circuit on a chain that is still serving fine from its fallback.
        """
        self._breaker.record_failure(reason)
        logger.warning("Gemini chain exhausted (%s): %s", ", ".join(self._chain), reason)
        return AIUnavailableError(
            "The AI provider timed out"
            if timed_out
            else "The AI provider returned an error",
            detail=reason,
        )

    # -- calls ---------------------------------------------------------------

    async def complete(self, prompt: str, *, system: str | None = None) -> str:
        self._guard()
        client = self._get_client()
        contents = self._contents(prompt, system)
        reason = "The AI provider returned an error."
        timed_out = False

        for index, attempt in enumerate(self._attempts()):
            try:
                response = await asyncio.wait_for(
                    client.aio.models.generate_content(
                        model=attempt.model,
                        contents=contents,
                        config=self._request_config(),
                    ),
                    timeout=attempt.timeout,
                )
            except TimeoutError:
                reason = (
                    f"{attempt.model} did not respond within "
                    f"{attempt.timeout:.0f} seconds."
                )
                timed_out = True
                logger.warning("Gemini timed out on %s", attempt.model)
                continue
            except Exception as exc:
                timed_out = False
                kind, reason = self._classify(exc, attempt.model)
                if kind is _Failure.FATAL:
                    raise self._fatal(reason) from exc
                if kind is _Failure.MODEL:
                    self._note_unreachable(attempt.model)
                logger.warning("Gemini failed on %s: %s", attempt.model, reason)
                continue

            if index:
                logger.info(
                    "Gemini answered on fallback model %s after %s failed",
                    attempt.model,
                    self._chain[index - 1],
                )
            self._breaker.record_success()
            return (getattr(response, "text", None) or "").strip()

        raise self._exhausted(reason, timed_out=timed_out)

    async def stream(
        self, prompt: str, *, system: str | None = None
    ) -> AsyncIterator[str]:
        self._guard()
        client = self._get_client()
        contents = self._contents(prompt, system)
        reason = "The AI provider returned an error."

        for index, attempt in enumerate(self._attempts()):
            produced = False
            try:
                iterator = await client.aio.models.generate_content_stream(
                    model=attempt.model,
                    contents=contents,
                    config=self._request_config(),
                )
                async for chunk in iterator:
                    text = getattr(chunk, "text", None)
                    if text:
                        produced = True
                        yield text
            except Exception as exc:
                kind, reason = self._classify(exc, attempt.model)
                if kind is _Failure.FATAL:
                    raise self._fatal(reason) from exc
                if kind is _Failure.MODEL:
                    self._note_unreachable(attempt.model)
                logger.warning("Gemini failed on %s: %s", attempt.model, reason)
                if produced:
                    # The caller already holds part of an answer. Restarting on
                    # another model would splice two different responses
                    # together, so this one cannot be retried.
                    raise self._exhausted(reason) from exc
                continue

            if index:
                logger.info("Gemini streamed from fallback model %s", attempt.model)
            self._breaker.record_success()
            return

        raise self._exhausted(reason)
