"""AI actions scoped to a single finding.

The client sends a report id, a finding id and one value from a closed enum.
It cannot supply prompt text, so this endpoint cannot be repurposed as a
general-purpose model proxy — see ``app/ai/prompts.py`` for the full threat
model.

Results are cached per (finding, action). Findings have deterministic ids
derived from rule, file, line and title, so re-opening a finding costs nothing.
"""

# NB: no `from __future__ import annotations` here. Postponed evaluation turns
# `body: AIActionRequest` into a string, which FastAPI then cannot resolve — it
# falls back to treating the parameter as a query argument and OpenAPI
# generation fails. Same reason as app/routers/analyze.py.

import logging
from collections import OrderedDict
from typing import Optional

from fastapi import APIRouter, Depends, Request

from app.ai.prompts import (
    AIAction,
    CodeContext,
    OutputRejected,
    build_prompt,
    validate_output,
)
from app.ai.provider import LLMProvider, provider_dependency
from app.config import Settings, get_settings
from app.errors import AIUnavailableError, VantageError, ReportNotFoundError
from app.limiter import limiter
from app.schemas import AIActionRequest, AIActionResponse, Finding
from app.store import get_store

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/reports", tags=["ai"])

_CACHE_CAPACITY = 256
_cache: OrderedDict[tuple[str, str], AIActionResponse] = OrderedDict()


class InvalidActionTarget(VantageError):
    status_code = 404
    code = "finding_not_found"


def _cache_get(key: tuple[str, str]) -> Optional[AIActionResponse]:
    response = _cache.get(key)
    if response is not None:
        _cache.move_to_end(key)
    return response


def _cache_put(key: tuple[str, str], value: AIActionResponse) -> None:
    _cache[key] = value
    _cache.move_to_end(key)
    while len(_cache) > _CACHE_CAPACITY:
        _cache.popitem(last=False)


def _language_of(path: str | None) -> str | None:
    if not path:
        return None
    from app.ingest.filter import detect_language
    from pathlib import PurePosixPath

    return detect_language(PurePosixPath(path))


def _context_for(finding: Finding, repository: str) -> CodeContext:
    return CodeContext(
        repository=repository,
        file_path=finding.file or "(project-wide)",
        language=_language_of(finding.file),
        start_line=finding.snippet_start_line or finding.line or 1,
        end_line=finding.end_line or finding.line or 1,
        code=finding.snippet or "(no source captured for this finding)",
        finding_title=finding.title,
        finding_description=finding.description,
        finding_severity=finding.severity.value,
        rule_id=finding.rule_id,
    )


def _describe_context(finding: Finding, repository: str) -> str:
    """Shown in the UI so the user knows exactly what the model was given."""
    if finding.file and finding.line:
        span = (
            f"lines {finding.snippet_start_line or finding.line}–"
            f"{finding.end_line or finding.line}"
        )
        return f"{repository} · {finding.file} · {span}"
    return f"{repository} · project-wide finding"


@router.post(
    "/{report_id}/findings/{finding_id}/ai",
    response_model=AIActionResponse,
)
@limiter.limit("30/hour")
async def run_ai_action(
    request: Request,
    report_id: str,
    finding_id: str,
    body: AIActionRequest,
    settings: Settings = Depends(get_settings),
    provider: LLMProvider = Depends(provider_dependency),
) -> AIActionResponse:
    status = provider.status()
    if not status.available:
        raise AIUnavailableError(
            "AI actions are unavailable",
            detail=status.reason,
        )

    try:
        report = await get_store().get(report_id)
    except ReportNotFoundError:
        raise

    finding = next((f for f in report.findings if f.id == finding_id), None)
    if finding is None:
        raise InvalidActionTarget(
            "That finding is not part of this report.",
            detail="The report may have been regenerated since the page loaded.",
        )

    cache_key = (finding_id, body.action)
    cached = _cache_get(cache_key)
    if cached is not None:
        return cached.model_copy(update={"cached": True})

    repository = (
        report.source.repository or report.source.filename or "uploaded archive"
    )
    action = AIAction(body.action)
    built = build_prompt(action, _context_for(finding, repository))

    raw = await provider.complete(built.user, system=built.system)

    try:
        output = validate_output(action, raw, sentinel=built.sentinel)
    except OutputRejected as exc:
        # The model broke format — possibly because the analysed source tried to
        # redirect it. Report the refusal rather than passing it through.
        logger.warning("Rejected model output for %s/%s: %s", finding_id, body.action, exc)
        raise AIUnavailableError(
            "The model returned an unusable response",
            detail=f"{exc} The response was discarded rather than shown.",
        ) from exc

    response = AIActionResponse(
        action=body.action,
        output=output,
        model=status.model,
        context=_describe_context(finding, repository),
        cached=False,
    )
    _cache_put(cache_key, response)
    return response
