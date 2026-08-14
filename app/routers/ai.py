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

from fastapi import APIRouter, Depends, Request

from app.ai.prompts import (
    MAX_CONTEXT_LINES,
    AIAction,
    CodeContext,
    OutputRejected,
    build_prompt,
    validate_output,
)
from app.ai.provider import LLMProvider, provider_dependency
from app.auth.dependencies import current_user
from app.auth.store import AuthenticatedUser
from app.config import Settings, get_settings
from app.errors import AIUnavailableError, ReportNotFoundError, VantageError
from app.ingest.github import GitHubCredentials
from app.limiter import limiter
from app.routers.analyze import _credentials_for
from app.schemas import AIActionRequest, AIActionResponse, Finding, Report
from app.source import SourceUnavailable, provider_for
from app.store import get_store

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/reports", tags=["ai"])

_CACHE_CAPACITY = 256
_cache: OrderedDict[tuple[str, str], AIActionResponse] = OrderedDict()


class InvalidActionTarget(VantageError):
    status_code = 404
    code = "finding_not_found"


class NoSourceForAction(VantageError):
    """Asked to write code for a finding that has none attached."""

    status_code = 422
    code = "no_source_for_action"


# Explain is deliberately absent: a dependency CVE can be explained from its
# description alone, and that is a genuinely useful answer. These two cannot —
# a diff and a test both have to be *of* something.
_NEEDS_SOURCE = frozenset({AIAction.PROPOSE_FIX, AIAction.GENERATE_TEST})

_VERB = {
    AIAction.PROPOSE_FIX: "propose a fix against",
    AIAction.GENERATE_TEST: "generate a test for",
}


def _cache_get(key: tuple[str, str]) -> AIActionResponse | None:
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
    from pathlib import PurePosixPath

    from app.ingest.filter import detect_language

    return detect_language(PurePosixPath(path))


async def _wider_source(
    report: Report,
    finding: Finding,
    settings: Settings,
    credentials: GitHubCredentials | None,
) -> tuple[str, int, int] | None:
    """A window of the real file around a finding, or ``None`` to keep the snippet.

    Findings carry ±3 lines, which is why *Propose fix* so often answered
    ``INSUFFICIENT_CONTEXT``: three lines rarely contain the imports, the
    surrounding function and the conventions a correct patch has to match.
    Now that source can be read after the fact, it is read.

    Centred on the finding rather than taken from the top of the file.
    ``clamp_context`` truncates from the start, so a window that overflowed
    would lose the very lines the finding points at.

    Best-effort by design: a rate-limited GitHub or a deleted repository must
    degrade to the snippet, not fail the action.
    """
    if not finding.file or not finding.line:
        return None

    try:
        provider = provider_for(report, settings, credentials)
        text = await provider.read(finding.file)
    except SourceUnavailable as exc:
        logger.info("Wider context unavailable for %s: %s", finding.id, exc.reason)
        return None
    except Exception:
        logger.exception("Could not widen context for %s", finding.id)
        return None

    lines = text.split("\n")
    if not lines:
        return None

    start = max(1, finding.line)
    end = max(start, finding.end_line or start)
    span = end - start + 1

    if span >= MAX_CONTEXT_LINES:
        first = start
    else:
        # Centre the finding in the window, then clamp to the file's bounds.
        pad = (MAX_CONTEXT_LINES - span) // 2
        first = max(1, start - pad)
    last = min(len(lines), first + MAX_CONTEXT_LINES - 1)
    first = max(1, min(first, last))

    return "\n".join(lines[first - 1 : last]), first, last


def _context_for(
    finding: Finding, repository: str, wider: tuple[str, int, int] | None
) -> CodeContext:
    if wider is not None:
        code, first, last = wider
    else:
        code = finding.snippet or "(no source captured for this finding)"
        first = finding.snippet_start_line or finding.line or 1
        last = finding.end_line or finding.line or 1

    return CodeContext(
        repository=repository,
        file_path=finding.file or "(project-wide)",
        language=_language_of(finding.file),
        start_line=first,
        end_line=last,
        code=code,
        finding_title=finding.title,
        finding_description=finding.description,
        finding_severity=finding.severity.value,
        rule_id=finding.rule_id,
    )


def _describe_context(
    finding: Finding, repository: str, wider: tuple[str, int, int] | None
) -> str:
    """Shown in the UI so the user knows exactly what the model was given.

    It has to reflect what was *actually* sent, including whether the wider
    read succeeded — otherwise it claims context the model never saw.
    """
    if wider is not None:
        _, first, last = wider
        return f"{repository} · {finding.file} · lines {first}–{last}"
    if finding.file and finding.line:
        span = (
            f"lines {finding.snippet_start_line or finding.line}–"
            f"{finding.end_line or finding.line}"
        )
        return f"{repository} · {finding.file} · {span} (snippet only)"
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
    user: AuthenticatedUser | None = Depends(current_user),
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
    wider = await _wider_source(
        report, finding, settings, _credentials_for(user, settings)
    )
    action = AIAction(body.action)
    if action in _NEEDS_SOURCE and wider is None and not finding.snippet:
        # Nothing to work from: _context_for would substitute a placeholder and
        # the model would spend a real request telling us so. Dependency and
        # project-wide findings are not anchored to a line, and a repository
        # that can no longer be read degrades to the same place.
        raise NoSourceForAction(
            f"There is no source attached to this finding to {_VERB[action]}.",
            detail=(
                "This finding is not anchored to a file, so there is no code to "
                "work from. Try Explain, which does not need the source."
                if not finding.file
                else f"{finding.file} could not be read from the repository, and "
                "no snippet was captured when the report was generated."
            ),
        )
    built = build_prompt(action, _context_for(finding, repository, wider))

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
        context=_describe_context(finding, repository, wider),
        cached=False,
    )
    _cache_put(cache_key, response)
    return response
