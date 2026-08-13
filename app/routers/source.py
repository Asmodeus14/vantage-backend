"""Browsing the source a report was produced from.

Findings record `file` and `line`, and until now that was a coordinate with
nothing behind it. These two endpoints are what turn "line 47" into "here is
line 47, in context, with the finding marked".

Read access follows the report: anyone holding the id may read it, because the
id is an unguessable capability and that is what makes a report shareable. The
source is no more sensitive than the findings already quoted from it.
"""

from __future__ import annotations

from collections import Counter
from pathlib import PurePosixPath

from fastapi import APIRouter, Depends, Query

from app.auth.dependencies import NotAuthorised, current_user
from app.auth.store import AuthenticatedUser
from app.config import Settings, get_settings
from app.errors import VantageError
from app.ingest.filter import detect_language
from app.routers.analyze import _credentials_for
from app.schemas import SourceFile, SourceFileEntry, SourceTree
from app.source import SourceUnavailable, provider_for
from app.store import get_store

router = APIRouter(prefix="/api/reports", tags=["source"])

MAX_TREE_FILES = 5_000


class SourceNotAvailableError(VantageError):
    """404 with the reason in words, never a bare 'not found'.

    Every way this fails is a different sentence someone can act on — the
    repository went private, the commit was force-pushed away, the upload
    predates blob storage. "Not found" tells nobody anything.
    """

    status_code = 404
    code = "source_unavailable"


def _guard_private(report, user: AuthenticatedUser | None) -> None:
    """Only someone who can already see a private repository may read its files.

    A report id is an unguessable *read* capability, which is what makes a
    report shareable — but the findings quote a few lines while this serves
    whole files. Sharing the link to a private analysis should not hand over the
    source.

    Uses the flag recorded at analysis time rather than asking GitHub, so it
    costs nothing and still works when the rate limit is exhausted.
    """
    if not report.source.private:
        return
    if user is not None:
        return
    raise NotAuthorised(
        "This report is of a private repository.",
        detail=(
            "Sign in to read its files. The report itself stays readable to "
            "anyone holding the link; its source does not."
        ),
    )


@router.get("/{report_id}/files", response_model=SourceTree)
async def list_files(
    report_id: str,
    settings: Settings = Depends(get_settings),
    user: AuthenticatedUser | None = Depends(current_user),
) -> SourceTree:
    report = await get_store().get(report_id)
    _guard_private(report, user)
    try:
        provider = provider_for(report, settings, _credentials_for(user, settings))
        entries = await provider.tree()
    except SourceUnavailable as exc:
        raise SourceNotAvailableError("Source is not available.", detail=exc.reason)

    # Finding counts ride along, so the tree can show where the problems are
    # without the client fetching every file to find out.
    per_file = Counter(f.file for f in report.findings if f.file)

    files = [
        SourceFileEntry(
            path=entry.path,
            size=entry.size,
            language=entry.language,
            analysable=entry.analysable,
            findings=per_file.get(entry.path, 0),
        )
        for entry in entries[:MAX_TREE_FILES]
    ]
    files.sort(key=lambda f: f.path)
    return SourceTree(files=files, truncated=len(entries) > MAX_TREE_FILES)


@router.get("/{report_id}/file", response_model=SourceFile)
async def read_file(
    report_id: str,
    path: str = Query(min_length=1, max_length=1024),
    settings: Settings = Depends(get_settings),
    user: AuthenticatedUser | None = Depends(current_user),
) -> SourceFile:
    """One file, with the findings that point into it.

    The findings come back with the file rather than being joined client-side:
    the viewer needs them to render the gutter on first paint, and a second
    round-trip would mean the markers arrive after the code.
    """
    report = await get_store().get(report_id)
    _guard_private(report, user)
    try:
        provider = provider_for(report, settings, _credentials_for(user, settings))
        content = await provider.read(path)
    except SourceUnavailable as exc:
        raise SourceNotAvailableError("That file is not available.", detail=exc.reason)

    return SourceFile(
        path=path,
        language=detect_language(PurePosixPath(path)),
        content=content,
        lines=content.count("\n") + 1 if content else 0,
        findings=[f for f in report.findings if f.file == path],
    )
