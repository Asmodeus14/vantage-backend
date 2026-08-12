"""Analysis endpoints.

A request starts a job and returns its id immediately; the client then attaches
to an SSE stream for real progress. Keeping the two separate means a slow
analysis never sits behind a request timeout, and the browser gets meaningful
state the whole way through.
"""

# NB: deliberately no `from __future__ import annotations` in this module.
# Postponed evaluation turns annotations into strings, and FastAPI then cannot
# resolve `UploadFile` when it builds the multipart body model — OpenAPI
# generation fails with "is not fully defined".

import asyncio
import logging
import tempfile
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, File, Request, UploadFile
from fastapi.responses import StreamingResponse

from app.analysis.runner import AnalysisRunner, jobs
from app.auth.dependencies import current_user
from app.auth.store import AuthenticatedUser, github_token_for
from app.config import Settings, get_settings
from app.errors import ArchiveTooLargeError, InvalidArchiveError
from app.ingest.github import GitHubCredentials
from app.limiter import limiter
from app.schemas import AnalysisStage, AnalyzeRepositoryRequest, ProgressEvent

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/analyze", tags=["analysis"])

_UPLOAD_CHUNK = 1024 * 1024


@router.post("/repository", status_code=202)
@limiter.limit("20/hour")
async def analyse_repository(
    request: Request,
    body: AnalyzeRepositoryRequest,
    settings: Settings = Depends(get_settings),
    user: Optional[AuthenticatedUser] = Depends(current_user),
) -> dict[str, str]:
    """Start analysis of a GitHub repository.

    Signed in, the analysis runs as the user: it is attributed to them, spends
    their 5000-per-hour GitHub budget rather than the server's shared 60, and
    can reach their private repositories if they granted that scope.
    """
    credentials = _credentials_for(user, settings)

    job = jobs.create()
    runner = AnalysisRunner(settings)
    job.task = asyncio.create_task(
        runner.run_repository(
            job,
            str(body.url),
            body.ref,
            owner_id=user.id if user else None,
            credentials=credentials,
        )
    )
    return {"job_id": job.id}


def _credentials_for(
    user: Optional[AuthenticatedUser], settings: Settings
) -> GitHubCredentials:
    """Prefer the user's own token, falling back to the server's.

    A token that can no longer be decrypted (the encryption key was rotated)
    degrades to the server credentials rather than failing the analysis — the
    user simply gets the shared budget until they sign in again.
    """
    if user is not None:
        token = github_token_for(user, settings)
        if token:
            return GitHubCredentials(token=token, source="user")
    return GitHubCredentials.for_server(settings)


@router.post("/upload", status_code=202)
@limiter.limit("10/hour")
async def analyse_upload(
    request: Request,
    file: UploadFile = File(...),
    settings: Settings = Depends(get_settings),
    user: Optional[AuthenticatedUser] = Depends(current_user),
) -> dict[str, str]:
    """Start analysis of an uploaded ZIP archive.

    The browser posts here directly rather than through the frontend's server,
    because serverless platforms cap proxied request bodies at a few megabytes.
    """
    filename = file.filename or "upload.zip"
    if not filename.lower().endswith(".zip"):
        raise InvalidArchiveError(
            "Only .zip archives are supported.",
            detail="Compress the project folder as a ZIP and try again.",
        )

    workspace = Path(tempfile.mkdtemp(prefix="vantage_upload_"))
    archive_path = workspace / "upload.zip"

    written = 0
    with archive_path.open("wb") as out:
        while chunk := await file.read(_UPLOAD_CHUNK):
            written += len(chunk)
            if written > settings.max_archive_bytes:
                out.close()
                archive_path.unlink(missing_ok=True)
                raise ArchiveTooLargeError(
                    "That archive is too large.",
                    detail=(
                        f"The limit is "
                        f"{settings.max_archive_bytes // (1024 * 1024)}MB. "
                        f"Analysing from a GitHub URL has no such limit."
                    ),
                )
            out.write(chunk)

    if written == 0:
        archive_path.unlink(missing_ok=True)
        raise InvalidArchiveError("The uploaded file is empty.")

    job = jobs.create()
    runner = AnalysisRunner(settings)
    job.task = asyncio.create_task(
        runner.run_upload(
            job, archive_path, filename, owner_id=user.id if user else None
        )
    )
    return {"job_id": job.id}


def _frame(event: ProgressEvent) -> str:
    return f"event: progress\ndata: {event.model_dump_json()}\n\n"


@router.get("/{job_id}/events")
async def stream_events(job_id: str) -> StreamingResponse:
    """Server-Sent Events carrying genuine per-stage progress."""
    job = jobs.get(job_id)
    if job is None:
        async def missing():
            payload = ProgressEvent(
                stage=AnalysisStage.FAILED,
                message="That analysis is no longer available.",
                error="Unknown or expired job id.",
            )
            yield _frame(payload)

        return StreamingResponse(missing(), media_type="text/event-stream")

    async def generate():
        # Read the log by index so a client attaching mid-run replays the
        # history and then continues, without receiving anything twice.
        cursor = 0
        while True:
            while cursor < len(job.events):
                yield _frame(job.events[cursor])
                cursor += 1

            if job.finished:
                break

            if not await job.wait_for_event_after(cursor, timeout=20.0):
                # Keep-alive comment; proxies drop idle connections.
                yield ": keep-alive\n\n"

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-transform",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",  # disable nginx buffering
        },
    )


@router.get("/{job_id}")
async def job_status(job_id: str) -> dict[str, object]:
    """Polling fallback for clients that cannot use SSE."""
    job = jobs.get(job_id)
    if job is None:
        return {"job_id": job_id, "status": "unknown"}
    last = job.events[-1] if job.events else None
    return {
        "job_id": job.id,
        "status": "finished" if job.finished else "running",
        "report_id": job.report_id,
        "stage": last.stage.value if last else AnalysisStage.QUEUED.value,
        "message": last.message if last else "",
    }
