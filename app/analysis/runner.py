"""End-to-end analysis jobs.

A job is started by an HTTP request and then observed over Server-Sent Events,
so the client can show what is actually happening — fetching, extracting,
indexing, which rule is running — instead of v2's progress bar, which was a
static element hardcoded to 100% width.

Jobs are held in this process. With a single web instance that is correct and
simple; scaling to several instances would need the queue moved out of process,
which is noted in the roadmap rather than pretended away.
"""

from __future__ import annotations

import asyncio
import logging
import secrets
import tempfile
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from app.analysis.diffing import compare, is_comparable
from app.analysis.engine import AnalysisEngine, compute_score, severity_counts
from app.analysis.priority import prioritise
from app.config import Settings
from app.errors import VantageError
from app.ingest.archive import (
    ExtractionLimits,
    extract_tar_gz,
    extract_zip,
    remove_tree,
)
from app.ingest.github import (
    GitHubCredentials,
    RepositoryRef,
    fetch_repository,
    parse_repository_url,
)
from app.ingest.history import WINDOW_DAYS as HISTORY_WINDOW_DAYS
from app.ingest.history import collect_activity
from app.ingest.snapshot import Snapshot
from app.jobs import record_failed, record_succeeded
from app.schemas import (
    AnalysisStage,
    Finding,
    FindingDelta,
    IngestStats,
    ProgressEvent,
    Report,
    RepositoryActivity,
    SourceInfo,
    SourceKind,
)
from app.source.blobs import get_blob_store
from app.store import get_store

logger = logging.getLogger(__name__)

JOB_RETENTION_SECONDS = 900


def new_id(prefix: str = "") -> str:
    return f"{prefix}{secrets.token_urlsafe(9)}"


def limits_from(settings: Settings) -> ExtractionLimits:
    return ExtractionLimits(
        max_extracted_bytes=settings.max_extracted_bytes,
        max_file_bytes=settings.max_file_bytes,
        max_file_count=settings.max_file_count,
        max_compression_ratio=settings.max_compression_ratio,
        max_path_depth=settings.max_path_depth,
    )


@dataclass
class Job:
    """Progress log for one analysis.

    The event list is the single source of truth and subscribers read it by
    index, waking on a condition. An earlier version kept both a list and a
    queue, so a client that attached mid-run replayed the history *and* then
    received the same events again from the queue.
    """

    id: str
    created_at: float = field(default_factory=time.monotonic)
    events: list[ProgressEvent] = field(default_factory=list)
    report_id: str | None = None
    finished: bool = False
    task: asyncio.Task | None = None
    _updated: asyncio.Condition = field(default_factory=asyncio.Condition)

    async def emit(self, event: ProgressEvent) -> None:
        async with self._updated:
            self.events.append(event)
            self._updated.notify_all()

    async def close(self) -> None:
        async with self._updated:
            self.finished = True
            self._updated.notify_all()

    async def wait_for_event_after(self, index: int, timeout: float) -> bool:
        """Block until an event beyond ``index`` exists, or the job ends.

        Returns False on timeout so the caller can send a keep-alive.
        """
        try:
            async with self._updated:
                await asyncio.wait_for(
                    self._updated.wait_for(
                        lambda: len(self.events) > index or self.finished
                    ),
                    timeout=timeout,
                )
            return True
        except TimeoutError:
            return False


class JobManager:
    def __init__(self) -> None:
        self._jobs: dict[str, Job] = {}

    def create(self) -> Job:
        self._sweep()
        job = Job(id=new_id("job_"))
        self._jobs[job.id] = job
        return job

    def get(self, job_id: str) -> Job | None:
        return self._jobs.get(job_id)

    def _sweep(self) -> None:
        cutoff = time.monotonic() - JOB_RETENTION_SECONDS
        for job_id in [j for j, job in self._jobs.items() if job.created_at < cutoff]:
            self._jobs.pop(job_id, None)


jobs = JobManager()


class AnalysisRunner:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.engine = AnalysisEngine(settings)

    async def run_repository(
        self,
        job: Job,
        url: str,
        ref: str | None,
        *,
        owner_id: str | None = None,
        credentials: GitHubCredentials | None = None,
    ) -> None:
        workspace = Path(tempfile.mkdtemp(prefix="vantage_"))
        try:
            repository = parse_repository_url(url)
            if ref:
                repository = RepositoryRef(repository.owner, repository.repo, ref)

            await job.emit(
                ProgressEvent(
                    stage=AnalysisStage.FETCHING,
                    message=f"Fetching {repository.full_name}",
                )
            )
            fetched = await fetch_repository(
                repository, workspace, self.settings, credentials
            )

            await job.emit(
                ProgressEvent(
                    stage=AnalysisStage.EXTRACTING,
                    message=f"Extracting {repository.repo}",
                )
            )
            root = workspace / "src"
            extraction = extract_tar_gz(
                fetched.archive_path,
                root,
                limits=limits_from(self.settings),
                strip_components=1,  # GitHub wraps everything in owner-repo-sha/
            )
            fetched.archive_path.unlink(missing_ok=True)

            source = SourceInfo(
                kind=SourceKind.REPOSITORY,
                repository=repository.full_name,
                ref=fetched.resolved_ref,
                commit=fetched.commit,
                url=repository.html_url,
                private=fetched.private,
            )
            await self._analyse(
                job,
                root,
                source,
                extraction,
                repository=repository,
                owner_id=owner_id,
                credentials=credentials,
            )
        except VantageError as exc:
            await self._fail(job, exc.message, exc.detail)
        except Exception:
            logger.exception("Repository analysis failed")
            await self._fail(job, "Analysis failed unexpectedly.")
        finally:
            remove_tree(workspace)

    async def run_upload(
        self,
        job: Job,
        archive: Path,
        filename: str,
        *,
        owner_id: str | None = None,
    ) -> None:
        workspace = archive.parent
        try:
            await job.emit(
                ProgressEvent(
                    stage=AnalysisStage.EXTRACTING, message=f"Extracting {filename}"
                )
            )
            root = workspace / "src"
            extraction = extract_zip(archive, root, limits=limits_from(self.settings))
            archive.unlink(missing_ok=True)

            source = SourceInfo(kind=SourceKind.UPLOAD, filename=filename)
            await self._analyse(job, root, source, extraction, owner_id=owner_id)
        except VantageError as exc:
            await self._fail(job, exc.message, exc.detail)
        except Exception:
            logger.exception("Upload analysis failed")
            await self._fail(job, "Analysis failed unexpectedly.")
        finally:
            remove_tree(workspace)

    # -- shared tail of both paths -------------------------------------

    async def _analyse(
        self,
        job: Job,
        root: Path,
        source: SourceInfo,
        extraction,
        repository: RepositoryRef | None = None,
        owner_id: str | None = None,
        credentials: GitHubCredentials | None = None,
    ) -> None:
        snapshot = Snapshot.build(root)

        findings, project, dependencies, duration, rule_ids = await asyncio.wait_for(
            self.engine.analyse(snapshot, progress=job.emit),
            timeout=self.settings.analysis_timeout_seconds,
        )

        await job.emit(
            ProgressEvent(stage=AnalysisStage.SCORING, message="Scoring results")
        )

        # Order before truncating. The cap used to fall wherever the rules
        # happened to finish, so a repository over the limit could lose a
        # critical secret and keep thirty long-file measurements — the cap
        # decided what mattered, arbitrarily. Sorted worst-first, the cap now
        # drops the least important findings by construction.
        findings = prioritise(findings)

        truncated = len(findings) > self.settings.max_findings
        findings = findings[: self.settings.max_findings]

        # Scored after truncation, as before: the score describes the findings
        # the report actually contains.
        score = compute_score(findings, project.analysed_files)

        activity = await self._activity(job, repository, findings, credentials)

        report = Report(
            id=new_id(),
            created_at=datetime.now(UTC),
            duration_seconds=round(duration, 2),
            source=source,
            project=project,
            score=score,
            severity_counts=severity_counts(findings),
            findings=findings,
            dependencies=dependencies,
            ingest=IngestStats(
                files_extracted=extraction.file_count,
                files_analysed=project.analysed_files,
                bytes_extracted=extraction.total_bytes,
                compression_ratio=extraction.compression_ratio,
                rejected_entries=dict(extraction.rejected),
            ),
            activity=activity,
            truncated=truncated,
            rule_ids=rule_ids,
        )

        report.delta = await self._delta(report, owner_id=owner_id)

        await job.emit(
            ProgressEvent(stage=AnalysisStage.PERSISTING, message="Saving report")
        )
        await get_store().save(report, owner_id=owner_id)
        await self._store_source(report, snapshot)

        job.report_id = report.id
        # Recorded before the event is emitted. A client that reconnects in the
        # gap between the two must find the outcome rather than a job that is
        # still marked running.
        await record_succeeded(job.id, report.id)
        await job.emit(
            ProgressEvent(
                stage=AnalysisStage.DONE,
                message=f"Found {len(findings)} findings",
                completed=1,
                total=1,
                report_id=report.id,
            )
        )
        await job.close()

    async def _store_source(self, report: Report, snapshot: Snapshot) -> None:
        """Keep an upload's files so they can be viewed later.

        Uploads only. A repository's source is re-fetched from GitHub pinned to
        the analysed commit, which costs nothing to store and cannot go stale;
        an upload is bytes someone sent once, with no URL that would produce
        them again.

        Failing here must not fail the analysis. The report is the product and
        it is already saved; losing the source means the viewer says so, which
        is a smaller loss than losing the findings.
        """
        if report.source.kind != SourceKind.UPLOAD:
            return
        try:
            kept = await get_blob_store().put(report.id, snapshot)
            logger.info("Stored %d source files for %s", kept, report.id)
        except Exception:
            logger.exception("Could not store source for %s", report.id)

    async def _delta(
        self, report: Report, *, owner_id: str | None = None
    ) -> FindingDelta | None:
        """Compare against the previous analysis of the same repository.

        Like commit history, this is context on top of the findings rather than
        the product itself, so a store hiccup must not lose a completed report.
        The difference is that a failure here is silent: there is no honest way
        to say "this comparison is partial", and a delta that omits half the
        resolved findings would assert something false. Absent means "not
        compared", which the UI already renders as nothing at all.
        """
        repository = report.source.repository
        if repository is None:
            return None
        try:
            previous = await get_store().latest_for(repository, owner_id=owner_id)
        except Exception:
            logger.exception("Could not load the previous report for %s", repository)
            return None
        if previous is None or not is_comparable(report, previous):
            return None
        return compare(report, previous)

    async def _activity(
        self,
        job: Job,
        repository: RepositoryRef | None,
        findings: list[Finding],
        credentials: GitHubCredentials | None = None,
    ) -> RepositoryActivity | None:
        """Commit history, if there is a repository to ask about.

        Enrichment must never fail an analysis. The findings are the product;
        commit history is context on top of them, and a GitHub outage or an
        exhausted rate limit is not a reason to throw away a completed report.
        """
        if repository is None:
            return None

        await job.emit(
            ProgressEvent(
                stage=AnalysisStage.ENRICHING, message="Reading commit history"
            )
        )
        try:
            return await collect_activity(
                repository, findings, self.settings, credentials
            )
        except Exception:
            logger.exception("Commit history enrichment failed")
            return RepositoryActivity(
                window_days=HISTORY_WINDOW_DAYS,
                partial=True,
                unavailable_reason=(
                    "Commit history could not be read for this analysis."
                ),
            )

    async def _fail(self, job: Job, message: str, detail: str | None = None) -> None:
        await record_failed(job.id, detail or message)
        await job.emit(
            ProgressEvent(
                stage=AnalysisStage.FAILED,
                message=message,
                error=detail or message,
            )
        )
        await job.close()
