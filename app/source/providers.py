"""The two ways a report's source is reachable, behind one interface."""

from __future__ import annotations

import base64
import binascii
import logging
from pathlib import PurePosixPath
from posixpath import normpath

import httpx

from app.config import Settings
from app.ingest.filter import detect_language
from app.ingest.github import GitHubCredentials, RepositoryRef, build_headers
from app.schemas import Report, SourceKind
from app.source.base import SourceEntry, SourceProvider, SourceUnavailable
from app.source.blobs import get_blob_store

logger = logging.getLogger(__name__)

GITHUB_API = "https://api.github.com"
# A tree response for a large monorepo is megabytes of JSON. The viewer shows a
# sidebar, not an inventory.
MAX_TREE_ENTRIES = 5_000
MAX_FILE_BYTES = 1_000_000


def safe_path(path: str) -> str:
    """Reject anything that tries to leave the project.

    The viewer takes a path straight from a URL, and both providers interpolate
    it — one into a GitHub URL, one into a SQL parameter. Normalising first
    means `..` is refused here rather than relied on to be harmless twice.
    """
    cleaned = path.strip().lstrip("/")
    if not cleaned:
        raise SourceUnavailable("No file was requested.")
    normalised = normpath(cleaned)
    if normalised.startswith("..") or normalised.startswith("/") or "\\" in cleaned:
        raise SourceUnavailable("That path is not inside this project.")
    return normalised


class StoredSourceProvider:
    """Uploads. The bytes were sent once and cannot be asked for again."""

    def __init__(self, report_id: str) -> None:
        self._report_id = report_id

    async def tree(self) -> list[SourceEntry]:
        entries = await get_blob_store().tree(self._report_id)
        if not entries:
            raise SourceUnavailable(
                "The source for this upload was not kept. Uploads analysed "
                "before file viewing existed did not store their files; "
                "re-upload the archive to browse it."
            )
        return entries

    async def read(self, path: str) -> str:
        return await get_blob_store().read(self._report_id, safe_path(path))


class GitHubSourceProvider:
    """Repositories, pinned to the commit that was analysed.

    Pinned, not "latest": a finding says line 47, and line 47 only means
    anything against the tree the analysis actually saw. Reading the branch head
    would quietly show the wrong line as soon as anyone pushed.
    """

    def __init__(
        self,
        repository: RepositoryRef,
        commit: str,
        settings: Settings,
        credentials: GitHubCredentials | None = None,
    ) -> None:
        self._repository = repository
        self._commit = commit
        self._settings = settings
        self._credentials = credentials

    def _client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            headers=build_headers(self._settings, self._credentials),
            timeout=self._settings.github_timeout_seconds,
            follow_redirects=True,
        )

    def _unavailable(self, status: int) -> SourceUnavailable:
        if status == 404:
            return SourceUnavailable(
                "GitHub no longer has this file at the analysed commit. The "
                "repository may have been deleted or made private, or the "
                "commit removed by a force-push."
            )
        if status in (401, 403):
            return SourceUnavailable(
                "GitHub refused the request. This is usually the API rate "
                "limit — signing in raises it from 60 requests an hour to "
                "5000 — or a private repository this account cannot read."
            )
        return SourceUnavailable(f"GitHub returned {status} for this file.")

    async def tree(self) -> list[SourceEntry]:
        owner, repo = self._repository.owner, self._repository.repo
        url = f"{GITHUB_API}/repos/{owner}/{repo}/git/trees/{self._commit}"
        try:
            async with self._client() as client:
                response = await client.get(url, params={"recursive": "1"})
        except httpx.HTTPError as exc:
            logger.warning("GitHub tree fetch failed: %s", exc)
            raise SourceUnavailable("Could not reach GitHub to list the files.")

        if response.status_code != 200:
            raise self._unavailable(response.status_code)

        payload = response.json()
        entries: list[SourceEntry] = []
        for node in payload.get("tree", [])[:MAX_TREE_ENTRIES]:
            if node.get("type") != "blob":
                continue
            path = node.get("path") or ""
            size = int(node.get("size") or 0)
            entries.append(
                SourceEntry(
                    path=path,
                    size=size,
                    language=detect_language(PurePosixPath(path)),
                    analysable=size <= MAX_FILE_BYTES,
                )
            )
        return entries

    async def read(self, path: str) -> str:
        cleaned = safe_path(path)
        owner, repo = self._repository.owner, self._repository.repo
        url = f"{GITHUB_API}/repos/{owner}/{repo}/contents/{cleaned}"
        try:
            async with self._client() as client:
                response = await client.get(url, params={"ref": self._commit})
        except httpx.HTTPError as exc:
            logger.warning("GitHub file fetch failed: %s", exc)
            raise SourceUnavailable("Could not reach GitHub to read that file.")

        if response.status_code != 200:
            raise self._unavailable(response.status_code)

        payload = response.json()
        if isinstance(payload, list):
            raise SourceUnavailable("That path is a directory, not a file.")
        if payload.get("encoding") != "base64":
            raise SourceUnavailable("GitHub returned that file in a form we cannot read.")

        try:
            raw = base64.b64decode(payload.get("content") or "")
        except (binascii.Error, ValueError):
            raise SourceUnavailable("That file could not be decoded.")
        if b"\x00" in raw[:8_000]:
            raise SourceUnavailable("That file is binary.")
        return raw.decode("utf-8", errors="replace")


def provider_for(
    report: Report,
    settings: Settings,
    credentials: GitHubCredentials | None = None,
) -> SourceProvider:
    """Pick an implementation from what the report was made from.

    The one place the hybrid split is decided. Callers take a provider.
    """
    if report.source.kind == SourceKind.UPLOAD:
        return StoredSourceProvider(report.id)

    repository, commit = report.source.repository, report.source.commit
    if not repository or "/" not in repository:
        raise SourceUnavailable("This report records no repository to read from.")
    if not commit:
        raise SourceUnavailable(
            "This report predates commit pinning, so its files cannot be "
            "matched to the code that was analysed. Re-analyse the repository "
            "to browse it."
        )

    owner, name = repository.split("/", 1)
    return GitHubSourceProvider(
        RepositoryRef(owner, name, report.source.ref or commit),
        commit,
        settings,
        credentials,
    )
