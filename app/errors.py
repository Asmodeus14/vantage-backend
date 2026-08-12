"""Domain exceptions.

Each carries an HTTP status and a stable machine-readable ``code`` so the
frontend can branch on failures without string-matching prose.
"""

from __future__ import annotations


class VantageError(Exception):
    """Base class for all expected (non-bug) failures."""

    status_code: int = 400
    code: str = "error"

    def __init__(self, message: str, *, detail: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.detail = detail

    def to_payload(self) -> dict[str, object]:
        payload: dict[str, object] = {"code": self.code, "message": self.message}
        if self.detail:
            payload["detail"] = self.detail
        return payload


class UnsafeArchiveError(VantageError):
    """Archive tried to do something it shouldn't (traversal, symlink, bomb)."""

    status_code = 422
    code = "unsafe_archive"


class ArchiveTooLargeError(VantageError):
    status_code = 413
    code = "archive_too_large"


class InvalidArchiveError(VantageError):
    status_code = 400
    code = "invalid_archive"


class InvalidRepositoryError(VantageError):
    status_code = 400
    code = "invalid_repository"


class RepositoryFetchError(VantageError):
    status_code = 502
    code = "repository_fetch_failed"


class RepositoryNotFoundError(VantageError):
    status_code = 404
    code = "repository_not_found"


class RateLimitedError(VantageError):
    status_code = 429
    code = "rate_limited"


class ReportNotFoundError(VantageError):
    status_code = 404
    code = "report_not_found"


class AIUnavailableError(VantageError):
    """The LLM is not configured, or is temporarily circuit-broken."""

    status_code = 503
    code = "ai_unavailable"


class AnalysisTimeoutError(VantageError):
    status_code = 504
    code = "analysis_timeout"
