"""API contract.

These models are the single source of truth for the shape of every response.
v2's frontend guessed at field names (`getSolutionText` checked four different
keys, `getIssueLocation` another four) because no contract existed and the UI
rendered several fields the backend never sent. Everything the client can rely
on is declared here.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Literal

from pydantic import BaseModel, Field, HttpUrl


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Category(str, Enum):
    SECURITY = "security"
    DEPENDENCIES = "dependencies"
    CORRECTNESS = "correctness"
    QUALITY = "quality"
    PERFORMANCE = "performance"
    TESTING = "testing"
    CONFIGURATION = "configuration"


class Confidence(str, Enum):
    """How sure the rule is. Surfaced so users can triage false positives."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class SourceKind(str, Enum):
    REPOSITORY = "repository"
    UPLOAD = "upload"


# --------------------------------------------------------------------------
# Findings
# --------------------------------------------------------------------------

class Finding(BaseModel):
    """A single issue, always anchored to a location when one exists.

    ``file``/``line`` are optional only for genuinely project-wide findings
    (e.g. "no test framework configured"), never as a fallback for "we didn't
    bother to record where".
    """

    id: str = Field(description="Stable within a report; used for AI actions.")
    rule_id: str = Field(description="e.g. 'js/prefer-let', 'dep/known-vulnerability'")
    title: str
    description: str
    category: Category
    severity: Severity
    confidence: Confidence = Confidence.HIGH

    file: str | None = Field(default=None, description="Repo-relative POSIX path.")
    line: int | None = Field(default=None, ge=1)
    end_line: int | None = Field(default=None, ge=1)
    snippet: str | None = Field(default=None, description="Source at the location.")
    snippet_start_line: int | None = Field(
        default=None,
        ge=1,
        description=(
            "1-indexed line of the snippet's first line, so a viewer can render "
            "correct gutter numbers instead of assuming it starts at `line`."
        ),
    )

    remediation: str | None = Field(default=None, description="What to do about it.")
    references: list[str] = Field(default_factory=list, description="URLs / CVE ids.")

    @property
    def is_located(self) -> bool:
        return self.file is not None and self.line is not None


# --------------------------------------------------------------------------
# Project intelligence
# --------------------------------------------------------------------------

class LanguageStat(BaseModel):
    language: str
    files: int
    lines: int
    share: float = Field(ge=0.0, le=1.0)


class DependencyInfo(BaseModel):
    name: str
    version_spec: str = Field(description="As written in the manifest, e.g. '^4.17.0'")
    resolved_version: str | None = Field(
        default=None, description="From the lockfile, when one is present."
    )
    ecosystem: str = "npm"
    is_dev: bool = False
    vulnerabilities: list[str] = Field(
        default_factory=list, description="OSV / CVE identifiers."
    )


class ProjectInfo(BaseModel):
    name: str | None = None
    description: str | None = None
    languages: list[LanguageStat] = Field(default_factory=list)
    frameworks: list[str] = Field(default_factory=list)
    package_managers: list[str] = Field(default_factory=list)
    entry_points: list[str] = Field(default_factory=list)
    total_files: int = 0
    analysed_files: int = 0
    total_lines: int = 0
    has_tests: bool = False
    has_ci: bool = False
    has_lockfile: bool = False


# --------------------------------------------------------------------------
# Scoring
# --------------------------------------------------------------------------

class CategoryScore(BaseModel):
    category: Category
    score: int = Field(ge=0, le=100)
    findings: int
    weight: float


class Score(BaseModel):
    """A health score the UI can explain rather than just display.

    v2 computed ``100 - 10*high`` which floored at 0 for any sizeable project
    and told the user nothing about why.
    """

    value: int = Field(ge=0, le=100)
    grade: Literal["A", "B", "C", "D", "F"]
    categories: list[CategoryScore] = Field(default_factory=list)
    summary: str = Field(description="One sentence explaining the score.")


class SeverityCounts(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0

    @property
    def total(self) -> int:
        return self.critical + self.high + self.medium + self.low + self.info


# --------------------------------------------------------------------------
# Ingestion provenance — what was actually analysed
# --------------------------------------------------------------------------

class SourceInfo(BaseModel):
    kind: SourceKind
    repository: str | None = Field(default=None, description="'owner/name'")
    ref: str | None = Field(default=None, description="Branch or commit analysed.")
    commit: str | None = None
    url: str | None = None
    filename: str | None = Field(default=None, description="For uploads.")


class IngestStats(BaseModel):
    """Transparency about what was skipped, and why."""

    files_extracted: int = 0
    files_analysed: int = 0
    bytes_extracted: int = 0
    compression_ratio: float = 0.0
    skipped_directories: list[str] = Field(default_factory=list)
    rejected_entries: dict[str, int] = Field(
        default_factory=dict,
        description="Unsafe archive entries by reason, e.g. {'symlink': 2}.",
    )


# --------------------------------------------------------------------------
# Reports
# --------------------------------------------------------------------------

class ReportSummary(BaseModel):
    """Row shape for the history list."""

    id: str
    created_at: datetime
    source: SourceInfo
    score: int
    grade: str
    severity_counts: SeverityCounts
    total_findings: int
    duration_seconds: float


class ChurnEntry(BaseModel):
    """How often a file carrying findings actually changes."""

    file: str
    changes: int = Field(description="Commits touching this file in the window.")
    findings: int
    top_severity: Severity


class RepositoryActivity(BaseModel):
    """Commit history for a repository, from the GitHub API.

    The analyser works from a tarball, which contains no ``.git`` — so none of
    this can be derived from the snapshot and it is fetched separately. It is
    always optional: an uploaded archive has no repository, and GitHub can be
    rate-limited or still computing its statistics.
    """

    window_days: int
    weekly_commits: list[int] = Field(
        default_factory=list,
        description="Oldest week first. Empty when GitHub had not computed it.",
    )
    churn: list[ChurnEntry] = Field(default_factory=list)
    files_with_findings: int = Field(
        default=0,
        description=(
            "Files carrying a finding. Larger than len(churn) when the "
            "per-file lookup was capped — the cap is a designed bound, not a "
            "failure, so it does not set `partial`."
        ),
    )
    partial: bool = Field(
        default=False, description="True when some of this could not be fetched."
    )
    unavailable_reason: str | None = Field(
        default=None, description="Why it is partial, in words fit for the UI."
    )


class Report(BaseModel):
    id: str
    created_at: datetime
    duration_seconds: float
    source: SourceInfo
    project: ProjectInfo
    score: Score
    severity_counts: SeverityCounts
    findings: list[Finding]
    dependencies: list[DependencyInfo] = Field(default_factory=list)
    ingest: IngestStats
    activity: RepositoryActivity | None = Field(
        default=None,
        description=(
            "Absent for uploads, and for repositories whose history could not "
            "be read at all."
        ),
    )
    truncated: bool = Field(
        default=False, description="True when findings were capped."
    )


# --------------------------------------------------------------------------
# Requests
# --------------------------------------------------------------------------

class AnalyzeRepositoryRequest(BaseModel):
    url: HttpUrl = Field(description="A GitHub repository URL.")
    ref: str | None = Field(
        default=None, description="Branch, tag or commit. Defaults to the default branch."
    )


# --------------------------------------------------------------------------
# Sign-in
# --------------------------------------------------------------------------

class AuthStatus(BaseModel):
    """Whether sign-in can be offered at all."""

    configured: bool
    reason: str | None = Field(
        default=None,
        description="Why sign-in is unavailable. Shown to the user verbatim.",
    )


class SessionRequest(BaseModel):
    """Server-to-server: the frontend hands over a freshly-issued GitHub token."""

    access_token: str = Field(min_length=1)
    scopes: str = Field(
        default="",
        description="Space-separated scopes GitHub actually granted.",
    )


class CurrentUser(BaseModel):
    id: str
    login: str
    name: str | None = None
    avatar_url: str | None = None
    scopes: list[str] = Field(default_factory=list)
    can_read_private_repositories: bool = False


class SessionCreated(BaseModel):
    session_token: str
    user: CurrentUser


# --------------------------------------------------------------------------
# Health
# --------------------------------------------------------------------------

class DependencyHealth(BaseModel):
    configured: bool
    available: bool
    detail: str | None = None


class AIHealth(BaseModel):
    configured: bool
    available: bool
    state: str
    model: str | None = None
    reason: str | None = None
    retry_after_seconds: float | None = None


class HealthResponse(BaseModel):
    status: Literal["ok", "degraded"]
    version: str
    environment: str
    auth: "AuthStatus" = Field(
        default_factory=lambda: AuthStatus(configured=False, reason=None)
    )
    timestamp: datetime
    ai: AIHealth
    database: DependencyHealth


# --------------------------------------------------------------------------
# Streaming progress
# --------------------------------------------------------------------------

class AnalysisStage(str, Enum):
    QUEUED = "queued"
    FETCHING = "fetching"
    EXTRACTING = "extracting"
    INDEXING = "indexing"
    ANALYSING = "analysing"
    SCORING = "scoring"
    ENRICHING = "enriching"
    PERSISTING = "persisting"
    DONE = "done"
    FAILED = "failed"


class AIActionRequest(BaseModel):
    """The only thing a client may ask the model to do.

    Note there is no free-text field. The caller selects an operation; the
    prompt is assembled server-side from stored analysis data. This is what
    stops the endpoint being usable as a general-purpose LLM proxy.
    """

    action: Literal["explain", "propose_fix", "generate_test"]


class AIActionResponse(BaseModel):
    action: str
    output: str
    model: str | None = None
    #: Exactly what the model was shown, so the user can judge the answer.
    context: str
    cached: bool = False


class ProgressEvent(BaseModel):
    """One SSE frame. Replaces v2's hardcoded 100%-width progress bar."""

    stage: AnalysisStage
    message: str
    completed: int = 0
    total: int = 0
    report_id: str | None = None
    error: str | None = None
