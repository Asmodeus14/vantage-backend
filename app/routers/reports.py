"""Report retrieval.

Reports have stable ids and their own URLs, which is what makes a result
shareable and survivable across a refresh — v2 held the result in React state
and lost it on reload.

Ownership model:

===================  ================  =====================  ==============
Report               Reachable by id   Appears in the listing  Deletable
===================  ================  =====================  ==============
Anonymous            yes               only when signed out    no
Owned                yes               for its owner only      by its owner
===================  ================  =====================  ==============

Ids are ``secrets.token_urlsafe(9)``, so "reachable by id" is an unguessable
capability, not an open door. Listing is the part that has to be scoped: before
this, ``GET /api/reports`` handed every caller the index of everyone's analyses.

Suppressions follow the same shape: reading a report applies its *owner's*
accepted findings, so a shared link means one thing to everyone, while
*changing* them requires being that owner.
"""

from __future__ import annotations

import json

from fastapi import APIRouter, Depends, Query
from fastapi.responses import Response

from app.analysis.scoring import compute_score
from app.auth.dependencies import NotAuthorised, current_user, require_user
from app.auth.store import AuthenticatedUser
from app.config import Settings, get_settings
from app.errors import ReportNotFoundError
from app.export.pr_comment import render_comment
from app.export.sarif import to_sarif
from app.ingest.pull_request import (
    fetch_pull_request,
    parse_pull_request_url,
    upsert_comment,
)
from app.routers.analyze import _credentials_for
from app.schemas import (
    Finding,
    PullRequestCommentRequest,
    PullRequestCommentResult,
    Report,
    ReportSummary,
    Suppression,
    SuppressionRequest,
)
from app.source.blobs import get_blob_store
from app.store import get_store
from app.suppressions import get_suppression_store, new_suppression

router = APIRouter(prefix="/api/reports", tags=["reports"])


@router.get("", response_model=list[ReportSummary])
async def list_reports(
    limit: int = Query(default=25, ge=1, le=100),
    repository: str | None = Query(
        default=None,
        max_length=255,
        description="Exact `owner/name` match, for a single project's history.",
    ),
    user: AuthenticatedUser | None = Depends(current_user),
) -> list[ReportSummary]:
    return await get_store().list(
        limit=limit,
        repository=repository,
        owner_id=user.id if user else None,
    )


def _mark(report: Report, reasons: dict[str, str]) -> int:
    """Flag accepted findings on ``report`` and return how many.

    The one place a report is measured against a suppression set, so the number
    on the report page and the number cached for the listing cannot disagree
    about what "accepted" means.
    """
    suppressed = 0
    for finding in report.findings:
        if finding.fingerprint and finding.fingerprint in reasons:
            finding.suppressed = True
            finding.suppression_reason = reasons[finding.fingerprint] or None
            suppressed += 1
    report.suppressed_count = suppressed
    if suppressed:
        report.effective_score = compute_score(
            [f for f in report.findings if not f.suppressed],
            report.project.analysed_files,
        )
    return suppressed


async def _refresh_effective_scores(owner_id: str, repository: str) -> None:
    """Recompute the cached score for every report of this repository.

    A suppression applies to the repository, not to one analysis, so accepting
    a finding changes the score of every past report that contained it — and
    History reads those from indexed columns rather than from the payload.

    Deliberately a fan-out write rather than work moved to read time: listings
    are frequent and this is not. It is bounded by ``reports_for``, and a
    failure here leaves the cache stale while the report pages stay correct,
    because those compute the value directly.
    """
    store = get_store()
    entries = await get_suppression_store().list(owner_id, repository)
    reasons = {entry.fingerprint: entry.reason for entry in entries}

    updates: list[tuple[str, int | None, int]] = []
    for report in await store.reports_for(repository, owner_id=owner_id):
        count = _mark(report, reasons)
        updates.append(
            (
                report.id,
                report.effective_score.value if report.effective_score else None,
                count,
            )
        )
    # Collected, then written once. Writing inside the loop meant one network
    # round-trip per report, and on a managed database that is tens of
    # milliseconds each — a click could block for seconds.
    await store.set_effective_scores(updates)


async def _apply_suppressions(report: Report, owner_id: str | None) -> Report:
    """Mark accepted findings and recompute the score without them.

    The *owner's* suppressions are applied, not the viewer's, so a shared link
    shows one thing to everyone who opens it. The alternative — filtering per
    viewer — means two people discussing the same URL are looking at different
    reports, which is worse than the mild oddity of seeing someone else's
    judgement.

    Findings are marked rather than removed. Dropping them would leave
    ``suppressed_count`` unverifiable and make "show suppressed" a second
    round-trip.
    """
    repository = report.source.repository
    if owner_id is None or repository is None:
        return report

    entries = await get_suppression_store().list(owner_id, repository)
    if not entries:
        return report

    # `score` stays exactly what the analysis produced; this is an addition, not
    # an edit. Computed on read so removing a suppression takes effect without
    # re-analysing, and so this page is right even when the listing's cache is.
    _mark(report, {entry.fingerprint: entry.reason for entry in entries})
    return report


@router.get("/{report_id}", response_model=Report)
async def get_report(
    report_id: str,
    user: AuthenticatedUser | None = Depends(current_user),
) -> Report:
    """Anyone holding the id may read it — that is what makes a report link
    shareable, and the id is unguessable."""
    store = get_store()
    # One round trip, not two. Both values come off the same row, and a query
    # on this path costs about 1.35s against the deployed database.
    report, owner_id = await store.get_with_owner(report_id)

    report = await _apply_suppressions(report, owner_id)
    # Varies by viewer, unlike the rest of the report: it exists so the UI can
    # omit an action that would only ever be refused.
    report.can_suppress = (
        user is not None
        and owner_id == user.id
        and report.source.repository is not None
    )
    return report


@router.get("/{report_id}/sarif")
async def get_report_sarif(report_id: str) -> Response:
    """The same report as SARIF 2.1.0.

    Exposure matches `get_report` exactly and deliberately: anyone holding the
    id may read it, because that is what makes a report link shareable and the
    id is unguessable. Adding an ownership check *here* would not protect
    anything — the same content is already served as JSON one route up — it
    would only make the export inconsistent with the page it exports.

    Suppressions are applied first, so an accepted finding is exported marked
    as suppressed rather than exported as though nobody had looked at it.

    Served as a download: the point of this endpoint is a file that goes into
    another tool, and `Content-Disposition` is the difference between that and
    a wall of JSON in a browser tab.
    """
    store = get_store()
    report, owner_id = await store.get_with_owner(report_id)
    report = await _apply_suppressions(report, owner_id)

    return Response(
        content=json.dumps(to_sarif(report), indent=2),
        media_type="application/sarif+json",
        headers={
            "Content-Disposition": (
                f'attachment; filename="{report_id}.vantage.sarif"'
            )
        },
    )


@router.post("/{report_id}/pull-request-comment", response_model=PullRequestCommentResult)
async def comment_on_pull_request(
    report_id: str,
    body: PullRequestCommentRequest,
    user: AuthenticatedUser = Depends(require_user),
    settings: Settings = Depends(get_settings),
) -> PullRequestCommentResult:
    """Leave one consolidated comment on a pull request.

    Posted as the signed-in user, on their own token and their own rate limit,
    reaching exactly the repositories they already granted. Sign-in is required
    because there is no anonymous identity that could write to someone's pull
    request — and GitHub, not this endpoint, decides whether they may.

    The report is read with its owner's suppressions applied, so an accepted
    finding does not reappear in the comment as though nobody had looked at it.
    """
    store = get_store()
    report, owner_id = await store.get_with_owner(report_id)
    report = await _apply_suppressions(report, owner_id)

    ref = parse_pull_request_url(body.pull_request_url)
    credentials = _credentials_for(user, settings)

    # Resolved before commenting so the comment names the commit it describes.
    # A comment that says "main" cannot be checked against anything later.
    info = await fetch_pull_request(ref, settings, credentials)

    markdown = render_comment(
        report,
        report_url=f"{settings.app_base_url.rstrip('/')}/r/{report.id}",
        head_sha=info.head_sha,
    )
    comment_url = await upsert_comment(ref, markdown, settings, credentials)

    return PullRequestCommentResult(
        comment_url=comment_url,
        pull_request_url=info.html_url or body.pull_request_url,
        head_sha=info.head_sha,
    )


@router.get("/{report_id}/suppressions", response_model=list[Suppression])
async def list_suppressions(
    report_id: str,
    user: AuthenticatedUser | None = Depends(current_user),
) -> list[Suppression]:
    """Everything the caller has accepted for this report's repository.

    Scoped to the caller rather than the report owner: this is the editable
    list, and offering someone a list they cannot act on is worse than not
    offering it.
    """
    report = await get_store().get(report_id)
    if user is None or report.source.repository is None:
        return []
    return await get_suppression_store().list(user.id, report.source.repository)


async def _owned_finding(
    report_id: str, finding_id: str, user: AuthenticatedUser | None
) -> tuple[Report, Finding]:
    """The report must be the caller's, and the finding must be in it."""
    store = get_store()
    report, owner_id = await store.get_with_owner(report_id)

    if user is None or owner_id != user.id:
        raise NotAuthorised(
            "That report isn't yours to change.",
            detail=(
                "Accepting a finding records who accepted it, so it needs an "
                "account — and reports created without signing in have no owner "
                "to check against."
            ),
        )

    if report.source.repository is None:
        raise NotAuthorised(
            "Findings from an uploaded archive cannot be accepted.",
            detail=(
                "An acceptance carries forward to future analyses of the same "
                "repository. An upload has no stable identity to carry it to."
            ),
        )

    finding = next((f for f in report.findings if f.id == finding_id), None)
    if finding is None:
        raise ReportNotFoundError("No finding with that id in this report.")
    if not finding.fingerprint:
        raise NotAuthorised(
            "This finding predates stable identity and cannot be accepted.",
            detail=(
                "It comes from a report analysed before findings carried a "
                "fingerprint, so an acceptance could not be matched on a "
                "re-run. Re-analyse the repository and accept it there."
            ),
        )
    return report, finding


@router.put("/{report_id}/findings/{finding_id}/suppression", status_code=204)
async def suppress_finding(
    report_id: str,
    finding_id: str,
    body: SuppressionRequest,
    user: AuthenticatedUser | None = Depends(current_user),
) -> None:
    """Accept a finding, for every analysis of this repository.

    ``PUT`` rather than ``POST``: accepting an already-accepted finding updates
    the reason and is otherwise a no-op, which is exactly idempotent.
    """
    report, finding = await _owned_finding(report_id, finding_id, user)
    assert user is not None and report.source.repository is not None
    await get_suppression_store().add(
        user.id,
        report.source.repository,
        new_suppression(
            fingerprint=finding.fingerprint,
            reason=body.reason,
            title=finding.title,
            rule_id=finding.rule_id,
        ),
    )
    await _refresh_effective_scores(user.id, report.source.repository)


@router.delete("/{report_id}/findings/{finding_id}/suppression", status_code=204)
async def unsuppress_finding(
    report_id: str,
    finding_id: str,
    user: AuthenticatedUser | None = Depends(current_user),
) -> None:
    """Restore a finding. Takes effect on the next read, with no re-analysis."""
    report, finding = await _owned_finding(report_id, finding_id, user)
    assert user is not None and report.source.repository is not None
    await get_suppression_store().remove(
        user.id, report.source.repository, finding.fingerprint
    )
    await _refresh_effective_scores(user.id, report.source.repository)


@router.delete("/{report_id}", status_code=204)
async def delete_report(
    report_id: str,
    user: AuthenticatedUser | None = Depends(current_user),
) -> None:
    store = get_store()
    owner = await store.owner_of(report_id)

    # Anonymous reports have no owner to authorise against, so nobody may
    # delete them through this endpoint. Allowing it would turn an unguessable
    # id into a destructive capability held by anyone it was ever shared with.
    if owner is None or user is None or owner != user.id:
        raise NotAuthorised(
            "That report isn't yours to delete.",
            detail=(
                "Reports created without signing in cannot be deleted, because "
                "there is no account to check against."
            ),
        )

    await store.delete(report_id)
    # Stored source outlives its report otherwise, and nothing would ever
    # reference it again — a leak that only shows up as a growing disk bill.
    await get_blob_store().delete(report_id)
