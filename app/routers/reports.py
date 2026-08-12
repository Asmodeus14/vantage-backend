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
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from app.auth.dependencies import NotAuthorised, current_user
from app.auth.store import AuthenticatedUser
from app.schemas import Report, ReportSummary
from app.store import get_store

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


@router.get("/{report_id}", response_model=Report)
async def get_report(report_id: str) -> Report:
    """Anyone holding the id may read it — that is what makes a report link
    shareable, and the id is unguessable."""
    return await get_store().get(report_id)


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
